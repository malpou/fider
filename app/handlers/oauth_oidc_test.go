package handlers_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
)

// mappedProviderConfig is a custom OIDC provider with role mapping configured.
func mappedProviderConfig() *entity.OAuthConfig {
	return &entity.OAuthConfig{
		ID:                1,
		Provider:          "_zitadel",
		DisplayName:       "Zitadel",
		Status:            enum.OAuthConfigEnabled,
		IsTrusted:         true,
		IssuerURL:         "https://idp.test",
		JSONUserIDPath:    "sub",
		JSONUserRolesPath: "urn:zitadel:iam:org:project:roles",
		AdminRoles:        "fider-admin",
		CollaboratorRoles: "fider-collab",
	}
}

// executeMappedOAuthToken runs the OAuthToken handler for the mapped provider with the
// given profile roles and returns the response.
func executeMappedOAuthToken(config *entity.OAuthConfig, roles []string, existingUser *entity.User) (int, *mock.Server) {
	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		if q.Provider == config.Provider {
			q.Result = config
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetOAuthProfile) error {
		q.Result = &dto.OAuthUserProfile{
			ID:    "ZI123",
			Name:  "Jon Snow",
			Email: "jon.snow@got.com",
			Roles: roles,
		}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		if existingUser != nil {
			q.Result = existingUser
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		return app.ErrNotFound
	})

	server := mock.NewServer()
	return 0, server
}

func TestOAuthTokenHandler_Mapping_NewUserGetsMappedRole(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	config := mappedProviderConfig()
	_, server := executeMappedOAuthToken(config, []string{"fider-admin"}, nil)

	var registeredUser *entity.User
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		c.User.ID = 7
		registeredUser = c.User
		return nil
	})

	code, response := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(registeredUser).IsNotNil()
	Expect(registeredUser.Role).Equals(enum.RoleAdministrator)
	ExpectFiderAuthCookie(response, registeredUser)
}

func TestOAuthTokenHandler_Mapping_NewUserWithoutMatchIsVisitor(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	config := mappedProviderConfig()
	// No allowedRoles configured: the user is let in, but maps to visitor.
	_, server := executeMappedOAuthToken(config, []string{"some-unrelated-role"}, nil)

	var registeredUser *entity.User
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		c.User.ID = 7
		registeredUser = c.User
		return nil
	})

	code, _ := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(registeredUser.Role).Equals(enum.RoleVisitor)
}

func TestOAuthTokenHandler_Mapping_MappedAdminBypassesAllowedRolesGate(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	config := mappedProviderConfig()
	config.AllowedRoles = "some-access-role"
	// User lacks the allowed role, but maps to administrator — mapping implies access.
	_, server := executeMappedOAuthToken(config, []string{"fider-admin"}, nil)

	var registeredUser *entity.User
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		c.User.ID = 7
		registeredUser = c.User
		return nil
	})

	code, response := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(response.Header().Get("Location")).Equals("/")
	Expect(registeredUser.Role).Equals(enum.RoleAdministrator)
}

func TestOAuthTokenHandler_Mapping_VisitorWithoutAccessRoleIsDenied(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	config := mappedProviderConfig()
	config.AllowedRoles = "some-access-role"
	_, server := executeMappedOAuthToken(config, []string{"some-unrelated-role"}, nil)

	code, response := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(response.Header().Get("Location")).Equals("/access-denied")
}

func TestOAuthTokenHandler_Mapping_ExistingUserPromoted(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	existing := &entity.User{
		ID:            2,
		Name:          "Arya Stark",
		Email:         "arya.stark@got.com",
		Tenant:        mock.DemoTenant,
		Status:        enum.UserActive,
		Role:          enum.RoleVisitor,
		SecurityStamp: "old-stamp",
		Providers:     []*entity.UserProvider{{UID: "ZI123", Name: "_zitadel"}},
	}

	config := mappedProviderConfig()
	_, server := executeMappedOAuthToken(config, []string{"fider-collab"}, existing)

	var roleChange *cmd.ChangeUserRole
	bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
		roleChange = c
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
		Expect(q.UserID).Equals(existing.ID)
		refreshed := *existing
		refreshed.Role = enum.RoleCollaborator
		refreshed.SecurityStamp = "fresh-stamp"
		q.Result = &refreshed
		return nil
	})

	code, response := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(roleChange).IsNotNil()
	Expect(roleChange.UserID).Equals(existing.ID)
	Expect(roleChange.Role).Equals(enum.RoleCollaborator)

	// The auth cookie must carry the re-fetched security stamp — the role change
	// rotates it, and a cookie with the old stamp would be immediately invalid.
	authCookie := findFiderAuthCookie(response.Header()["Set-Cookie"])
	Expect(authCookie).IsNotEmpty()
	claims, err := jwt.DecodeFiderClaims(authCookie)
	Expect(err).IsNil()
	Expect(claims.SecurityStamp).Equals("fresh-stamp")
}

func TestOAuthTokenHandler_Mapping_ExistingAdminDemoted(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	existing := &entity.User{
		ID:        3,
		Name:      "Ned Stark",
		Email:     "ned.stark@got.com",
		Tenant:    mock.DemoTenant,
		Status:    enum.UserActive,
		Role:      enum.RoleAdministrator,
		Providers: []*entity.UserProvider{{UID: "ZI123", Name: "_zitadel"}},
	}

	config := mappedProviderConfig()
	_, server := executeMappedOAuthToken(config, []string{"some-unrelated-role"}, existing)

	bus.AddHandler(func(ctx context.Context, q *query.CountUsersByRole) error {
		Expect(q.Role).Equals(enum.RoleAdministrator)
		q.Result = 3
		return nil
	})

	var roleChange *cmd.ChangeUserRole
	bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
		roleChange = c
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
		refreshed := *existing
		refreshed.Role = enum.RoleVisitor
		q.Result = &refreshed
		return nil
	})

	code, _ := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(roleChange).IsNotNil()
	Expect(roleChange.Role).Equals(enum.RoleVisitor)
}

func TestOAuthTokenHandler_Mapping_LastAdminNotDemoted(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	existing := &entity.User{
		ID:        3,
		Name:      "Ned Stark",
		Email:     "ned.stark@got.com",
		Tenant:    mock.DemoTenant,
		Status:    enum.UserActive,
		Role:      enum.RoleAdministrator,
		Providers: []*entity.UserProvider{{UID: "ZI123", Name: "_zitadel"}},
	}

	config := mappedProviderConfig()
	_, server := executeMappedOAuthToken(config, []string{"some-unrelated-role"}, existing)

	bus.AddHandler(func(ctx context.Context, q *query.CountUsersByRole) error {
		q.Result = 1
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
		panic("role must not change for the last administrator")
	})

	code, response := server.
		WithURL("http://demo.test.fider.io/oauth/_zitadel/token?code=123&redirect=/&handoff="+newHandoff("_zitadel", "http://demo.test.fider.io", "MY_SESSION_ID")).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", "_zitadel").
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	ExpectFiderAuthCookie(response, existing)
}

func TestOAuthTokenHandler_NoncePropagatesFromHandoff(t *testing.T) {
	RegisterT(t)
	initOAuthWithMocks()

	var receivedNonce string
	bus.AddHandler(func(ctx context.Context, q *query.GetOAuthProfile) error {
		receivedNonce = q.Nonce
		q.Result = &dto.OAuthUserProfile{ID: "FB123", Name: "Jon Snow", Email: "jon.snow@got.com"}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		q.Result = mock.JonSnow
		return nil
	})

	sum := sha256.Sum256([]byte("MY_SESSION_ID"))
	handoff, err := jwt.Encode(jwt.OAuthHandoffClaims{
		Provider:      app.FacebookProvider,
		Origin:        "http://demo.test.fider.io",
		SessionIDHash: hex.EncodeToString(sum[:]),
		Nonce:         "the-nonce",
		Metadata: jwt.Metadata{
			ExpiresAt: jwt.Time(time.Now().Add(2 * time.Minute)),
		},
	})
	Expect(err).IsNil()

	server := mock.NewServer()
	code, _ := server.
		WithURL("http://demo.test.fider.io/oauth/facebook/token?code=123&redirect=/&handoff="+handoff).
		OnTenant(mock.DemoTenant).
		AddCookie(web.CookieSessionName, "MY_SESSION_ID").
		AddParam("provider", app.FacebookProvider).
		Use(middlewares.Session()).
		Execute(handlers.OAuthToken())

	Expect(code).Equals(http.StatusTemporaryRedirect)
	Expect(receivedNonce).Equals("the-nonce")
}

func findFiderAuthCookie(cookies []string) string {
	for _, c := range cookies {
		cookie := web.ParseCookie(c)
		if cookie.Name == web.CookieAuthName {
			return cookie.Value
		}
	}
	return ""
}
