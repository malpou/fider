package middlewares_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/MetsaApp/platform-kit/edgeauth"
	"github.com/MetsaApp/platform-kit/edgeauth/edgeauthtest"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/middlewares"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/pkg/mock"
	"github.com/getfider/fider/app/pkg/web"
)

const guardHost = "feedback.test"

// The custom OAuth provider existing users were signed in through before guard.
const legacyProvider = "_c144tcijpa"

// enableGuard turns the guard identity on against a fresh in-memory issuer.
func enableGuard(t *testing.T) *edgeauthtest.Issuer {
	issuer := edgeauthtest.NewIssuer(t)
	env.Config.GuardIdentity.Enabled = true
	env.Config.GuardIdentity.JWKSURL = issuer.JWKSURL()
	env.Config.GuardIdentity.Audiences = guardHost
	env.Config.GuardIdentity.Provider = legacyProvider
	env.Config.GuardIdentity.AdminRoles = "fider-admin"
	env.Config.GuardIdentity.CollaboratorRoles = ""
	env.Config.GuardIdentity.AllowedRoles = "fider-user"
	return issuer
}

func guardServer(issuer *edgeauthtest.Issuer, id edgeauth.Identity) *mock.Server {
	server := mock.NewServer()
	server.Use(middlewares.User())
	return server.
		OnTenant(mock.DemoTenant).
		AddHeader("Accept", "application/json").
		AddHeader(edgeauth.Header, issuer.Mint(id, guardHost))
}

func showUser(c *web.Context) error {
	if !c.IsAuthenticated() {
		return c.NoContent(http.StatusNoContent)
	}
	return c.String(http.StatusOK, c.User().Name)
}

func notFoundByProvider() {
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return app.ErrNotFound
	})
}

func TestUser_Guard_ExistingUserByProviderUID(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	server := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-jon", Email: "someone.else@got.com", EmailVerified: true, Roles: []string{"fider-admin"},
	})
	mock.JonSnow.Providers = append(mock.JonSnow.Providers, &entity.UserProvider{UID: "zitadel-jon", Name: legacyProvider})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		if q.Provider == legacyProvider && q.UID == "zitadel-jon" {
			q.Result = mock.JonSnow
			return nil
		}
		return app.ErrNotFound
	})

	status, response := server.Execute(showUser)

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Jon Snow")
	// No session of Fider's own: nothing is minted.
	Expect(response.Header()["Set-Cookie"]).HasLen(0)
}

func TestUser_Guard_ExistingUserByEmail_LinksProvider(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	notFoundByProvider()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		if q.Email == "arya.stark@got.com" {
			q.Result = mock.AryaStark
			return nil
		}
		return app.ErrNotFound
	})
	var linked *cmd.RegisterUserProvider
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUserProvider) error {
		linked = c
		return nil
	})

	status, response := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-arya", Email: "Arya.Stark@got.com", EmailVerified: true, Roles: []string{"fider-user"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Arya Stark")
	Expect(linked).IsNotNil()
	Expect(linked.UserID).Equals(mock.AryaStark.ID)
	Expect(linked.ProviderName).Equals(legacyProvider)
	Expect(linked.ProviderUID).Equals("zitadel-arya")
}

func TestUser_Guard_UnverifiedEmail_NeverLinksAccount(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	notFoundByProvider()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		panic("an unverified email must not be looked up")
	})
	var registered *entity.User
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		c.User.ID = 42
		registered = c.User
		return nil
	})

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-mallory", Email: "arya.stark@got.com", EmailVerified: false, Roles: []string{"fider-user"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusOK)
	Expect(registered).IsNotNil()
	Expect(registered.Email).Equals("")
	Expect(registered.Name).Equals("Anonymous")
}

func TestUser_Guard_NewUser_OnPrivateSite(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)
	server := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-sansa", Email: "sansa@got.com", EmailVerified: true, Name: "Sansa Stark", Roles: []string{"fider-user"},
	})
	mock.DemoTenant.IsPrivate = true

	notFoundByProvider()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		return app.ErrNotFound
	})
	var registered *entity.User
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		c.User.ID = 42
		registered = c.User
		return nil
	})

	status, response := server.Execute(showUser)

	Expect(status).Equals(http.StatusOK)
	Expect(response.Body.String()).Equals("Sansa Stark")
	Expect(registered.Role).Equals(enum.RoleVisitor)
	Expect(registered.Email).Equals("sansa@got.com")
	Expect(registered.Tenant).Equals(mock.DemoTenant)
	Expect(registered.Providers).HasLen(1)
	Expect(registered.Providers[0].Name).Equals(legacyProvider)
	Expect(registered.Providers[0].UID).Equals("zitadel-sansa")
}

func TestUser_Guard_AdminRoleMapsToAdministrator(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	arya := *mock.AryaStark
	arya.Providers = []*entity.UserProvider{{UID: "zitadel-arya", Name: legacyProvider}}
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		q.Result = &arya
		return nil
	})
	var changed *cmd.ChangeUserRole
	bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
		changed = c
		return nil
	})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
		promoted := arya
		promoted.Role = changed.Role
		q.Result = &promoted
		return nil
	})

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-arya", Roles: []string{"fider-admin", "fider-user"},
	}).Execute(func(c *web.Context) error {
		if c.User().IsAdministrator() {
			return c.NoContent(http.StatusOK)
		}
		return c.NoContent(http.StatusTeapot)
	})

	Expect(status).Equals(http.StatusOK)
	Expect(changed).IsNotNil()
	Expect(changed.UserID).Equals(mock.AryaStark.ID)
	Expect(changed.Role).Equals(enum.RoleAdministrator)
}

func TestUser_Guard_LostAdminRoleIsDemoted_ButNeverTheLastAdmin(t *testing.T) {
	for _, tc := range []struct {
		admins   int
		demoted  bool
		expected enum.Role
	}{
		{admins: 2, demoted: true, expected: enum.RoleVisitor},
		{admins: 1, demoted: false, expected: enum.RoleAdministrator},
	} {
		RegisterT(t)
		issuer := enableGuard(t)

		jon := *mock.JonSnow
		jon.Providers = []*entity.UserProvider{{UID: "zitadel-jon", Name: legacyProvider}}
		bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
			q.Result = &jon
			return nil
		})
		bus.AddHandler(func(ctx context.Context, q *query.CountUsersByRole) error {
			q.Result = tc.admins
			return nil
		})
		var changed *cmd.ChangeUserRole
		bus.AddHandler(func(ctx context.Context, c *cmd.ChangeUserRole) error {
			changed = c
			return nil
		})
		bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
			demoted := jon
			demoted.Role = changed.Role
			q.Result = &demoted
			return nil
		})

		var role enum.Role
		status, _ := guardServer(issuer, edgeauth.Identity{
			Subject: "zitadel-jon", Roles: []string{"fider-user"},
		}).Execute(func(c *web.Context) error {
			role = c.User().Role
			return c.NoContent(http.StatusOK)
		})

		Expect(status).Equals(http.StatusOK)
		Expect(changed != nil).Equals(tc.demoted)
		Expect(role).Equals(tc.expected)
	}
}

func TestUser_Guard_MissingRole_Refused(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	notFoundByProvider()
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		return app.ErrNotFound
	})
	bus.AddHandler(func(ctx context.Context, c *cmd.RegisterUser) error {
		panic("a user without an allowed role must not be created")
	})

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-stranger", Email: "stranger@got.com", EmailVerified: true, Roles: []string{"some-other-role"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusForbidden)
}

func TestUser_Guard_BlockedUser_Refused(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)

	arya := *mock.AryaStark
	arya.Status = enum.UserBlocked
	arya.Providers = []*entity.UserProvider{{UID: "zitadel-arya", Name: legacyProvider}}
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		q.Result = &arya
		return nil
	})

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-arya", Roles: []string{"fider-user"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusUnauthorized)
}

func TestUser_Guard_InvalidIdentity_Unauthorized(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)
	other := edgeauthtest.NewIssuer(t)

	for _, token := range []string{
		"not-a-jwt",
		// signed for another host
		issuer.Mint(edgeauth.Identity{Subject: "zitadel-jon", Roles: []string{"fider-admin"}}, "evil.test"),
		// signed by a key guard never published
		other.Mint(edgeauth.Identity{Subject: "zitadel-jon", Roles: []string{"fider-admin"}}, guardHost),
	} {
		server := mock.NewServer()
		server.Use(middlewares.User())
		status, _ := server.
			OnTenant(mock.DemoTenant).
			AddHeader("Accept", "application/json").
			AddHeader(edgeauth.Header, token).
			Execute(showUser)

		Expect(status).Equals(http.StatusUnauthorized)
	}
}

func TestUser_Guard_KeysUnavailable_ServiceUnavailable(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)
	env.Config.GuardIdentity.JWKSURL = "http://127.0.0.1:1/jwks.json"

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-jon", Roles: []string{"fider-admin"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusServiceUnavailable)
}

func TestUser_Guard_NoIdentity_IsAnonymous_AndAuthCookieIsIgnored(t *testing.T) {
	RegisterT(t)
	enableGuard(t)

	token, _ := jwt.Encode(jwt.FiderClaims{UserID: mock.JonSnow.ID, UserName: mock.JonSnow.Name})
	bus.AddHandler(func(ctx context.Context, q *query.GetUserByID) error {
		q.Result = mock.JonSnow
		return nil
	})

	server := mock.NewServer()
	server.Use(middlewares.User())
	status, response := server.
		OnTenant(mock.DemoTenant).
		AddHeader("Accept", "application/json").
		AddCookie(web.CookieAuthName, token).
		Execute(showUser)

	Expect(status).Equals(http.StatusNoContent)
	// The leftover cookie is cleared.
	Expect(response.Header()["Set-Cookie"]).HasLen(1)
}

func TestUser_GuardDisabled_IdentityHeaderIgnored(t *testing.T) {
	RegisterT(t)
	issuer := enableGuard(t)
	env.Config.GuardIdentity.Enabled = false

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		panic("the identity header must not be read when guard is off")
	})

	status, _ := guardServer(issuer, edgeauth.Identity{
		Subject: "zitadel-jon", Roles: []string{"fider-admin"},
	}).Execute(showUser)

	Expect(status).Equals(http.StatusNoContent)
}
