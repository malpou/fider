package actions_test

import (
	"context"
	"testing"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/actions"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/rand"
)

func newValidOIDCAction() *actions.CreateEditOAuthConfig {
	return &actions.CreateEditOAuthConfig{
		Logo:              &dto.ImageUpload{},
		DisplayName:       "Zitadel",
		Status:            enum.OAuthConfigEnabled,
		ClientID:          "the-client-id",
		ClientSecret:      "the-client-secret",
		IssuerURL:         "https://idp.test",
		Scope:             "openid profile email",
		JSONUserIDPath:    "sub",
		JSONUserNamePath:  "name",
		JSONUserEmailPath: "email",
		JSONUserRolesPath: "urn:zitadel:iam:org:project:roles",
		AdminRoles:        "fider-admin",
		CollaboratorRoles: "fider-collab",
	}
}

func oidcActionContext() context.Context {
	return context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})
}

func stubDiscovery() {
	bus.AddHandler(func(ctx context.Context, q *query.GetOpenIDConfiguration) error {
		q.Result = &dto.OpenIDConfiguration{
			Issuer:                q.IssuerURL,
			AuthorizationEndpoint: q.IssuerURL + "/oauth/v2/authorize",
			TokenEndpoint:         q.IssuerURL + "/oauth/v2/token",
			UserinfoEndpoint:      q.IssuerURL + "/oidc/v1/userinfo",
			JWKSURI:               q.IssuerURL + "/oauth/v2/keys",
		}
		return nil
	})
}

func TestCreateEditOAuthConfig_OIDC_DiscoveryFillsEndpoints(t *testing.T) {
	RegisterT(t)
	stubDiscovery()

	action := newValidOIDCAction()
	result := action.Validate(oidcActionContext(), nil)

	ExpectSuccess(result)
	Expect(action.AuthorizeURL).Equals("https://idp.test/oauth/v2/authorize")
	Expect(action.TokenURL).Equals("https://idp.test/oauth/v2/token")
	Expect(action.ProfileURL).Equals("https://idp.test/oidc/v1/userinfo")
	Expect(action.JWKSURL).Equals("https://idp.test/oauth/v2/keys")
}

func TestCreateEditOAuthConfig_OIDC_ManualURLsWinOverDiscovery(t *testing.T) {
	RegisterT(t)
	stubDiscovery()

	action := newValidOIDCAction()
	action.AuthorizeURL = "https://idp.test/custom/authorize"
	action.ProfileURL = "https://idp.test/custom/userinfo"
	result := action.Validate(oidcActionContext(), nil)

	ExpectSuccess(result)
	Expect(action.AuthorizeURL).Equals("https://idp.test/custom/authorize")
	Expect(action.TokenURL).Equals("https://idp.test/oauth/v2/token")
	Expect(action.ProfileURL).Equals("https://idp.test/custom/userinfo")
	Expect(action.JWKSURL).Equals("https://idp.test/oauth/v2/keys")
}

func TestCreateEditOAuthConfig_OIDC_DiscoveryFailure(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetOpenIDConfiguration) error {
		return errors.New("connection refused")
	})

	action := newValidOIDCAction()
	result := action.Validate(oidcActionContext(), nil)

	// The issuerURL failure alone blocks the save; authorize/token URLs are not
	// flagged since they are resolved from discovery for OIDC providers.
	ExpectFailed(result, "issuerURL")
}

func TestCreateEditOAuthConfig_OIDC_InvalidIssuerURL(t *testing.T) {
	RegisterT(t)

	action := newValidOIDCAction()
	action.IssuerURL = "not-a-url"
	result := action.Validate(oidcActionContext(), nil)
	ExpectFailed(result, "issuerURL")

	action = newValidOIDCAction()
	action.IssuerURL = "https://" + rand.String(300)
	result = action.Validate(oidcActionContext(), nil)
	ExpectFailed(result, "issuerURL")
}

func TestCreateEditOAuthConfig_RoleMappingRequiresRolesPath(t *testing.T) {
	RegisterT(t)
	stubDiscovery()

	action := newValidOIDCAction()
	action.JSONUserRolesPath = ""
	result := action.Validate(oidcActionContext(), nil)
	ExpectFailed(result, "adminRoles", "collaboratorRoles")
}

func TestCreateEditOAuthConfig_RoleMappingTooLong(t *testing.T) {
	RegisterT(t)
	stubDiscovery()

	action := newValidOIDCAction()
	action.AdminRoles = rand.String(501)
	action.CollaboratorRoles = rand.String(501)
	result := action.Validate(oidcActionContext(), nil)
	ExpectFailed(result, "adminRoles", "collaboratorRoles")
}
