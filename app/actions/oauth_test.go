package actions_test

import (
	"context"
	"testing"

	"github.com/getfider/fider/app/models/dto"

	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/actions"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/rand"
)

func TestCreateEditOAuthConfig_InvalidInput(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	testCases := []struct {
		expected []string
		action   *actions.CreateEditOAuthConfig
	}{
		{
			expected: []string{"displayName", "status", "tokenURL", "clientID", "clientSecret", "scope", "authorizeURL", "tokenURL", "jsonUserIDPath"},
			action:   &actions.CreateEditOAuthConfig{},
		},
		{
			expected: []string{"displayName", "status", "tokenURL", "clientID", "clientSecret", "scope", "authorizeURL", "tokenURL", "profileURL", "jsonUserIDPath", "jsonUserNamePath", "jsonUserEmailPath"},
			action: &actions.CreateEditOAuthConfig{
				DisplayName:       rand.String(51),
				ClientID:          rand.String(101),
				Status:            0,
				ClientSecret:      rand.String(501),
				AuthorizeURL:      rand.String(301),
				TokenURL:          rand.String(301),
				Scope:             rand.String(101),
				ProfileURL:        rand.String(301),
				JSONUserIDPath:    rand.String(101),
				JSONUserNamePath:  rand.String(101),
				JSONUserEmailPath: rand.String(101),
			},
		},
	}
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})

	for _, testCase := range testCases {
		result := testCase.action.Validate(ctx, nil)
		ExpectFailed(result, testCase.expected...)
	}
}

func TestCreateEditOAuthConfig_DefaultValues(t *testing.T) {
	RegisterT(t)

	action := actions.NewCreateEditOAuthConfig()
	Expect(action.Logo.BlobKey).Equals("")
}

func TestCreateEditOAuthConfig_AddNew_ValidInput(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	action := &actions.CreateEditOAuthConfig{
		DisplayName:       "My Provider",
		Status:            enum.OAuthConfigEnabled,
		ClientID:          "823187ahjjfdha8fds7yfdashfjkdsa",
		ClientSecret:      "jijads78d76cn347768x3t4668q275@ˆ&Tnycasdgsacuyhij",
		AuthorizeURL:      "http://provider/oauth/authorize",
		TokenURL:          "http://provider/oauth/token",
		Scope:             "profile email",
		ProfileURL:        "http://provider/profile/me",
		JSONUserIDPath:    "user.id",
		JSONUserNamePath:  "user.name",
		JSONUserEmailPath: "user.email",
	}
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})

	result := action.Validate(ctx, nil)
	ExpectSuccess(result)
	Expect(action.ID).Equals(0)
	Expect(action.Provider).HasLen(11)
	Expect(string(action.Provider[0])).Equals("_")
}

func TestCreateEditOAuthConfig_EditExisting_NewSecret(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		if q.Provider == "_NAME" {
			q.Result = &entity.OAuthConfig{
				ID:          4,
				Provider:    q.Provider,
				LogoBlobKey: "hello-world.png",
			}
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	action := actions.NewCreateEditOAuthConfig()
	action.Provider = "_NAME"
	action.DisplayName = "My Provider"
	action.Status = enum.OAuthConfigDisabled
	action.ClientID = "823187ahjjfdha8fds7yfdashfjkdsa"
	action.ClientSecret = "jijads78d76cn347768x3t4668q275@ˆ&Tnycasdgsacuyhij"
	action.AuthorizeURL = "http://provider/oauth/authorize"
	action.TokenURL = "http://provider/oauth/token"
	action.Scope = "profile email"
	action.ProfileURL = "http://provider/profile/me"
	action.JSONUserIDPath = "user.id"
	action.JSONUserNamePath = "user.name"
	action.JSONUserEmailPath = "user.email"
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})

	result := action.Validate(ctx, nil)
	ExpectSuccess(result)
	Expect(action.ID).Equals(4)
	Expect(action.Logo.BlobKey).Equals("hello-world.png")
	Expect(action.ClientSecret).Equals("jijads78d76cn347768x3t4668q275@ˆ&Tnycasdgsacuyhij")
}

func TestCreateEditOAuthConfig_EditExisting_OmitSecret(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		if q.Provider == "_NAME2" {
			q.Result = &entity.OAuthConfig{
				ID:           5,
				Provider:     q.Provider,
				DisplayName:  "My Provider",
				ClientSecret: "MY_OLD_SECRET",
			}
			return nil
		}
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	action := actions.NewCreateEditOAuthConfig()
	action.Provider = "_NAME2"
	action.DisplayName = "My Provider"
	action.Status = enum.OAuthConfigDisabled
	action.ClientID = "823187ahjjfdha8fds7yfdashfjkdsa"
	action.AuthorizeURL = "http://provider/oauth/authorize"
	action.TokenURL = "http://provider/oauth/token"
	action.Scope = "profile email"
	action.ProfileURL = "http://provider/profile/me"
	action.JSONUserIDPath = "user.id"
	action.JSONUserNamePath = "user.name"
	action.JSONUserEmailPath = "user.email"
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})

	result := action.Validate(ctx, nil)
	ExpectSuccess(result)
	Expect(action.ID).Equals(5)
	Expect(action.ClientSecret).Equals("MY_OLD_SECRET")
}

func TestCreateEditOAuthConfig_EditNonExisting(t *testing.T) {
	RegisterT(t)

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	action := actions.NewCreateEditOAuthConfig()
	action.Provider = "_MY_NEW_PROVIDER"
	action.DisplayName = "My Provider"
	action.Status = enum.OAuthConfigDisabled
	action.ClientID = "823187ahjjfdha8fds7yfdashfjkdsa"
	action.AuthorizeURL = "http://provider/oauth/authorize"
	action.TokenURL = "http://provider/oauth/token"
	action.Scope = "profile email"
	action.ProfileURL = "http://provider/profile/me"
	action.JSONUserIDPath = "user.id"
	action.JSONUserNamePath = "user.name"
	action.JSONUserEmailPath = "user.email"
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{
		IsEmailAuthAllowed: true,
	})

	result := action.Validate(ctx, nil)
	Expect(result.Err).Equals(app.ErrNotFound)
	Expect(result.Ok).IsFalse()
}

func envManagedOAuthSetup(t *testing.T) *actions.CreateEditOAuthConfig {
	original := env.Config.OAuth.Custom
	env.Config.OAuth.Custom.ClientID = "ENV_CL_ID"
	env.Config.OAuth.Custom.Secret = "ENV_SECRET"
	t.Cleanup(func() { env.Config.OAuth.Custom = original })

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			ID:           6,
			Provider:     q.Provider,
			DisplayName:  "Zitadel",
			ClientID:     "ENV_CL_ID",
			ClientSecret: "STORED_SECRET",
		}
		return nil
	})
	bus.AddHandler(func(ctx context.Context, q *query.ListActiveOAuthProviders) error {
		q.Result = []*dto.OAuthProviderOption{}
		return nil
	})

	action := actions.NewCreateEditOAuthConfig()
	action.Provider = "_ENV"
	action.DisplayName = "Zitadel renamed"
	action.Status = enum.OAuthConfigDisabled
	action.ClientID = "ENV_CL_ID"
	action.AuthorizeURL = "http://provider/oauth/authorize"
	action.TokenURL = "http://provider/oauth/token"
	action.Scope = "openid profile email"
	action.ProfileURL = "http://provider/profile/me"
	action.JSONUserIDPath = "sub"
	action.JSONUserNamePath = "name"
	action.JSONUserEmailPath = "email"
	return action
}

func TestCreateEditOAuthConfig_EnvManaged_KeepsStoredCredentials(t *testing.T) {
	for _, submitted := range []string{"", "NEW_SECRET"} {
		RegisterT(t)
		action := envManagedOAuthSetup(t)
		action.ClientSecret = submitted
		ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{IsEmailAuthAllowed: true})

		result := action.Validate(ctx, nil)
		ExpectSuccess(result)
		Expect(action.ClientID).Equals("ENV_CL_ID")
		Expect(action.ClientSecret).Equals("STORED_SECRET")
	}
}

func TestCreateEditOAuthConfig_EnvManaged_RejectsClientIDChange(t *testing.T) {
	RegisterT(t)
	action := envManagedOAuthSetup(t)
	action.ClientID = "SOMETHING_ELSE"
	ctx := context.WithValue(context.Background(), app.TenantCtxKey, &entity.Tenant{IsEmailAuthAllowed: true})

	result := action.Validate(ctx, nil)
	ExpectFailed(result, "clientID")
}
