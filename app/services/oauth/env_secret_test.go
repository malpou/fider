package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/services/oauth"
)

// TestGetOAuthRawProfile_CustomSecretFromEnv checks which client secret the
// code exchange sends for a custom provider under OAUTH_CUSTOM_CLIENTID/SECRET.
func TestGetOAuthRawProfile_CustomSecretFromEnv(t *testing.T) {
	testCases := []struct {
		name       string
		envID      string
		envSecret  string
		wantSecret string
	}{
		{"matching client id uses env secret", "CU_CL_ID", "ENV_SECRET", "ENV_SECRET"},
		{"other client id keeps stored secret", "OTHER_ID", "ENV_SECRET", "CU_SECRET"},
		{"unset keeps stored secret", "", "", "CU_SECRET"},
		{"id without secret keeps stored secret", "CU_CL_ID", "", "CU_SECRET"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RegisterT(t)
			bus.Init(&oauth.Service{})

			// Let the code exchange reach the local httptest token server.
			originalPrivate := env.Config.AllowPrivateNetworkTargets
			env.Config.AllowPrivateNetworkTargets = true
			originalCustom := env.Config.OAuth.Custom
			env.Config.OAuth.Custom.ClientID = tc.envID
			env.Config.OAuth.Custom.Secret = tc.envSecret
			t.Cleanup(func() {
				env.Config.AllowPrivateNetworkTargets = originalPrivate
				env.Config.OAuth.Custom = originalCustom
			})

			var gotSecret string
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, gotSecret, _ = r.BasicAuth()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"a.e30.c","token_type":"Bearer"}`))
			}))
			defer tokenServer.Close()

			stored := &entity.OAuthConfig{
				Provider:     "_custom",
				ClientID:     "CU_CL_ID",
				ClientSecret: "CU_SECRET",
				TokenURL:     tokenServer.URL,
			}
			bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
				q.Result = stored
				return nil
			})

			ctx := newGetContext("http://login.test.fider.io:3000")
			err := bus.Dispatch(ctx, &query.GetOAuthRawProfile{Provider: "_custom", Code: "the-code"})
			Expect(err).IsNil()
			Expect(gotSecret).Equals(tc.wantSecret)
			Expect(stored.ClientSecret).Equals("CU_SECRET")
		})
	}
}
