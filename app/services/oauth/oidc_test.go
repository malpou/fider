package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/jwt"
	"github.com/getfider/fider/app/services/oauth"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

var oidcRSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func oidcJWKSBody() []byte {
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "key-1",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(oidcRSAKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			},
		},
	})
	return body
}

func allowPrivateTargets(t *testing.T) {
	original := env.Config.AllowPrivateNetworkTargets
	env.Config.AllowPrivateNetworkTargets = true
	t.Cleanup(func() { env.Config.AllowPrivateNetworkTargets = original })
}

func discoveryDocument(issuer string) []byte {
	body, _ := json.Marshal(map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/v2/authorize",
		"token_endpoint":         issuer + "/oauth/v2/token",
		"userinfo_endpoint":      issuer + "/oidc/v1/userinfo",
		"jwks_uri":               issuer + "/oauth/v2/keys",
	})
	return body
}

func TestGetOpenIDConfiguration(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})
	allowPrivateTargets(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		Expect(c.URL).Equals("https://idp.test/.well-known/openid-configuration")
		c.ResponseStatusCode = 200
		c.ResponseBody = discoveryDocument("https://idp.test")
		return nil
	})

	q := &query.GetOpenIDConfiguration{IssuerURL: "https://idp.test/"}
	err := bus.Dispatch(context.Background(), q)
	Expect(err).IsNil()
	Expect(q.Result.AuthorizationEndpoint).Equals("https://idp.test/oauth/v2/authorize")
	Expect(q.Result.TokenEndpoint).Equals("https://idp.test/oauth/v2/token")
	Expect(q.Result.UserinfoEndpoint).Equals("https://idp.test/oidc/v1/userinfo")
	Expect(q.Result.JWKSURI).Equals("https://idp.test/oauth/v2/keys")
}

func TestGetOpenIDConfiguration_IssuerMismatch(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})
	allowPrivateTargets(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		c.ResponseStatusCode = 200
		c.ResponseBody = discoveryDocument("https://evil.test")
		return nil
	})

	q := &query.GetOpenIDConfiguration{IssuerURL: "https://idp.test"}
	err := bus.Dispatch(context.Background(), q)
	Expect(err).IsNotNil()
}

func TestGetOpenIDConfiguration_Incomplete(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})
	allowPrivateTargets(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		c.ResponseStatusCode = 200
		c.ResponseBody = []byte(`{"issuer":"https://idp.test"}`)
		return nil
	})

	q := &query.GetOpenIDConfiguration{IssuerURL: "https://idp.test"}
	err := bus.Dispatch(context.Background(), q)
	Expect(err).IsNotNil()
}

func TestGetOpenIDConfiguration_BlocksInternalIssuer(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		panic("must not be called")
	})

	q := &query.GetOpenIDConfiguration{IssuerURL: "http://169.254.169.254"}
	err := bus.Dispatch(context.Background(), q)
	Expect(err).IsNotNil()
}

func TestGetAuthURL_OIDCIncludesNonce(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			Provider:     q.Provider,
			ClientID:     "CU_CL_ID",
			Scope:        "openid profile email",
			IssuerURL:    "https://idp.test",
			AuthorizeURL: "https://idp.test/oauth/v2/authorize",
		}
		return nil
	})

	ctx := newGetContext("http://login.test.fider.io:3000")
	authURL := &query.GetOAuthAuthorizationURL{
		Provider:   "_oidc",
		Redirect:   "http://example.org",
		Identifier: "456",
	}

	err := bus.Dispatch(ctx, authURL)
	Expect(err).IsNil()

	u, err := url.Parse(authURL.Result)
	Expect(err).IsNil()

	nonce := u.Query().Get("nonce")
	Expect(nonce).IsNotEmpty()

	claims, err := jwt.DecodeOAuthStateClaims(u.Query().Get("state"))
	Expect(err).IsNil()
	Expect(claims.Nonce).Equals(nonce)
}

func TestGetAuthURL_NonOIDCHasNoNonce(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			Provider:     q.Provider,
			ClientID:     "CU_CL_ID",
			Scope:        "profile email",
			AuthorizeURL: "https://example.org/oauth/authorize",
		}
		return nil
	})

	ctx := newGetContext("http://login.test.fider.io:3000")
	authURL := &query.GetOAuthAuthorizationURL{
		Provider:   "_custom",
		Redirect:   "http://example.org",
		Identifier: "456",
	}

	err := bus.Dispatch(ctx, authURL)
	Expect(err).IsNil()

	u, _ := url.Parse(authURL.Result)
	Expect(u.Query().Has("nonce")).IsFalse()

	claims, err := jwt.DecodeOAuthStateClaims(u.Query().Get("state"))
	Expect(err).IsNil()
	Expect(claims.Nonce).Equals("")
}

// TestGetOAuthRawProfile_OIDC drives the whole OIDC exchange: the code is traded at a
// real (test) token endpoint, the returned id_token is verified against the JWKS, and
// its claims become the raw profile.
func TestGetOAuthRawProfile_OIDC(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})
	allowPrivateTargets(t)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := jwtgo.MapClaims{
			"iss":   "https://idp.test",
			"aud":   "CU_CL_ID",
			"sub":   "user-42",
			"email": "jon.snow@got.com",
			"nonce": "the-nonce",
			"exp":   time.Now().Add(time.Hour).Unix(),
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, _ := token.SignedString(oidcRSAKey)

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"opaque-token","token_type":"Bearer","id_token":"%s"}`, idToken)
	}))
	defer tokenServer.Close()

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			Provider:     q.Provider,
			ClientID:     "CU_CL_ID",
			ClientSecret: "CU_SECRET",
			IssuerURL:    "https://idp.test",
			JWKSURL:      "https://idp.test/oauth/v2/keys",
			AuthorizeURL: "https://idp.test/oauth/v2/authorize",
			TokenURL:     tokenServer.URL,
		}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		Expect(c.URL).Equals("https://idp.test/oauth/v2/keys")
		c.ResponseStatusCode = 200
		c.ResponseBody = oidcJWKSBody()
		return nil
	})

	ctx := newGetContext("http://login.test.fider.io:3000")
	rawProfile := &query.GetOAuthRawProfile{Provider: "_oidc", Code: "the-code", Nonce: "the-nonce"}
	err := bus.Dispatch(ctx, rawProfile)
	Expect(err).IsNil()

	var claims map[string]any
	Expect(json.Unmarshal([]byte(rawProfile.Result), &claims)).IsNil()
	Expect(claims["sub"]).Equals("user-42")
	Expect(claims["email"]).Equals("jon.snow@got.com")
}

// TestGetOAuthRawProfile_OIDC_NoNonce ensures an OIDC exchange without a nonce is rejected,
// even when the provider would have returned a valid id_token.
func TestGetOAuthRawProfile_OIDC_NoNonce(t *testing.T) {
	RegisterT(t)
	bus.Init(&oauth.Service{})
	allowPrivateTargets(t)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"opaque-token","token_type":"Bearer","id_token":"irrelevant"}`)
	}))
	defer tokenServer.Close()

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomOAuthConfigByProvider) error {
		q.Result = &entity.OAuthConfig{
			Provider:     q.Provider,
			ClientID:     "CU_CL_ID",
			IssuerURL:    "https://idp.test",
			JWKSURL:      "https://idp.test/oauth/v2/keys",
			AuthorizeURL: "https://idp.test/oauth/v2/authorize",
			TokenURL:     tokenServer.URL,
		}
		return nil
	})

	ctx := newGetContext("http://login.test.fider.io:3000")
	rawProfile := &query.GetOAuthRawProfile{Provider: "_oidc", Code: "the-code"}
	err := bus.Dispatch(ctx, rawProfile)
	Expect(err).IsNotNil()
}
