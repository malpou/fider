package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/entity"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/env"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

// allowPrivateNetworkTargets disables the SSRF network check so tests don't depend
// on DNS resolution of the fake hostnames used here.
func allowPrivateNetworkTargets(t *testing.T) {
	original := env.Config.AllowPrivateNetworkTargets
	env.Config.AllowPrivateNetworkTargets = true
	t.Cleanup(func() { env.Config.AllowPrivateNetworkTargets = original })
}

var testRSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func testJWKSBody(kid string) []byte {
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(testRSAKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			},
		},
	})
	return body
}

func signTestIDToken(kid string, claims jwtgo.MapClaims) string {
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "https://idp.test"
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = "CU_CL_ID"
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(testRSAKey)
	if err != nil {
		panic(err)
	}
	return signed
}

func newOIDCTestConfig() *entity.OAuthConfig {
	return &entity.OAuthConfig{
		Provider:  "_oidc",
		ClientID:  "CU_CL_ID",
		IssuerURL: "https://idp.test",
		JWKSURL:   "https://idp.test/keys",
	}
}

func stubJWKSEndpoint(t *testing.T, kid string) *int {
	allowPrivateNetworkTargets(t)
	requests := 0
	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		requests++
		c.ResponseStatusCode = 200
		c.ResponseBody = testJWKSBody(kid)
		return nil
	})
	t.Cleanup(jwksCache.Flush)
	jwksCache.Flush()
	return &requests
}

func TestGetOIDCProfileBody_Valid(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	stubJWKSEndpoint(t, "key-1")

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{
		"sub":   "user-42",
		"email": "jon.snow@got.com",
		"nonce": "the-nonce",
	})

	body, err := getOIDCProfileBody(context.Background(), newOIDCTestConfig(), idToken, "the-access-token", "the-nonce")
	Expect(err).IsNil()

	var claims map[string]any
	Expect(json.Unmarshal([]byte(body), &claims)).IsNil()
	Expect(claims["sub"]).Equals("user-42")
	Expect(claims["email"]).Equals("jon.snow@got.com")
}

func TestGetOIDCProfileBody_MissingIDToken(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	stubJWKSEndpoint(t, "key-1")

	_, err := getOIDCProfileBody(context.Background(), newOIDCTestConfig(), "", "the-access-token", "the-nonce")
	Expect(err).IsNotNil()
}

func TestGetOIDCProfileBody_MissingNonce(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	stubJWKSEndpoint(t, "key-1")

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{"sub": "user-42", "nonce": "the-nonce"})

	_, err := getOIDCProfileBody(context.Background(), newOIDCTestConfig(), idToken, "the-access-token", "")
	Expect(err).IsNotNil()
}

func TestGetOIDCProfileBody_NonceMismatch(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	stubJWKSEndpoint(t, "key-1")

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{"sub": "user-42", "nonce": "another-nonce"})

	_, err := getOIDCProfileBody(context.Background(), newOIDCTestConfig(), idToken, "the-access-token", "the-nonce")
	Expect(err).IsNotNil()
}

func TestGetOIDCProfileBody_UserinfoMerge(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	allowPrivateNetworkTargets(t)

	jwksRequests := 0
	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		if c.URL == "https://idp.test/keys" {
			jwksRequests++
			c.ResponseStatusCode = 200
			c.ResponseBody = testJWKSBody("key-1")
			return nil
		}

		Expect(c.URL).Equals("https://idp.test/userinfo")
		Expect(c.Headers["Authorization"]).Equals("Bearer the-access-token")
		c.ResponseStatusCode = 200
		c.ResponseBody = []byte(`{"email":"fresh@got.com","urn:zitadel:iam:org:project:roles":{"admin":{"1":"org"}}}`)
		return nil
	})
	t.Cleanup(jwksCache.Flush)
	jwksCache.Flush()

	config := newOIDCTestConfig()
	config.ProfileURL = "https://idp.test/userinfo"

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{
		"sub":   "user-42",
		"email": "stale@got.com",
		"nonce": "the-nonce",
	})

	body, err := getOIDCProfileBody(context.Background(), config, idToken, "the-access-token", "the-nonce")
	Expect(err).IsNil()

	var claims map[string]any
	Expect(json.Unmarshal([]byte(body), &claims)).IsNil()
	// Userinfo overrides id_token claims; id_token-only claims survive.
	Expect(claims["email"]).Equals("fresh@got.com")
	Expect(claims["sub"]).Equals("user-42")
	Expect(claims["urn:zitadel:iam:org:project:roles"]).IsNotNil()
	Expect(jwksRequests).Equals(1)
}

func TestGetOIDCProfileBody_UserinfoFailureIsHardError(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	allowPrivateNetworkTargets(t)

	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		if c.URL == "https://idp.test/keys" {
			c.ResponseStatusCode = 200
			c.ResponseBody = testJWKSBody("key-1")
			return nil
		}
		c.ResponseStatusCode = 500
		return nil
	})
	t.Cleanup(jwksCache.Flush)
	jwksCache.Flush()

	config := newOIDCTestConfig()
	config.ProfileURL = "https://idp.test/userinfo"

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{"sub": "user-42", "nonce": "the-nonce"})

	_, err := getOIDCProfileBody(context.Background(), config, idToken, "the-access-token", "the-nonce")
	Expect(err).IsNotNil()
}

func TestGetOIDCProfileBody_UnknownKidRefetchesOnce(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	allowPrivateNetworkTargets(t)

	// The cached JWKS has an old key; the refetch serves the new one.
	requests := 0
	bus.AddHandler(func(ctx context.Context, c *cmd.HTTPRequest) error {
		requests++
		c.ResponseStatusCode = 200
		if requests == 1 {
			c.ResponseBody = testJWKSBody("old-key")
		} else {
			c.ResponseBody = testJWKSBody("new-key")
		}
		return nil
	})
	t.Cleanup(jwksCache.Flush)
	jwksCache.Flush()

	idToken := signTestIDToken("new-key", jwtgo.MapClaims{"sub": "user-42", "nonce": "the-nonce"})

	body, err := getOIDCProfileBody(context.Background(), newOIDCTestConfig(), idToken, "the-access-token", "the-nonce")
	Expect(err).IsNil()
	Expect(body).IsNotEmpty()
	Expect(requests).Equals(2)

	// A second token with yet another unknown kid must NOT trigger another refetch:
	// the per-URL refetch happened moments ago and is rate limited.
	idToken = signTestIDToken("newer-key", jwtgo.MapClaims{"sub": "user-42", "nonce": "the-nonce"})
	_, err = getOIDCProfileBody(context.Background(), newOIDCTestConfig(), idToken, "the-access-token", "the-nonce")
	Expect(err).IsNotNil()
	Expect(requests).Equals(2)
}

func TestGetOIDCProfileBody_MissingJWKSURL(t *testing.T) {
	RegisterT(t)
	bus.Init(&Service{})
	stubJWKSEndpoint(t, "key-1")

	config := newOIDCTestConfig()
	config.JWKSURL = ""

	idToken := signTestIDToken("key-1", jwtgo.MapClaims{"sub": "user-42", "nonce": "the-nonce"})

	_, err := getOIDCProfileBody(context.Background(), config, idToken, "the-access-token", "the-nonce")
	Expect(err).IsNotNil()
}
