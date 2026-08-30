package oidc_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/oidc"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

var rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var ecdsaKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndianBytes(key.E)),
	}
}

func ecJWK(kid string, key *ecdsa.PublicKey) map[string]any {
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"kty": "EC",
		"kid": kid,
		"use": "sig",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, byteLen))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, byteLen))),
	}
}

func bigEndianBytes(e int) []byte {
	return []byte{byte(e >> 16), byte(e >> 8), byte(e)}
}

func jwksJSON(keys ...map[string]any) []byte {
	body, _ := json.Marshal(map[string]any{"keys": keys})
	return body
}

func defaultKeys(t *testing.T) map[string]crypto.PublicKey {
	keys, err := oidc.ParseJWKS(jwksJSON(rsaJWK("key-1", &rsaKey.PublicKey), ecJWK("key-2", &ecdsaKey.PublicKey)))
	Expect(err).IsNil()
	return keys
}

type tokenOpts struct {
	kid      string
	method   jwtgo.SigningMethod
	key      any
	issuer   string
	audience jwtgo.ClaimStrings
	nonce    string
	expires  *time.Time
	issued   *time.Time
}

func signToken(opts tokenOpts) string {
	if opts.method == nil {
		opts.method = jwtgo.SigningMethodRS256
		opts.key = rsaKey
	}
	if opts.issuer == "" {
		opts.issuer = "https://idp.test"
	}
	if opts.audience == nil {
		opts.audience = jwtgo.ClaimStrings{"my-client"}
	}
	expiresAt := time.Now().Add(1 * time.Hour)
	if opts.expires != nil {
		expiresAt = *opts.expires
	}

	claims := jwtgo.MapClaims{
		"iss":   opts.issuer,
		"aud":   opts.audience,
		"sub":   "user-42",
		"name":  "Jon Snow",
		"email": "jon.snow@got.com",
		"exp":   expiresAt.Unix(),
	}
	if opts.nonce != "" {
		claims["nonce"] = opts.nonce
	}
	if opts.issued != nil {
		claims["iat"] = opts.issued.Unix()
	}

	token := jwtgo.NewWithClaims(opts.method, claims)
	if opts.kid != "" {
		token.Header["kid"] = opts.kid
	}
	signed, err := token.SignedString(opts.key)
	if err != nil {
		panic(err)
	}
	return signed
}

func defaultVerifyOptions() oidc.VerifyOptions {
	return oidc.VerifyOptions{
		Issuer:   "https://idp.test",
		ClientID: "my-client",
		Nonce:    "the-nonce",
	}
}

func TestParseJWKS_Valid(t *testing.T) {
	RegisterT(t)

	keys, err := oidc.ParseJWKS(jwksJSON(rsaJWK("key-1", &rsaKey.PublicKey), ecJWK("key-2", &ecdsaKey.PublicKey)))
	Expect(err).IsNil()
	Expect(len(keys)).Equals(2)
	Expect(keys["key-1"]).IsNotNil()
	Expect(keys["key-2"]).IsNotNil()
}

func TestParseJWKS_SkipsUnusableKeys(t *testing.T) {
	RegisterT(t)

	encKey := rsaJWK("enc-key", &rsaKey.PublicKey)
	encKey["use"] = "enc"
	unknownKty := map[string]any{"kty": "OKP", "kid": "okp-key"}

	keys, err := oidc.ParseJWKS(jwksJSON(rsaJWK("key-1", &rsaKey.PublicKey), encKey, unknownKty))
	Expect(err).IsNil()
	Expect(len(keys)).Equals(1)
	Expect(keys["key-1"]).IsNotNil()
}

func TestParseJWKS_NoUsableKeys(t *testing.T) {
	RegisterT(t)

	_, err := oidc.ParseJWKS([]byte(`{"keys":[]}`))
	Expect(err).IsNotNil()

	_, err = oidc.ParseJWKS([]byte(`not json`))
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_ValidRS256(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce"})
	claims, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNil()

	var parsed map[string]any
	Expect(json.Unmarshal(claims, &parsed)).IsNil()
	Expect(parsed["sub"]).Equals("user-42")
	Expect(parsed["email"]).Equals("jon.snow@got.com")
}

func TestVerifyIDToken_ValidES256(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-2", method: jwtgo.SigningMethodES256, key: ecdsaKey, nonce: "the-nonce"})
	claims, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNil()
	Expect(strings.Contains(string(claims), `"user-42"`)).IsTrue()
}

func TestVerifyIDToken_RejectsHS256(t *testing.T) {
	RegisterT(t)

	// Algorithm confusion: HS256 token "signed" with a value the attacker knows.
	token := signToken(tokenOpts{kid: "key-1", method: jwtgo.SigningMethodHS256, key: []byte("public-knowledge"), nonce: "the-nonce"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_TamperedPayload(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce"})
	parts := strings.Split(token, ".")
	payload := fmt.Sprintf(`{"iss":"https://idp.test","aud":"my-client","sub":"user-43","nonce":"the-nonce","exp":%d}`, time.Now().Add(time.Hour).Unix())
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(payload))

	_, err := oidc.VerifyIDToken(strings.Join(parts, "."), defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_Expired(t *testing.T) {
	RegisterT(t)

	expired := time.Now().Add(-10 * time.Minute)
	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", expires: &expired})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_ExpiredWithinLeeway(t *testing.T) {
	RegisterT(t)

	// Expired 1 minute ago, but the 2 minute clock-skew leeway lets it pass.
	expired := time.Now().Add(-1 * time.Minute)
	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", expires: &expired})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNil()
}

func TestVerifyIDToken_MissingExpiry(t *testing.T) {
	RegisterT(t)

	claims := jwtgo.MapClaims{"iss": "https://idp.test", "aud": "my-client", "nonce": "the-nonce"}
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	token.Header["kid"] = "key-1"
	signed, _ := token.SignedString(rsaKey)

	_, err := oidc.VerifyIDToken(signed, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_IssuedInFuture(t *testing.T) {
	RegisterT(t)

	issued := time.Now().Add(10 * time.Minute)
	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", issued: &issued})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()

	// Within leeway is fine.
	issued = time.Now().Add(1 * time.Minute)
	token = signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", issued: &issued})
	_, err = oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNil()
}

func TestVerifyIDToken_WrongIssuer(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", issuer: "https://evil.test"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_WrongAudience(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", audience: jwtgo.ClaimStrings{"another-client"}})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_AudienceArray(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "the-nonce", audience: jwtgo.ClaimStrings{"another-client", "my-client"}})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNil()
}

func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1", nonce: "another-nonce"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_NonceRequiredButAbsent(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "key-1"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).IsNotNil()
}

func TestVerifyIDToken_UnknownKeyID(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{kid: "rotated-key", nonce: "the-nonce"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).Equals(oidc.ErrUnknownKeyID)
}

func TestVerifyIDToken_NoKidSingleKey(t *testing.T) {
	RegisterT(t)

	keys, err := oidc.ParseJWKS(jwksJSON(rsaJWK("key-1", &rsaKey.PublicKey)))
	Expect(err).IsNil()

	token := signToken(tokenOpts{nonce: "the-nonce"})
	_, err = oidc.VerifyIDToken(token, keys, defaultVerifyOptions())
	Expect(err).IsNil()
}

func TestVerifyIDToken_NoKidMultipleKeys(t *testing.T) {
	RegisterT(t)

	token := signToken(tokenOpts{nonce: "the-nonce"})
	_, err := oidc.VerifyIDToken(token, defaultKeys(t), defaultVerifyOptions())
	Expect(err).Equals(oidc.ErrUnknownKeyID)
}
