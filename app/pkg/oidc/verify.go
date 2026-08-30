package oidc

import (
	"crypto"
	"encoding/base64"
	stderrors "errors"
	"strings"
	"time"

	"github.com/getfider/fider/app/pkg/errors"
	jwtgo "github.com/golang-jwt/jwt/v4"
)

// clockSkewLeeway compensates for clock drift between Fider and the OIDC provider
// when validating time-based claims (exp, nbf, iat).
const clockSkewLeeway = 2 * time.Minute

// allowedSigningMethods are the asymmetric algorithms accepted for id_tokens.
// Symmetric algorithms (HS*) are deliberately excluded: accepting them with a
// public key as the secret is the classic JWT algorithm-confusion attack.
var allowedSigningMethods = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
}

// ErrUnknownKeyID is returned when the id_token references a signing key that is
// not present in the given key set. Callers can use it to refetch a rotated JWKS.
var ErrUnknownKeyID = errors.New("id_token is signed with an unknown key")

// VerifyOptions carries the expected values an id_token is validated against.
type VerifyOptions struct {
	// Issuer must exactly match the token's iss claim.
	Issuer string
	// ClientID must be present in the token's aud claim.
	ClientID string
	// Nonce, when non-empty, must exactly match the token's nonce claim.
	Nonce string
	// Now overrides the time source, for tests. Defaults to time.Now.
	Now func() time.Time
}

type idTokenClaims struct {
	Nonce string `json:"nonce"`
	jwtgo.RegisteredClaims
}

// VerifyIDToken verifies the signature and claims of an OIDC id_token against the
// given key set and returns the raw claims JSON on success.
func VerifyIDToken(rawToken string, keys map[string]crypto.PublicKey, opts VerifyOptions) ([]byte, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	parser := jwtgo.NewParser(
		jwtgo.WithValidMethods(allowedSigningMethods),
		// Time-based claims are validated manually below so a clock-skew leeway can be applied.
		jwtgo.WithoutClaimsValidation(),
	)

	claims := &idTokenClaims{}
	_, err := parser.ParseWithClaims(rawToken, claims, func(t *jwtgo.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		// A token without a kid can still be verified when there is only one candidate key.
		if kid == "" && len(keys) == 1 {
			for _, key := range keys {
				return key, nil
			}
		}
		return nil, ErrUnknownKeyID
	})
	if err != nil {
		// jwt-go wraps keyfunc errors in its own ValidationError, so unwrap with the standard library.
		if stderrors.Is(err, ErrUnknownKeyID) {
			return nil, ErrUnknownKeyID
		}
		return nil, errors.Wrap(err, "failed to verify id_token signature")
	}

	moment := now()

	if claims.ExpiresAt == nil {
		return nil, errors.New("id_token has no expiry (exp) claim")
	}
	if !claims.VerifyExpiresAt(moment.Add(-clockSkewLeeway), true) {
		return nil, errors.New("id_token is expired")
	}
	if !claims.VerifyNotBefore(moment.Add(clockSkewLeeway), false) {
		return nil, errors.New("id_token is not valid yet (nbf)")
	}
	if !claims.VerifyIssuedAt(moment.Add(clockSkewLeeway), false) {
		return nil, errors.New("id_token is issued in the future (iat)")
	}

	if opts.Issuer == "" || claims.Issuer != opts.Issuer {
		return nil, errors.New("id_token issuer %q does not match expected issuer %q", claims.Issuer, opts.Issuer)
	}

	if opts.ClientID == "" || !containsAudience(claims.Audience, opts.ClientID) {
		return nil, errors.New("id_token audience does not include client ID")
	}

	if opts.Nonce != "" && claims.Nonce != opts.Nonce {
		return nil, errors.New("id_token nonce does not match the value sent in the authorization request")
	}

	return decodePayload(rawToken)
}

func containsAudience(audience jwtgo.ClaimStrings, clientID string) bool {
	for _, aud := range audience {
		if aud == clientID {
			return true
		}
	}
	return false
}

// decodePayload returns the raw claims JSON of an already-verified token.
// The original payload segment is used verbatim rather than re-marshalling the
// parsed claims, so numeric and provider-specific claims keep their exact shape.
func decodePayload(rawToken string) ([]byte, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode id_token payload")
	}
	return payload, nil
}
