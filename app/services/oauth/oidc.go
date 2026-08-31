package oauth

import (
	"context"
	"crypto"
	"encoding/json"
	"strings"
	"time"

	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/oidc"
	"github.com/getfider/fider/app/pkg/validate"
	cache "github.com/patrickmn/go-cache"
)

// jwksCache holds parsed JWKS key sets per URL so every sign in doesn't hit the
// provider. Providers rotate keys, so entries expire and an unknown key ID
// triggers a (rate-limited) refetch.
var jwksCache = cache.New(15*time.Minute, 30*time.Minute)

// jwksRefetchInterval limits how often an unknown key ID may force a JWKS refetch
// per URL, so a flood of tokens with bogus key IDs cannot hammer the provider.
const jwksRefetchInterval = 1 * time.Minute

// getOpenIDConfiguration fetches the OpenID Connect discovery document for an issuer.
func getOpenIDConfiguration(ctx context.Context, q *query.GetOpenIDConfiguration) error {
	issuer := strings.TrimSuffix(strings.TrimSpace(q.IssuerURL), "/")

	// Guard against SSRF: the issuer URL is admin-configurable and fetched server-side.
	if msgs := validate.WebhookURL(issuer); len(msgs) > 0 {
		return errors.New("Issuer URL is not allowed: %s", strings.Join(msgs, "; "))
	}

	req := &cmd.HTTPRequest{
		URL:    issuer + "/.well-known/openid-configuration",
		Method: "GET",
	}
	if err := bus.Dispatch(ctx, req); err != nil {
		return errors.Wrap(err, "failed to fetch OpenID configuration from %s", req.URL)
	}
	if req.ResponseStatusCode != 200 {
		return errors.New("failed to fetch OpenID configuration. Status Code: %d. Body: %s", req.ResponseStatusCode, string(req.ResponseBody))
	}

	config := &dto.OpenIDConfiguration{}
	if err := json.Unmarshal(req.ResponseBody, config); err != nil {
		return errors.Wrap(err, "failed to parse OpenID configuration")
	}

	// OIDC Discovery §4.3: the issuer in the document must match the issuer it was fetched from.
	if strings.TrimSuffix(config.Issuer, "/") != issuer {
		return errors.New("OpenID configuration issuer mismatch: expected %s, got %s", issuer, config.Issuer)
	}

	if config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" || config.JWKSURI == "" {
		return errors.New("OpenID configuration is incomplete: authorization_endpoint, token_endpoint and jwks_uri are required")
	}

	// The discovered endpoints are fetched server-side later, so they get the same SSRF guard.
	for _, endpoint := range []string{config.AuthorizationEndpoint, config.TokenEndpoint, config.UserinfoEndpoint, config.JWKSURI} {
		if endpoint == "" {
			continue
		}
		if msgs := validate.WebhookURL(endpoint); len(msgs) > 0 {
			return errors.New("OpenID configuration endpoint %s is not allowed: %s", endpoint, strings.Join(msgs, "; "))
		}
	}

	q.Result = config
	return nil
}

// getOIDCProfileBody verifies an id_token and returns the profile JSON for an OIDC provider.
// The id_token claims are the base profile; when a userinfo endpoint (ProfileURL) is also
// configured, its claims are merged on top. This covers providers like Zitadel, which by
// default only expose role grants through the userinfo endpoint.
func getOIDCProfileBody(ctx context.Context, config *entity.OAuthConfig, rawIDToken string, accessToken string, nonce string) (string, error) {
	if rawIDToken == "" {
		return "", errors.New("provider %s did not return an id_token; is the 'openid' scope configured?", config.Provider)
	}

	// The nonce is minted when the sign in starts and travels through Fider's signed
	// state/handoff tokens. An OIDC exchange without one is not a flow Fider started.
	if nonce == "" {
		return "", errors.New("missing nonce for OIDC token exchange; restart the sign in flow")
	}

	if config.JWKSURL == "" {
		return "", errors.New("provider %s has no JWKS URL configured; re-save the provider to re-run discovery", config.Provider)
	}

	keys, err := getJWKS(ctx, config.JWKSURL)
	if err != nil {
		return "", err
	}

	verifyOpts := oidc.VerifyOptions{
		Issuer:   strings.TrimSuffix(config.IssuerURL, "/"),
		ClientID: config.ClientID,
		Nonce:    nonce,
	}

	claims, err := oidc.VerifyIDToken(rawIDToken, keys, verifyOpts)
	if err == oidc.ErrUnknownKeyID {
		// The provider may have rotated its signing keys since the JWKS was cached.
		if keys, err = refetchJWKS(ctx, config.JWKSURL); err == nil {
			claims, err = oidc.VerifyIDToken(rawIDToken, keys, verifyOpts)
		}
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to verify id_token from provider %s", config.Provider)
	}

	if config.ProfileURL == "" {
		return string(claims), nil
	}

	userinfo, err := fetchUserProfile(ctx, config.ProfileURL, accessToken)
	if err != nil {
		// Userinfo may carry the roles claim that gates access, so a failure is a hard error.
		return "", err
	}

	return mergeClaims(claims, []byte(userinfo))
}

// mergeClaims overlays userinfo claims on top of id_token claims.
// Userinfo wins on conflicts: it is the fresher, more complete source.
func mergeClaims(idTokenClaims []byte, userinfoClaims []byte) (string, error) {
	var base map[string]json.RawMessage
	if err := json.Unmarshal(idTokenClaims, &base); err != nil {
		return "", errors.Wrap(err, "failed to parse id_token claims")
	}

	var overlay map[string]json.RawMessage
	if err := json.Unmarshal(userinfoClaims, &overlay); err != nil {
		return "", errors.Wrap(err, "failed to parse userinfo response")
	}

	for key, value := range overlay {
		base[key] = value
	}

	merged, err := json.Marshal(base)
	if err != nil {
		return "", errors.Wrap(err, "failed to merge OIDC claims")
	}
	return string(merged), nil
}

// getJWKS returns the parsed key set for a JWKS URL, from cache when possible.
func getJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
	if cached, ok := jwksCache.Get(jwksURL); ok {
		return cached.(map[string]crypto.PublicKey), nil
	}
	return fetchJWKS(ctx, jwksURL)
}

// refetchJWKS drops the cached key set and fetches a fresh one, at most once per
// jwksRefetchInterval per URL.
func refetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
	refetchKey := "refetched-at:" + jwksURL
	if _, recentlyRefetched := jwksCache.Get(refetchKey); recentlyRefetched {
		return nil, oidc.ErrUnknownKeyID
	}
	jwksCache.Set(refetchKey, true, jwksRefetchInterval)
	jwksCache.Delete(jwksURL)
	return fetchJWKS(ctx, jwksURL)
}

func fetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
	// Guard against SSRF: the JWKS URL comes from provider configuration and is fetched server-side.
	if msgs := validate.WebhookURL(jwksURL); len(msgs) > 0 {
		return nil, errors.New("JWKS URL is not allowed: %s", strings.Join(msgs, "; "))
	}

	req := &cmd.HTTPRequest{
		URL:    jwksURL,
		Method: "GET",
	}
	if err := bus.Dispatch(ctx, req); err != nil {
		return nil, errors.Wrap(err, "failed to fetch JWKS from %s", jwksURL)
	}
	if req.ResponseStatusCode != 200 {
		return nil, errors.New("failed to fetch JWKS. Status Code: %d. Body: %s", req.ResponseStatusCode, string(req.ResponseBody))
	}

	keys, err := oidc.ParseJWKS(req.ResponseBody)
	if err != nil {
		return nil, err
	}

	jwksCache.Set(jwksURL, keys, cache.DefaultExpiration)
	return keys, nil
}
