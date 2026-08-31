package entity

import "encoding/json"

// TenantProvider represents tenant-level OAuth provider settings
type TenantProvider struct {
	ID        int
	TenantID  int
	Provider  string
	IsEnabled bool
}

// OAuthConfig is the configuration of a custom OAuth provider
type OAuthConfig struct {
	ID                int
	Provider          string
	DisplayName       string
	LogoBlobKey       string
	Status            int
	ClientID          string
	ClientSecret      string
	AuthorizeURL      string
	TokenURL          string
	ProfileURL        string
	Scope             string
	IsTrusted         bool
	JSONUserIDPath    string
	JSONUserNamePath  string
	JSONUserEmailPath string
	JSONUserRolesPath string
	AllowedRoles      string
	IssuerURL         string
	JWKSURL           string
	AdminRoles        string
	CollaboratorRoles string
}

// IsOIDC returns true when this provider is configured as an OpenID Connect provider.
// OIDC providers exchange and verify id_tokens instead of decoding access tokens.
func (o OAuthConfig) IsOIDC() bool {
	return o.IssuerURL != ""
}

// MarshalJSON returns the JSON encoding of OAuthConfig
func (o OAuthConfig) MarshalJSON() ([]byte, error) {
	secret := "..."
	if len(o.ClientSecret) >= 10 {
		secret = o.ClientSecret[0:3] + "..." + o.ClientSecret[len(o.ClientSecret)-3:]
	}
	return json.Marshal(map[string]any{
		"id":                o.ID,
		"provider":          o.Provider,
		"displayName":       o.DisplayName,
		"logoBlobKey":       o.LogoBlobKey,
		"status":            o.Status,
		"clientID":          o.ClientID,
		"clientSecret":      secret,
		"authorizeURL":      o.AuthorizeURL,
		"tokenURL":          o.TokenURL,
		"profileURL":        o.ProfileURL,
		"scope":             o.Scope,
		"isTrusted":         o.IsTrusted,
		"jsonUserIDPath":    o.JSONUserIDPath,
		"jsonUserNamePath":  o.JSONUserNamePath,
		"jsonUserEmailPath": o.JSONUserEmailPath,
		"jsonUserRolesPath": o.JSONUserRolesPath,
		"allowedRoles":      o.AllowedRoles,
		"issuerURL":         o.IssuerURL,
		"jwksURL":           o.JWKSURL,
		"adminRoles":        o.AdminRoles,
		"collaboratorRoles": o.CollaboratorRoles,
	})
}
