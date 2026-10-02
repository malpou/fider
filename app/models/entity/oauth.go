package entity

import (
	"encoding/json"

	"github.com/getfider/fider/app/pkg/env"
)

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
}

// IsClientSecretFromEnv returns true when OAUTH_CUSTOM_CLIENTID/OAUTH_CUSTOM_SECRET
// supply this provider's credentials, so they cannot be edited in the admin UI.
func (o OAuthConfig) IsClientSecretFromEnv() bool {
	_, ok := env.CustomOAuthSecret(o.ClientID)
	return ok
}

// MarshalJSON returns the JSON encoding of OAuthConfig.
// The masked clientSecret always comes from the stored value, never from the environment.
func (o OAuthConfig) MarshalJSON() ([]byte, error) {
	secret := "..."
	if len(o.ClientSecret) >= 10 {
		secret = o.ClientSecret[0:3] + "..." + o.ClientSecret[len(o.ClientSecret)-3:]
	}
	return json.Marshal(map[string]any{
		"id":                  o.ID,
		"provider":            o.Provider,
		"displayName":         o.DisplayName,
		"logoBlobKey":         o.LogoBlobKey,
		"status":              o.Status,
		"clientID":            o.ClientID,
		"clientSecret":        secret,
		"clientSecretFromEnv": o.IsClientSecretFromEnv(),
		"authorizeURL":        o.AuthorizeURL,
		"tokenURL":            o.TokenURL,
		"profileURL":          o.ProfileURL,
		"scope":               o.Scope,
		"isTrusted":           o.IsTrusted,
		"jsonUserIDPath":      o.JSONUserIDPath,
		"jsonUserNamePath":    o.JSONUserNamePath,
		"jsonUserEmailPath":   o.JSONUserEmailPath,
		"jsonUserRolesPath":   o.JSONUserRolesPath,
		"allowedRoles":        o.AllowedRoles,
	})
}
