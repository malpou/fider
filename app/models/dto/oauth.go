package dto

//OAuthUserProfile represents an OAuth user profile
type OAuthUserProfile struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

//OpenIDConfiguration is the subset of the OpenID Connect discovery document Fider uses
type OpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

//OAuthProviderOption represents an OAuth provider that can be used to authenticate
type OAuthProviderOption struct {
	Provider         string `json:"provider"`
	DisplayName      string `json:"displayName"`
	ClientID         string `json:"clientID"`
	URL              string `json:"url"`
	CallbackURL      string `json:"callbackURL"`
	LogoBlobKey      string `json:"logoBlobKey"`
	IsCustomProvider bool   `json:"isCustomProvider"`
	IsEnabled        bool   `json:"isEnabled"`
}
