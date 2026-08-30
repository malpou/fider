package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/getfider/fider/app"

	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"

	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/rand"
	"github.com/getfider/fider/app/pkg/validate"
)

// CreateEditOAuthConfig is used to create/edit OAuth config
type CreateEditOAuthConfig struct {
	ID                int
	Logo              *dto.ImageUpload `json:"logo"`
	Provider          string           `json:"provider"`
	Status            int              `json:"status"`
	DisplayName       string           `json:"displayName"`
	ClientID          string           `json:"clientID"`
	ClientSecret      string           `json:"clientSecret"`
	AuthorizeURL      string           `json:"authorizeURL"`
	TokenURL          string           `json:"tokenURL"`
	Scope             string           `json:"scope"`
	ProfileURL        string           `json:"profileURL"`
	IsTrusted         bool             `json:"isTrusted"`
	JSONUserIDPath    string           `json:"jsonUserIDPath"`
	JSONUserNamePath  string           `json:"jsonUserNamePath"`
	JSONUserEmailPath string           `json:"jsonUserEmailPath"`
	JSONUserRolesPath string           `json:"jsonUserRolesPath"`
	AllowedRoles      string           `json:"allowedRoles"`
	IssuerURL         string           `json:"issuerURL"`
	AdminRoles        string           `json:"adminRoles"`
	CollaboratorRoles string           `json:"collaboratorRoles"`
	// JWKSURL is filled from the OIDC discovery document during validation, never from user input.
	JWKSURL string `json:"-"`
}

func NewCreateEditOAuthConfig() *CreateEditOAuthConfig {
	return &CreateEditOAuthConfig{
		Logo: &dto.ImageUpload{},
	}
}

// IsAuthorized returns true if current user is authorized to perform this action
func (action *CreateEditOAuthConfig) IsAuthorized(ctx context.Context, user *entity.User) bool {
	return user != nil && user.IsAdministrator()
}

// SetSystemProviderStatus is used to enable/disable built-in OAuth providers
type SetSystemProviderStatus struct {
	Provider  string `json:"provider"`
	IsEnabled bool   `json:"isEnabled"`
}

// IsAuthorized returns true if current user is authorized to perform this action
func (action *SetSystemProviderStatus) IsAuthorized(ctx context.Context, user *entity.User) bool {
	return user != nil && user.IsAdministrator()
}

// Validate if current model is valid
func (action *SetSystemProviderStatus) Validate(ctx context.Context, user *entity.User) *validate.Result {
	result := validate.Success()

	if !action.IsEnabled {
		tenant := ctx.Value(app.TenantCtxKey).(*entity.Tenant)
		activeProviders := &query.ListActiveOAuthProviders{}
		if err := bus.Dispatch(ctx, activeProviders); err != nil {
			return validate.Failed("Cannot retrieve OAuth providers")
		}

		if !tenant.IsEmailAuthAllowed && len(activeProviders.Result) == 1 {
			result.AddFieldFailure("isEnabled", "You cannot disable this provider with neither email auth nor any other provider enabled.")
		}
	}

	if action.Provider == "" {
		result.AddFieldFailure("provider", "Provider is required.")
	}

	return result
}

func (action *CreateEditOAuthConfig) Validate(ctx context.Context, user *entity.User) *validate.Result {
	result := validate.Success()

	if action.Status == enum.OAuthConfigDisabled {
		tenant := ctx.Value(app.TenantCtxKey).(*entity.Tenant)
		activeProviders := &query.ListActiveOAuthProviders{}
		if err := bus.Dispatch(ctx, activeProviders); err != nil {
			return validate.Failed("Cannot retrieve OAuth providers")
		}

		if !tenant.IsEmailAuthAllowed && len(activeProviders.Result) == 1 {
			result.AddFieldFailure("status", "You cannot disable this provider with neither email auth nor any other provider enabled.")
		}
	}

	if action.Provider != "" {
		getConfig := &query.GetCustomOAuthConfigByProvider{Provider: action.Provider}
		err := bus.Dispatch(ctx, getConfig)
		if err != nil {
			return validate.Error(err)
		}

		action.ID = getConfig.Result.ID
		action.Logo.BlobKey = getConfig.Result.LogoBlobKey
		if action.ClientSecret == "" {
			action.ClientSecret = getConfig.Result.ClientSecret
		}
	} else {
		action.Provider = "_" + strings.ToLower(rand.String(10))
	}

	messages, err := validate.ImageUpload(ctx, action.Logo, validate.ImageUploadOpts{
		IsRequired:   false,
		MinHeight:    24,
		MinWidth:     24,
		ExactRatio:   true,
		MaxKilobytes: 50,
	})
	if err != nil {
		return validate.Error(err)
	}
	result.AddFieldFailure("logo", messages...)

	if action.Status != enum.OAuthConfigEnabled &&
		action.Status != enum.OAuthConfigDisabled {
		result.AddFieldFailure("status", "Invalid status.")
	}

	if action.DisplayName == "" {
		result.AddFieldFailure("displayName", "Display Name is required.")
	} else if len(action.DisplayName) > 50 {
		result.AddFieldFailure("displayName", "Display Name must have less than 50 characters.")
	}

	if action.ClientID == "" {
		result.AddFieldFailure("clientID", "Client ID is required.")
	} else if len(action.ClientID) > 100 {
		result.AddFieldFailure("clientID", "Client ID must have less than 100 characters.")
	}

	if action.ClientSecret == "" {
		result.AddFieldFailure("clientSecret", "Client Secret is required.")
	} else if len(action.ClientSecret) > 500 {
		result.AddFieldFailure("clientSecret", "Client Secret must have less than 500 characters.")
	}

	if action.Scope == "" {
		result.AddFieldFailure("scope", "Scope is required.")
	} else if len(action.Scope) > 100 {
		result.AddFieldFailure("scope", "Scope must have less than 100 characters.")
	}

	if action.IssuerURL != "" {
		if len(action.IssuerURL) > 300 {
			result.AddFieldFailure("issuerURL", "Issuer URL must have less than 300 characters.")
		} else if messages := validate.URL(ctx, action.IssuerURL); len(messages) > 0 {
			result.AddFieldFailure("issuerURL", messages...)
		} else {
			// OIDC mode: resolve endpoints from the issuer's discovery document.
			// Explicitly entered URLs always win over discovered ones.
			discovery := &query.GetOpenIDConfiguration{IssuerURL: action.IssuerURL}
			if err := bus.Dispatch(ctx, discovery); err != nil {
				result.AddFieldFailure("issuerURL", fmt.Sprintf("Could not fetch OpenID configuration: %s", errors.Cause(err).Error()))
			} else {
				if action.AuthorizeURL == "" {
					action.AuthorizeURL = discovery.Result.AuthorizationEndpoint
				}
				if action.TokenURL == "" {
					action.TokenURL = discovery.Result.TokenEndpoint
				}
				if action.ProfileURL == "" {
					action.ProfileURL = discovery.Result.UserinfoEndpoint
				}
				action.JWKSURL = discovery.Result.JWKSURI
			}
		}
	}

	if action.AuthorizeURL == "" {
		if action.IssuerURL == "" {
			result.AddFieldFailure("authorizeURL", "Authorize URL is required.")
		}
	} else if messages := validate.URL(ctx, action.AuthorizeURL); len(messages) > 0 {
		result.AddFieldFailure("authorizeURL", messages...)
	}

	if action.TokenURL == "" {
		if action.IssuerURL == "" {
			result.AddFieldFailure("tokenURL", "Token URL is required.")
		}
	} else if messages := validate.URL(ctx, action.TokenURL); len(messages) > 0 {
		result.AddFieldFailure("tokenURL", messages...)
	}

	if action.ProfileURL != "" {
		if messages := validate.URL(ctx, action.ProfileURL); len(messages) > 0 {
			result.AddFieldFailure("profileURL", messages...)
		}
	}

	if action.JSONUserIDPath == "" {
		result.AddFieldFailure("jsonUserIDPath", "JSON User ID Path is required.")
	} else if len(action.JSONUserIDPath) > 100 {
		result.AddFieldFailure("jsonUserIDPath", "JSON User ID Path must have less than 100 characters.")
	}

	if len(action.JSONUserNamePath) > 100 {
		result.AddFieldFailure("jsonUserNamePath", "JSON User Name Path must have less than 100 characters.")
	}

	if len(action.JSONUserEmailPath) > 100 {
		result.AddFieldFailure("jsonUserEmailPath", "JSON User Email Path must have less than 100 characters.")
	}

	if len(action.JSONUserRolesPath) > 100 {
		result.AddFieldFailure("jsonUserRolesPath", "JSON User Roles Path must have less than 100 characters.")
	}

	if len(action.AllowedRoles) > 500 {
		result.AddFieldFailure("allowedRoles", "Allowed Roles must have less than 500 characters.")
	}

	if len(action.AdminRoles) > 500 {
		result.AddFieldFailure("adminRoles", "Administrator Roles must have less than 500 characters.")
	}

	if len(action.CollaboratorRoles) > 500 {
		result.AddFieldFailure("collaboratorRoles", "Collaborator Roles must have less than 500 characters.")
	}

	// Role mapping silently does nothing without a roles path, so surface it at save time.
	if action.JSONUserRolesPath == "" {
		if action.AdminRoles != "" {
			result.AddFieldFailure("adminRoles", "Administrator Roles requires a JSON User Roles Path.")
		}
		if action.CollaboratorRoles != "" {
			result.AddFieldFailure("collaboratorRoles", "Collaborator Roles requires a JSON User Roles Path.")
		}
	}

	return result
}
