package handlers

import (
	"net/url"
	"strings"

	"github.com/MetsaApp/platform-kit/edgeauth"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/web"
)

// Guard answers these on every host it signs users in for.
const (
	guardLoginPath  = "/.well-known/bastion/login"
	guardLogoutPath = "/.well-known/bastion/logout"
)

// guardRolesPath stands in for a provider's JSON roles path: guard's identity already
// carries the role keys, but the shared role rules only run when a path is set.
const guardRolesPath = "roles"

// SignInGuardIdentity signs in the user behind an identity guard verified, with the same
// rules as a custom OAuth provider (SignInExternalUser). The role mapping and the allowed
// roles come from GUARD_IDENTITY_*; guard is trusted to create users on a private site,
// since its own rule already refused anyone without a role.
func SignInGuardIdentity(c *web.Context, id edgeauth.Identity) (*entity.User, ExternalSignInOutcome, error) {
	cfg := env.Config.GuardIdentity

	// An unverified address is neither stored nor used to find an existing account,
	// or anyone could claim another user's account by setting their email.
	email := ""
	if id.EmailVerified {
		email = strings.ToLower(strings.TrimSpace(id.Email))
	}
	name := strings.TrimSpace(id.Name)
	if name == "" && email != "" {
		name = strings.Split(email, "@")[0]
	}
	if name == "" {
		name = "Anonymous"
	}

	profile := &dto.OAuthUserProfile{ID: id.Subject, Name: name, Email: email, Roles: id.Roles}
	config := &entity.OAuthConfig{
		Provider:          cfg.Provider,
		JSONUserRolesPath: guardRolesPath,
		AllowedRoles:      cfg.AllowedRoles,
		AdminRoles:        cfg.AdminRoles,
		CollaboratorRoles: cfg.CollaboratorRoles,
		IsTrusted:         true,
	}
	return SignInExternalUser(c, cfg.Provider, profile, config)
}

// guardLoginURL is guard's login on this host, returning to a path on it.
func guardLoginURL(c *web.Context, redirect string) string {
	return guardLoginPath + "?return_to=" + url.QueryEscape(sanitiseOAuthRedirect(c, redirect))
}
