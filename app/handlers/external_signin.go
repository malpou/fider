package handlers

import (
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/log"
	"github.com/getfider/fider/app/pkg/web"
)

// ExternalSignInOutcome says whether an external identity may sign in.
type ExternalSignInOutcome int

const (
	// ExternalSignInOK means the returned user is signed in.
	ExternalSignInOK ExternalSignInOutcome = iota
	// ExternalSignInDenied means the identity holds none of the roles the provider allows.
	ExternalSignInDenied
	// ExternalSignInNotInvited means the user is new and the private site does not
	// trust the provider to create accounts.
	ExternalSignInNotInvited
)

// SignInExternalUser finds the Fider user an external identity belongs to, by its
// provider UID first and then by email, or creates one. It is shared by the OAuth
// callback (OAuthToken) and the guard identity (middlewares.User), so both apply the
// same rules:
//
//   - config is the provider's role configuration (nil for built-in providers). When it
//     has a roles path, AllowedRoles gates the sign in, and AdminRoles/CollaboratorRoles
//     map the identity's roles onto a Fider role authoritatively: the user is promoted or
//     demoted to it, except that the last administrator is never demoted.
//   - Administrators and collaborators already trusted in Fider, and identities mapped to
//     one of those roles, pass the allowed-roles gate.
//   - A new user on a private site needs a trusted provider.
//
// The caller decides what a signed-in user gets (a cookie, or the request's user).
func SignInExternalUser(c *web.Context, provider string, profile *dto.OAuthUserProfile, config *entity.OAuthConfig) (*entity.User, ExternalSignInOutcome, error) {
	// Look up the existing Fider user first (by provider UID, then by email).
	// We need this before the role check so that administrators and collaborators
	// can always sign in regardless of role changes at the provider.
	var user *entity.User

	userByProvider := &query.GetUserByProvider{Provider: provider, UID: profile.ID}
	err := bus.Dispatch(c, userByProvider)
	user = userByProvider.Result

	if errors.Cause(err) == app.ErrNotFound && profile.Email != "" {
		userByEmail := &query.GetUserByEmail{Email: profile.Email}
		err = bus.Dispatch(c, userByEmail)
		user = userByEmail.Result
	}

	// Check if user has the required roles for this provider.
	// Both AllowedRoles and JSONUserRolesPath must be set on the provider for the check to run.
	var providerRolesPath, providerAllowedRoles string
	if config != nil {
		providerRolesPath = config.JSONUserRolesPath
		providerAllowedRoles = config.AllowedRoles
	}

	// Resolve the Fider role the provider's role mapping assigns to this user.
	// A user mapped to collaborator or administrator is implicitly allowed through
	// the allowed-roles gate, mirroring the isFiderPrivileged bypass below.
	mappedRole, hasMappedRole := enum.RoleVisitor, false
	if config != nil && providerRolesPath != "" {
		mappedRole, hasMappedRole = resolveMappedRole(profile.Roles, config.AdminRoles, config.CollaboratorRoles)
	}

	isFiderPrivileged := user != nil && (user.Role == enum.RoleAdministrator || user.Role == enum.RoleCollaborator)
	isMappedPrivileged := hasMappedRole && mappedRole >= enum.RoleCollaborator
	if !isFiderPrivileged && !isMappedPrivileged && !hasAllowedRole(profile.Roles, providerRolesPath, providerAllowedRoles) {
		log.Warnf(c, "User @{UserID} attempted to sign in through @{Provider} but does not have required role. User roles: @{UserRoles}, Allowed roles: @{AllowedRoles}",
			dto.Props{
				"UserID":       profile.ID,
				"Provider":     provider,
				"UserRoles":    profile.Roles,
				"AllowedRoles": providerAllowedRoles,
			})
		return nil, ExternalSignInDenied, nil
	}
	if err != nil {
		if errors.Cause(err) != app.ErrNotFound {
			return nil, ExternalSignInOK, err
		}

		isTrusted := config != nil && config.IsTrusted
		if c.Tenant().IsPrivate && !isTrusted {
			return nil, ExternalSignInNotInvited, nil
		}

		role := enum.RoleVisitor
		if hasMappedRole {
			role = mappedRole
		}

		user = &entity.User{
			Name:   profile.Name,
			Tenant: c.Tenant(),
			Email:  profile.Email,
			Role:   role,
			Providers: []*entity.UserProvider{
				{
					UID:  profile.ID,
					Name: provider,
				},
			},
		}

		if err = bus.Dispatch(c, &cmd.RegisterUser{User: user}); err != nil {
			return nil, ExternalSignInOK, err
		}
	} else if !user.HasProvider(provider) {
		if err = bus.Dispatch(c, &cmd.RegisterUserProvider{
			UserID:       user.ID,
			ProviderName: provider,
			ProviderUID:  profile.ID,
		}); err != nil {
			return nil, ExternalSignInOK, err
		}
	}

	// Sync the Fider role with the provider's role mapping on every sign in.
	// The identity provider is the source of truth: users are promoted and
	// demoted to whatever their current roles map to.
	if hasMappedRole && user.Role != mappedRole {
		if err := syncUserRole(c, user, mappedRole); err != nil {
			return nil, ExternalSignInOK, err
		}
	}

	return user, ExternalSignInOK, nil
}
