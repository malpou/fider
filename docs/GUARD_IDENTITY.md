# Sign in through guard (fork only)

This fork can run behind guard, metsa's edge proxy, and take the signed-in user from the
identity guard verifies instead of running a sign in of its own. Guard is the OIDC client
(Zitadel stays the identity provider), owns the session, and hands every request upstream
with a short-lived signed identity JWT in the `x-bastion-identity` header. Fider verifies
that JWT with the shared verifier (`github.com/MetsaApp/platform-kit/edgeauth`) against
guard's JWKS and never trusts a plain header.

## Turning it on

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_IDENTITY_ENABLED` | `false` | Sign users in from guard's identity only. |
| `PLATFORM_KIT_EDGEAUTH_AUDIENCES` | (required when enabled) | The hosts Fider is served on, comma separated (`feedback.metsa.app`). |
| `PLATFORM_KIT_EDGEAUTH_JWKS_URL` | guard's in-cluster JWKS | Where guard's public keys are. |
| `GUARD_IDENTITY_PROVIDER` | `_guard` | The `user_providers` name the identity's subject is stored under. Set it to the key of the custom OAuth provider users signed in through before, so they keep their accounts. |
| `GUARD_IDENTITY_ADMIN_ROLES` | `fider-admin` | Roles mapped to Fider administrator. |
| `GUARD_IDENTITY_COLLABORATOR_ROLES` | (none) | Roles mapped to Fider collaborator. |
| `GUARD_IDENTITY_ALLOWED_ROLES` | `fider-user` | Roles that sign in as a visitor. |

## What happens on a request

`middlewares.User()` verifies the header and signs the user in with the same rules a
custom OAuth provider's callback applies (`handlers.SignInExternalUser`, shared by both):

* The user is found by provider and subject, then by email (only a verified email), or
  created. Guard is trusted to create users on a private site: its own rule has already
  refused anyone without a role.
* The roles map onto Fider's role on every request, promoting and demoting, except that
  the last administrator is never demoted.
* An identity holding none of the allowed or mapped roles gets 403, an identity that does
  not verify 401, and 503 when guard's keys cannot be fetched. Blocked users get 401.
* No request header means anonymous. Fider's own `auth` cookie is ignored and cleared, and
  no cookie is minted: identity is per request, so guard's logout or a revoked session
  takes effect on the next request.

`/signin` redirects to `/.well-known/bastion/login?return_to=…`, `/signout` to
`/.well-known/bastion/logout`, and the sign-in control and the user menu link there
directly (`settings.guardIdentity`). API keys keep working where guard lets the request
through. The OAuth provider code stays compiled; with guard on, a provider sign in can
no longer produce a session, so the provider can be disabled.
