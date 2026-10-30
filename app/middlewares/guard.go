package middlewares

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/MetsaApp/platform-kit/edgeauth"
	"github.com/getfider/fider/app/handlers"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/entity"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/log"
	"github.com/getfider/fider/app/pkg/web"
)

// guardVerifier is the one edgeauth verifier for the process. It is rebuilt only when
// the configuration changes (tests point it at their own issuer), so its JWKS cache
// survives across requests.
var guardVerifier struct {
	sync.Mutex
	jwksURL, audiences string
	verifier           *edgeauth.Verifier
}

// identityVerifier returns the verifier for env.Config.GuardIdentity.
func identityVerifier() (*edgeauth.Verifier, error) {
	cfg := env.Config.GuardIdentity
	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		jwksURL = edgeauth.DefaultJWKSURL
	}

	guardVerifier.Lock()
	defer guardVerifier.Unlock()

	if guardVerifier.verifier != nil && guardVerifier.jwksURL == jwksURL && guardVerifier.audiences == cfg.Audiences {
		return guardVerifier.verifier, nil
	}

	v, err := edgeauth.New(edgeauth.Config{JWKSURL: jwksURL, Audiences: strings.Split(cfg.Audiences, ",")})
	if err != nil {
		return nil, err
	}
	guardVerifier.jwksURL, guardVerifier.audiences, guardVerifier.verifier = jwksURL, cfg.Audiences, v
	return v, nil
}

// guardIdentityUser signs in the user behind the request's guard identity. It returns a
// nil user for a request without one (anonymous), and a non-zero HTTP status when the
// request must be refused: 401 for an identity that does not verify, 503 when guard's
// keys cannot be fetched, 403 for an identity holding none of the allowed roles.
func guardIdentityUser(c *web.Context) (*entity.User, int, error) {
	token := c.Request.GetHeader(edgeauth.Header)
	if token == "" || c.Tenant() == nil {
		return nil, 0, nil
	}

	verifier, err := identityVerifier()
	if err != nil {
		return nil, 0, err
	}

	id, err := verifier.Verify(c, token)
	if err != nil {
		log.Warnf(c, "Guard identity refused: @{Error}", dto.Props{"Error": err.Error()})
		if errors.Is(err, edgeauth.ErrUnavailable) {
			return nil, http.StatusServiceUnavailable, nil
		}
		return nil, http.StatusUnauthorized, nil
	}

	user, outcome, err := handlers.SignInGuardIdentity(c, id)
	if err != nil {
		return nil, 0, err
	}
	if outcome != handlers.ExternalSignInOK {
		return nil, http.StatusForbidden, nil
	}
	return user, 0, nil
}
