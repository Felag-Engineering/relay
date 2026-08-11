// Package controlplane is the Relay's control-plane HTTP surface: MCP (#117)
// and the Control API (#116) mount onto the one *Server this package exposes,
// behind a single shared bearer-auth Middleware. This is the only control path
// — never build a parallel one (ADR-0009/0010, CLAUDE.md invariant 10).
//
// Every request on this listener authenticates as an **Account**, presenting a
// per-Account API Token (#296). The Relay stores only each token's SHA-256
// hash; a presented credential is never logged, echoed in an error, or
// otherwise persisted (ADR-0023).
package controlplane

import (
	"context"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// bearerPrefix is the required Authorization header scheme.
const bearerPrefix = "Bearer "

// genericAuthError is the body returned on every authentication failure. It is
// identical for a missing header, a malformed header, an unknown token, a
// revoked or expired one, and a disabled Account, so a caller cannot
// distinguish any of them (no oracle), and it never contains the presented
// value.
const genericAuthError = "unauthorized"

// principalContextKey is an unexported type so no other package can collide
// with or forge this context key (standard Go context-key idiom).
type principalContextKey struct{}

// FoundingAdmin returns the founding admin's Principal shape: the identity the
// bootstrap credential authenticates as.
//
// In production the acting Principal is always projected from the **stored**
// Account, so it carries a real ID, the current role, and the Account's
// off-switch. This function is the name/role shape that projection produces
// for the founding admin, and exists so tests can state the expected audit
// attribution without reaching into a store.
func FoundingAdmin() capability.Principal {
	return capability.Principal{Account: accounts.FoundingAdminName, Role: string(accounts.RoleAdmin)}
}

// TokenVerifier authenticates a presented API Token credential and returns the
// Account it authenticates as. *accounts.TokenService satisfies it.
//
// Narrow on purpose: the authenticator can verify a credential and nothing
// else. It cannot mint, revoke, or list tokens — a component sitting on the
// unauthenticated edge of the process must not be able to issue credentials.
type TokenVerifier interface {
	Verify(ctx context.Context, credential string) (accounts.Account, accounts.APIToken, error)
}

// PrincipalFromContext returns the Principal that Middleware injected into ctx
// after successful authentication. It is the seam the Control API and the MCP
// surface read to pass a Principal into capability.Service.Run for audit
// attribution. ok is false if ctx was never authenticated by Middleware.
func PrincipalFromContext(ctx context.Context) (capability.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(capability.Principal)
	return p, ok
}

// Authenticator validates the bearer credential presented on the control
// plane.
//
// Since #298 there is exactly one kind of credential: a per-Account API Token
// (#296). The config-seeded shared credential it replaced is gone — not
// deprecated, removed — so there is no second comparison path, no digest held
// in memory, and no identity that several callers share. Every authenticated
// request now attributes to exactly one Account, and every credential can be
// revoked without affecting any other caller (ADR-0023).
//
// The Authenticator holds no secret material of any kind. It delegates to a
// TokenVerifier, which itself compares only hashes.
type Authenticator struct {
	tokens TokenVerifier
}

// NewAuthenticator constructs an Authenticator over the given verifier.
//
// The verifier is required, not optional: an Authenticator without one would
// authenticate nobody, which is fail-closed but useless, and would more likely
// mean a wiring mistake than an intent. NewAuthenticator panics on a nil
// verifier — at construction, in the composition root, rather than serving a
// listener that refuses every request for a reason nobody can see.
func NewAuthenticator(tokens TokenVerifier) *Authenticator {
	if tokens == nil {
		panic("controlplane: NewAuthenticator requires a TokenVerifier")
	}
	return &Authenticator{tokens: tokens}
}

// Middleware wraps next so every request must present a valid bearer
// credential in the Authorization header. On success it injects the acting
// Account's Principal into the request context (retrievable via
// PrincipalFromContext) and calls next. On failure it writes a generic 401
// with a WWW-Authenticate: Bearer header and does not call next.
//
// The presented credential is never logged or echoed in any response, on
// either the success or failure path — only hashes are ever compared.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential, ok := bearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}

		principal, ok := a.authenticate(r.Context(), credential)
		if !ok {
			// EVERY failure lands here with the same generic 401: malformed
			// header, unknown token, wrong secret, revoked token, expired
			// token, disabled Account, unreadable store. Distinguishing them
			// would tell an attacker that a credential is real and only its
			// Account is switched off.
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate turns a presented credential into the acting identity.
//
// The Account is read fresh by the verifier on every call rather than cached
// here, which is what makes a role change or a disablement take effect on the
// very next request instead of at the next restart.
func (a *Authenticator) authenticate(ctx context.Context, credential string) (capability.Principal, bool) {
	// TokenService.Verify refuses a revoked or expired token and a missing or
	// disabled Account, and collapses every one of those into a single
	// indistinguishable error. Nothing to re-check here — a second copy of the
	// rule is a second place for it to drift.
	acct, _, err := a.tokens.Verify(ctx, credential)
	if err != nil {
		return capability.Principal{}, false
	}
	return principalFromAccount(acct), true
}

// principalFromAccount projects a stored Account into the capability layer's
// acting identity.
//
// It lives here, at the authentication boundary, rather than in package
// capability: that package's import allowlist is deliberately narrow (jobs +
// registry). It does not consult Enabled — the verifier has already refused a
// disabled Account before this is reached.
func principalFromAccount(a accounts.Account) capability.Principal {
	return capability.Principal{
		AccountID: a.ID,
		Account:   a.Name,
		Role:      string(a.Role),
	}
}

// bearerToken extracts the token from a well-formed "Authorization: Bearer
// <token>" header. ok is false for a missing header, wrong scheme, or empty
// token.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, bearerPrefix) {
		return "", false
	}
	token := strings.TrimPrefix(header, bearerPrefix)
	if token == "" {
		return "", false
	}
	return token, true
}

// unauthorized writes the generic 401 response common to every auth failure.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(genericAuthError))
}
