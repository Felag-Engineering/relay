package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// bearerPrefix is the required Authorization header scheme.
const bearerPrefix = "Bearer "

// genericAuthError is the body returned on every authentication failure. It is
// identical for a missing header, a malformed header, and a wrong credential so
// a caller cannot distinguish "no token" from "wrong token" (no oracle), and it
// never contains the presented value.
const genericAuthError = "unauthorized"

// principalContextKey is an unexported type so no other package can collide
// with or forge this context key (standard Go context-key idiom).
type principalContextKey struct{}

// FoundingAdmin returns the acting identity the seeded control-plane
// credential authenticates as when no Account store is wired (tests, and any
// deployment predating the accounts table).
//
// With a store wired (WithAccounts), the credential resolves to the **stored**
// founding admin Account instead — same name, but a real row with a real ID,
// a mutable role, and an off-switch. This fallback keeps the constructor's
// existing call sites working; it is not the production path.
func FoundingAdmin() capability.Principal {
	return capability.Principal{Account: accounts.FoundingAdminName, Role: string(accounts.RoleAdmin)}
}

// AccountReader is the narrow view of the Account store the authenticator
// needs: resolve a name, and record that it authenticated. Deliberately not
// accounts.Repository — an authenticator that could create or re-role an
// Account is a privilege-escalation surface sitting on the unauthenticated
// edge of the process.
type AccountReader interface {
	GetByName(ctx context.Context, name string) (accounts.Account, error)
	TouchLastSeen(ctx context.Context, id string, at time.Time) error
}

// AuthOption configures an Authenticator.
type AuthOption func(*Authenticator)

// WithAccounts resolves the seeded credential to its stored Account (#295).
//
// Two consequences, both acceptance criteria of v0.3.0 [1/6]:
//   - audit attributes the credential to the founding admin **Account**, with
//     its ID and its current role, rather than to a hardcoded string;
//   - a **disabled** Account authenticates nowhere: the credential is refused
//     with the same generic 401 as a wrong credential, so disabling the
//     identity is immediate and does not wait for a credential rotation.
//
// A role change likewise takes effect on the next request, because the role is
// read from the store at authentication time rather than baked in at startup.
func WithAccounts(r AccountReader) AuthOption {
	return func(a *Authenticator) { a.accounts = r }
}

// PrincipalFromContext returns the Principal that Middleware injected into ctx
// after successful authentication. It is the seam #116 (Control API) and #117
// (MCP) read to pass a Principal into capability.Service.Run for audit
// attribution. ok is false if ctx was never authenticated by Middleware.
func PrincipalFromContext(ctx context.Context) (capability.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(capability.Principal)
	return p, ok
}

// Authenticator validates the bearer credential presented on the control
// plane. It holds only the credential's SHA-256 digest — never plaintext — so
// nothing that reaches into an Authenticator (including a future audit sink)
// can recover or leak the credential itself.
type Authenticator struct {
	want []byte // sha256 digest of the valid credential; never plaintext

	// accounts resolves the credential to its stored Account. Nil falls back
	// to the static FoundingAdmin identity (see WithAccounts).
	accounts AccountReader

	// now is the clock for last-seen stamping; overridable in tests.
	now func() time.Time
}

// NewAuthenticator constructs an Authenticator that accepts only credentials
// whose SHA-256 digest equals digest (typically loaded via
// LoadCredentialHashFile / ParseCredentialHash).
func NewAuthenticator(digest []byte, opts ...AuthOption) *Authenticator {
	a := &Authenticator{want: digest, now: time.Now}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Middleware wraps next so every request must present a valid bearer
// credential in the Authorization header. On success it injects FoundingAdmin
// into the request context (retrievable via PrincipalFromContext) and calls
// next. On failure it writes a generic 401 with a WWW-Authenticate: Bearer
// header and does not call next.
//
// The presented token is never logged or echoed in any response, on either
// the success or failure path — only its SHA-256 digest is ever compared, and
// only against the stored digest held in memory.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok || !a.validToken(token) {
			unauthorized(w)
			return
		}

		principal, ok := a.resolve(r.Context())
		if !ok {
			// A valid credential whose Account is disabled (or unresolvable)
			// gets the SAME generic 401 as a wrong credential: distinguishing
			// them would tell an attacker that a credential is real and only
			// its Account is switched off.
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolve turns a validated credential into the acting identity, reading the
// Account fresh on every request so a disablement or a role change takes
// effect immediately rather than at the next restart.
//
// ok is false when the Account exists but is disabled, or cannot be read at
// all — fail closed: an identity the Relay cannot confirm authorizes nothing.
func (a *Authenticator) resolve(ctx context.Context) (capability.Principal, bool) {
	if a.accounts == nil {
		return FoundingAdmin(), true
	}

	acct, err := a.accounts.GetByName(ctx, accounts.FoundingAdminName)
	if err != nil {
		return capability.Principal{}, false
	}
	if !acct.Enabled {
		return capability.Principal{}, false
	}

	// Best-effort: last-seen is advisory, and the caller has already
	// authenticated — a write failure here must never fail their request.
	_ = a.accounts.TouchLastSeen(ctx, acct.ID, a.now())

	return principalFromAccount(acct), true
}

// principalFromAccount projects a stored Account into the capability layer's
// acting identity.
//
// It lives here, at the authentication boundary, rather than in package
// capability: that package's import allowlist is deliberately narrow (jobs +
// registry) and #295 is not the change that should widen it. It does not
// consult Enabled — resolve has already refused a disabled Account before
// calling this.
func principalFromAccount(a accounts.Account) capability.Principal {
	return capability.Principal{
		AccountID: a.ID,
		Account:   a.Name,
		Role:      string(a.Role),
	}
}

// validToken reports whether token's SHA-256 digest constant-time-equals the
// Authenticator's stored digest (mirrors enroll.Service.Validate's secret
// comparison — see relay/internal/enroll/token.go).
func (a *Authenticator) validToken(token string) bool {
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], a.want) == 1
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
