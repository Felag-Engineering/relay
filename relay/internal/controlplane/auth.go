package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

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

// FoundingAdmin returns the single Principal the seeded control-plane
// credential authenticates as. Pre-Account (ADR-0010): the credential maps to
// exactly this Principal today and becomes the first admin Account in v0.3.0.
func FoundingAdmin() capability.Principal {
	return capability.Principal{Account: "founding-admin", Role: "admin"}
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
}

// NewAuthenticator constructs an Authenticator that accepts only credentials
// whose SHA-256 digest equals digest (typically loaded via
// LoadCredentialHashFile / ParseCredentialHash).
func NewAuthenticator(digest []byte) *Authenticator {
	return &Authenticator{want: digest}
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

		ctx := context.WithValue(r.Context(), principalContextKey{}, FoundingAdmin())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
