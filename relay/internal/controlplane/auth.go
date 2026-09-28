// Package controlplane is the Relay's control-plane HTTP surface: MCP (#117)
// and the Control API (#116) mount onto the one *Server this package exposes,
// behind a single shared bearer-auth Middleware. This is the only control path
// — never build a parallel one (ADR-0009/0010, AGENTS.md invariant 10).
//
// Every request on this listener authenticates as an **Account**, presenting a
// per-Account API Token (#296). The Relay stores only each token's SHA-256
// hash; a presented credential is never logged, echoed in an error, or
// otherwise persisted (ADR-0023).
package controlplane

import (
	"context"
	"net"
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
	return capability.Principal{
		Account: accounts.FoundingAdminName,
		Role:    string(accounts.RoleAdmin),
		// The seeded founding admin is a HUMAN Account
		// (store.EnsureFoundingAdmin), and this shape must agree with what that
		// projection produces or the two would disagree about who may take
		// ADR-0027's self-confirmation rung.
		Kind: string(accounts.KindHuman),
	}
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

// authResult is what ONE credential lane established: the acting identity,
// plus whatever else that lane knows. Only the browser lane sets console —
// the bearer/OAuth lanes have no session to carry.
type authResult struct {
	principal capability.Principal
	console   *ConsoleSession // nil on every lane but the browser's
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

	// oauth is the OAuth 2.1 resource-server half (#299, ADR-0024). Nil when
	// no IdP is configured, in which case a non-token credential is simply
	// refused — the Relay advertises no flow it cannot complete.
	oauth *oauthResolver

	// console is the human browser lane (#418, ADR-0009). Nil when the Admin
	// Console is not mounted, in which case a session cookie is simply
	// ignored: no Console, no session to resolve it against, and no
	// unauthenticated surface punched in this wrapper. See consolesession.go.
	console *consoleLane
}

// AuthOption configures an Authenticator.
type AuthOption func(*Authenticator)

// WithOAuth makes the control plane accept OAuth sessions from the configured
// IdP alongside per-Account API Tokens.
//
// verifier is built once at startup (NewOIDCVerifier), so a misconfigured
// issuer fails the Relay's boot rather than every request. metadataURL is the
// absolute URL of this Relay's protected-resource document, advertised in
// WWW-Authenticate so a harness can discover the flow unaided.
func WithOAuth(cfg OAuthConfig, verifier OIDCVerifier, lookup AccountLookup, metadataURL string) AuthOption {
	claim := cfg.AccountClaim
	if claim == "" {
		claim = "email"
	}
	return func(a *Authenticator) {
		a.oauth = &oauthResolver{
			verifier:     verifier,
			accounts:     lookup,
			accountClaim: claim,
			scope:        cfg.RequiredScope,
			issuer:       cfg.Issuer,
			audience:     cfg.Audience,
			metadataURL:  metadataURL,
		}
	}
}

// NewAuthenticator constructs an Authenticator over the given verifier.
//
// The verifier is required, not optional: an Authenticator without one would
// authenticate nobody, which is fail-closed but useless, and would more likely
// mean a wiring mistake than an intent. NewAuthenticator panics on a nil
// verifier — at construction, in the composition root, rather than serving a
// listener that refuses every request for a reason nobody can see.
func NewAuthenticator(tokens TokenVerifier, opts ...AuthOption) *Authenticator {
	if tokens == nil {
		panic("controlplane: NewAuthenticator requires a TokenVerifier")
	}
	a := &Authenticator{tokens: tokens}
	for _, o := range opts {
		o(a)
	}
	return a
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
		// The Console's sign-in page and its stylesheet are the only routes
		// on this listener, besides RFC 9728 metadata, that may be reached
		// without a credential — a sign-in page behind the authentication it
		// establishes is a locked door with the key inside.
		//
		// "Public" means NEVER REFUSED, not "never authenticated": a
		// credential that resolves is still injected, so the sign-in page can
		// recognise someone who is already signed in and send them on rather
		// than asking them to authenticate twice. A public handler that needs
		// a Principal and finds none still gets the defensive 500 in
		// console.principal, never an unattributed action.
		if a.console != nil && a.console.public(r) {
			if res, ok := a.authenticateRequest(r); ok {
				next.ServeHTTP(w, r.WithContext(a.contextWith(r.Context(), res)))
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		res, ok := a.authenticateRequest(r)
		if !ok {
			// EVERY failure lands here with the same generic refusal:
			// malformed header, unknown token, wrong secret, revoked token,
			// expired token, expired or unknown session, disabled Account,
			// unreadable store. Distinguishing them would tell an attacker
			// that a credential is real and only its Account is switched off.
			a.refuse(w, r)
			return
		}

		// Asserted attribution is read AFTER authentication, never before: an
		// unauthenticated caller must not be able to reach validation logic,
		// and a malformed header on an unauthenticated request should still
		// answer 401 rather than 400 (which would reveal that the credential
		// was fine).
		asserted, err := assertionsFromRequest(r)
		if err != nil {
			badAssertedAttribution(w, err)
			return
		}

		ctx := a.contextWith(r.Context(), res)
		ctx = capability.WithAssertions(ctx, asserted)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextWith injects what one credential lane established, so the
// sign-in-page branch above and the main branch inject the same shape from
// the same code rather than two hand-rolled context.WithValue calls that can
// drift.
func (a *Authenticator) contextWith(ctx context.Context, res authResult) context.Context {
	ctx = context.WithValue(ctx, principalContextKey{}, res.principal)
	if res.console != nil {
		ctx = context.WithValue(ctx, consoleSessionContextKey{}, *res.console)
	}
	return ctx
}

// authenticateRequest picks the credential lane from the SHAPE of the request
// and runs exactly that one.
//
// An Authorization header means a machine caller and is only ever checked
// against the token/OAuth verifiers; its absence, with the Console mounted,
// means a browser and is only ever checked against a session. A request
// carrying a bearer header is never resolved as a session even if it also
// carries a cookie — so a browser cannot be talked into presenting a stolen
// session alongside a header, and a script cannot fall back to one.
//
// Shape picks the lane; it does not decide the lane's REACH. The cookie lane
// is additionally bounded by where the Console is (#459): a credential binds
// to the surface that issued it, and a session cookie the browser attaches to
// every path — the `__Host-` prefix forces Path=/ — is a credential for the
// Console and for nothing else on this listener. The token lanes carry no such
// bound: an API Token is a control-plane credential by construction.
func (a *Authenticator) authenticateRequest(r *http.Request) (authResult, bool) {
	source := SourceAddress(r)

	if credential, ok := bearerToken(r); ok {
		p, ok := a.authenticate(r.Context(), credential)
		if !ok {
			return authResult{}, false
		}
		p.Source = source
		return authResult{principal: p}, true
	}

	// The cookie is only a credential ON THE CONSOLE (#459). The `__Host-`
	// prefix forces it to Path=/, so the browser presents it on /api/v1 and
	// /mcp as well; the lane is the Console's, and it ends where the Console
	// does. Off-scope the cookie is not resolved and not even read, so a
	// request carrying one is refused exactly like a request carrying nothing.
	if a.console != nil && a.console.scope(r) {
		if id, ok := consoleSessionFromRequest(r); ok {
			return a.authenticateConsole(r.Context(), id, source)
		}
	}
	return authResult{}, false
}

// SourceAddress is the peer address, port stripped, as read off the
// connection.
//
// Never from X-Forwarded-For or any other header. A header is a claim, and the
// verified attribution lane is not where claims go (audit.Verified.Source). A
// deployment behind a proxy will see the proxy here, which is honest; the
// alternative is an audit trail an attacker can write.
func SourceAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// refuse renders an authentication failure in the shape the caller can act on:
// a browser reaching the Console is sent to the sign-in page, everything else
// gets the generic 401 challenge.
//
// The DISTINCTION IS PRESENTATION ONLY. Both paths refuse identically and
// disclose nothing about why, and the branch is taken on where the request was
// going, never on anything about the credential presented.
func (a *Authenticator) refuse(w http.ResponseWriter, r *http.Request) {
	if a.console != nil && !hasBearer(r) {
		a.console.unauthorized.ServeHTTP(w, r)
		return
	}
	a.unauthorized(w)
}

// hasBearer reports whether r carries an Authorization: Bearer header at all.
func hasBearer(r *http.Request) bool {
	_, ok := bearerToken(r)
	return ok
}

// authenticate turns a presented credential into the acting identity.
//
// The Account is read fresh by the verifier on every call rather than cached
// here, which is what makes a role change or a disablement take effect on the
// very next request instead of at the next restart.
// Two credential kinds share this boundary since #299: per-Account API Tokens
// and OAuth sessions. They are routed by PREFIX, never tried in turn — the
// rule ADR-0023 set for the retired seeded credential, for the same reasons. A
// `glp_`-shaped credential is only ever checked against the token verifier, and
// anything else only against the OAuth resolver. Trying both would make a
// failure's cost depend on which check rejected it, and would let a near-miss
// on one kind be scored against the other.
func (a *Authenticator) authenticate(ctx context.Context, credential string) (capability.Principal, bool) {
	if accounts.LooksLikeAPIToken(credential) {
		// TokenService.Verify refuses a revoked or expired token and a missing
		// or disabled Account, and collapses every one of those into a single
		// indistinguishable error. Nothing to re-check here — a second copy of
		// the rule is a second place for it to drift.
		acct, tok, err := a.tokens.Verify(ctx, credential)
		if err != nil {
			return capability.Principal{}, false
		}
		p := principalFromAccount(acct)
		p.AuthMethod = capability.AuthMethodAPIToken
		// The token ID travels with the identity into the verified audit lane:
		// "which of this Account's credentials acted" is what makes revoking
		// the compromised one a targeted act (#300).
		p.TokenID = tok.ID
		return p, true
	}

	// Fail closed: with no IdP configured there is nothing a non-token
	// credential could be checked against.
	if a.oauth == nil {
		return capability.Principal{}, false
	}
	p, err := a.oauth.resolve(ctx, credential)
	if err != nil {
		return capability.Principal{}, false
	}
	return p, true
}

// principalFromAccount projects a stored Account into the capability layer's
// acting identity.
//
// It lives here, at the authentication boundary, rather than in package
// capability: that package's import allowlist is deliberately narrow (jobs +
// registry). It does not consult Enabled — the verifier has already refused a
// disabled Account before this is reached.
//
// Kind is copied through because ADR-0027's confirmation ladder needs to know
// whether a person is behind the Account (rung 2 is human-only), and this is the
// only place in the process that holds the stored Account and the acting
// identity at the same time. It is carried as the Account's own wire value, not
// re-derived downstream: a fact established at authentication must not be
// guessed at by whichever surface happens to need it.
func principalFromAccount(a accounts.Account) capability.Principal {
	return capability.Principal{
		AccountID: a.ID,
		Account:   a.Name,
		Role:      string(a.Role),
		Kind:      string(a.Kind),
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
//
// The challenge carries the RFC 9728 resource_metadata pointer when OAuth is
// configured, which is how an off-the-shelf harness discovers the flow: it
// reads this header, fetches the metadata, and starts the authorization it
// needs — without anyone configuring the client for this Relay specifically.
func (a *Authenticator) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", a.wwwAuthenticate())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(genericAuthError))
}
