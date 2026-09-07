package controlplane

// consolesession.go adds the BROWSER credential lane to the one authentication
// boundary (#418).
//
// # Why here and not in package console
//
// Invariant 10: one capability layer, three thin surfaces. There is likewise
// one authentication boundary, and every surface reads the Principal it
// injects. A Console that authenticated its own requests would be a second
// auth path — the first one to be forgotten when a control is added, and
// exactly the "parallel control path" the invariant exists to forbid. So the
// Console gets a lane here, beside API Tokens and OAuth, rather than a
// mechanism of its own.
//
// # Why the lanes are chosen structurally and never tried in turn
//
// ADR-0023 set the rule for the retired shared credential and #299 kept it: a
// presented credential is routed to exactly one verifier, never offered to
// each until one accepts. Trying both makes a failure's cost depend on which
// check rejected it and lets a near-miss on one kind be scored against the
// other. Here the discriminator is structural and unambiguous — an
// Authorization header is a machine caller, a cookie is a browser — so a
// request that carries a bearer header is NEVER checked against a session, and
// a request with no bearer header is never checked against a token.

import (
	"context"
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
)

// ConsoleSessionResolver turns a presented Console session identifier into the
// session and the CURRENT Account behind it. *consoleauth.Service satisfies it.
//
// Narrow on purpose, exactly like TokenVerifier: the authenticator can resolve
// a session and nothing else. It cannot issue one, end one, or step one up — a
// component sitting on the unauthenticated edge of the process must not be
// able to mint credentials.
type ConsoleSessionResolver interface {
	Resolve(ctx context.Context, id consoleauth.SessionID) (consoleauth.Session, accounts.Account, error)
}

// consoleLane is the browser credential lane's configuration.
type consoleLane struct {
	resolver ConsoleSessionResolver

	// public reports whether a request targets the Console's UNAUTHENTICATED
	// surface — the sign-in page and the stylesheet it needs, and nothing
	// else.
	//
	// A predicate rather than a config-file list, deliberately. This punches
	// the only hole in the control plane's auth wrapper besides RFC 9728
	// metadata, and a hole an operator could widen from a file is a hole an
	// operator will widen. The predicate is supplied in code by the package
	// that owns those routes, and that package asserts its exact extent in a
	// test.
	public func(*http.Request) bool

	// scope reports whether a request targets the Console at all — the
	// surface this credential is FOR (#459).
	//
	// Without it the lane is chosen by request shape alone, and the shape of
	// a Console request ("no Authorization header, and a Console is
	// mounted") is also the shape of a cross-origin form POST to
	// /api/v1/raw-exec. The `__Host-` prefix forces the cookie to Path=/, so
	// the browser attaches it to every path on this listener; this is what
	// makes it authenticate only the surface that issued it.
	//
	// Supplied by the package that owns the routes, exactly like public
	// above, and for the same reason: their extent is one fact, asserted
	// there against the route table, not two descriptions that agree today.
	scope func(*http.Request) bool

	// unauthorized renders the refusal for a browser: a redirect to the
	// sign-in page rather than a bare 401 with a WWW-Authenticate challenge no
	// browser can satisfy.
	unauthorized http.Handler
}

// ConsoleSessionOptions configures the browser lane.
type ConsoleSessionOptions struct {
	// Public reports whether a request may proceed with no credential.
	// Required: a nil predicate would make the sign-in page itself
	// unreachable, so WithConsoleSessions refuses one.
	Public func(*http.Request) bool

	// Scope reports whether a request targets the Console, and so whether a
	// session cookie is a credential for it at all (#459).
	//
	// Required, and deliberately not defaulted to "everything": a nil
	// predicate would silently restore the control-plane-wide cookie this
	// exists to prevent, and a default that admits every path is the one
	// default a security predicate must never have.
	Scope func(*http.Request) bool

	// Unauthorized renders the refusal for an unauthenticated Console request.
	// Required for the same reason: the fallback would be a 401 the browser
	// shows as a blank page.
	Unauthorized http.Handler
}

// WithConsoleSessions makes the control plane accept human browser sessions
// alongside API Tokens and OAuth.
//
// It panics on a missing resolver, predicate or refusal handler — at
// construction, in the composition root, rather than serving a listener whose
// Console is unreachable or whose sign-in page is behind the auth it provides.
func WithConsoleSessions(resolver ConsoleSessionResolver, opts ConsoleSessionOptions) AuthOption {
	switch {
	case resolver == nil:
		panic("controlplane: WithConsoleSessions requires a ConsoleSessionResolver")
	case opts.Public == nil:
		panic("controlplane: WithConsoleSessions requires a Public predicate; without one the sign-in page sits behind the authentication it establishes")
	case opts.Scope == nil:
		panic("controlplane: WithConsoleSessions requires a Scope predicate; without one a Console session cookie authenticates every surface on this listener, including /api/v1/raw-exec")
	case opts.Unauthorized == nil:
		panic("controlplane: WithConsoleSessions requires an Unauthorized handler")
	}
	return func(a *Authenticator) {
		a.console = &consoleLane{
			resolver:     resolver,
			public:       opts.Public,
			scope:        opts.Scope,
			unauthorized: opts.Unauthorized,
		}
	}
}

// consoleSessionFromRequest reads the session cookie, if present.
func consoleSessionFromRequest(r *http.Request) (consoleauth.SessionID, bool) {
	c, err := r.Cookie(consoleauth.SessionCookieName)
	if err != nil || c.Value == "" {
		return consoleauth.SessionID{}, false
	}
	return consoleauth.ParseSessionID(c.Value), true
}

// authenticateConsole resolves a browser session into the acting identity.
//
// The Account is read fresh by the resolver on every call, exactly as the token
// lane does, which is what makes a demotion or a disablement take effect on the
// very next click rather than at the next sign-in.
func (a *Authenticator) authenticateConsole(ctx context.Context, id consoleauth.SessionID, source string) (capability.Principal, bool) {
	sess, acct, err := a.console.resolver.Resolve(ctx, id)
	if err != nil {
		return capability.Principal{}, false
	}
	p := principalFromAccount(acct)
	p.AuthMethod = capability.AuthMethodConsoleSession
	p.Source = source
	// No TokenID: a Console session presents no API Token. The audit trail's
	// verified lane carries the method instead, which is what distinguishes
	// "someone's browser did this" from "someone's script did this".
	_ = sess
	return p, true
}
