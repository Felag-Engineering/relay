package console

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// Browser security for the Console is not hygiene.
//
// ADR-0009 kept execution out of the browser because that ELIMINATED the
// "session hijack / XSS / CSRF -> fleet-wide RCE" consequence class. ADR-0026
// gave the surface back, deliberately, and named what that costs: the class
// returns, mitigated rather than eliminated, and CSP and CSRF stop being
// hygiene and become controls with a fleet blast radius. A forged click here
// would counterfeit the strongest per-action credential in the system.
//
// Everything in this file is therefore a security control. Weakening one is an
// ADR-level decision, not a convenience.
//
// # THE SCHEME (#460)
//
// This is the durable record of the decision this file enforces — written
// here, at the point of enforcement, so it is readable by the next person who
// touches this file and liftable verbatim into #475's shell-decisions ADR
// when a human writes it. (#475 is open and loop:needs-human; this file does
// not resolve it, it records the reasoning that ADR will need.)
//
// The Console's CSRF control is TWO LANES, chosen by the request's ROUTE and
// never tried in turn:
//
//  1. **The session lane** (sessionCSRFValid), for every authenticated
//     mutating request. The token is not a cookie at all: it is
//     consoleauth.Store.CSRFToken(id), an HMAC of the session identifier
//     keyed by a pepper that lives only in the Relay's process memory,
//     derived fresh on every request and compared against whatever the
//     request submitted in the header or the hidden field. There is nothing
//     for a sibling host to plant, because there is no cookie this lane
//     reads at all: a planted cookie of any name, including one carrying the
//     `__Host-` prefix, is simply never consulted here. See
//     consoleauth.Store.CSRFToken's doc for the derivation and the rejected
//     stored-secret alternative.
//
//  2. **The sign-in lane** (signInCSRFValid), for POST /console/login only —
//     the one request with no session to derive anything from. This keeps
//     the classic double-submit cookie, and `__Host-` is the ENTIRE security
//     argument for keeping it: the prefix is browser-enforced (refused
//     unless Secure, Path=/, and — the part that matters — no Domain
//     attribute), so a same-site sibling that wants its cookie sent to the
//     Console's host must set Domain= and thereby disqualify the prefix. The
//     only writer of `__Host-relay_console_signin_csrf` on this host is this
//     Console. A stateless HMAC does not help here the way it does for the
//     session lane: an attacker can fetch a legitimate login page and its
//     token themselves, because nothing about the sign-in request is bound to
//     a caller yet. This also closes classic LOGIN CSRF — forcing a victim's
//     browser to sign in to an attacker's Account — which is a real attack
//     with no session to bind to on either side of it.
//
// **The discriminator is Unauthenticated(r), never whether a session
// resolved.** That is the same predicate the authentication boundary takes as
// ConsoleSessionOptions.Public, so the CSRF lane and the auth lane cannot
// disagree about what is public, and it follows consolesession.go's existing
// rule (ADR-0023, #299): a presented credential is routed to exactly one
// verifier, never offered to each until one accepts. sessionCSRFValid refuses
// outright — never falls back to a cookie — when no ConsoleSession is in
// context; that is the one branch that could ever become a downgrade, and it
// fails closed.
//
// # Why the cookie does not survive on the session lane
//
// Once a token is compared against a per-request-derived, session-bound
// value, a double-submit cookie adds nothing an attacker who can write
// cookies on this host could not already defeat, and it costs a whole
// desync/rotation failure mode for no benefit. Removing it also removes the
// entire planted-cookie class for every authenticated route — including the
// class this issue was filed against. The cookie's only remaining job would
// have been delivering the token to the page, and that job never actually
// existed here: the server renders the token into the HTML directly
// (layout.go's hx-headers attribute and the hidden field), and no shipped
// script reads any cookie. Verified precisely, because the loose version of
// this claim invites a grep that appears to refute it: the three shipped
// scripts (activity.js, dayone.js, stream.js) contain no occurrence of
// "cookie" or "csrf" and make exactly one network call between them, an
// EventSource GET. console.css mentions both words in prose comments, which is
// not a reader.
//
// # `__Host-` forces Path=/; accepted
//
// Precedent is direct: consoleauth.SessionCookieName is already
// `__Host-relay_console_session` with Path=/, and #459 built
// console.SessionScope precisely because the prefix's forced path cannot be
// bounded — the AUTHORITY is bounded instead. The sign-in CSRF cookie carries
// no authority at all: possessing it authenticates nothing, it is one half of
// an equality check only the Console performs, it is HttpOnly, it holds a
// value the login page already rendered into HTML for this same browser, it
// lives at most ten minutes, and it is deleted the moment a sign-in succeeds
// — so on /api/v1 and /mcp it is normally absent and always inert. Neither
// surface reads a cookie of any name.
//
// # Considered and declined: `Sec-Fetch-Site` / `Origin` checking
//
// Either would close the same-site-sibling gap independently of cookies, and
// would need no configuration in the Sec-Fetch form. Declined as out of
// scope: the `__Host-` prefix already closes the class this issue names, an
// Origin check would need the Relay's own origin — configuration the Console
// must not hold (invariant 11) — and adding a second, unrequested browser
// control inside a security fix is how a focused change becomes
// unreviewable. Recorded rather than silently omitted.
//
// # CSP reporting: a recorded deferral, not an endpoint
//
// See contentSecurityPolicy's doc and docs/design/console/99-open-decisions.md
// D15 for the four reasons a `report-to`/`Reporting-Endpoints` pair naming a
// sink with nothing behind it is not shipped here.
const (
	// signInCSRFCookieName is the double-submit cookie for the one
	// unauthenticated mutating request the Console has. Named for its
	// narrowed scope, deliberately NOT `__Host-relay_console_csrf`: this
	// cookie covers exactly one lane, and a name that implied it covered the
	// Console would mislead the next reader into thinking it still does.
	signInCSRFCookieName = "__Host-relay_console_signin_csrf"

	// signInCSRFMaxAge is generous enough to read a sign-in form and type a
	// password, and short enough that a token from an abandoned tab is not a
	// standing credential.
	signInCSRFMaxAge = 600 // ten minutes

	csrfHeaderName = "X-CSRF-Token"
	csrfFieldName  = "csrf_token"
)

// wellFormedSignInCSRFToken is the shape base64.RawURLEncoding of 32 random
// bytes always produces: exactly 43 characters from the URL-safe alphabet,
// no padding. Checking the SHAPE, not merely a minimum length, is what
// signInCSRFValid and signInCSRFToken use to decide whether a presented
// cookie is one this Console actually minted — `len(v) >= 32` (the previous
// behaviour) accepted anything long enough, including a value an attacker
// chose.
var wellFormedSignInCSRFToken = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// contentSecurityPolicy admits scripts and styles only from the Console's own
// origin, and nothing inline.
//
// No inline script is what makes the HTMX conventions in the specification
// mandatory rather than stylistic: hx-* attributes are ATTRIBUTES and are
// unaffected by script-src, which is precisely why `hx-on:` — which is script —
// must never appear in a template. no_inline_script_test.go's
// TestConsole_NoInlineScript* family asserts that it does not.
//
// connect-src 'self' keeps the SSE stream on this origin. frame-ancestors
// 'none' and form-action 'self' close the clickjacking and form-retarget paths
// that a fleet-execution surface cannot afford to leave open.
//
// # CSP reporting is a recorded deferral, not an omission (#460, D15)
//
// Spec 11 calls a CSP violation a security event, so shipping a `report-to`
// naming a group with no endpoint behind it would be worse than shipping
// nothing: a control that appears to exist and silently drops every report.
// Four reasons this stays deferred, recorded in full at
// docs/design/console/99-open-decisions.md D15: (1) a report sink is an
// UNAUTHENTICATED POST that writes attacker-controlled JSON into a
// security-critical process's logs, and needs a body cap, a rate limit and a
// redaction rule before it is safe to expose at all; (2) it cannot live
// behind Secure — the browser's Reporting API sends reports without this
// Console's CSRF token and, by default, without credentials, so Secure would
// 403 every single report — it needs a route outside both Secure and the
// authenticator, a THIRD hole in the auth wrapper whose extent
// Unauthenticated's doc says is exactly two routes and no more; (3) *where*
// reports go is an open product decision — if it is a security event per spec
// 11 it belongs in the audit trail under a kind that does not exist yet,
// against ADR-0025's posture that the Relay authors its own audit records
// rather than a caller; (4) it is on neither spec 11's acceptance list nor
// v0.6.0's.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// Secure wraps h with the Console's browser-security controls: the content
// security policy, the companion hardening headers, and CSRF verification on
// every unsafe method.
//
// Order matters. This sits INSIDE Authenticator.Middleware — CSRF verification
// on an unauthenticated request is meaningless — and outside the route table,
// so a route added later cannot forget it.
//
// Secure mints nothing and can no longer fail with a 500: the session lane
// reads a value Middleware already put on the context, and the sign-in lane's
// mint (signInCSRFToken) only ever fails on a broken entropy source. Every
// OTHER minting call in this process treats that as a panic; this one still
// returns an error, unchanged from the ensureCSRFCookie it replaces, because
// login.go's callers need it request-scoped — they have a page to re-render.
func Secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		if isSafeMethod(r.Method) {
			h.ServeHTTP(w, r)
			return
		}

		// The lane is chosen by the ROUTE (Unauthenticated), never by
		// whether a session happened to resolve — see THE SCHEME above and
		// ADR-0023/#299's rule that a credential is routed to exactly one
		// verifier, never offered to each until one accepts.
		// if/else, not assign-then-override: the two lanes are mutually
		// exclusive and the code should say so syntactically rather than
		// leave it to be inferred from which result survives. The file's
		// claim above is that they are never tried in turn; an `else` is
		// what makes that literally true of the control flow.
		var valid bool
		if Unauthenticated(r) {
			boundUnauthenticatedBody(w, r)
			valid = signInCSRFValid(r)
		} else {
			valid = sessionCSRFValid(r)
		}
		if !valid {
			// Rendered as a refusal a human can act on, not a bare 403: a user
			// whose token rotated mid-action needs to know what happened rather
			// than losing the page.
			http.Error(w,
				"this request could not be verified as coming from your Console session. Reload the page and try again.",
				http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Bounds on a request body read before anyone has authenticated: the sign-in POST,
// whose CSRF check (signInCSRFValid) parses the form right here. The control-plane
// listener deliberately sets no server-wide ReadTimeout (controlplane.New explains
// why), so without these a client could trickle a body for as long as it liked,
// holding a connection and a goroutine each. Every other route refuses an
// unauthenticated request before reading its body.
const (
	// DefaultUnauthenticatedBodyTimeout is how long such a body may take to arrive.
	DefaultUnauthenticatedBodyTimeout = 10 * time.Second
	// unauthenticatedBodyMaxBytes caps it: a username, a password, a CSRF token and
	// a return path are a few hundred bytes, against ParseForm's own 10 MB default.
	unauthenticatedBodyMaxBytes = 64 << 10
)

// unauthenticatedBodyTimeout is DefaultUnauthenticatedBodyTimeout, as a variable only so
// this package's tests can shorten it; nothing else may change it (a pre-authentication
// bound is security floor, invariant 11).
var unauthenticatedBodyTimeout = DefaultUnauthenticatedBodyTimeout

// boundUnauthenticatedBody applies both bounds to r before its body is first read.
// Per-request rather than a server-wide ReadTimeout: the sign-in handler reads the whole
// form up front and answers well inside the bound, so the deadline never outlives the
// read it guards. ErrNotSupported (a ResponseRecorder in tests) means there is no
// connection to hold; TestConsole_TrickledSignInBodyIsCut proves the deadline reaches a
// real connection through the middleware chain.
func boundUnauthenticatedBody(w http.ResponseWriter, r *http.Request) {
	err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(unauthenticatedBodyTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.Warn("console: could not bound an unauthenticated request body", "error", err)
	}
	r.Body = http.MaxBytesReader(w, r.Body, unauthenticatedBodyMaxBytes)
}

// isSafeMethod reports whether m is read-only by definition.
//
// The Console's side of this contract is that no mutating action is EVER
// reachable by GET — a mutating GET is a CSRF hole no token scheme repairs,
// because the browser will issue it from an <img> tag. console_test.go's
// TestConsole_NoMutatingGet asserts the route table holds to it.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// sessionCSRFValid is the session lane: every authenticated mutating request
// except the sign-in POST.
//
// It reads controlplane.ConsoleSessionFromContext rather than deriving
// anything itself. Secure is middleware with no Deps — it has no
// *consoleauth.Service to ask — which is exactly why the derivation happens
// once, at the authentication boundary (controlplane.authenticateConsole),
// and rides the context from there. A future reader tempted to "clean this
// up" by reaching for a Service here has nothing to reach for: this function
// cannot see one, on purpose, because giving it one would be a second place
// that resolves a credential.
//
// If no ConsoleSession is present, this returns false — no fallback of any
// kind. This is the ONLY branch in the whole scheme that could ever become a
// downgrade, so it fails closed: a bearer-lane caller aimed at a Console POST
// (Authorization: Bearer with no cookie) lands here and is refused, the same
// way handleLogout already fails closed on the identical condition for its
// own reason (an authenticated request with no resolved browser session is a
// wiring alarm, not a caller to please).
func sessionCSRFValid(r *http.Request) bool {
	cs, ok := controlplane.ConsoleSessionFromContext(r.Context())
	if !ok {
		return false
	}
	// Reveal() only here, in sessionCSRFToken and in requireStepUp (which
	// re-derives the token after a rotation): the token is a redacting type
	// precisely so the few places that must handle the raw value are the ones
	// that name it out loud.
	return consoleauth.CSRFTokensEqual(cs.CSRFToken.Reveal(), submittedCSRFToken(r))
}

// signInCSRFValid is the sign-in lane: POST /console/login only.
//
// It reads the cookie named signInCSRFCookieName and no other name — in
// particular, never the legacy `relay_console_csrf` name the issue's finding
// describes, and never anything a request supplies that merely LOOKS like a
// CSRF cookie. The cookie must be well-formed (see wellFormedSignInCSRFToken)
// before it is compared at all: accepting anything of a plausible length —
// `len(v) >= 32`, this scheme's predecessor — is the defect #460 was filed
// against, because it let an attacker plant their OWN chosen value as the
// cookie and echo that same value in the form field, defeating the double
// submit entirely.
func signInCSRFValid(r *http.Request) bool {
	// SELF-GATING, and this is the load-bearing half. Unauthenticated(r) — the
	// predicate Secure uses to pick this lane — is true for the whole
	// AssetsPrefix subtree as well as LoginPath, because it is simultaneously
	// the authentication wrapper's Public predicate. So without this check, ONE
	// edit widening the auth hole would silently also move the new route onto
	// the weaker double-submit lane: two security decisions made by one change,
	// with no test going red (the existing guard asserts the PREDICATE's extent
	// and says nothing about CSRF lanes).
	//
	// That is not hypothetical. This change's own deferred CSP report sink
	// (99-open-decisions D15) needs a route outside both Secure and the
	// authenticator, and a browser sends those reports with no token and no
	// credentials — so arriving on this lane it would either be refused
	// forever or be "made to work" by a cookie pair a same-host writer can
	// plant. Refusing anything but the one request this lane exists for means
	// such a route fails closed on the session lane instead of inheriting the
	// weaker one, and makes "POST /console/login only" true in code rather
	// than by inference from a doc comment.
	if r.Method != http.MethodPost || cleanPath(r.URL.Path) != LoginPath {
		return false
	}

	c, err := r.Cookie(signInCSRFCookieName)
	if err != nil || !wellFormedSignInCSRFToken.MatchString(c.Value) {
		return false
	}
	// consoleauth.CSRFTokensEqual is reused here rather than duplicated: its
	// job — a constant-time comparison with the empty-guard against
	// subtle.ConstantTimeCompare("", "") == 1 — is identical for a plain
	// double-submit cookie and a derived, session-bound token. Only WHERE the
	// two values come from differs, and that is already decided above and in
	// sessionCSRFValid, not here.
	return consoleauth.CSRFTokensEqual(c.Value, submittedCSRFToken(r))
}

// signInCSRFToken returns the sign-in form's double-submit token, reusing the
// request's existing cookie when it is well-formed and minting a fresh one
// otherwise.
//
// Cookie attributes:
//   - Path: "/", no Domain, Secure: the `__Host-` prefix REQUIRES all three;
//     see THE SCHEME above for why the forced Path=/ is accepted here.
//   - HttpOnly: true. The coordinator's finding, stated plainly so nobody
//     "fixes" this back: no shipped script reads this cookie at all — the
//     server renders the token straight into the HTML, in layout.go's
//     hx-headers attribute and in the hidden `csrf_token` field — so the
//     previous comment here ("read by the page to populate hx-headers") was
//     simply false about this codebase, and HttpOnly costs nothing.
//   - SameSite=Strict: matches the session cookie's posture; belt-and-braces
//     alongside the prefix, not a substitute for it.
//   - MaxAge: signInCSRFMaxAge (ten minutes) — long enough to fill in a
//     password, short enough that an abandoned tab is not a standing token.
func signInCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(signInCSRFCookieName); err == nil && wellFormedSignInCSRFToken.MatchString(c.Value) {
		return c.Value, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     signInCSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   signInCSRFMaxAge,
	})
	return token, nil
}

// clearSignInCSRFCookie expires the sign-in CSRF cookie. Called the moment a
// sign-in succeeds ("clear on login" — see login.go's handleLoginSubmit): from
// there the token that matters is the session's derived one, and this cookie
// has no further job.
//
// The attributes must match signInCSRFToken's or the browser keeps the
// original — the same rule clearSessionCookie already documents.
func clearSignInCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     signInCSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// sessionCSRFToken is the single reader of ConsoleSession.CSRFToken for
// RENDERING — page() calls this, never sessionCSRFValid's context read
// directly, so there is exactly one place that turns "no session" into an
// empty token for a template rather than two call sites that could disagree
// about the fallback.
//
// ok is false when no ConsoleSession is in context: a bearer-lane caller
// rendering Console HTML (every screen test in this package authenticates
// that way — see console_test.go's request helper). page() renders
// CSRFToken: "" in that case rather than failing the request, which is safe
// under two independent guards: sessionCSRFValid refuses every unsafe method
// on the session lane before any comparison runs, and CSRFTokensEqual refuses
// an empty submitted token outright. Making Console GETs browser-lane-only
// would remove the need for this fallback entirely, but it is a separate,
// larger change — the whole screen-test suite authenticates on the bearer
// lane today — and is out of scope here.
func sessionCSRFToken(r *http.Request) (string, bool) {
	cs, ok := controlplane.ConsoleSessionFromContext(r.Context())
	if !ok {
		return "", false
	}
	return cs.CSRFToken.Reveal(), true
}

// submittedCSRFToken reads whatever token r carries, header first and then
// the form field, without judging it — comparison is entirely the two lane
// validators' job.
func submittedCSRFToken(r *http.Request) string {
	if got := r.Header.Get(csrfHeaderName); got != "" {
		return got
	}
	return r.PostFormValue(csrfFieldName)
}
