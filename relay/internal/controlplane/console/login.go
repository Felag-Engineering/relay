package console

// login.go is the Console's only unauthenticated surface (#418, spec
// docs/design/console/12-login.md).
//
// # What this file is careful about
//
// Everything here is reachable without a credential, so every line is
// attacker-reachable. Three properties carry the weight:
//
//  1. **No user enumeration.** The handler never branches on WHY a sign-in
//     failed — it cannot, because consoleauth.Login returns one error for all
//     of them — and it renders one message for all of them.
//  2. **No deployment information before authentication.** No version string,
//     no fleet count, no Account hints, no "this Relay exists and is large".
//     A sign-in page is a reconnaissance surface if you let it be one.
//  3. **A throttle is not a failure.** Spec 12: say so plainly, and say when
//     the next attempt is accepted. Pretending the password was wrong teaches
//     operators the product is flaky.

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// The Console's unauthenticated paths, and the destination after signing in.
const (
	// LoginPath renders the sign-in form (GET) and accepts it (POST).
	LoginPath = "/console/login"

	// LogoutPath ends a session. POST only — a sign-out reachable by GET is a
	// link anyone can make a colleague click, and while the damage is small,
	// the rule that mutating actions are never GET has no exceptions worth
	// arguing about.
	LogoutPath = "/console/logout"

	// AssetsPrefix is the stylesheet the sign-in page needs. Static CSS,
	// served from this origin, disclosing nothing.
	AssetsPrefix = "/console/assets/"

	// HomePath is where a signed-in operator lands.
	HomePath = "/console/"

	// PathPrefix is the subtree this surface occupies on the control-plane
	// listener: the composition root mounts the whole route table at
	// "/console/" and every row in [Routes] lives beneath it. It reads the
	// same as HomePath and means something different — HomePath is a
	// destination, this is the Console's extent — so [SessionScope] names
	// this one.
	PathPrefix = "/console/"

	// interruptedCookieName marks that UnauthorizedHandler, and only it, sent
	// this browser to sign in. See UnauthorizedHandler and handleLoginForm
	// for why this is a cookie rather than a query parameter: the sign-in
	// page is reachable by anyone, and every byte of its URL is
	// attacker-writable, so a `?interrupted=1` query parameter would record a
	// provenance check that provides none. A cookie for this origin is the
	// one thing a cross-site attacker cannot write.
	interruptedCookieName = "relay_console_interrupted"
)

// Authenticator is the Console's view of the sign-in service: it can start a
// session, end one, and re-prove presence. It cannot resolve one — that
// belongs to the authentication boundary (controlplane), not to a screen.
//
// An interface rather than a *consoleauth.Service so this package stays
// renderable in a test without a store, and so the set of things a Console
// handler can do to a session is enumerable by reading four method names.
type Authenticator interface {
	Login(ctx context.Context, a consoleauth.Attempt) (consoleauth.SessionID, consoleauth.Session, error)
	Logout(ctx context.Context, id consoleauth.SessionID, source string) error
	StepUp(ctx context.Context, id consoleauth.SessionID, password accounts.Password, source string) error
	StepUpWindow() time.Duration
}

// Unauthenticated reports whether r targets the Console's unauthenticated
// surface: the sign-in page and the stylesheet it needs, and nothing else.
//
// This predicate is the ONLY hole punched in the control plane's auth wrapper
// besides RFC 9728 metadata, so its extent is asserted exactly in
// login_test.go rather than described here and hoped for. It matches on the
// cleaned path, so `/console/../console/login` and `/console/nodes/../login`
// cannot smuggle a different route through it.
func Unauthenticated(r *http.Request) bool {
	path := cleanPath(r.URL.Path)
	return path == LoginPath || strings.HasPrefix(path, AssetsPrefix)
}

// cleanPath normalises a request path the way the router will see it, so a
// traversal cannot make two components disagree about which route is being
// asked for.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	// path.Clean strips a trailing slash, which matters for the assets prefix.
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// UnauthorizedHandler sends an unauthenticated browser to the sign-in page.
//
// A 303 rather than a 401: a browser cannot satisfy a `WWW-Authenticate:
// Bearer` challenge, and rendering one leaves an operator staring at a blank
// page. It carries the requested path so the sign-in can return them to it —
// spec 12's "session expired mid-action ... then back to where they were. Do
// not silently discard the work."
func UnauthorizedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := LoginPath
		if next := safeReturnPath(r.URL.RequestURI()); next != "" && next != HomePath {
			target += "?next=" + url.QueryEscape(next)
			// A real interruption, with somewhere to return to: mark it so
			// the sign-in page can say what happened rather than guessing
			// from the URL alone (which any link could have crafted).
			setInterruptedMarker(w)
		}
		// Never cache a redirect to a sign-in page: the next request from
		// this browser may well be authenticated.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// setInterruptedMarker records that THIS response is the one sending the
// browser to sign in mid-action.
//
// Path=LoginPath, not "/console/": the narrowest scope that still reaches the
// only handler that reads it, so the marker never rides on /api/v1 the way a
// `__Host-` cookie's forced Path=/ would. No `__Host-` prefix for the same
// reason — the trade is named, not hidden: a sibling subdomain could plant a
// false note, but a false note carries no authority and no attacker-supplied
// content, which is strictly better than today, where any link at all can
// render this copy. HttpOnly/Secure/SameSite=Strict match the session
// cookie's posture, which already assumes a secure context. Max-Age 300 is
// long enough to type a password and short enough that "that action" is not
// stale. Value "1": presence is the entire signal, so there is nothing to
// parse and nothing to inject.
//
// security.go's sign-in CSRF cookie reaches the opposite conclusion about a
// `__Host-` prefix's forced Path=/, and the difference is what each cookie
// IS: a planted interruption marker carries no authority at all — at worst a
// false "your session ended" note — whereas a planted CSRF cookie would BE
// the attack this scheme exists to stop. Path=/ is mandatory on the one
// where a sibling host's ability to plant it is the entire threat, and
// wasteful on the one where planting it costs nothing.
func setInterruptedMarker(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     interruptedCookieName,
		Value:    "1",
		Path:     LoginPath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
}

// takeInterruptedMarker reports whether the marker cookie is present and
// clears it in the same response, so a marker set for one visit cannot
// survive to color a later, unrelated one.
func takeInterruptedMarker(w http.ResponseWriter, r *http.Request) bool {
	_, err := r.Cookie(interruptedCookieName)
	present := err == nil
	http.SetCookie(w, &http.Cookie{
		Name:     interruptedCookieName,
		Value:    "",
		Path:     LoginPath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	return present
}

// safeReturnPath sanitises a post-sign-in destination.
//
// An open redirect on a sign-in page is a phishing primitive: it lends this
// Relay's hostname to somebody else's page, moments after an operator typed
// their password. So a return path must be rooted at the Console and may not
// be protocol-relative, and anything else is discarded rather than repaired.
//
// # The dot-segment defect this closes
//
// The previous check prefix-matched EscapedPath() against "/console/" and
// resolved no dot segment at all. That was NOT an escaping bug — the plain,
// unescaped "/console/../api/v1/x" passed it too, because EscapedPath()
// returns that string verbatim and the prefix test is satisfied regardless.
// Switching EscapedPath() for the decoded Path would have fixed neither form.
// The fix below decides membership on the DECODED path (parsed.Path), which
// collapses "..", "%2e%2e", "%2E%2E", "..%2f" and "//" to the same reading,
// and rejects anything that is not already in that canonical form rather than
// repairing it (see cleanPath and GLOSSARY.md's Canonical form). The value
// actually returned is still EscapedPath() — byte-identical to what the
// browser asked for — so a legitimately percent-encoded segment like "a%2fb"
// is never silently rewritten to "a/b".
//
// cleanPath is the same helper Unauthenticated and SessionScope use, so the
// return path, the public-route predicate and the cookie's reach cannot
// disagree about what a path is. It preserves a trailing slash, so
// "/console/" and "/console/nodes/" still pass.
func safeReturnPath(raw string) string {
	if raw == "" {
		return ""
	}
	// "//evil.example" is a protocol-relative URL, and "/\evil.example" is
	// the same trick with the slash some parsers normalise.
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return ""
	}
	p := parsed.Path // percent-decoded
	if p != cleanPath(p) {
		return ""
	}
	if !strings.HasPrefix(p, "/console/") || p == LoginPath || p == LogoutPath {
		return ""
	}
	// The ESCAPED form must be rooted at the Console too, not only the decoded
	// one. Deciding on the decoded path is what catches `..` and `%2e%2e`
	// alike, but on its own it admits a value that is not rooted at `/` at
	// all: `%2fconsole%2fnodes` decodes to the canonical, correctly-prefixed
	// "/console/nodes" and passes both checks above, while the value RETURNED
	// below is the escaped "%2fconsole%2fnodes" — a relative reference. The
	// old EscapedPath-based prefix check refused that by accident; this keeps
	// it refused on purpose.
	//
	// Not exploitable through today's two callers, which hand the result to
	// http.Redirect from a request at /console/login, so Go anchors it to the
	// current directory and the Location stays inside /console/. That is a
	// property of where those call sites happen to live, not of anything this
	// function guarantees, and this function is the one that claims the value
	// is safe to redirect to.
	if !strings.HasPrefix(parsed.EscapedPath(), "/console/") {
		return ""
	}
	if q := parsed.RawQuery; q != "" {
		return parsed.EscapedPath() + "?" + q
	}
	return parsed.EscapedPath()
}

// loginView is what the sign-in template renders.
//
// Note what is NOT here: no version, no fleet size, no Account hint, no
// indication that this deployment exists at any particular scale. Everything
// on this page is either a form control or a message about the attempt just
// made.
type loginView struct {
	CSRFToken string
	Next      string

	// Username is echoed back ONLY on a throttled re-render, as typed, and
	// never the password. A throttle refuses before any credential is
	// checked, so nothing about the submitted name is revealed by returning
	// it; a bad-credentials or infrastructure refusal leaves it empty.
	Username string

	// Message is shown to the operator. It is one of exactly two strings for a
	// refused attempt (see loginHandler), never a description of what went
	// wrong with the credential.
	Message string

	// Throttled changes the message's tone from "that did not work" to "we are
	// slowing you down, here is when to try again". A throttle rendered as a
	// failure is a lie about the system's state.
	Throttled bool

	// Interrupted marks the "your session expired mid-action" arrival, so the
	// page can say what was interrupted rather than looking like a random
	// sign-out.
	Interrupted bool
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in &mdash; Relay Console</title>
<link rel="stylesheet" href="/console/assets/console.css">
<link rel="icon" type="image/svg+xml" href="/console/assets/brand/relay-icon.svg">
</head>
<body class="loginpage">
<main class="loginbox">
  <div class="brand"><picture><source media="(prefers-color-scheme: light)" srcset="/console/assets/brand/relay-wordmark-light.svg"><img src="/console/assets/brand/relay-wordmark-dark.svg" alt="Relay"></picture> <span>console</span></div>
  {{if .Interrupted}}<p class="loginnote">Your session ended before that action completed. Sign in to pick it back up.</p>{{end}}
  {{if .Message}}<p class="loginmsg{{if .Throttled}} slow{{end}}" role="alert">{{.Message}}</p>{{end}}
  <form method="post" action="/console/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    {{if .Next}}<input type="hidden" name="next" value="{{.Next}}">{{end}}
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username"
           autocapitalize="none" autocorrect="off" spellcheck="false" required
           value="{{.Username}}" {{if not .Username}}autofocus{{end}}>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required {{if .Username}}autofocus{{end}}>
    <button type="submit">Sign in</button>
  </form>
</main>
</body>
</html>
`))

// handleLoginForm renders the sign-in page.
func handleLoginForm(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read and clear the marker FIRST, before any early return: a marker
		// left unread here would survive to color a later, unrelated visit to
		// this page.
		interrupted := takeInterruptedMarker(w, r)

		// Already signed in: go where they were headed. The authentication
		// boundary injects a Principal on a public route when one resolves,
		// so this is a read of what it already established rather than the
		// Console resolving a session of its own.
		if _, ok := controlplane.PrincipalFromContext(r.Context()); ok {
			redirectAfterLogin(w, r, safeReturnPath(r.URL.Query().Get("next")))
			return
		}
		token, err := signInCSRFToken(w, r)
		if err != nil {
			http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
			return
		}
		next := safeReturnPath(r.URL.Query().Get("next"))
		renderLogin(w, http.StatusOK, loginView{
			CSRFToken: token,
			Next:      next,
			// Both conditions matter: the marker says a real interruption
			// happened, and the validated Next says there is somewhere to
			// return to. A marker with no surviving Next means safeReturnPath
			// threw the crafted destination away, and the copy about "that
			// action" must not render for a destination that no longer
			// exists.
			Interrupted: interrupted && next != "",
		})
	}
}

// handleLoginSubmit authenticates a sign-in attempt.
func handleLoginSubmit(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil {
			http.Error(w, "the Console has no authentication service configured", http.StatusInternalServerError)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not read the sign-in form", http.StatusBadRequest)
			return
		}
		token, err := signInCSRFToken(w, r)
		if err != nil {
			http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
			return
		}
		next := safeReturnPath(r.PostFormValue("next"))

		attempt := consoleauth.Attempt{
			Name:     r.PostFormValue("username"),
			Password: accounts.NewPassword(r.PostFormValue("password")),
			Source:   controlplane.SourceAddress(r),
		}
		// Whatever identifier the browser already holds is handed over to be
		// RETIRED, not reused. It may have been planted before the
		// authentication boundary — that is session fixation, and rotating
		// here is the control.
		//
		// Deliberately the raw cookie, not controlplane.ConsoleSessionFromContext:
		// Attempt.Existing must carry whatever identifier the browser
		// PRESENTED so it can be retired, including a planted one that
		// resolves to nothing at all. The boundary's resolved session is
		// exactly the wrong thing to read here — it is empty for the one
		// identifier this control exists to catch.
		if c, err := r.Cookie(consoleauth.SessionCookieName); err == nil {
			attempt.Existing = consoleauth.ParseSessionID(c.Value)
		}

		id, _, err := d.Auth.Login(r.Context(), attempt)
		switch {
		case err == nil:
			setSessionCookie(w, id)
			// "Clear on login" (spec 11's rotation requirement, the other
			// half of which — "rotate on login" — is structural: Issue mints
			// a fresh derivation for the new session automatically, see
			// consoleauth.Store.CSRFToken). The sign-in cookie's whole job
			// ends the instant a session exists; from here the token that
			// matters is the session's own derived one. A stale sign-in form
			// left open in another tab will now refuse its next submission
			// with the existing "Reload the page and try again" copy — a
			// correctness cost, paid in the fail-closed direction, not a bug.
			clearSignInCSRFCookie(w)
			redirectAfterLogin(w, r, next)
			return

		case isThrottled(err):
			wait, _ := consoleauth.Throttled(err)
			setRetryAfter(w, wait)
			renderLogin(w, http.StatusTooManyRequests, loginView{
				CSRFToken: token,
				Next:      next,
				Username:  r.PostFormValue("username"),
				Throttled: true,
				Message:   throttleMessage(wait),
			})
			return

		case errors.Is(err, consoleauth.ErrBadCredentials):
			// ONE message for every way a sign-in can fail. There is nothing
			// to branch on here even if someone wanted to: consoleauth
			// collapses the distinctions below this call, so a wrong username
			// and a wrong password are the same value by the time they arrive.
			renderLogin(w, http.StatusUnauthorized, loginView{
				CSRFToken: token,
				Next:      next,
				Message:   "That username and password did not match. Check both and try again.",
			})
			return

		default:
			// An infrastructure failure — the audit trail is unreachable, the
			// store is down. Say that it is not the operator's credential, and
			// say nothing about which component failed.
			renderLogin(w, http.StatusInternalServerError, loginView{
				CSRFToken: token,
				Next:      next,
				Message:   "The Relay could not complete a sign-in. This is not a problem with your credentials — check the Relay's logs.",
			})
			return
		}
	}
}

// handleLogout ends the session and returns to the sign-in page.
//
// It reads the session ID from the authentication boundary
// (controlplane.ConsoleSessionFromContext) rather than re-reading the raw
// cookie: LogoutPath is never a public route, so Middleware has already
// resolved this very cookie by the time this handler runs, and reading it a
// second time here would be a second, independent parse of the same
// credential. Production-identical to the old read; the difference is that
// there is now exactly one place that turns the cookie into a SessionID.
//
// This is also "clear the CSRF token on logout" (#460, spec 11), and there is
// no line of code here that does it: d.Auth.Logout ends the session through
// Store.End, so the very next request carrying the old session cookie fails
// to resolve a Session at all — Resolve returns ErrNoSession, so no
// ConsoleSession reaches the context, so sessionCSRFValid's no-session branch
// refuses it before any token comparison is even attempted. The token dies
// with the session structurally, the same way Issue's fresh derivation makes
// "rotate on login" automatic rather than a step someone has to remember.
func handleLogout(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cs, ok := controlplane.ConsoleSessionFromContext(r.Context())
		if !ok && d.Auth != nil {
			// FAIL CLOSED, do not fall through to the happy path. An
			// authenticated request reached a gated /console/ route without a
			// resolved browser session, which on the cookie lane cannot
			// happen — Middleware sets the value for every request it lets
			// through there. The one way here is a request that authenticated
			// on ANOTHER lane: authenticateRequest prefers the bearer lane
			// unconditionally and with no path scope, so an API Token or OAuth
			// bearer aimed at this route takes it.
			//
			// Falling through would clear the cookie, 303 to the sign-in page,
			// and leave the server-side session alive — "a sign-out an operator
			// believes happened and did not", which is the exact failure the
			// comment below refuses to allow for a different reason. It is not
			// browser-reachable, so this is a wiring alarm rather than a live
			// hole; it is a 500 because the next consumer of this seam (#428's
			// step-up POST) will copy whatever shape it finds here, and the
			// shape it must copy is "no session, no action".
			slog.Error("console sign-out reached without a resolved browser session",
				"path", r.URL.Path)
			http.Error(w, "the Relay could not identify the session to end", http.StatusInternalServerError)
			return
		}
		if ok && d.Auth != nil {
			if err := d.Auth.Logout(r.Context(), cs.ID, controlplane.SourceAddress(r)); err != nil {
				http.Error(w, "the Relay could not record the sign-out", http.StatusInternalServerError)
				return
			}
		}
		// Clear the cookie regardless. A sign-out that leaves the cookie in
		// place because something else failed is a sign-out an operator
		// believes happened and did not.
		clearSessionCookie(w)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, LoginPath, http.StatusSeeOther)
	}
}

// renderLogin writes the sign-in page with the given status.
func renderLogin(w http.ResponseWriter, status int, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A sign-in page in a shared cache, or in the back-button history of a
	// borrowed laptop, is a page with somebody's username still in it.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, v); err != nil {
		// The header is already written; a truncated page beats a 200 with
		// the error swallowed.
		return
	}
}

// throttleMessage says plainly that the Relay is slowing the caller down, and
// when the next attempt will be accepted. It never suggests the credential was
// wrong.
func throttleMessage(wait time.Duration) string {
	seconds := throttleSeconds(wait)
	if seconds <= 1 {
		return "Too many recent attempts. The next one will be accepted in a second."
	}
	return fmt.Sprintf("Too many recent attempts. The next one will be accepted in %d seconds. Your password was not checked.", seconds)
}

// throttleSeconds is the throttle's wait rounded UP to whole seconds: rounding
// down would tell a caller to retry while the throttle still refuses.
func throttleSeconds(wait time.Duration) int {
	return int(math.Ceil(wait.Seconds()))
}

// setRetryAfter sets Retry-After from a throttle's wait, so the header and the
// message beside it (throttleMessage) always agree.
func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(throttleSeconds(wait)))
}

// isThrottled reports whether err is a throttle rather than a failure.
func isThrottled(err error) bool {
	_, ok := consoleauth.Throttled(err)
	return ok
}

// redirectAfterLogin sends the operator to their destination.
func redirectAfterLogin(w http.ResponseWriter, r *http.Request, next string) {
	target := next
	if target == "" {
		target = HomePath
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: every caller passes safeReturnPath's output or HomePath
}

// setSessionCookie writes the session cookie.
//
// Every attribute here is a control, and the `__Host-` prefix in the cookie's
// name is a browser-enforced assertion that three of them hold:
//
//   - HttpOnly: script cannot read it. On a surface that reaches fleet
//     execution, an XSS that could read the session is an XSS that owns the
//     fleet.
//   - Secure: never sent in the clear. Enforced by the prefix.
//   - SameSite=Strict: not attached to cross-site requests at all, which
//     closes the CSRF path ahead of the token check rather than relying on it.
//   - Path=/ and NO Domain: host-only, enforced by the prefix, so a sibling
//     subdomain cannot plant or overwrite a Console session.
//
// No Expires or Max-Age: the cookie is a session cookie in the browser's sense
// too, so closing the browser ends it. The Relay's own absolute and idle
// bounds are authoritative regardless (consoleauth.Store).
func setSessionCookie(w http.ResponseWriter, id consoleauth.SessionID) {
	http.SetCookie(w, &http.Cookie{
		Name:     consoleauth.SessionCookieName,
		Value:    id.Reveal(),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie expires the session cookie. The attributes must match
// setSessionCookie's or the browser keeps the original.
//
// There is no CSRF cookie to clear alongside it (#460): the session lane's
// token is derived from the session identifier, not carried in a cookie, so
// there is nothing here to clear — once d.Auth.Logout ends the session this
// cookie named, no later request resolves a ConsoleSession to derive or
// compare a token against in the first place. See handleLogout's doc.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     consoleauth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
