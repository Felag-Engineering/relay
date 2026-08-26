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
	"math"
	"net"
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
		}
		// Never cache a redirect to a sign-in page: the next request from
		// this browser may well be authenticated.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// safeReturnPath sanitises a post-sign-in destination.
//
// An open redirect on a sign-in page is a phishing primitive: it lends this
// Relay's hostname to somebody else's page, moments after an operator typed
// their password. So a return path must be rooted at the Console and may not
// be protocol-relative, and anything else is discarded rather than repaired.
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
	p := parsed.EscapedPath()
	if !strings.HasPrefix(p, "/console/") || p == LoginPath || p == LogoutPath {
		return ""
	}
	if q := parsed.RawQuery; q != "" {
		return p + "?" + q
	}
	return p
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
</head>
<body class="loginpage">
<main class="loginbox">
  <div class="brand"><b>Relay</b> <span>console</span></div>
  {{if .Interrupted}}<p class="loginnote">Your session ended before that action completed. Sign in to pick it back up.</p>{{end}}
  {{if .Message}}<p class="loginmsg{{if .Throttled}} slow{{end}}" role="alert">{{.Message}}</p>{{end}}
  <form method="post" action="/console/login" autocomplete="on">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    {{if .Next}}<input type="hidden" name="next" value="{{.Next}}">{{end}}
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username"
           autocapitalize="none" autocorrect="off" spellcheck="false" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</main>
</body>
</html>
`))

// handleLoginForm renders the sign-in page.
func handleLoginForm(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Already signed in: go where they were headed. The authentication
		// boundary injects a Principal on a public route when one resolves,
		// so this is a read of what it already established rather than the
		// Console resolving a session of its own.
		if _, ok := controlplane.PrincipalFromContext(r.Context()); ok {
			redirectAfterLogin(w, r, safeReturnPath(r.URL.Query().Get("next")))
			return
		}
		token, err := ensureCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
			return
		}
		renderLogin(w, http.StatusOK, loginView{
			CSRFToken:   token,
			Next:        safeReturnPath(r.URL.Query().Get("next")),
			Interrupted: r.URL.Query().Get("next") != "",
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
		token, err := ensureCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
			return
		}
		next := safeReturnPath(r.PostFormValue("next"))

		attempt := consoleauth.Attempt{
			Name:     r.PostFormValue("username"),
			Password: accounts.NewPassword(r.PostFormValue("password")),
			Source:   sourceAddress(r),
		}
		// Whatever identifier the browser already holds is handed over to be
		// RETIRED, not reused. It may have been planted before the
		// authentication boundary — that is session fixation, and rotating
		// here is the control.
		if c, err := r.Cookie(consoleauth.SessionCookieName); err == nil {
			attempt.Existing = consoleauth.ParseSessionID(c.Value)
		}

		id, _, err := d.Auth.Login(r.Context(), attempt)
		switch {
		case err == nil:
			setSessionCookie(w, id)
			redirectAfterLogin(w, r, next)
			return

		case isThrottled(err):
			wait, _ := consoleauth.Throttled(err)
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			renderLogin(w, http.StatusTooManyRequests, loginView{
				CSRFToken: token,
				Next:      next,
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
func handleLogout(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(consoleauth.SessionCookieName); err == nil && d.Auth != nil {
			if err := d.Auth.Logout(r.Context(), consoleauth.ParseSessionID(c.Value), sourceAddress(r)); err != nil {
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
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds <= 1 {
		return "Too many recent attempts. The next one will be accepted in a second."
	}
	return fmt.Sprintf("Too many recent attempts. The next one will be accepted in %d seconds. Your password was not checked.", seconds)
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
	http.Redirect(w, r, target, http.StatusSeeOther)
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

// sourceAddress is the peer address, port stripped, read off the connection.
// Never from a header: a claimed source is an assertion, and the login trail's
// source is in the verified lane.
func sourceAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
