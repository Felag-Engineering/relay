package console

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
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

const (
	csrfCookieName = "relay_console_csrf"
	csrfHeaderName = "X-CSRF-Token"
	csrfFieldName  = "csrf_token"
)

// contentSecurityPolicy admits scripts and styles only from the Console's own
// origin, and nothing inline.
//
// No inline script is what makes the HTMX conventions in the specification
// mandatory rather than stylistic: hx-* attributes are ATTRIBUTES and are
// unaffected by script-src, which is precisely why `hx-on:` — which is script —
// must never appear in a template. layout_test.go asserts that it does not.
//
// connect-src 'self' keeps the SSE stream on this origin. frame-ancestors
// 'none' and form-action 'self' close the clickjacking and form-retarget paths
// that a fleet-execution surface cannot afford to leave open.
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
func Secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		token, err := ensureCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
			return
		}

		if !isSafeMethod(r.Method) && !csrfTokenValid(r, token) {
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

// isSafeMethod reports whether m is read-only by definition.
//
// The Console's side of this contract is that no mutating action is EVER
// reachable by GET — a mutating GET is a CSRF hole no token scheme repairs,
// because the browser will issue it from an <img> tag. routes_test.go asserts
// the route table holds to it.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// ensureCSRFCookie returns the request's CSRF token, minting and setting one
// when the request does not carry a usable cookie.
//
// This is the double-submit form, which needs no server-side session store and
// therefore works before the Account-backed session lands. When it does
// (issue #418), the token binds to the session and rotates with it; the
// verification below does not change shape.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 32 {
		return c.Value, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/console/",
		HttpOnly: false, // read by the page to populate hx-headers; the SESSION cookie is HttpOnly.
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

// csrfTokenValid reports whether r carries want in its header or form field,
// compared in constant time.
func csrfTokenValid(r *http.Request, want string) bool {
	got := r.Header.Get(csrfHeaderName)
	if got == "" {
		got = r.PostFormValue(csrfFieldName)
	}
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
