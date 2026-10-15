package console

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

// security_test.go is the REAL seam for #460: every test here runs over
// loginFixture (login_test.go), which wires a real consoleauth.Service over a
// real store, the real controlplane.Authenticator with WithConsoleSessions,
// and Secure(mux) — the production stack, not a stand-in for any part of it.
// A unit test of a helper function does not discharge this issue; only an
// end-to-end simulation of the two lanes described in security.go's file doc
// does.

// TestConsoleCSRF_APlantedCookieCannotForgeAMutatingRequest is the issue's
// core claim, simulated end to end: sign in for real, then attempt the exact
// sibling-host attack the issue describes — a cookie the attacker planted,
// carrying the very `__Host-`-prefixed name #460's fix uses, echoed verbatim
// in the submitted form field.
//
// *Fails if*: any cookie read is reintroduced into the session lane's
// verification, including a "fix" that merely renames the cookie to a
// `__Host-` one — the planted cookie here already carries that exact name, so
// a name check alone cannot pass this test.
func TestConsoleCSRF_APlantedCookieCannotForgeAMutatingRequest(t *testing.T) {
	f := newLoginFixture(t)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	before := f.sessions.Len()

	// 43 characters drawn from the base64url alphabet: WELL-FORMED BY SHAPE, so
	// wellFormedSignInCSRFToken cannot be what refuses it and only the lane
	// separation can. This is load-bearing in the fixture, not decoration. The
	// first version of this test planted a 51-character string, which the shape
	// check rejected before the lane logic was ever consulted — so the test
	// passed while a "try the session lane, then fall back to the cookie lane"
	// downgrade went undetected. An attacker picks a well-formed value; the
	// fixture has to as well.
	const planted = "AttackerChosenValue-well_formed-by-shape-00"
	body := url.Values{"csrf_token": {planted}}
	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := f.do(t, req, session, &http.Cookie{Name: signInCSRFCookieName, Value: planted})

	if out.Code != http.StatusForbidden {
		t.Fatalf("a planted __Host- cookie forged a mutating request: status = %d, body = %s", out.Code, out.Body.String())
	}
	if got := f.sessions.Len(); got != before {
		t.Errorf("live session count changed %d -> %d: the forged logout took effect", before, got)
	}
	if _, err := f.sessions.Lookup(consoleauth.ParseSessionID(session.Value)); err != nil {
		t.Errorf("the session did not survive the forged request: %v", err)
	}
}

// TestConsoleCSRF_TheSignInPostReadsOnlyTheHostPrefixedCookie is the sign-in
// lane's simulable half: a well-formed-LOOKING token under the OLD, non-
// `__Host-` cookie name must not be accepted.
//
// *Fails if*: the verifier reads any cookie name other than
// signInCSRFCookieName, or re-adopts the `len(value) >= 32` acceptance test
// the issue names as the defect.
func TestConsoleCSRF_TheSignInPostReadsOnlyTheHostPrefixedCookie(t *testing.T) {
	f := newLoginFixture(t)

	value := strings.Repeat("a", 43) // well-formed BY SHAPE, wrong cookie name
	body := url.Values{"username": {"mike"}, "password": {consolePassword}, "csrf_token": {value}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, &http.Cookie{Name: "relay_console_csrf", Value: value})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("sign-in carrying only a legacy-named cookie = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName) != nil {
		t.Error("a sign-in with no valid CSRF cookie issued a session")
	}
}

// TestConsoleCSRF_TheSignInLaneRejectsAnAttackerChosenValue is the other half
// of the well-formedness check: a cookie carrying the CORRECT name but a
// value that is merely long (the old `len(value) >= 32` rule) rather than
// actually SHAPED like base64.RawURLEncoding of 32 random bytes.
//
// *Fails if*: signInCSRFValid re-adopts a bare length check — an attacker who
// can write same-name, same-shape-ignoring cookies (any sibling host, absent
// the __Host- shape check being what it is) could otherwise plant any value
// of their choosing here and echo it in the form field.
func TestConsoleCSRF_TheSignInLaneRejectsAnAttackerChosenValue(t *testing.T) {
	f := newLoginFixture(t)

	const attackerChosen = "this-is-attacker-chosen-and-happens-to-be-long-enough-too"
	body := url.Values{"username": {"mike"}, "password": {consolePassword}, "csrf_token": {attackerChosen}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, &http.Cookie{Name: signInCSRFCookieName, Value: attackerChosen})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("an attacker-chosen, merely-long cookie value = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName) != nil {
		t.Error("a sign-in with a malformed CSRF cookie issued a session")
	}
}

// TestConsoleCSRF_TheSignInCookieIsHostOnlyAndUnreadableByScript is a
// contract-with-the-browser assertion, not a simulation: Go's
// http.SetCookie/AddCookie do not enforce cookie prefixes, so no Go test can
// reproduce a browser refusing a sibling's `__Host-` cookie. What the
// guarantee is bought with is these attributes, so these attributes are what
// is pinned.
//
// *Fails if*: the prefix, HttpOnly, Secure or Path=/ is weakened, or a Domain
// is added.
func TestConsoleCSRF_TheSignInCookieIsHostOnlyAndUnreadableByScript(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	c := cookieNamed(rec.Result().Cookies(), signInCSRFCookieName)
	if c == nil {
		t.Fatal("the sign-in form set no CSRF cookie")
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("cookie name = %q, want the __Host- prefix", c.Name)
	}
	if !c.Secure {
		t.Error("the sign-in CSRF cookie is not Secure")
	}
	if !c.HttpOnly {
		t.Error("the sign-in CSRF cookie is not HttpOnly — no shipped script reads it, so this costs nothing")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want / (the __Host- prefix requires it)", c.Path)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, want none (the __Host- prefix requires it, and it is what makes the cookie host-only)", c.Domain)
	}
}

// TestConsoleCSRF_ASignedInResponseNeverSetsACSRFCookie walks every GET route
// this fixture actually mounts (Routes(f.deps), not a hand-reconstructed
// table that could drift from it) and asserts a signed-in render sets neither
// CSRF cookie.
//
// *Fails if*: cookie minting creeps back into Secure or page().
func TestConsoleCSRF_ASignedInResponseNeverSetsACSRFCookie(t *testing.T) {
	f := newLoginFixture(t)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	paths := walkableScreens(Routes(f.deps), fixtureIDs)
	if len(paths) == 0 {
		t.Fatal("the sweep found zero GET screens — it is not running")
	}
	for _, path := range paths {
		rec := f.do(t, httptest.NewRequest(http.MethodGet, path, nil), session)
		for _, c := range rec.Result().Cookies() {
			if c.Name == signInCSRFCookieName || c.Name == consoleauth.SessionCookieName {
				t.Errorf("a signed-in GET %s set a Set-Cookie named %q", path, c.Name)
			}
		}
	}
}

// TestConsoleCSRF_ATokenFromAnotherSessionIsRefused: two independent
// sessions, each with its own derived token; session A's rendered token must
// not validate a request carrying session B's cookie.
//
// *Fails if*: the token is process-wide, or keyed on anything other than the
// session identifier.
func TestConsoleCSRF_ATokenFromAnotherSessionIsRefused(t *testing.T) {
	f := newLoginFixture(t)

	_, cookiesA := f.signIn(t, "mike", consolePassword)
	sessionA := cookieNamed(cookiesA, consoleauth.SessionCookieName)
	pageA := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), sessionA)
	tokenA := renderedCSRFToken(pageA.Body.String())
	if tokenA == "" {
		t.Fatal("session A's fleet view rendered no CSRF token")
	}

	_, cookiesB := f.signIn(t, "mike", consolePassword)
	sessionB := cookieNamed(cookiesB, consoleauth.SessionCookieName)

	body := url.Values{"csrf_token": {tokenA}}
	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, sessionB)

	if rec.Code != http.StatusForbidden {
		t.Errorf("session B's request carrying session A's token = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if _, err := f.sessions.Lookup(consoleauth.ParseSessionID(sessionB.Value)); err != nil {
		t.Errorf("session B did not survive the refused request: %v", err)
	}
}

// TestConsoleCSRF_TheTokenRotatesOnLogin captures the token rendered after
// one sign-in, signs in again, and asserts the newly rendered token differs
// and the old one is refused.
//
// *Fails if*: Issue reuses a value, or a cookie survives a sign-in to carry
// the old token forward.
func TestConsoleCSRF_TheTokenRotatesOnLogin(t *testing.T) {
	f := newLoginFixture(t)

	_, cookies1 := f.signIn(t, "mike", consolePassword)
	session1 := cookieNamed(cookies1, consoleauth.SessionCookieName)
	page1 := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session1)
	token1 := renderedCSRFToken(page1.Body.String())
	if token1 == "" {
		t.Fatal("the first sign-in rendered no CSRF token")
	}

	_, cookies2 := f.signIn(t, "mike", consolePassword)
	session2 := cookieNamed(cookies2, consoleauth.SessionCookieName)
	page2 := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session2)
	token2 := renderedCSRFToken(page2.Body.String())
	if token2 == "" {
		t.Fatal("the second sign-in rendered no CSRF token")
	}
	if token1 == token2 {
		t.Error("signing in again rendered the same CSRF token: rotation did not happen")
	}

	// The pre-rotation token, replayed against the NEW session, must be
	// refused — it is not enough that the two tokens merely differ.
	body := url.Values{"csrf_token": {token1}}
	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, session2)
	if rec.Code != http.StatusForbidden {
		t.Errorf("the pre-rotation token was accepted after a fresh sign-in: status = %d", rec.Code)
	}
}

// TestConsoleCSRF_TheTokenDiesWithTheSession signs in, captures the token,
// signs out, then replays a POST carrying the old session cookie and the old
// token.
//
// *Fails if*: a token is cached anywhere outside the store, letting a dead
// session's old token still reach and act on the handler — which would show
// up here as the handler running a second time (a second Set-Cookie clearing
// the session), rather than the auth boundary's ordinary no-such-session
// refusal.
func TestConsoleCSRF_TheTokenDiesWithTheSession(t *testing.T) {
	f := newLoginFixture(t)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(page.Body.String())
	if token == "" {
		t.Fatal("the signed-in fleet view rendered no CSRF token")
	}

	logoutBody := url.Values{"csrf_token": {token}}.Encode()
	logoutReq := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(logoutBody))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := f.do(t, logoutReq, session)
	if out.Code != http.StatusSeeOther {
		t.Fatalf("sign-out = %d, want %d", out.Code, http.StatusSeeOther)
	}

	replayReq := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(logoutBody))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay := f.do(t, replayReq, session)

	// The replay must not reach handleLogout a second time: that handler
	// unconditionally clears the session cookie on every path it runs, so a
	// second Set-Cookie for it is exactly what a cached, still-valid token
	// would produce.
	if cleared := cookieNamed(replay.Result().Cookies(), consoleauth.SessionCookieName); cleared != nil {
		t.Errorf("a dead session's old token still reached the handler: got a second Set-Cookie for %s", consoleauth.SessionCookieName)
	}
	if _, err := f.sessions.Lookup(consoleauth.ParseSessionID(session.Value)); err == nil {
		t.Error("the session survived its own sign-out")
	}
}

// hxHeadersTokenPattern extracts the token layout.go's hx-headers attribute
// carries, so a test can compare it against the hidden field's value.
var hxHeadersTokenPattern = regexp.MustCompile(`hx-headers='\{"X-CSRF-Token": "([^"]*)"\}'`)

// TestConsoleCSRF_TheRenderedTokenIsTheSessionSecret asserts the two
// rendering sites — the body's hx-headers attribute and the logout form's
// hidden field — carry the SAME value, and that the value actually validates
// on a real POST.
//
// *Fails if*: the two rendering sites diverge, or the rendered value stops
// being the compared value.
func TestConsoleCSRF_TheRenderedTokenIsTheSessionSecret(t *testing.T) {
	f := newLoginFixture(t)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	body := page.Body.String()

	hidden := renderedCSRFToken(body)
	if hidden == "" {
		t.Fatal("the fleet view rendered no hidden CSRF field")
	}
	header := hxHeadersTokenPattern.FindStringSubmatch(body)
	if header == nil {
		t.Fatal("the fleet view rendered no hx-headers attribute")
	}
	if header[1] != hidden {
		t.Errorf("hx-headers token %q != hidden field token %q", header[1], hidden)
	}

	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(url.Values{"csrf_token": {hidden}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, session)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("a POST with the rendered token = %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

// TestConsoleCSRF_ABearerLaneRequestCannotMutateTheConsole: a bearer-header
// request has no ConsoleSession, so the session lane must refuse it outright
// — before handleLogout ever runs (and, absent the fix, 500s trying to find a
// session that was never resolved).
//
// *Fails if*: the no-session branch falls back to a cookie instead of
// refusing.
func TestConsoleCSRF_ABearerLaneRequestCannotMutateTheConsole(t *testing.T) {
	f := newLoginFixture(t)

	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := f.do(t, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a bearer-lane POST to logout = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestConsoleCSRF_AnEmptyRenderedTokenCannotValidate: a bearer-lane GET
// renders csrf_token=""; submitting "" back (header and field, both empty)
// must still be refused.
//
// *Fails if*: the lane's requirement for a resolved session is removed.
//
// Deliberately NOT claiming both guards. CSRFTokensEqual's empty guard is the
// second line of defence here and this test does not reach it: the bearer-lane
// request is refused by sessionCSRFValid's no-session branch before any
// comparison runs, so removing the empty guard leaves this test green (verified
// by mutation). That guard is covered where it can actually be exercised, in
// consoleauth's TestCSRFTokensEqual_RefusesEmptiesAndZero. Saying "either
// guard" here would have been a comment taking credit for coverage it has not
// got — the failure mode this repo keeps finding.
func TestConsoleCSRF_AnEmptyRenderedTokenCannotValidate(t *testing.T) {
	f := newLoginFixture(t)

	getReq := httptest.NewRequest(http.MethodGet, "/console/", nil)
	getReq.Header.Set("Authorization", "Bearer "+testCredential)
	page := f.do(t, getReq)
	if page.Code != http.StatusOK {
		t.Fatalf("bearer-lane GET /console/ = %d, want 200", page.Code)
	}
	if got := renderedCSRFToken(page.Body.String()); got != "" {
		t.Fatalf("a bearer-lane render carried a non-empty CSRF token: %q", got)
	}

	postReq := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader("csrf_token="))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Authorization", "Bearer "+testCredential)
	rec := f.do(t, postReq)
	if rec.Code != http.StatusForbidden {
		t.Errorf("an empty token submitted on the bearer lane = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestConsoleCSRF_TheSessionTokenIsAccepted is the other half of
// TestConsole_CSRFRefusesUnsafeMethodWithoutToken (console_test.go): the
// control must admit a legitimate request, or it is not a control but an
// outage. It lives here, over the real stack, because the session lane no
// longer mints from a bare GET — admitting a real token needs a real session.
func TestConsoleCSRF_TheSessionTokenIsAccepted(t *testing.T) {
	f := newLoginFixture(t)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(page.Body.String())
	if token == "" {
		t.Fatal("the signed-in fleet view rendered no CSRF token")
	}

	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(url.Values{"csrf_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeaderName, token) // exercise the header-extraction path too
	rec := f.do(t, req, session)

	if rec.Code == http.StatusForbidden {
		t.Errorf("a request carrying a matching CSRF token was refused: code=%d", rec.Code)
	}
}

// TestConsoleCSRF_SuccessfulSignInClearsTheSignInCookie pins "clear on login",
// one of #460's four stated requirements.
//
// Worth its own test because nothing else notices its absence: the sign-in
// cookie is only ever read on the Unauthenticated lane, so a copy left behind
// after sign-in opens no hole and breaks no other assertion — it simply means a
// signed-in visitor returning to the form reuses a stale token instead of being
// issued a fresh one. A coordinator mutation pass found that deleting the
// clear-on-login call left the whole suite green.
//
// *Fails if*: clearSignInCSRFCookie stops being called on the success path, or
// is called with attributes that do not match the cookie it is clearing (a
// browser keeps the original when Path or Name differ, so an expiry that does
// not match is an expiry that does not happen).
func TestConsoleCSRF_SuccessfulSignInClearsTheSignInCookie(t *testing.T) {
	f := newLoginFixture(t)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}

	cleared := cookieNamed(cookies, signInCSRFCookieName)
	if cleared == nil {
		t.Fatal("the successful sign-in response did not clear the sign-in CSRF cookie at all")
	}
	if cleared.MaxAge >= 0 {
		t.Errorf("sign-in CSRF cookie MaxAge = %d, want negative so the browser drops it", cleared.MaxAge)
	}
	if cleared.Value != "" {
		t.Errorf("sign-in CSRF cookie Value = %q, want empty", cleared.Value)
	}
	// The clearing cookie must match the original's scope, or the browser keeps
	// the one it already has and the clear is cosmetic.
	if cleared.Path != "/" {
		t.Errorf("clearing cookie Path = %q, want \"/\" to match the cookie being cleared", cleared.Path)
	}
}

// TestConsoleCSRF_TheWeakLaneRefusesAnythingButTheSignInPost pins finding 1 of
// #460's security review: the double-submit lane must gate itself, not rely on
// Secure's choice of lane being correct forever.
//
// Unauthenticated(r) is true for the whole assets subtree as well as LoginPath,
// and it is the SAME predicate the authentication wrapper uses as Public. So
// one edit widening the auth hole would otherwise also move the new route onto
// the weaker lane — two security decisions in one change, with nothing going
// red. A route added to the unauthenticated set must fail closed on the session
// lane instead of inheriting the cookie lane.
//
// *Fails if*: signInCSRFValid stops checking the method and path, which is the
// shape a reader "simplifying" the lane selection would most plausibly produce.
func TestConsoleCSRF_TheWeakLaneRefusesAnythingButTheSignInPost(t *testing.T) {
	// A well-formed cookie/field pair an attacker can plant and echo. On the
	// sign-in POST this pair is exactly what the lane accepts, so if any other
	// unauthenticated path admitted it, that path would be forgeable.
	const planted = "AttackerChosenValue-well_formed-by-shape-00"

	for _, path := range []string{
		AssetsPrefix + "report",      // the shape D15's deferred CSP sink would take
		AssetsPrefix + "console.css", // a real asset, reached with an unsafe method
	} {
		t.Run(path, func(t *testing.T) {
			if !Unauthenticated(httptest.NewRequest(http.MethodPost, path, nil)) {
				t.Fatalf("fixture is not exercising the weak lane: Unauthenticated(%q) is false", path)
			}
			body := url.Values{"csrf_token": {planted}}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if signInCSRFValid(withCookies(req, &http.Cookie{Name: signInCSRFCookieName, Value: planted})) {
				t.Errorf("the double-submit lane accepted %s %s; it must serve POST %s and nothing else",
					http.MethodPost, path, LoginPath)
			}
		})
	}

	// And the requests it DOES serve still work, or the gate is an outage.
	//
	// The traversal form is ACCEPTED deliberately, and that is worth pinning
	// rather than leaving to surprise: the gate compares cleanPath(), so a path
	// that normalises back to LoginPath IS the sign-in POST by the time the
	// router sees it. Comparing the raw path instead would refuse a request the
	// router is about to send to the sign-in handler — a gate and a router
	// disagreeing about which route is being asked for, which is the whole
	// reason cleanPath exists.
	for _, path := range []string{LoginPath, LoginPath + "/../login"} {
		body := url.Values{"csrf_token": {planted}}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if !signInCSRFValid(withCookies(req, &http.Cookie{Name: signInCSRFCookieName, Value: planted})) {
			t.Errorf("the double-submit lane refused POST %s, which resolves to the one request it exists for", path)
		}
	}

	// A SAFE method on the sign-in path is refused too: Secure never reaches a
	// lane for those, so this only pins that the gate does not widen on its own.
	getReq := httptest.NewRequest(http.MethodGet, LoginPath, nil)
	if signInCSRFValid(withCookies(getReq, &http.Cookie{Name: signInCSRFCookieName, Value: planted})) {
		t.Error("the double-submit lane accepted a GET; it must serve the sign-in POST only")
	}
}

// withCookies attaches cookies to a request and returns it, so a table row
// stays one expression.
func withCookies(r *http.Request, cookies ...*http.Cookie) *http.Request {
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}
