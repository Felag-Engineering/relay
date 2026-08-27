package console

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

const consolePassword = "a console password"

// csrfTokenPattern normalises the one legitimately-varying value in a rendered
// sign-in page, so a comparison across failures is about the MESSAGE.
var csrfTokenPattern = regexp.MustCompile(`value="[A-Za-z0-9_-]{20,}"`)

// loginFixture mounts the Console the way the composition root must, with a
// REAL consoleauth.Service over a real store — the sign-in path is the one
// place a fake would hide the properties under test.
type loginFixture struct {
	handler  http.Handler
	sessions *consoleauth.Store
	accounts accounts.Repository
	mike     accounts.Account
	clk      *testClock
}

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	mike, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword(consolePassword))
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, mike.ID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}

	clk := &testClock{t: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	sessions := consoleauth.NewStore(consoleauth.WithClock(clk.now))
	svc := consoleauth.NewService(st.Accounts(), st.Passwords(), sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now)), nil)

	authn := controlplane.NewAuthenticator(
		roleVerifier{role: accounts.RoleAdmin},
		controlplane.WithConsoleSessions(svc, controlplane.ConsoleSessionOptions{
			Public:       Unauthenticated,
			Unauthorized: UnauthorizedHandler(),
		}),
	)
	mux := http.NewServeMux()
	// The sign-in tests land on the fleet view, so the fixture wires the same
	// minimal read seams every screen test uses. Without them the landing page
	// is a 500 by design (an unwired registry is a wiring bug, not an empty
	// fleet), and the sign-in assertion would fail for a reason that has
	// nothing to do with signing in.
	d := renderableDeps()
	d.Auth = svc
	Register(mux, d)

	return &loginFixture{
		handler:  authn.Middleware(Secure(mux)),
		sessions: sessions,
		accounts: st.Accounts(),
		mike:     mike,
		clk:      clk,
	}
}

// do issues a request, carrying cookies forward the way a browser would.
func (f *loginFixture) do(t *testing.T, req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// signIn posts credentials and returns the response plus every cookie set.
func (f *loginFixture) signIn(t *testing.T, username, password string, extra ...*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()

	// Fetch the form first so the CSRF cookie exists, exactly as a browser
	// would: the double-submit token is worthless if a test can skip it.
	formRec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil), extra...)
	csrf := cookieNamed(formRec.Result().Cookies(), csrfCookieName)
	if csrf == nil {
		t.Fatal("the sign-in form set no CSRF cookie")
	}

	body := url.Values{"username": {username}, "password": {password}, "csrf_token": {csrf.Value}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, append([]*http.Cookie{csrf}, extra...)...)
	return rec, rec.Result().Cookies()
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- The unauthenticated surface -------------------------------------------

// TestConsole_OnlyLoginAndItsAssetsAreReachableUnauthenticated is spec 12's
// "No route other than login, its assets and health is reachable
// unauthenticated" — and it is the assertion that keeps the ONE hole in the
// control plane's auth wrapper the size it was designed to be.
func TestConsole_OnlyLoginAndItsAssetsAreReachableUnauthenticated(t *testing.T) {
	public := []string{
		LoginPath,
		"/console/assets/console.css",
	}
	private := []string{
		"/console/",
		"/console/agents",
		"/console/activity",
		"/console/reads",
		"/console/policy",
		"/console/approvals",
		"/console/nodes/add",
		"/console/accounts",
		"/console/incident",
		"/console/nodes/node-1",
		"/console/jobs/job-1",
		"/console/compare",
		LogoutPath,
		// Traversals must not smuggle a private route through the predicate:
		// it matches on the CLEANED path for exactly this reason.
		"/console/nodes/../login/../",
		"/console/login/../accounts",
	}

	for _, p := range public {
		if !Unauthenticated(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("%s is not reachable unauthenticated; the sign-in page cannot sit behind the authentication it establishes", p)
		}
	}
	for _, p := range private {
		if Unauthenticated(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("%s is reachable unauthenticated", p)
		}
	}
}

func TestConsole_UnauthenticatedRequestIsSentToSignIn(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/activity", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d (a browser cannot satisfy a Bearer challenge)", rec.Code, http.StatusSeeOther)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, LoginPath) {
		t.Fatalf("Location = %q, want the sign-in page", loc)
	}
	// Spec 12: do not silently discard the work — come back here afterwards.
	if !strings.Contains(loc, url.QueryEscape("/console/activity")) {
		t.Errorf("Location = %q, want it to carry the interrupted destination", loc)
	}
}

// --- Signing in -------------------------------------------------------------

func TestConsole_SignInIssuesASessionAndLands(t *testing.T) {
	f := newLoginFixture(t)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != HomePath {
		t.Errorf("Location = %q, want %q", got, HomePath)
	}

	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	if !session.HttpOnly {
		t.Error("the session cookie is not HttpOnly: script can read a fleet-execution credential")
	}
	if !session.Secure {
		t.Error("the session cookie is not Secure")
	}
	if session.SameSite != http.SameSiteStrictMode {
		t.Errorf("the session cookie is SameSite=%v, want Strict", session.SameSite)
	}
	if session.Domain != "" {
		t.Errorf("the session cookie sets Domain=%q; it must be host-only", session.Domain)
	}
	if session.Path != "/" {
		t.Errorf("the session cookie sets Path=%q, want / (required by the __Host- prefix)", session.Path)
	}
	if !strings.HasPrefix(session.Name, "__Host-") {
		t.Errorf("the session cookie is named %q; the __Host- prefix is what makes host-only browser-enforced", session.Name)
	}

	// And it actually authenticates the next request.
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	if page.Code != http.StatusOK {
		t.Fatalf("a signed-in request to the fleet view = %d, want 200", page.Code)
	}
	if !strings.Contains(page.Body.String(), "mike") {
		t.Error("the rendered page does not name the signed-in Account")
	}
}

// TestConsole_SignInIsIndistinguishableAcrossFailures is the no-enumeration
// acceptance criterion at the HTTP boundary: whatever the reason, the operator
// sees the same status and the same words.
func TestConsole_SignInIsIndistinguishableAcrossFailures(t *testing.T) {
	type attempt struct{ user, pass string }
	attempts := map[string]attempt{
		"an unknown username": {"no-such-person", consolePassword},
		"a wrong password":    {"mike", "not the password"},
		"an empty password":   {"mike", ""},
	}

	var bodies []string
	for name, a := range attempts {
		t.Run(name, func(t *testing.T) {
			f := newLoginFixture(t) // a fresh fixture so no throttle carries over
			rec, cookies := f.signIn(t, a.user, a.pass)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if cookieNamed(cookies, consoleauth.SessionCookieName) != nil {
				t.Error("a refused sign-in set a session cookie")
			}
			body := rec.Body.String()
			if strings.Contains(strings.ToLower(body), "unknown") ||
				strings.Contains(strings.ToLower(body), "no such") ||
				strings.Contains(strings.ToLower(body), "does not exist") {
				t.Errorf("the refusal hints that the username is not real: %s", body)
			}
			// The CSRF token legitimately differs per request; everything
			// else about the page must not.
			bodies = append(bodies, csrfTokenPattern.ReplaceAllString(body, `value="TOKEN"`))
		})
	}

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Error("two different sign-in failures rendered different pages: the form enumerates Accounts")
		}
	}
}

func TestConsole_SignInPageRevealsNothingAboutTheDeployment(t *testing.T) {
	f := newLoginFixture(t)
	body := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil)).Body.String()

	// Spec 12: no fleet or deployment information before authentication, and
	// no hint of whether a username exists. Anything that grew onto this page
	// later — a version string, a node count, a "3 operators" line — is
	// reconnaissance handed to an unauthenticated caller.
	for _, forbidden := range []string{"mike", "Node", "node:", "version", "fleet", "enrolled"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("the sign-in page mentions %q", forbidden)
		}
	}
	// The password field must be a password field, with sane autocomplete.
	if !strings.Contains(body, `type="password"`) {
		t.Error("the password field is not type=password")
	}
	if !strings.Contains(body, `autocomplete="current-password"`) {
		t.Error("the password field has no autocomplete hint")
	}
}

func TestConsole_SignInRotatesAPresentedSessionIdentifier(t *testing.T) {
	f := newLoginFixture(t)

	// A cookie an attacker planted before the authentication boundary.
	planted, err := f.sessions.Issue(consoleauth.Session{AccountID: "acct-x", Account: "victim"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	plantedCookie := &http.Cookie{Name: consoleauth.SessionCookieName, Value: planted.Reveal()}

	_, cookies := f.signIn(t, "mike", consolePassword, plantedCookie)
	fresh := cookieNamed(cookies, consoleauth.SessionCookieName)
	if fresh == nil {
		t.Fatal("no session cookie was set")
	}
	if fresh.Value == planted.Reveal() {
		t.Fatal("the sign-in reused the presented identifier: session fixation is open")
	}
	if _, err := f.sessions.Lookup(planted); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("the planted identifier still resolves after signing in: %v", err)
	}
}

func TestConsole_ThrottleSaysSoAndSaysWhen(t *testing.T) {
	f := newLoginFixture(t)

	if rec, _ := f.signIn(t, "mike", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first failure status = %d", rec.Code)
	}
	rec, _ := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After header on a throttled sign-in")
	}
	body := rec.Body.String()
	// Spec 12: "say so plainly, and when the next attempt is accepted; do not
	// pretend the password was wrong".
	if !strings.Contains(body, "Too many recent attempts") {
		t.Errorf("the throttle does not say what happened: %s", body)
	}
	if strings.Contains(body, "did not match") {
		t.Error("a throttled attempt was dressed up as a wrong password")
	}

	// And it is not a lockout: waiting it out lets the real operator in.
	f.clk.advance(2 * time.Minute)
	if rec, _ := f.signIn(t, "mike", consolePassword); rec.Code != http.StatusSeeOther {
		t.Fatalf("after waiting out the delay, sign-in = %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestConsole_SignInRequiresItsCSRFToken(t *testing.T) {
	f := newLoginFixture(t)

	// The sign-in POST is unauthenticated but NOT unprotected: a cross-site
	// form post that could log a victim into an attacker's Account is a real
	// attack (login CSRF), and it is how a victim ends up doing their work
	// inside a session somebody else can read.
	body := url.Values{"username": {"mike"}, "password": {consolePassword}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a sign-in with no CSRF token = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName) != nil {
		t.Error("a sign-in with no CSRF token issued a session")
	}
}

func TestConsole_SignOutEndsTheSession(t *testing.T) {
	f := newLoginFixture(t)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d", rec.Code)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	csrf := cookieNamed(cookies, csrfCookieName)
	if csrf == nil {
		// The sign-in response may not re-set it; take it from the form fetch.
		formRec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil))
		csrf = cookieNamed(formRec.Result().Cookies(), csrfCookieName)
	}

	body := url.Values{"csrf_token": {csrf.Value}}
	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := f.do(t, req, session, csrf)

	if out.Code != http.StatusSeeOther {
		t.Fatalf("sign-out = %d, want %d; body = %s", out.Code, http.StatusSeeOther, out.Body.String())
	}
	cleared := cookieNamed(out.Result().Cookies(), consoleauth.SessionCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Error("sign-out did not expire the session cookie")
	}
	// The credential must be dead server-side too, not merely dropped by the
	// browser: a cookie already copied elsewhere is not un-copied by clearing
	// it locally.
	if _, err := f.sessions.Lookup(consoleauth.ParseSessionID(session.Value)); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("the session survived sign-out server-side: %v", err)
	}
}

func TestConsole_SignOutIsNotReachableByGET(t *testing.T) {
	f := newLoginFixture(t)
	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, LogoutPath, nil), session)
	if rec.Code == http.StatusSeeOther || rec.Code == http.StatusOK {
		t.Fatalf("GET %s = %d; a mutating action reachable by GET is a CSRF hole no token repairs", LogoutPath, rec.Code)
	}
	if _, err := f.sessions.Lookup(consoleauth.ParseSessionID(session.Value)); err != nil {
		t.Errorf("a GET ended the session: %v", err)
	}
}

func TestConsole_DisablingAnAccountEndsItsConsoleSession(t *testing.T) {
	f := newLoginFixture(t)
	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	if page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session); page.Code != http.StatusOK {
		t.Fatalf("signed-in page = %d", page.Code)
	}
	if err := f.accounts.SetEnabled(context.Background(), f.mike.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	// The durable off-switch reaches sessions already in flight. Waiting for
	// the session to lapse would leave a disabled operator with a working
	// Console for up to its idle timeout.
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	if page.Code != http.StatusSeeOther {
		t.Fatalf("after disabling the Account the Console still answers %d, want a redirect to sign-in", page.Code)
	}
}

func TestConsole_ReturnPathCannotLeaveTheConsole(t *testing.T) {
	// An open redirect on a sign-in page lends this Relay's hostname to
	// somebody else's page, moments after an operator typed their password.
	refused := []string{
		"https://evil.example/",
		"//evil.example/",
		"/\\evil.example/",
		"http://evil.example/console/",
		"/api/v1/ping",
		"/mcp",
		"javascript:alert(1)",
		LoginPath,  // no loops
		LogoutPath, // no sign-in that signs you out
		"",
	}
	for _, raw := range refused {
		if got := safeReturnPath(raw); got != "" {
			t.Errorf("safeReturnPath(%q) = %q, want it discarded", raw, got)
		}
	}
	allowed := map[string]string{
		"/console/activity":               "/console/activity",
		"/console/nodes/node-1":           "/console/nodes/node-1",
		"/console/activity?filter=denied": "/console/activity?filter=denied",
	}
	for raw, want := range allowed {
		if got := safeReturnPath(raw); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestConsole_AlreadySignedInSkipsTheForm(t *testing.T) {
	f := newLoginFixture(t)
	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil), session)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a signed-in visit to the sign-in page = %d, want a redirect", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != HomePath {
		t.Errorf("Location = %q, want %q", got, HomePath)
	}
}

func TestConsole_SignInPageIsNeverCached(t *testing.T) {
	f := newLoginFixture(t)
	rec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	// A sign-in page in a shared cache, or in the back-button history of a
	// borrowed laptop, is a page with somebody's username still in it.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// TestConsole_StylesheetIsActuallyServed is a regression guard for a bug that
// survived the whole shell issue (#439): the embedded asset FS is rooted at
// "assets/", and the FileServer was handed the request path unmodified, so it
// looked for "console/assets/console.css" and 404'd. Every Console page
// rendered completely unstyled.
//
// It went unnoticed because nothing mounted the Console until #418 — which is
// the general lesson: a surface nobody stands up is a surface whose obvious
// failures are invisible.
//
// It asserts the BODY and not just the status, because Go's FileServer answers
// a missing file with a perfectly well-formed 404 page.
func TestConsole_StylesheetIsActuallyServed(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/assets/console.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, ".navitem") || !strings.Contains(body, ".loginbox") {
		t.Errorf("the response is not the Console stylesheet: %.200s", body)
	}

	// And the page that needs it actually points at it.
	page := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil)).Body.String()
	if !strings.Contains(page, `href="/console/assets/console.css"`) {
		t.Error("the sign-in page does not link the stylesheet")
	}
}
