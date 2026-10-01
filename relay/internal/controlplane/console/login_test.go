package console

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
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

	// passwords is kept alongside accounts so a test can mint a SECOND
	// console-signable Account at a role other than mike's admin (#595's
	// viewer-finds-the-route-absent test) through createAccountWithPassword,
	// without reopening a store of its own.
	passwords accounts.PasswordRepository

	mike accounts.Account
	clk  *testClock

	// svc is the same real sign-in service the handler above authenticates
	// against, exposed so a test can build a SECOND boundary over it — see
	// sessionscope_test.go, which needs the real Authenticator and the real
	// SessionScope in front of a route that is not the Console's.
	svc *consoleauth.Service

	// deps is the exact Deps Register mounted handler over. Exposed so a
	// test that needs to walk Routes(d) — security_test.go's sweep for a
	// leaked CSRF cookie — walks the table this fixture actually serves,
	// rather than reconstructing one that could silently drift from it.
	deps Deps

	// st is the store behind the fixture, kept so an audited fixture's
	// records can be read back.
	st *store.Store
}

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newLoginFixture(t *testing.T) *loginFixture {
	return newLoginFixtureWith(t, nil)
}

// newLoginFixtureWith is newLoginFixture with the chance to adjust the Deps
// Register mounts before it does — for a test that needs a seam
// newLoginFixture does not wire by default (#595's fakeCanceller and a
// running Job). mutate may be nil, in which case this is newLoginFixture.
func newLoginFixtureWith(t *testing.T, mutate func(*Deps)) *loginFixture {
	return buildLoginFixture(t, false, mutate)
}

// newAuditedLoginFixture is newLoginFixture with a REAL audit sink behind the
// sign-in service, for a test that reads what a sign-in recorded.
func newAuditedLoginFixture(t *testing.T) *loginFixture {
	return buildLoginFixture(t, true, nil)
}

func buildLoginFixture(t *testing.T, audited bool, mutate func(*Deps)) *loginFixture {
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
	var auditor consoleauth.Auditor
	if audited {
		auditor = auditsink.New(st.Audit(), auditsink.WithClock(clk.now))
	}
	svc := consoleauth.NewService(st.Accounts(), st.Passwords(), sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now)), auditor)

	authn := controlplane.NewAuthenticator(
		roleVerifier{role: accounts.RoleAdmin},
		controlplane.WithConsoleSessions(svc, controlplane.ConsoleSessionOptions{
			Public:       Unauthenticated,
			Scope:        SessionScope,
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
	if mutate != nil {
		mutate(&d)
	}
	Register(mux, d)

	return &loginFixture{
		handler:   authn.Middleware(Secure(mux)),
		svc:       svc,
		sessions:  sessions,
		accounts:  st.Accounts(),
		passwords: st.Passwords(),
		mike:      mike,
		clk:       clk,
		deps:      d,
		st:        st,
	}
}

// createAccountWithPassword mints a second console-signable Account at role,
// for a test that needs a session other than mike's admin one (#595's
// viewer-finds-the-route-absent test).
func (f *loginFixture) createAccountWithPassword(t *testing.T, name string, role accounts.Role, password string) accounts.Account {
	t.Helper()
	acct, err := f.accounts.Create(context.Background(), accounts.Account{
		Name: name, Kind: accounts.KindHuman, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account %q: %v", name, err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword(password))
	if err != nil {
		t.Fatalf("hash password for %q: %v", name, err)
	}
	if err := f.passwords.SetPassword(context.Background(), acct.ID, hash); err != nil {
		t.Fatalf("set password for %q: %v", name, err)
	}
	return acct
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
	csrf := cookieNamed(formRec.Result().Cookies(), signInCSRFCookieName)
	if csrf == nil {
		t.Fatal("the sign-in form set no CSRF cookie")
	}

	body := url.Values{"username": {username}, "password": {password}, "csrf_token": {csrf.Value}}
	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, append([]*http.Cookie{csrf}, extra...)...)
	return rec, rec.Result().Cookies()
}

// renderedCSRFTokenPattern extracts the value layout.go's hidden field
// renders (`<input type="hidden" name="csrf_token" value="...">`), so a test
// can read the token a signed-in page actually carries rather than a cookie —
// under #460's scheme the session lane has no cookie, so this is how a test
// plays the part of a browser reading its own page before submitting a form.
var renderedCSRFTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

// renderedCSRFToken returns the CSRF token rendered into body, or "" if the
// page carried none (a bearer-lane render, or a page with no form at all).
func renderedCSRFToken(body string) string {
	m := renderedCSRFTokenPattern.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
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
		"/console/access",
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

// TestConsole_UnauthenticatedUnknownPathRedirectsToSignIn (#640, item 5): a
// path this package never mounts at all is no different from any other
// private route to an unauthenticated caller — it never reaches the mux (and
// so never reaches the new styled 404) because Authenticator.Middleware
// redirects first. No route enumeration before sign-in.
func TestConsole_UnauthenticatedUnknownPathRedirectsToSignIn(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/does-not-exist", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, LoginPath) {
		t.Fatalf("Location = %q, want the sign-in page", loc)
	}
}

// TestConsole_UnauthenticatedPublicPathVariantGetsAPlainNotFoundOnce (#640
// cycle-2 review, BLOCKING 1): LoginPath is on Unauthenticated's exact-match
// list, so Authenticator.Middleware treats an OPTIONS on it as PUBLIC and
// calls next.ServeHTTP with no Principal in context at all — the route table
// only registers GET and POST /console/login, so this request reaches
// Register's method-less catch-all directly, not through gated or
// methodMismatch. renderNotFound must handle that missing Principal itself,
// with net/http's own plain 404 (never the styled page, which needs a Page
// built from a Principal): the earlier code called [principal] first, which
// already wrote a 500 for the missing Principal, and then wrote a second,
// styled 404 on top of it. Pin a single write: net/http's plain 404, with no
// "authenticated principal" text anywhere in the response.
func TestConsole_UnauthenticatedPublicPathVariantGetsAPlainNotFoundOnce(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodOptions, LoginPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	body := rec.Body.String()
	if strings.Contains(body, "authenticated principal") {
		t.Errorf("body contains the defensive 500 message alongside the 404: %q", body)
	}
	if body != "404 page not found\n" {
		t.Errorf("body = %q, want exactly net/http's plain 404 (a single write, not two)", body)
	}
}

// TestConsole_UnauthorizedRedirectDropsATraversalDestination drives a crafted
// dot-segment destination through the REAL middleware, not just
// safeReturnPath in isolation: a fix applied in handleLoginForm rather than
// in safeReturnPath itself would still mint the crafted destination into
// THIS redirect, because UnauthorizedHandler calls safeReturnPath directly.
//
// The targets must clean to a path INSIDE the Console, or the boundary never
// calls UnauthorizedHandler at all: a request whose cleaned path is off the
// Console gets the 401 challenge, not a redirect (the second loop below).
func TestConsole_UnauthorizedRedirectDropsATraversalDestination(t *testing.T) {
	f := newLoginFixture(t)

	for _, target := range []string{
		"/console/nodes/../activity",             // plain
		"/console/nodes/%2e%2e/activity",         // escaped
		"/api/v1/../../console/activity",         // from outside the Console, into it
		"/api/v1/%2e%2e/%2e%2e/console/activity", // the same, escaped
	} {
		t.Run(target, func(t *testing.T) {
			rec := f.do(t, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if loc := rec.Header().Get("Location"); loc != LoginPath {
				t.Errorf("Location = %q, want exactly %q with no next at all", loc, LoginPath)
			}
		})
	}

	// A traversal OUT of the Console is not the Console's to refuse: it gets
	// the 401 challenge and no Location at all, so there is no redirect for a
	// crafted destination to ride on.
	for _, target := range []string{
		"/console/../api/v1/x",     // plain
		"/console/%2e%2e/api/v1/x", // escaped
	} {
		t.Run(target, func(t *testing.T) {
			rec := f.do(t, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("Location = %q, want none", loc)
			}
		})
	}
}

// TestConsole_InterruptedNoteRequiresARealRedirect pins the provenance fix:
// the "your session ended" copy must render only when UnauthorizedHandler
// itself sent the browser here with somewhere real to return to — never for
// an operator who merely typed a `?next=` onto the sign-in URL by hand.
func TestConsole_InterruptedNoteRequiresARealRedirect(t *testing.T) {
	f := newLoginFixture(t)

	// (a) A hand-crafted ?next= with no marker cookie: the note must not
	// render. This is the defect `Interrupted: query.Get("next") != ""` was —
	// it fires on ANY next, including one nobody was redirected to attach.
	crafted := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath+"?next=/console/activity", nil))
	if strings.Contains(crafted.Body.String(), "Your session ended") {
		t.Error("(a) an unmarked, hand-typed ?next= rendered the interrupted note")
	}

	// (b) A real interruption: an unauthenticated request to a protected
	// route, redirected by UnauthorizedHandler.
	redirected := f.do(t, httptest.NewRequest(http.MethodGet, "/console/activity", nil))
	if redirected.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", redirected.Code, http.StatusSeeOther)
	}
	loc := redirected.Header().Get("Location")
	marker := cookieNamed(redirected.Result().Cookies(), interruptedCookieName)
	if marker == nil {
		t.Fatal("UnauthorizedHandler set no interrupted marker cookie")
	}
	landed := f.do(t, httptest.NewRequest(http.MethodGet, loc, nil), marker)
	if !strings.Contains(landed.Body.String(), "Your session ended") {
		t.Error("(b) a real interruption, carrying the marker, did not render the note")
	}
	if !strings.Contains(landed.Body.String(), `name="next"`) {
		t.Error("(b) the note rendered without the hidden next field to resume the interrupted action")
	}

	// (c) The marker is one-shot: the response that read it must clear it.
	cleared := cookieNamed(landed.Result().Cookies(), interruptedCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Error("(c) the interrupted marker was not cleared after being read")
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

// usernameValueAttr masks the value a throttled re-render echoes into the
// username input to its own submitter (#640), by design.
var usernameValueAttr = regexp.MustCompile(`(?s)(id="username".*?value=")[^"]*(")`)

// TestConsole_FailedSignInRecordsDifferByD19WhileResponsesDoNot is the one
// boundary where both halves of D19 are observable: the sign-in RESPONSE is
// identical whether or not the typed name is an Account, while the stored
// RECORD keeps the name only when it is one.
func TestConsole_FailedSignInRecordsDifferByD19WhileResponsesDoNot(t *testing.T) {
	const secret = "d19-secret-typed-as-a-name"

	// maskedBody drops the two legitimately-varying parts of a page: the CSRF
	// token and, on a throttled page, the echoed username.
	maskedBody := func(body string) string {
		body = usernameValueAttr.ReplaceAllString(body, `${1}NAME${2}`)
		return csrfTokenPattern.ReplaceAllString(body, `value="TOKEN"`)
	}
	records := func(f *loginFixture, kind string) audit.Record {
		t.Helper()
		all, err := f.st.Audit().List(context.Background())
		if err != nil {
			t.Fatalf("list audit records: %v", err)
		}
		var found []audit.Record
		for _, r := range all {
			if r.Kind == kind {
				found = append(found, r)
			}
		}
		if len(found) != 1 {
			t.Fatalf("got %d %s records, want exactly 1", len(found), kind)
		}
		r := found[0]
		r.ID, r.Timestamp = "", time.Time{}
		return r
	}

	for _, tc := range []struct {
		name string
		kind string
		code int
		// attempts is how many times each name is submitted: a throttle is
		// the immediate second attempt.
		attempts int
	}{
		{"a failed sign-in", audit.KindLoginFailed, http.StatusUnauthorized, 1},
		{"a throttled sign-in", audit.KindLoginThrottled, http.StatusTooManyRequests, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realFix := newAuditedLoginFixture(t)
			otherFix := newAuditedLoginFixture(t)
			var a, b *httptest.ResponseRecorder
			for i := 0; i < tc.attempts; i++ {
				var cookiesA, cookiesB []*http.Cookie
				a, cookiesA = realFix.signIn(t, "mike", "not the password")
				b, cookiesB = otherFix.signIn(t, secret, "anything")
				for _, c := range [][]*http.Cookie{cookiesA, cookiesB} {
					if cookieNamed(c, consoleauth.SessionCookieName) != nil {
						t.Error("a refused sign-in set a session cookie")
					}
				}
			}
			if a.Code != tc.code || b.Code != tc.code {
				t.Fatalf("statuses = %d and %d, want both %d", a.Code, b.Code, tc.code)
			}
			if maskedBody(a.Body.String()) != maskedBody(b.Body.String()) {
				t.Error("the two responses differ: the sign-in response enumerates Accounts")
			}

			recA, recB := records(realFix, tc.kind), records(otherFix, tc.kind)
			if got := recA.Attribution.Asserted.OnBehalfOf; got != "mike" {
				t.Errorf("the real Account's %s record names %q, want \"mike\"", tc.kind, got)
			}
			if got := recB.Attribution.Asserted.OnBehalfOf; got != "" {
				t.Errorf("the other name's %s record kept %q, want no typed text", tc.kind, got)
			}
			recA.Attribution.Asserted.OnBehalfOf = ""
			if !reflect.DeepEqual(recA, recB) {
				t.Errorf("the two %s records differ in more than the asserted name:\n%+v\n%+v", tc.kind, recA, recB)
			}
		})
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

// TestConsole_ThrottledSignInKeepsTheUsernameNotThePassword (#640, item 4):
// a throttled re-render must not make the operator retype what they already
// typed, and must never echo the password regardless.
func TestConsole_ThrottledSignInKeepsTheUsernameNotThePassword(t *testing.T) {
	f := newLoginFixture(t)

	firstRec, _ := f.signIn(t, "mike", "wrong")
	if firstRec.Code != http.StatusUnauthorized {
		t.Fatalf("first failure status = %d", firstRec.Code)
	}
	if strings.Contains(firstRec.Body.String(), `value="mike"`) {
		t.Error("a bad-credentials re-render echoed the username — this scope is throttle-only")
	}

	rec, _ := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="mike"`) {
		t.Error("a throttled re-render did not keep the submitted username")
	}
	if strings.Contains(body, consolePassword) {
		t.Error("a throttled re-render echoed the password")
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

	// Under #460's scheme a signed-in POST carries no CSRF cookie at all: the
	// session lane checks the submitted token against the session's own
	// derived secret. A browser gets that token from the page it already
	// has, so this reads it the same way — off the fleet view's hidden
	// field, rendered with the session cookie the sign-in just issued.
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(page.Body.String())
	if token == "" {
		t.Fatal("the signed-in fleet view rendered no CSRF token")
	}

	body := url.Values{"csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, LogoutPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := f.do(t, req, session)

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
	// A second enabled admin, so disabling mike below does not trip the
	// last-enabled-admin guard (#653) this test is not about.
	if _, err := f.accounts.Create(context.Background(), accounts.Account{
		Name: "other-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatalf("create other admin: %v", err)
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

		// The dot-segment defect (#477): the OLD check prefix-matched
		// EscapedPath() against "/console/" and resolved no ".." at all.
		"/console/../api/v1/x", // PLAIN. Passes the CURRENT-BEFORE-THE-FIX
		// check, because EscapedPath() returns this verbatim and the prefix
		// test is satisfied regardless — this is the row an escape-only fix
		// (e.g. `strings.Contains(raw, "..")` catching only the encoded
		// forms below) would still let through, and the one the issue's own
		// "escaping bug" diagnosis would have missed.
		"/console/%2e%2e/api/v1/x", // escaped
		"/console/%2E%2E/api/v1/x", // case
		"/console/..%2fapi/v1/x",   // mixed: literal ".." + an escaped slash
		"/console/nodes/../login",  // traversal back onto the sign-in page —
		// catches a fix that CLEANS and RETURNS the cleaned path (this would
		// come back as LoginPath, which safeReturnPath must never allow)
		// instead of rejecting a non-canonical input outright.
		"/console//evil.example", // empty segment
		// Decodes to a canonical, /console/-prefixed path, so the decoded
		// checks pass — but the value returned would be the escaped form,
		// which is not rooted at "/" at all. Found by security review.
		"%2fconsole%2fnodes",
		"%2fconsole%2f",
	}
	for _, raw := range refused {
		if got := safeReturnPath(raw); got != "" {
			t.Errorf("safeReturnPath(%q) = %q, want it discarded", raw, got)
		}
	}
	allowed := map[string]string{
		"/console/":                       "/console/", // cleanPath's trailing-slash restoration
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

// TestConsole_BrandAssetsAreServedAndCurrent guards the wordmark and favicon
// the same way TestConsole_StylesheetIsActuallyServed guards the stylesheet:
// by the bytes served, not the status, because a missing image is a broken
// icon in the corner rather than a failure anyone sees in a log.
//
// It also pins the Console's copies to docs/brand/, the source of truth. The
// Console must serve its own copies (the content security policy admits images
// only from this origin, and go:embed cannot reach outside the package), and a
// copy nobody checks is a copy that drifts.
func TestConsole_BrandAssetsAreServedAndCurrent(t *testing.T) {
	f := newLoginFixture(t)

	for _, name := range []string{"relay-icon.svg", "relay-wordmark-light.svg", "relay-wordmark-dark.svg"} {
		rec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/assets/brand/"+name, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec.Code)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "brand", name))
		if err != nil {
			t.Fatalf("read docs/brand/%s: %v", name, err)
		}
		if rec.Body.String() != string(want) {
			t.Errorf("the Console's assets/brand/%s differs from docs/brand/%s; copy it across", name, name)
		}
	}

	// And both shells point at them: the sign-in page here, the layout below.
	page := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil)).Body.String()
	shell := httptest.NewRecorder()
	Render(shell, Page{Title: "t"})
	for where, body := range map[string]string{"sign-in page": page, "layout": shell.Body.String()} {
		for _, ref := range []string{
			`rel="icon" type="image/svg+xml" href="/console/assets/brand/relay-icon.svg"`,
			`srcset="/console/assets/brand/relay-wordmark-light.svg"`,
			`src="/console/assets/brand/relay-wordmark-dark.svg" alt="Relay"`,
		} {
			if !strings.Contains(body, ref) {
				t.Errorf("the %s does not carry %s", where, ref)
			}
		}
	}
}

// TestConsole_SignInPageCarriesNoInlineScript closes the one gap in the
// package's script policy.
//
// Both rendered-body sweeps skip /console/login, and correctly: it answers a
// signed-in request with a redirect, so a sweep built from authenticated
// renders would assert nothing about it. But it is THE ONLY PAGE REACHABLE
// WITHOUT A CREDENTIAL, which makes it the one page where an inline handler
// would be reachable by anyone who can route to the control plane at all — and
// it renders through the same shell that now carries the layout's script hook.
//
// So it gets its own unauthenticated render. The ban list is the shell's,
// deliberately: a page whose whole job is to accept a password is not the place
// to start making exceptions.
func TestConsole_SignInPageCarriesNoInlineScript(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s unauthenticated = %d, want 200", LoginPath, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "password") {
		t.Fatal("the sign-in form did not render, so this asserts nothing")
	}

	assertCSPClean(t, LoginPath, body)
}
