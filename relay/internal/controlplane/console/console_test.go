package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// sessionRoles are the three roles a real signed-in session can carry — the
// fixture the per-role gate tests sweep over.
var sessionRoles = []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}

const testCredential = accounts.TokenPrefix + "1234567890abcdef.test-secret" //nolint:gosec // test fixture, not a real credential

// roleVerifier accepts one credential as an Account with the given role, so a
// test can ask "what does a viewer see?" through the REAL authentication path
// rather than by hand-injecting a principal. Invariant 10 is one auth path;
// a test harness that invents a second one stops testing the thing that ships.
//
// The Account carries an ID as well as a name. That is not decoration: the
// approval queue asks whether a Request is the CALLER'S OWN, and the rule
// requires both identities to be non-empty — without an ID here, every fixture
// would land on the empty-equals-empty branch and every such assertion would
// pass without meaning anything.
type roleVerifier struct{ role accounts.Role }

// testAccountName and testAccountID are what roleVerifier issues, so a fixture
// can name the caller as a requester or in an audience without re-deriving the
// string.
func testAccountName(role accounts.Role) string { return "test-" + string(role) }
func testAccountID(role accounts.Role) string   { return "acct-test-" + string(role) }

func (v roleVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != testCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID:      testAccountID(v.role),
		Name:    testAccountName(v.role),
		Kind:    accounts.KindHuman,
		Role:    v.role,
		Enabled: true,
	}, accounts.APIToken{ID: "tok-test"}, nil
}

// newTestHandler mounts the Console the way the composition root must: the
// route table inside this package's Secure middleware, inside the real
// Authenticator.Middleware.
func newTestHandler(d Deps, role accounts.Role) http.Handler {
	d = mirrorFleetIntoLane(d)
	authn := controlplane.NewAuthenticator(roleVerifier{role: role})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(Secure(mux))
}

// mirrorFleetIntoLane makes a fixture's fleet visible through BOTH doors the
// Console reads the registry through.
//
// #450 moved the fleet listing and node detail onto the capability layer's
// AUDITED read lane (Deps.Queries), while the comparison screen still reads
// FleetReader. Screen fixtures name their fleet once — d.Fleet = fakeFleet{…}
// — and a fixture that fed only that door would describe a fleet half the
// Console cannot see, which renders as an empty page rather than as a failing
// assertion about the thing the test is really about.
//
// So this copies, and only ever in the direction that cannot mask a bug: it
// fills the lane's nodes when a fixture left them UNSET, and never touches a
// fixture that set them deliberately. A test that wants the two doors to
// disagree — or wants the lane to fail — sets fakeQueries.nodes (or
// nodesErr) itself and this leaves it alone.
func mirrorFleetIntoLane(d Deps) Deps {
	q, ok := d.Queries.(*fakeQueries)
	if !ok || q == nil || q.nodes != nil || d.Fleet == nil {
		return d
	}
	q.nodes = d.Fleet.List()
	return d
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, h, http.MethodGet, path)
}

// request is [get] with an explicit method, so a sweep can probe with
// something other than GET — see the method-oracle sub-loop in
// TestConsole_ARouteAboveTheSessionRoleIsAbsent.
func request(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestConsole_ViewerNavigationIsStructurallySmaller is the acceptance criterion
// from docs/design/console/11-console-shell.md, and it is the one an
// implementation is most likely to pass while getting wrong: a greyed-out
// control also "cannot be used", and reads to a reviewer as compliant.
//
// ADR-0009's insight, which ADR-0026 preserved as the reason the flag exists at
// all, is that ABSENT BEATS FORBIDDEN. So the assertion is about what is not
// drawn, not about what refuses.
//
// Three of the four items in the `absent` list (Policy, Add Nodes, Accounts)
// now hold for EVERY role, not only a viewer, because #464 unmounted them —
// this test still holds, but it is no longer the only thing keeping the
// property true. When #438/#448/#475 re-add those screens with a real
// MinRole, [Route.ReachableBy] and Register's mount-time gate are what will
// keep a viewer's Console structurally smaller again; this test would fail
// first if that stopped being so.
func TestConsole_ViewerNavigationIsStructurallySmaller(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), true), accounts.RoleViewer)
	// Scoped to the navigation, not the whole page. The assertion is about what
	// is DRAWN IN THE NAV, and a screen is free to use the same words for its
	// own purposes — the fleet view's fingerprint column is headed "Policy",
	// which made the unscoped version of this test fail on a page that was
	// entirely correct. A guard that fires on unrelated copy gets deleted by
	// the third person it inconveniences, and this one is worth keeping.
	nav := navOf(get(t, h, "/console/").Body.String())

	for _, absent := range []string{">Run<", ">Policy<", ">Add Nodes<", ">Accounts<"} {
		if strings.Contains(nav, absent) {
			t.Errorf("a viewer's navigation contains %s — it must be structurally smaller, not merely refusing", absent)
		}
	}
	for _, present := range []string{">Fleet<", ">Agents<", ">Activity<", ">Read egress<"} {
		if !strings.Contains(nav, present) {
			t.Errorf("a viewer's navigation is missing %s, which a viewer may read", present)
		}
	}
}

// TestConsole_ExecutionOffMakesTheComposerAbsent is ADR-0026 decision 5: when
// console_execution is off "the execution routes are not mounted and the
// composer is not rendered — an absent capability, not an RBAC refusal,
// preserving ADR-0009's original property verbatim for deployments that want
// it."
//
// 404 rather than 403 is the whole point. A 403 would confirm the route exists.
func TestConsole_ExecutionOffMakesTheComposerAbsent(t *testing.T) {
	off := newTestHandler(withExecution(renderableDeps(), false), accounts.RoleAdmin)
	if got := get(t, off, "/console/run").Code; got != http.StatusNotFound {
		t.Errorf("GET /console/run with console_execution off = %d, want 404 — the route must be unmounted, not refused", got)
	}
	if body := get(t, off, "/console/").Body.String(); strings.Contains(body, ">Run<") {
		t.Error("navigation advertises Run with console_execution off")
	}

	on := newTestHandler(withExecution(renderableDeps(), true), accounts.RoleAdmin)
	if got := get(t, on, "/console/run").Code; got != http.StatusOK {
		t.Errorf("GET /console/run with console_execution on = %d, want 200", got)
	}
}

// TestConsole_NoInlineScript guards the content security policy from the
// inside. script-src 'self' silently breaks any inline handler, so a template
// that grows one produces a page that renders and quietly does not work —
// exactly the failure a reviewer does not see.
//
// hx-on: is called out by name because it is the one HTMX attribute that IS
// script, and it is the natural thing to reach for.
//
// The script rule itself is assertNoInlineScript (no_inline_script_test.go):
// the property is that no script is INLINE, not that no script exists, since
// the specification requires the one external file day one loads. The rest of
// this list is unchanged.
func TestConsole_NoInlineScript(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), true), accounts.RoleAdmin)
	body := get(t, h, "/console/").Body.String()

	assertNoInlineScript(t, "/console/", body)

	for _, banned := range []string{"hx-on:", "javascript:", " onclick=", " onload=", " onerror=", " onfocus="} {
		if strings.Contains(body, banned) {
			t.Errorf("rendered page contains %q — the content security policy admits no inline script", banned)
		}
	}
}

// TestConsole_SecurityHeaders asserts the policy actually ships. A CSP that is
// computed and never sent is the most convincing kind of absent control.
func TestConsole_SecurityHeaders(t *testing.T) {
	h := newTestHandler(renderableDeps(), accounts.RoleAdmin)
	res := get(t, h, "/console/").Result()

	csp := res.Header.Get("Content-Security-Policy")
	for _, directive := range []string{
		"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'",
		"form-action 'self'", "base-uri 'none'", "object-src 'none'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("Content-Security-Policy is missing %q; got %q", directive, csp)
		}
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestConsole_CSRFRefusesUnsafeMethodWithoutToken exercises Secure directly,
// because the route table is all-GET today and the middleware must already be
// correct when the first mutating route arrives — not correct as of the change
// that adds one.
func TestConsole_CSRFRefusesUnsafeMethodWithoutToken(t *testing.T) {
	reached := false
	h := Secure(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodPost, "/console/anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without a CSRF token = %d, want 403", rec.Code)
	}
	if reached {
		t.Error("a POST without a CSRF token reached the handler")
	}
}

// TestConsole_CSRFAcceptsMatchingToken is the other half: the control must
// admit a legitimate request, or it is not a control but an outage.
func TestConsole_CSRFAcceptsMatchingToken(t *testing.T) {
	reached := false
	h := Secure(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	// A GET mints the cookie the page would carry.
	seed := httptest.NewRequest(http.MethodGet, "/console/", nil)
	seedRec := httptest.NewRecorder()
	h.ServeHTTP(seedRec, seed)

	var token string
	for _, c := range seedRec.Result().Cookies() {
		if c.Name == csrfCookieName {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no CSRF cookie was minted on a GET")
	}

	req := httptest.NewRequest(http.MethodPost, "/console/anything", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	req.Header.Set(csrfHeaderName, token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached || rec.Code == http.StatusForbidden {
		t.Errorf("a request carrying a matching CSRF token was refused: code=%d reached=%v", rec.Code, reached)
	}
}

// TestConsole_NoMutatingGet holds the line the specification draws: "Every
// mutating request is POST/PUT/DELETE, never GET. A GET that mutates is a CSRF
// hole regardless of tokens" — because a browser will issue it from an <img>
// tag, before any token scheme is consulted.
//
// Navigation destinations are pages, so they are GET by definition; this fails
// the day someone gives a nav entry a mutating method.
func TestConsole_NoMutatingGet(t *testing.T) {
	for _, r := range Routes(withExecution(renderableDeps(), true)) {
		if r.Nav.Label != "" && r.Method != http.MethodGet {
			t.Errorf("navigation destination %q uses %s — a destination is a page and must be GET", r.Nav.Label, r.Method)
		}
		if !isSafeMethod(r.Method) && r.Nav.Label != "" {
			t.Errorf("route %s %s is both a navigation destination and unsafe", r.Method, r.Path)
		}
	}
}

// TestConsole_UnauthenticatedIsRefused: the Console is behind the same
// Authenticator as every other control-plane surface, and this asserts the
// harness has not accidentally mounted it outside one.
func TestConsole_UnauthenticatedIsRefused(t *testing.T) {
	h := newTestHandler(renderableDeps(), accounts.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("an unauthenticated request rendered a Console page")
	}
}

// TestConsole_ARouteAboveTheSessionRoleIsAbsent is the mount-time half of
// #464: Register's gate must refuse a request below a route's MinRole with
// exactly the 404 a route that was never mounted would give, and it must
// never refuse a request that meets MinRole — this gate is subtractive only.
//
// Iterates Routes(withExecution(sweepFixture(), true)) rather than a
// hand-written path list, so a route added later is swept without anyone
// remembering to add it here. sweepFixture (not the bare renderableDeps)
// because a parameterised route's object has to actually exist, or a missing
// fixture 404s for every role and is indistinguishable from a role refusal.
// Execution stays ON so /console/run (MinRole RoleOperator) is in the table as
// a real fixture above RoleViewer — the four v0.7.0 placeholders that used to
// supply that shape are gone as of this change
// (TestConsole_V060MountsNoUnbuiltScreen pins their removal).
//
// GET is not the only method a session can probe with, and the property has
// to hold for all of them: net/http's ServeMux answers a method mismatch on a
// REGISTERED pattern itself, with a 405 before any handler runs, which is a
// method oracle if the pattern's mere registration leaks past a role that
// 404s on GET (#464 cycle 2, F1). The second sub-loop below probes every
// route [Route.constrainsReach] is true for — i.e. every route [gated]
// actually wraps — with OPTIONS instead of GET, so this test fails again if
// that oracle ever comes back.
func TestConsole_ARouteAboveTheSessionRoleIsAbsent(t *testing.T) {
	d := withExecution(sweepFixture(), true)
	routes := Routes(d)

	checked, methodChecked := 0, 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		// The control for the indistinguishability assertion: a path this
		// package never mounts at all, walked through the same session.
		miss := get(t, h, "/console/no-such-route")
		missOptions := request(t, h, http.MethodOptions, "/console/no-such-route")

		for _, r := range routes {
			if r.Method != http.MethodGet {
				continue
			}
			if r.Path == "/console/events" || r.Path == LoginPath || strings.Contains(r.Path, "{path...}") {
				continue
			}
			path := r.Link()
			for placeholder, id := range fixtureIDs {
				path = strings.ReplaceAll(path, placeholder, id)
			}
			if strings.Contains(path, "{") {
				continue
			}
			checked++

			rec := get(t, h, path)
			if r.ReachableBy(role) {
				if rec.Code == http.StatusNotFound {
					t.Errorf("role %s: GET %s = 404, want reachable (MinRole %s)", role, path, r.MinRole)
				}
			} else if rec.Code != http.StatusNotFound {
				t.Errorf("role %s: GET %s = %d, want 404 — a role below MinRole %s must find the route absent", role, path, rec.Code, r.MinRole)
			} else {
				// Absent, not forbidden: a refused route must be byte-identical
				// to a route that was never mounted, or the 404 is a
				// status-code coincidence rather than a tested property.
				res, missRes := rec.Result(), miss.Result()
				if res.Status != missRes.Status {
					t.Errorf("role %s: GET %s status line %q, want %q (same as an unmounted path)", role, path, res.Status, missRes.Status)
				}
				if got, want := res.Header.Get("Content-Type"), missRes.Header.Get("Content-Type"); got != want {
					t.Errorf("role %s: GET %s Content-Type %q, want %q", role, path, got, want)
				}
				if got, want := res.Header.Get("X-Content-Type-Options"), missRes.Header.Get("X-Content-Type-Options"); got != want {
					t.Errorf("role %s: GET %s X-Content-Type-Options %q, want %q", role, path, got, want)
				}
				if got, want := rec.Body.String(), miss.Body.String(); got != want {
					t.Errorf("role %s: GET %s body %q, want %q (same as an unmounted path)", role, path, got, want)
				}
			}

			if !r.constrainsReach() {
				// RoleViewer and below: no MinRole excludes anyone, so
				// Register mounts no method-less fallback for this route
				// ([Route.constrainsReach]) and an ordinary method mismatch on
				// it discloses nothing a GET does not already.
				continue
			}
			methodChecked++

			optRec := request(t, h, http.MethodOptions, path)
			if r.ReachableBy(role) {
				// In role: the method-less fallback must reproduce what
				// net/http would answer if r's method-specific pattern were
				// the only thing registered for this path — 405 with an Allow
				// header naming the real method — never a silent 404 (which
				// would hide the route from its own legitimate caller) and
				// never a 200 (which would mean OPTIONS reached the handler).
				if optRec.Code != http.StatusMethodNotAllowed {
					t.Errorf("role %s: OPTIONS %s = %d, want 405 (MinRole %s, method mismatch on an in-role route)", role, path, optRec.Code, r.MinRole)
				}
				if allow := optRec.Header().Get("Allow"); !strings.Contains(allow, r.Method) {
					t.Errorf("role %s: OPTIONS %s Allow = %q, want it to name %s", role, path, allow, r.Method)
				}
				continue
			}

			// Below MinRole: OPTIONS must be just as absent as GET was above —
			// this is the assertion that fails if the method oracle returns.
			if optRec.Code != http.StatusNotFound {
				t.Errorf("role %s: OPTIONS %s = %d, want 404 — a role below MinRole %s must find the route absent regardless of method", role, path, optRec.Code, r.MinRole)
				continue
			}
			optRes, missOptRes := optRec.Result(), missOptions.Result()
			if optRes.Status != missOptRes.Status {
				t.Errorf("role %s: OPTIONS %s status line %q, want %q (same as an unmounted path)", role, path, optRes.Status, missOptRes.Status)
			}
			if got, want := optRes.Header.Get("Content-Type"), missOptRes.Header.Get("Content-Type"); got != want {
				t.Errorf("role %s: OPTIONS %s Content-Type %q, want %q", role, path, got, want)
			}
			if got, want := optRec.Body.String(), missOptions.Body.String(); got != want {
				t.Errorf("role %s: OPTIONS %s body %q, want %q (same as an unmounted path)", role, path, got, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the sweep checked zero routes — it is not running")
	}
	if methodChecked == 0 {
		t.Fatal("the method-oracle sweep checked zero routes — it is not running")
	}
}

// navHrefPattern extracts the href of every rendered navigation link, so the
// nav-implies-reachable property can be checked against the rendered markup
// rather than against Nav's own return value — which would only prove the
// projection agrees with itself.
var navHrefPattern = regexp.MustCompile(`class="navitem[^"]*" href="([^"]+)"`)

// TestConsole_NavDrawsNoLinkTheSessionCannotReach is spec 11's property, in
// both directions: every href the navigation draws for a role must resolve to
// a route that role can reach, and every reachable, Nav-labelled route must
// actually appear in the rendered navigation — so the projection (Nav) and the
// gate (Register) cannot drift apart from each other.
func TestConsole_NavDrawsNoLinkTheSessionCannotReach(t *testing.T) {
	d := withExecution(sweepFixture(), true)

	walked, navItems := 0, 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		reachable := routesFor(d, role)

		byLink := map[string]Route{}
		for _, r := range reachable {
			byLink[r.Link()] = r
		}

		for _, path := range walkableScreens(reachable, fixtureIDs) {
			walked++
			nav := navOf(get(t, h, path).Body.String())
			for _, m := range navHrefPattern.FindAllStringSubmatch(nav, -1) {
				href := m[1]
				if _, ok := byLink[href]; !ok {
					t.Errorf("role %s: nav rendered on %s links to %s, which this role cannot reach", role, path, href)
				}
			}
		}

		nav := navOf(get(t, h, "/console/").Body.String())
		for _, r := range reachable {
			if r.Nav.Label == "" {
				continue
			}
			navItems++
			if want := ">" + r.Nav.Label + "<"; !strings.Contains(nav, want) {
				t.Errorf("role %s: %s is reachable and labelled %q, but the nav does not draw it", role, r.Path, r.Nav.Label)
			}
		}
	}
	if walked == 0 {
		t.Fatal("the sweep walked zero screens — it is not running")
	}
	if navItems == 0 {
		t.Fatal("the sweep found zero nav items — it is not running")
	}
}

// TestConsole_V060MountsNoUnbuiltScreen is a regression pin for the exact
// defect #464 fixed, not a derived property: these four specific v0.7.0
// screens (console/06, 09, 15, 16) must not be reachable in v0.6.0, however
// the route table changes around them. A hand-written list is correct here.
func TestConsole_V060MountsNoUnbuiltScreen(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), false), accounts.RoleAdmin)
	for _, path := range []string{
		"/console/policy",
		"/console/nodes/add",
		"/console/accounts",
		"/console/incident",
	} {
		if got := get(t, h, path).Code; got != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — this v0.7.0 screen must not be mounted in v0.6.0", path, got)
		}
	}
}

// fixtureIDs are the object ids the screen fixtures actually contain, so a
// parameterised route can be walked rather than skipped.
var fixtureIDs = map[string]string{
	"{node_id}":     "node-web-1",
	"{job_id}":      "job-1",
	"{approval_id}": "ap-1",
}

// walkableScreens derives the GET screens a sweep should render FROM A ROUTE
// TABLE, substituting ids from subs.
//
// Derived rather than hand-listed because a hand-listed sweep is a list that
// silently stops covering the package: a screen added later is simply not in
// it, and nothing fails. The two sweeps that use this — the inline-script guard
// and the zeroed-statistic guard — are exactly the ones whose value comes from
// being exhaustive.
//
// Takes a []Route rather than a Deps so a caller can pass either every route
// the process mounts (Routes(d)) or the routes one role may reach
// (routesFor(d, role)) — the per-role nav sweep needs the latter.
//
// Three routes are never walked, with reasons:
//   - /console/events streams until its context is cancelled;
//   - /console/assets/{path...} serves bytes, not a screen;
//   - /console/login answers a signed-in request with a redirect.
//
// A parameterised route with no substitution in subs is skipped: the caller's
// fixture has no such object to name.
func walkableScreens(routes []Route, subs map[string]string) []string {
	var paths []string
	for _, r := range routes {
		if r.Method != http.MethodGet {
			continue
		}
		if r.Path == "/console/events" || r.Path == LoginPath || strings.Contains(r.Path, "{path...}") {
			continue
		}
		path := r.Link()
		for placeholder, id := range subs {
			path = strings.ReplaceAll(path, placeholder, id)
		}
		if strings.Contains(path, "{") {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

// navOf extracts the shell's navigation aside from a rendered page, so an
// assertion about what the navigation advertises cannot be satisfied — or
// broken — by a screen that happens to use the same word.
func navOf(body string) string {
	const open = `<aside class="nav">`
	i := strings.Index(body, open)
	if i < 0 {
		return body
	}
	rest := body[i+len(open):]
	if j := strings.Index(rest, "</aside>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestConsole_FontsAreServedFromThisOrigin guards the pairing between the
// stylesheet and the content security policy.
//
// The policy admits `font-src 'self'` and nothing else, so a webfont pulled
// from a CDN is silently blocked: the page still renders, in a system fallback,
// looking to whoever wrote it exactly like it worked. That failure mode is why
// this asserts the BYTES come back rather than that the CSS mentions a URL.
func TestConsole_FontsAreServedFromThisOrigin(t *testing.T) {
	h := newTestHandler(renderableDeps(), accounts.RoleAdmin)

	css := get(t, h, "/console/assets/console.css").Body.String()
	for _, external := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "//cdn.", "http://", "https://"} {
		if strings.Contains(css, external) {
			t.Errorf("the stylesheet references %q — the content security policy blocks every origin but this one, "+
				"so an external asset fails silently and renders as a fallback", external)
		}
	}

	for _, f := range []string{
		"ibm-plex-sans-400.woff2", "ibm-plex-sans-500.woff2", "ibm-plex-sans-600.woff2",
		"ibm-plex-mono-400.woff2", "ibm-plex-mono-500.woff2",
	} {
		if !strings.Contains(css, f) {
			t.Errorf("the stylesheet does not reference %s", f)
		}
		rec := get(t, h, "/console/assets/fonts/"+f)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /console/assets/fonts/%s = %d, want 200 — the font is not in the embedded FS", f, rec.Code)
			continue
		}
		// A 404 page is also a 200-shaped thing to a careless assertion, so
		// check it is really a woff2: the format's magic number is "wOF2".
		if body := rec.Body.String(); len(body) < 4 || body[:4] != "wOF2" {
			t.Errorf("/console/assets/fonts/%s did not return a woff2 (magic %q)", f, body[:min(4, len(body))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
