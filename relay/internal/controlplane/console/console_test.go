package console

import (
	"bytes"
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

const testCredential = accounts.TokenPrefix + "1234567890abcdef.test-secret" // test fixture, not a real credential

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
	authn := controlplane.NewAuthenticator(roleVerifier{role: role})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(Secure(mux, nil))
}

// newTestHandlerWithEventsLimiter is newTestHandler with GET /console/events'
// own handler substituted for one built over a caller-chosen *streamLimiter —
// the per-principal-cap test seam events_audit_test.go's B7 needs now that
// maxStreamsPerPrincipal is a const again and perCap lives on the limiter
// instance instead (#539 fix round, Finding 3). It walks the real route
// table exactly as Register does, rather than hardcoding the route's method,
// path or MinRole a second time, so it cannot drift from what Register
// actually mounts.
func newTestHandlerWithEventsLimiter(d Deps, role accounts.Role, limiter *streamLimiter) http.Handler {
	authn := controlplane.NewAuthenticator(roleVerifier{role: role})
	mux := http.NewServeMux()
	nf := notFoundHandler(d)
	for _, r := range Routes(d) {
		h := r.Handler(d)
		if r.Path == "/console/events" {
			h = newEventsHandler(d, limiter)
		}
		mux.HandleFunc(r.Pattern(), gated(r, h, nf))
		if r.constrainsReach() {
			mux.HandleFunc(r.Path, methodMismatch(r, nf))
		}
	}
	mux.HandleFunc("/console/", nf)
	return authn.Middleware(Secure(mux, nil))
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
// Two of the four items in the `absent` list (Policy, Add Nodes) still hold
// for EVERY role, not only a viewer, because #464 unmounted them — for those
// this test still holds, but it is not the only thing keeping the property
// true.
//
// Accounts is now the first item here that is absent FOR THE REASON THIS TEST
// IS ABOUT. #654 mounted GET /console/accounts at admin, so the screen exists
// and an admin's nav draws it; a viewer's does not, because
// [Route.ReachableBy] excludes the route from [routesFor] and Nav is a
// projection of that. When #438/#448/#475 re-add the rest with a real MinRole
// they will join it, and this test would fail first if the mount-time gate
// stopped being what keeps a viewer's Console structurally smaller.
func TestConsole_ViewerNavigationIsStructurallySmaller(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), true), accounts.RoleViewer)
	// Scoped to the navigation, not the whole page. The assertion is about what
	// is DRAWN IN THE NAV, and a screen is free to use the same words for its
	// own purposes — the fleet view's fingerprint column is headed "Policy",
	// which made the unscoped version of this test fail on a page that was
	// entirely correct. A guard that fires on unrelated copy gets deleted by
	// the third person it inconveniences, and this one is worth keeping.
	nav := navOf(get(t, h, "/console/").Body.String())

	for _, absent := range []string{">Run<", ">Policy<", ">Add Nodes<", ">Accounts<", ">Access<", ">Agents<"} {
		if strings.Contains(nav, absent) {
			t.Errorf("a viewer's navigation contains %s — it must be structurally smaller, not merely refusing", absent)
		}
	}
	for _, present := range []string{">Fleet<", ">Activity<"} {
		if !strings.Contains(nav, present) {
			t.Errorf("a viewer's navigation is missing %s, which a viewer may read", present)
		}
	}

	// Observe lists exactly Fleet and Activity: Agents (#787) and Read egress
	// (#828) were both retired into Activity. Derived from Nav, not from HTML.
	observe := map[string]bool{}
	for _, section := range Nav(withExecution(renderableDeps(), true), accounts.RoleViewer, "") {
		if section.Group != NavObserve {
			continue
		}
		for _, item := range section.Items {
			observe[item.Label] = true
		}
	}
	for _, want := range []string{"Fleet", "Activity"} {
		if !observe[want] {
			t.Errorf("Observe is missing %s", want)
		}
	}
	for label := range observe {
		switch label {
		case "Fleet", "Activity":
		default:
			t.Errorf("Observe lists %q, which is not one of Fleet or Activity", label)
		}
	}
}

// TestConsole_AgentsScreenIsNotMounted: the Agents screen was retired into
// Activity (#787, spec 04). /console/agents is a path that was never mounted,
// so it answers the Console's ordinary 404 for every role, and there is no
// redirect: a redirect would advertise the old path.
func TestConsole_AgentsScreenIsNotMounted(t *testing.T) {
	const retired = "/console/agents"
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin} {
		for _, execution := range []bool{false, true} {
			d := withExecution(sweepFixture(), execution)
			for _, r := range append(routesFor(d, role), Routes(d)...) {
				if r.Path == retired {
					t.Errorf("%s/execution=%v: a route is mounted at %s", role, execution, retired)
				}
			}

			h := newTestHandler(d, role)
			for _, path := range []string{retired, retired + "?account=" + sweepMachineAccountID} {
				if got := get(t, h, path).Code; got != http.StatusNotFound {
					t.Errorf("%s/execution=%v: GET %s = %d, want 404 and never a redirect", role, execution, path, got)
				}
			}

			nav := navOf(get(t, h, "/console/").Body.String())
			if strings.Contains(nav, ">Agents<") {
				t.Errorf("%s/execution=%v: the navigation still names Agents", role, execution)
			}
			for _, present := range []string{">Fleet<", ">Activity<"} {
				if !strings.Contains(nav, present) {
					t.Errorf("%s/execution=%v: the navigation is missing %s", role, execution, present)
				}
			}
		}
	}
}

// TestConsole_NoRenderedScreenLinksToTheRetiredAgentsScreen: no link anywhere
// in the Console points at /console/agents (#787). The screens are derived from
// the route table, like the other exhaustive sweeps, so a screen added later
// is covered. The 404 page is walked too, since it renders the navigation.
func TestConsole_NoRenderedScreenLinksToTheRetiredAgentsScreen(t *testing.T) {
	const retired = "/console/agents"
	d := withExecution(sweepFixture(), true)
	ok := 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		paths := append(walkableScreens(routesFor(d, role), fixtureIDs), retired)
		for _, path := range paths {
			rec := get(t, h, path)
			if rec.Code == http.StatusOK {
				ok++
			}
			if strings.Contains(rec.Body.String(), retired) {
				t.Errorf("%s: GET %s renders a reference to %s", role, path, retired)
			}
		}
	}
	if ok == 0 {
		t.Fatal("no screen rendered 200, so this guard is not running")
	}

	// Non-vacuity: the link Accounts used to point at the retired screen from
	// is rendered, and now goes to Activity.
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/accounts").Body.String()
	if want := "/console/activity?account=" + sweepMachineAccountID; !strings.Contains(body, want) {
		t.Errorf("the Accounts screen does not render %q, so the sweep never met the repointed link", want)
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
// The whole ban list — the <script> shape rule, hx-on:, javascript:, every
// inline handler attribute, and an inline style in either quote form — now
// lives in assertCSPClean (no_inline_script_test.go); this test keeps its
// name and its purpose, the shell rendered as admin with execution on, and
// simply stops carrying its own copy of the list.
func TestConsole_NoInlineScript(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), true), accounts.RoleAdmin)
	body := get(t, h, "/console/").Body.String()

	assertCSPClean(t, "/console/", body)
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
//
// Since #460 this pins the SESSION lane's fail-closed branch specifically: a
// bare Secure with no ConsoleSession in context (this request carries none —
// it is not even routed through Authenticator.Middleware) refuses every
// unsafe method outright, with no fallback of any kind. The sign-in lane's
// own refusal is covered end to end in security_test.go, over the real
// stack, because it needs a real cookie to refuse correctly rather than an
// absent one.
func TestConsole_CSRFRefusesUnsafeMethodWithoutToken(t *testing.T) {
	reached := false
	h := Secure(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }), nil)

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

// TestConsole_RegisterMountsEveryRouteWithoutPatternConflict turns a startup
// PANIC into a named test failure.
//
// Register mounts a SECOND, method-less pattern on r.Path for every route
// [Route.constrainsReach] is true for, which creates two hazards that net/http
// only reports by panicking at registration time — in production, that is a
// process that does not start:
//
//   - two constrained routes sharing one Path (the bare pattern is registered
//     twice, and ServeMux refuses a duplicate);
//   - a constrained LITERAL segment beneath a constrained "{id}" pattern of
//     the same shape, the "/console/nodes/add" hazard console.go documents.
//
// A route-table edit is therefore not a test-time nit, and nothing else in
// this package calls Register with both Execution settings. This does.
func TestConsole_RegisterMountsEveryRouteWithoutPatternConflict(t *testing.T) {
	for _, execution := range []bool{true, false} {
		d := withExecution(sweepFixture(), execution)

		// The shared-path hazard, checked FIRST and by hand, because it is
		// the one this test can name better than net/http can: a failure here
		// prints both colliding routes. Register panics on it too, and a
		// panic ends the test before anything else runs.
		owner := map[string]Route{}
		constrained := 0
		for _, r := range Routes(d) {
			if !r.constrainsReach() {
				continue
			}
			constrained++
			if prior, taken := owner[r.Path]; taken {
				t.Errorf("execution=%v: %q and %q both constrain reach and share the path %q — "+
					"Register mounts methodMismatch on that BARE path once per route, so it would "+
					"register the pattern twice and net/http panics at registration",
					execution, prior.Pattern(), r.Pattern(), r.Path)
			}
			owner[r.Path] = r
		}
		if constrained == 0 {
			t.Fatalf("execution=%v: no route constrains reach — this check is inspecting nothing", execution)
		}

		// And the whole table through the real Register, which is the only
		// thing that catches the OTHER hazard: a constrained literal segment
		// beneath a constrained "{id}" pattern of the same shape — the
		// "/console/nodes/add" case console.go documents, which no
		// path-equality check can see.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Register(execution=%v) panicked: %v\n"+
						"net/http refuses conflicting patterns at registration, so this is a Relay "+
						"that does not START — not a test-time nit. Register mounts methodMismatch "+
						"on the BARE r.Path for every route constrainsReach() is true for; a "+
						"constrained literal may not sit under a constrained {id} of the same "+
						"shape (console.go).", execution, r)
				}
			}()
			Register(http.NewServeMux(), d)
		}()
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
// 404s on GET (#464 cycle 2, F1). The OPTIONS sub-loop below probes every
// route [Route.constrainsReach] is true for — i.e. every route [gated]
// actually wraps — so this test fails again if that oracle ever comes back.
//
// THE SWEEP COVERS EVERY METHOD, NOT ONLY GET (#655). It used to `continue`
// on every non-GET route, which left POST /console/jobs/{job_id}/cancel and
// POST /console/approvals/{approval_id}/decision unswept, and would have left
// this issue's five Accounts write routes unswept beside them. Two things
// carry the widening:
//
//   - the OPTIONS method-oracle sub-loop is now UNCONDITIONAL on method. It
//     already asserted the right thing for any route, and moving it out of the
//     GET branch sweeps every POST route for the registration oracle with no
//     CSRF handling involved at all;
//   - a probe with the route's OWN method, which must use
//     [newTestHandlerSkippingCSRF] and its own POST miss control. This is not
//     a convenience: [newTestHandler] wraps the mux in [Secure], and Secure
//     refuses every unsafe method on the session lane with a 403 FROM THE
//     MIDDLEWARE, BEFORE ROUTING (security.go — sessionCSRFValid returns false
//     with no ConsoleSession in context). Under newTestHandler every POST
//     probe would be 403 for every role, and the absent-not-forbidden
//     assertion would be uniformly vacuous. Do not "unify" the two handlers.
func TestConsole_ARouteAboveTheSessionRoleIsAbsent(t *testing.T) {
	d := withExecution(sweepFixture(), true)
	routes := Routes(d)

	checked, methodChecked, postChecked := 0, 0, 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		// The control for the indistinguishability assertion: a path this
		// package never mounts at all, walked through the same session.
		miss := get(t, h, "/console/no-such-route")
		missOptions := request(t, h, http.MethodOptions, "/console/no-such-route")

		// The own-method probe's handler and its own control — see the doc
		// comment for why this cannot be h.
		unchecked := newTestHandlerSkippingCSRF(d, role)
		missPost := postSkippingCSRF(t, unchecked, "/console/no-such-route")

		for _, r := range routes {
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

			if r.Method == http.MethodGet {
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
			}

			if r.Method == http.MethodPost {
				postChecked++

				rec := postSkippingCSRF(t, unchecked, path)
				if !r.ReachableBy(role) {
					if rec.Code != http.StatusNotFound {
						t.Errorf("role %s: POST %s = %d, want 404 — a role below MinRole %s must find the route absent", role, path, rec.Code, r.MinRole)
					} else if got, want := rec.Body.String(), missPost.Body.String(); got != want {
						t.Errorf("role %s: POST %s body %q, want %q (same as an unmounted path)", role, path, got, want)
					}
				} else if rec.Code == http.StatusNotFound {
					// Deliberately weak in this direction: with CSRF skipped
					// the real handler runs against fixture fakes and its
					// status depends on the route (401 for a granting act
					// with no password, 400 for a missing field, 303 for a
					// reducing one). "Not absent" is the property this sweep
					// is for; per-route behaviour is pinned in the route's
					// own tests.
					t.Errorf("role %s: POST %s = 404, want reachable (MinRole %s)", role, path, r.MinRole)
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
	if postChecked == 0 {
		t.Fatal("the own-method POST sweep checked zero routes — it is not running, which is " +
			"exactly the state this sweep was in before #655 widened it")
	}
}

// TestConsole_UnknownPathRendersTheStyledNotFound (#640, item 5): a path
// under /console/ that this package never mounts at all must get the styled
// Console 404, not net/http's plain-text "404 page not found" — the same
// gap TestConsole_ARouteAboveTheSessionRoleIsAbsent's own "miss" control
// already exercises implicitly, asserted directly here.
func TestConsole_UnknownPathRendersTheStyledNotFound(t *testing.T) {
	h := newTestHandler(renderableDeps(), accounts.RoleViewer)

	for _, path := range []string{"/console/does-not-exist", "/console/nodes-typo/x"} {
		rec := get(t, h, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s Content-Type = %q, want text/html", path, ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `aside class="nav"`) {
			t.Errorf("GET %s did not render the Console shell (no aside class=\"nav\")", path)
		}
		if !strings.Contains(body, "Nothing in the Console lives at this address.") {
			t.Errorf("GET %s did not render the styled not-found sentence", path)
		}
		if strings.Contains(body, "404 page not found") {
			t.Errorf("GET %s rendered net/http's plain 404 text", path)
		}
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

// retiredReadsLink matches a link to the retired Read egress screen without
// matching a longer path that merely starts with the same letters.
var retiredReadsLink = regexp.MustCompile(`/console/reads(["'?/#&]|$)`)

// TestConsole_ReadEgressIsRetired: the Read egress screen was dropped on
// 2026-10-01 (owner decision) — Activity is the single log of control-plane
// traffic. /console/reads answers the Console's ORDINARY 404 for every role,
// the nav no longer offers it, and no rendered screen links to it.
func TestConsole_ReadEgressIsRetired(t *testing.T) {
	d := withExecution(sweepFixture(), true)

	walked := 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)

		// Byte-identical to an unmounted path's page: the ordinary 404, not a
		// bespoke "this moved" page and not a redirect.
		want := get(t, h, "/console/nonesuch")
		if want.Code != http.StatusNotFound {
			t.Fatalf("role %s: /console/nonesuch = %d, want 404", role, want.Code)
		}
		for _, path := range []string{"/console/reads", "/console/reads/", "/console/reads?window=7d&principal=acct-1"} {
			got := get(t, h, path)
			if got.Code != http.StatusNotFound {
				t.Errorf("role %s: GET %s = %d, want 404", role, path, got.Code)
				continue
			}
			if !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
				t.Errorf("role %s: GET %s is not the Console's ordinary 404 page", role, path)
			}
		}

		reachable := routesFor(d, role)
		for _, r := range reachable {
			if r.Path == "/console/reads" {
				t.Errorf("role %s: the route table still mounts %s", role, r.Path)
			}
		}
		if nav := navOf(get(t, h, "/console/").Body.String()); strings.Contains(nav, "Read egress") {
			t.Errorf("role %s: the navigation still offers Read egress", role)
		}

		for _, path := range walkableScreens(reachable, fixtureIDs) {
			walked++
			if body := get(t, h, path).Body.String(); retiredReadsLink.MatchString(body) {
				t.Errorf("role %s: %s links to the retired /console/reads", role, path)
			}
		}
		// The kind note, drawn only with a filter kept.
		if body := get(t, h, "/console/activity?account=acct-9").Body.String(); retiredReadsLink.MatchString(body) {
			t.Errorf("role %s: Activity's read-records note links to the retired /console/reads", role)
		}
	}
	if walked == 0 {
		t.Fatal("the sweep walked zero screens — it is not running")
	}
}

// TestConsole_V060MountsNoUnbuiltScreen is a regression pin for the exact
// defect #464 fixed, not a derived property: these specific v0.7.0 screens
// (console/06, 09, 16) must not be reachable in v0.6.0, however the route
// table changes around them. A hand-written list is correct here.
//
// Spec 15 (Accounts) was the fourth entry until #654 mounted its read half at
// GET /console/accounts. It leaves this list because the screen now EXISTS —
// which is a different fact from the one this pin defends. What keeps a
// viewer from reaching it is the route's own admin MinRole, swept by
// TestConsole_ARouteAboveTheSessionRoleIsAbsent and pinned by name in
// TestAccounts_AViewerFindsTheScreenAbsentNotForbidden.
func TestConsole_V060MountsNoUnbuiltScreen(t *testing.T) {
	h := newTestHandler(withExecution(renderableDeps(), false), accounts.RoleAdmin)
	for _, path := range []string{
		"/console/policy",
		"/console/nodes/add",
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

	// The Accounts write half's two parameters (#655). Both exist in
	// sweepAccounts (fakes_test.go), and acct-mike is chosen deliberately: it
	// is NEITHER the founding admin NOR the Account a test session signs in
	// as, so a reachability probe does not collide with
	// capability.ErrSelfTargeted or the last-enabled-admin guard and come back
	// refused for a reason that has nothing to do with reach.
	"{account_id}": "acct-mike",
	"{token_id}":   "tok-live",
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

// TestConsole_EveryRenderedFormCarriesACSRFToken is a PACKAGE-WIDE property,
// swept over every walkable screen for every session role (#655).
//
// A new form silently missing its hidden csrf_token is refused only at submit
// time and only over a real session — which is to say, by nobody in this test
// suite until somebody clicks it. Before this sweep existed, no test in the
// package looked for it at all.
//
// It drives walkableScreens(routesFor(d, role), fixtureIDs) rather than one
// screen, for the reason walkableScreens itself gives: a hand-listed sweep is
// a list that silently stops covering the package. The layout's own sign-out
// form is swept too, which is correct — it is a form on every page.
func TestConsole_EveryRenderedFormCarriesACSRFToken(t *testing.T) {
	d := withExecution(sweepFixture(), true)

	formsChecked := 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		for _, path := range walkableScreens(routesFor(d, role), fixtureIDs) {
			rec := get(t, h, path)
			if rec.Code != http.StatusOK {
				continue
			}
			for _, form := range postForms(rec.Body.String()) {
				formsChecked++
				if !strings.Contains(form, `name="csrf_token"`) {
					t.Errorf("role %s: a form on %s carries no csrf_token input. It will be "+
						"refused at submit time over a real session, and nothing but this sweep "+
						"says so before then:\n%s", role, path, form)
				}
			}
		}
	}
	if formsChecked == 0 {
		t.Fatal("the sweep found zero POST forms — it is not inspecting anything")
	}
}

// postForms splits a rendered page into its <form method="post"> elements.
// Each returned string is one form's own markup, so a token belonging to a
// NEIGHBOURING form cannot satisfy an assertion about this one.
func postForms(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, `<form method="post"`)
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, "</form>")
		if j < 0 {
			return append(out, rest)
		}
		out = append(out, rest[:j])
		rest = rest[j+len("</form>"):]
	}
}
