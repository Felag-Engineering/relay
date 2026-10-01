package api

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/console"
)

// preflightDetectorRegex is deliberately narrower than the obvious guess.
// After ADR-0038, "plan" names the Plan capability
// (docs/specs/plan.md, Status "designed, not built") — its own routes
// (GET /api/v1/plans, GET /api/v1/plans/{id}, POST /api/v1/plans/{id}/abandon)
// all carry the bare token "plan" and none of them is a preflight, so a
// preflight-detector regex carrying that token would false-match every one
// of them the moment plan.md is built. The detection that would give up is
// recovered, more strongly, by this test's own exact-route-set assertion: a
// route literally named /api/v1/plan (or any other plan-named route) is
// caught there, reviewed, and named — never silently exempted by a regex
// allowlist.
var preflightDetectorRegex = regexp.MustCompile(`(?i)preflight|preview|dry.?run|simulate|what.?if`)

// TestNoSeparatePreflightRouteIsServed proves PF-1's Control API half
// (docs/specs/policy-preflight.md): "no surface exposes a separate preflight
// tool or route" — the only way in is the plan option on
// POST /api/v1/operations and POST /api/v1/raw-exec.
//
// Coverage inherited for free: openapi_test.go's TestOpenAPISpec_MatchesServedRoutes
// already pins Routes() and docs/api/openapi.yaml to each other in both
// directions, so a preflight path cannot appear in the published document
// without appearing in this table first. The exact-set assertion here is a
// SECOND pin with a different reason: openapi_test asks "is the document
// honest", this asks "was a new route read against PF-1".
//
// Scope, narrowed on security review (cycle 2, SR2): this guard's reach is
// api.Routes() alone, and /api/v1 is not served EXCLUSIVELY from it —
// controlplane.New (internal/controlplane/server.go) registers
// "GET /api/v1/ping" directly on the same mux, as a stand-in route that
// predates the Control API. This test does not, and cannot cleanly, prove
// no OTHER file under that prefix exists: net/http.ServeMux exposes no way
// to enumerate a live mux's registered patterns, so seeing the actually-
// composed mux would mean either reflecting into ServeMux's unexported
// internals or reconstructing cmd/relay/main.go's full composition inside a
// package that should not own it. "/api/v1/ping" itself is a known,
// harmless exception (it matches neither the regex above nor any preflight
// shape) — the residual is that this guard cannot see a HYPOTHETICAL
// second registrar the way it sees every route inside Routes() itself.
//
// The Console is covered by its own mirror below
// (TestConsoleServesNoSeparatePreflightRoute), not skipped: PF-21 previews
// before an apply on the composer's own route, and a SEPARATE Console
// preflight route is exactly the shape PF-1 forbids — so the guard
// constrains what PF-21 may build rather than blocking it.
func TestNoSeparatePreflightRouteIsServed(t *testing.T) {
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("Routes() returned zero routes — this guard has nothing to check")
	}

	seen := make(map[string]bool, len(routes))
	for _, r := range routes {
		pattern := r.Pattern()
		if seen[pattern] {
			t.Errorf("Routes() serves %q more than once — a duplicate execution route is exactly the shape a second, un-reviewed preflight door would take", pattern)
		}
		seen[pattern] = true

		if preflightDetectorRegex.MatchString(r.Path) {
			t.Errorf("route %q matches the preflight-detector regex — PF-1 says no surface exposes a separate preflight route", pattern)
		}
		for _, execPath := range []string{"/api/v1/operations", "/api/v1/raw-exec"} {
			if r.Path != execPath && strings.HasPrefix(r.Path, execPath+"/") {
				t.Errorf("route %q is a sub-path of the execution route %q — a preflight must never get its own path under the executing route", pattern, execPath)
			}
		}
	}

	// The exact set of Route.Pattern() values served today, grouped and
	// commented by the same families api.go groups Routes() into. This is
	// the assertion that carries the weight a bare "plan" token in the
	// regex above used to carry: a route literally named /api/v1/plan, or
	// any other plan-named route, is caught HERE and lands in front of a
	// reviewer instead of being silently exempted. Updating this set is a
	// one-line edit AND a moment to ask whether the new route is a
	// preflight.
	want := map[string]bool{
		// Enrollment Tokens, Node revocation, Freeze.
		"POST /api/v1/enrollment-tokens":        true,
		"DELETE /api/v1/enrollment-tokens/{id}": true,
		"GET /api/v1/nodes/{node_id}":           true,
		"POST /api/v1/nodes/{node_id}/revoke":   true,
		"POST /api/v1/freeze/engage":            true,
		"POST /api/v1/freeze/release":           true,

		// Identity management (Accounts / API Tokens).
		"POST /api/v1/accounts":                true,
		"GET /api/v1/accounts":                 true,
		"GET /api/v1/accounts/{id}":            true,
		"POST /api/v1/accounts/{id}/role":      true,
		"POST /api/v1/accounts/{id}/enable":    true,
		"POST /api/v1/accounts/{id}/disable":   true,
		"POST /api/v1/accounts/{id}/tokens":    true,
		"GET /api/v1/accounts/{id}/tokens":     true,
		"DELETE /api/v1/api-tokens/{token_id}": true,

		// Execution — the pair PF-1 says is the only way in.
		"POST /api/v1/operations": true,
		"POST /api/v1/raw-exec":   true,

		// Job read + cancel.
		"GET /api/v1/jobs/{id}":         true,
		"POST /api/v1/jobs/{id}/cancel": true,

		// Out-of-band approval decisions.
		"GET /api/v1/approvals":                true,
		"GET /api/v1/approvals/{id}":           true,
		"POST /api/v1/approvals/{id}/decision": true,

		// Batch/window approvals (Grants).
		"POST /api/v1/approval-grants":             true,
		"GET /api/v1/approval-grants":              true,
		"GET /api/v1/approval-grants/{id}":         true,
		"POST /api/v1/approval-grants/{id}/revoke": true,
	}

	if !reflect.DeepEqual(seen, want) {
		t.Errorf("Routes() pattern set changed:\n  got:  %v\n  want: %v\n"+
			"any addition must be named here and reviewed against PF-1 before this set is updated", seen, want)
	}

	if !seen["POST /api/v1/operations"] || !seen["POST /api/v1/raw-exec"] {
		t.Error("Routes() is missing POST /api/v1/operations or POST /api/v1/raw-exec — PF-1's positive half (the preview and the act are the same request) has nowhere to attach")
	}
}

// TestRunOperationAndRawExecShareOnePlanFlag proves PF-1's positive half: the
// preview and the act are the same request body, with one documented flag
// (json tag "plan") as the only door.
func TestRunOperationAndRawExecShareOnePlanFlag(t *testing.T) {
	assertHasPlanJSONField(t, reflect.TypeOf(runOperationRequest{}))
	assertHasPlanJSONField(t, reflect.TypeOf(rawExecRequest{}))
}

// TestConsoleServesNoSeparatePreflightRoute is
// TestNoSeparatePreflightRouteIsServed's mirror over the Console's own route
// table (security review, cycle 2, SR3), built with Execution: true so the
// composer route (/console/run, mounted only when console_execution is on)
// is IN this guard's scope rather than absent from it — the placeholder it
// serves today is what PF-21's real composer replaces, and a separate
// Console preflight route would be exactly the shape PF-1 forbids. This is
// a mirror, not a duplicate: package api's guard above cannot see this
// table (the Console is a different package with its own Routes()), and
// console.Routes(Deps{Execution: true}) is already a lightweight, no-fixture
// call used the same way elsewhere in that package's own tests.
func TestConsoleServesNoSeparatePreflightRoute(t *testing.T) {
	routes := console.Routes(console.Deps{Execution: true})
	if len(routes) == 0 {
		t.Fatal("console.Routes(Deps{Execution: true}) returned zero routes — this guard has nothing to check")
	}

	seen := make(map[string]bool, len(routes))
	for _, r := range routes {
		pattern := r.Pattern()
		if seen[pattern] {
			t.Errorf("console.Routes() serves %q more than once", pattern)
		}
		seen[pattern] = true

		if preflightDetectorRegex.MatchString(r.Path) {
			t.Errorf("Console route %q matches the preflight-detector regex — PF-1 says no surface exposes a separate preflight route", pattern)
		}
	}

	// The exact set of console.Route.Pattern() values served today with
	// Execution on. Any addition must be named here and reviewed against
	// PF-1 — exactly the discipline the Control API's route set above
	// carries, so the composer PF-21 will build lands under this guard
	// rather than beside it.
	want := map[string]bool{
		"GET /console/{$}":                     true,
		"GET /console/nodes/{node_id}":         true,
		"GET /console/activity":                true,
		"GET /console/jobs/{job_id}":           true,
		"GET /console/compare":                 true,
		"GET /console/reads":                   true,
		"GET /console/approvals":               true,
		"GET /console/approvals/{approval_id}": true,
		"GET /console/accounts":                true,
		// Access (spec 20, D17, #785): who signed in and who changed who can
		// get in, admin-only. A read screen over the audit trail, not a
		// preflight route — reviewed against PF-1 in the same PR that added
		// it.
		"GET /console/access":                            true,
		"POST /console/accounts/create":                  true,
		"POST /console/accounts/{account_id}/role":       true,
		"POST /console/accounts/{account_id}/enabled":    true,
		"POST /console/accounts/{account_id}/tokens":     true,
		"POST /console/api-tokens/{token_id}/revoke":     true,
		"GET /console/assets/{path...}":                  true,
		"GET /console/events":                            true,
		"GET " + console.LoginPath:                       true,
		"POST " + console.LoginPath:                      true,
		"POST " + console.LogoutPath:                     true,
		"POST /console/jobs/{job_id}/cancel":             true,
		"POST /console/approvals/{approval_id}/decision": true,
		// The one route this guard exists to constrain: the composer PF-21
		// describes, mounted only with Execution on. It is a placeholder
		// today (#438, the console-execution gap), not a preflight route —
		// PF-21 previews and applies through THIS route, never a second one.
		"GET /console/run": true,
	}

	if !reflect.DeepEqual(seen, want) {
		t.Errorf("console.Routes(Deps{Execution: true}) pattern set changed:\n  got:  %v\n  want: %v\n"+
			"any addition must be named here and reviewed against PF-1 before this set is updated", seen, want)
	}
}

func assertHasPlanJSONField(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name != "Plan" {
			continue
		}
		if f.Type.Kind() != reflect.Bool {
			t.Errorf("%s.Plan has type %s, want bool", typ.Name(), f.Type)
		}
		if tag := f.Tag.Get("json"); tag != "plan" {
			t.Errorf("%s.Plan json tag = %q, want %q — the wire spelling is still \"plan\" until PF-19 lands", typ.Name(), tag, "plan")
		}
		return
	}
	t.Errorf("%s has no Plan field — the preview and the act must be the same request with one flag (PF-1)", typ.Name())
}
