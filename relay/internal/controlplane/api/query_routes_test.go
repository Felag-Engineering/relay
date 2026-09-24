package api

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// queryDisclosureNameRegex names the Query capability's two Control-API
// absences — the Policy view and Operation-vocabulary discovery — by the
// tokens a route disclosing either of them would have to be called.
//
// Deliberately NOT "operation": POST /api/v1/operations is execution, and
// QRY-1 is a statement about reads.
var queryDisclosureNameRegex = regexp.MustCompile(`(?i)polic|vocabular|template|fingerprint`)

// violatesQRY1 reports why r would breach QRY-1, or "" if it would not.
//
// Three predicates, applied to EVERY route regardless of method — a non-GET
// route that disclosed registry, Policy-view or vocabulary data would be just
// as much a second query surface as a GET one.
func violatesQRY1(r Route) string {
	switch {
	case r.Path == "/api/v1/nodes":
		return "it enumerates the fleet; QRY-1 says fleet enumeration is MCP and Console only"
	case r.Method == http.MethodGet &&
		strings.HasPrefix(r.Path, "/api/v1/nodes") &&
		r.Path != "/api/v1/nodes/{node_id}":
		return "it is a second registry read under /api/v1/nodes; QRY-1 says the single-Node read is the only one"
	case queryDisclosureNameRegex.MatchString(r.Path):
		return "its name reads as a Policy-view or vocabulary disclosure; QRY-1 says both are MCP and Console only"
	}
	return ""
}

// TestQueryRoutes_TheControlAPIServesNoEnumerationPolicyOrVocabularyRead
// proves QRY-1's negative half (docs/specs/query.md): of the registry,
// Policy-view and vocabulary reads, the Control API exposes exactly one — the
// single-Node read — so there is no fleet-enumeration route, no Policy-view
// route and no vocabulary route.
//
// Seam: api.Routes(), the same data-as-table the OpenAPI drift gate and
// TestNoSeparatePreflightRouteIsServed read. This adds no fourth hand-kept
// copy of the route set: preflight_route_test.go pins the exact Pattern() set
// and openapi_test.go pins it against the published document. What is new
// here is three targeted absence predicates, armed below against routes that
// deliberately violate each one.
//
// Residual: this is api.Routes(), not the composed mux — controlplane.New
// registers GET /api/v1/ping straight on the mux and net/http.ServeMux cannot
// be enumerated (the identical residual PF-1's row carries). The three
// predicates are a NAME HEURISTIC: a route disclosing registry, Policy-view or
// vocabulary data under a name matching none of those tokens and not under
// /api/v1/nodes is not caught. QRY-1's positive half — that fleet enumeration,
// the Policy view and vocabulary discovery are MCP and Console only — is not
// asserted here; the MCP and Console presence rests on QRY-3's, QRY-7's and
// QRY-11's own rows.
func TestQueryRoutes_TheControlAPIServesNoEnumerationPolicyOrVocabularyRead(t *testing.T) {
	// Armed: each of violatesQRY1's three branches is breached by at least one
	// control route below — not one branch each, since the policy route
	// breaches both the second-registry-read branch and the name regex and is
	// only reported under the former because the switch reaches it first. A
	// walker that flagged nothing — an inverted condition, a regex that
	// compiled to something harmless — would otherwise report the real table
	// clean.
	controls := []Route{
		{Method: "GET", Path: "/api/v1/nodes"},
		{Method: "GET", Path: "/api/v1/nodes/{node_id}/policy"},
		{Method: "POST", Path: "/api/v1/template-vocabulary"},
	}
	for _, c := range controls {
		if violatesQRY1(c) == "" {
			t.Fatalf("violatesQRY1 did not flag the deliberately-violating control route %q — "+
				"this test's predicates cannot fail and prove nothing", c.Pattern())
		}
	}

	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("Routes() returned zero routes — this guard has nothing to check")
	}

	var singleNodeRead bool
	for _, r := range routes {
		if reason := violatesQRY1(r); reason != "" {
			t.Errorf("route %q breaches QRY-1: %s\n"+
				"a new route here is reviewed against QRY-1 BEFORE either route set is updated — "+
				"preflight_route_test.go's `want` set is the sibling list that also has to move",
				r.Pattern(), reason)
		}
		if r.Pattern() == "GET /api/v1/nodes/{node_id}" {
			singleNodeRead = true
		}
	}

	// QRY-1's "exactly one" has to attach to something: the one read the
	// Control API does serve.
	if !singleNodeRead {
		t.Error("Routes() is missing GET /api/v1/nodes/{node_id} — QRY-1's single-Node read, " +
			"the one registry read the Control API exposes, has nowhere to attach")
	}
}
