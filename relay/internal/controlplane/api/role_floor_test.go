package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// role_floor_test.go is #397's guard-the-guard, and the third of that issue's
// suggested resolutions: every route in Routes() must be deliberately
// classified as reaching a role check on this surface, inheriting one from
// the capability layer, or having no floor at all.
//
// It exists because the defect it closes was not a wrong decision — it was a
// route group nobody thought about. The identity routes carry a comment
// saying "the gate lives in each handler ... so a route added later cannot
// silently miss it", and the enrollment/freeze group directly above them had
// neither the comment nor the gate. A prose promise did not survive the next
// route; a failing test will.
//
// It is deliberately mechanical in the gated direction (the handler's call
// graph really is walked, so deleting its ControlGate call fails here) and
// deliberately declarative in the other two (a capability-layer floor cannot
// be proven from this package's AST). The declarative half still earns its
// keep: a NEW route cannot be added without someone writing down which of the
// three it is.

// floorKind classifies where a route's role floor is enforced.
type floorKind int

const (
	// floorGate: the floor is decided in the capability layer through a
	// ControlGate method the handler must call before it reads the request
	// (#397's administrative routes: both enrollment-token routes, Node
	// revoke). Verified by walking the call graph.
	floorGate floorKind = iota

	// floorCapability: the floor is enforced inside the capability layer, and
	// this surface only renders the refusal. Execution (authz.RoleGate via
	// capability.Execution.Run), Freeze (capability.Control; AuthorizeControl via EngageFreeze/
	// ReleaseFreeze), approvals (AuthorizeApprovalDecision), and identity
	// management (#653: AuthorizeControl via Accounts/CreateAccount/
	// SetAccountRole/...) are all here. A handler in this class must NOT
	// re-derive the rule — that would be the second control path invariant
	// 10 forbids, and TestCapabilityFlooredRoutesDoNotReachASurfaceGate below
	// pins it as a mechanical fact rather than a comment.
	floorCapability

	// floorNone: no role floor. Any authenticated Account may call it. Only
	// legitimate for reads, whose floor is `viewer` — which is to say, the
	// floor every authenticated caller already clears.
	floorNone
)

func (f floorKind) String() string {
	switch f {
	case floorGate:
		return "floorGate"
	case floorCapability:
		return "floorCapability"
	default:
		return "floorNone"
	}
}

// routeFloors classifies every route in Routes(). Adding a route without
// adding it here fails TestEveryRouteIsRoleClassified — which is the point.
var routeFloors = map[string]floorKind{
	// Administrative routes (#397). admin, admin, admin; the Freeze pair is
	// operator+/admin and is decided in the capability layer with the same
	// RoleGate object.
	// The mint is floorGate: the route asks the capability layer before it
	// reads the body (EN-1), and the layer then asks the same RoleGate again.
	"POST /api/v1/enrollment-tokens":        floorGate,
	"DELETE /api/v1/enrollment-tokens/{id}": floorGate,
	"POST /api/v1/nodes/{node_id}/revoke":   floorGate,
	// Reading one Node is a read, and the read floor is `viewer` — which every
	// authenticated Account already clears. Consistent with MCP's describe_node,
	// which is likewise ungated, and with the Console's own rule that a viewer
	// sees everything and changes nothing.
	//
	// Ungated does not mean unrecorded: the handler audits the read before it
	// answers anything and fails closed if it cannot (ADR-0025).
	"GET /api/v1/nodes/{node_id}": floorNone,
	"POST /api/v1/freeze/engage":  floorCapability,
	"POST /api/v1/freeze/release": floorCapability,

	// Tag writes (ADR-0050): a human Account at operator or above, decided in
	// the capability layer behind AuthorizeControl(ControlTagWrite).
	"POST /api/v1/nodes/{node_id}/tags": floorCapability,
	"POST /api/v1/tags":                 floorCapability,

	// Identity management (#297; #653: the floor moved into capability.AccountAdmin
	// behind AuthorizeControl; this surface renders the refusal and re-derives
	// nothing).
	"POST /api/v1/accounts":                floorCapability,
	"GET /api/v1/accounts":                 floorCapability,
	"GET /api/v1/accounts/{id}":            floorCapability,
	"POST /api/v1/accounts/{id}/role":      floorCapability,
	"POST /api/v1/accounts/{id}/enable":    floorCapability,
	"POST /api/v1/accounts/{id}/disable":   floorCapability,
	"POST /api/v1/accounts/{id}/tokens":    floorCapability,
	"GET /api/v1/accounts/{id}/tokens":     floorCapability,
	"DELETE /api/v1/api-tokens/{token_id}": floorCapability,

	// Execution (#356): operator for a typed Operation, admin for Raw Exec —
	// authz.RoleGate, reached through capability.Execution.Run/Plan.
	"POST /api/v1/operations": floorCapability,
	"POST /api/v1/raw-exec":   floorCapability,

	// Jobs (#357). Reading a Job is a read (audited, ADR-0025); cancelling one
	// is floored by AuthorizeControl(ControlCancelJob) at operator, inside the
	// capability layer (#595).
	"GET /api/v1/jobs/{id}":         floorNone,
	"POST /api/v1/jobs/{id}/cancel": floorCapability,

	// Approvals (#270, ADR-0027). Listing and reading a parked request is a
	// read; deciding one is floored by AuthorizeApprovalDecision at the SAME
	// role the request itself needed, inside the capability layer.
	"GET /api/v1/approvals":                floorNone,
	"GET /api/v1/approvals/{id}":           floorNone,
	"POST /api/v1/approvals/{id}/decision": floorCapability,
}

// routeGate names the ControlGate method each floorGate route's handler must
// reach: one per act, so a route cannot satisfy its floor with another act's.
var routeGate = map[string]string{
	"POST /api/v1/enrollment-tokens":        "AuthorizeEnrollmentTokenMint",
	"DELETE /api/v1/enrollment-tokens/{id}": "AuthorizeEnrollmentTokenRevoke",
	"POST /api/v1/nodes/{node_id}/revoke":   "AuthorizeNodeRevoke",
}

// controlGateMethods are the ControlGate methods, and so the only role checks
// a handler in this package may reach.
var controlGateMethods = map[string]bool{
	"AuthorizeEnrollmentTokenMint":   true,
	"AuthorizeEnrollmentTokenRevoke": true,
	"AuthorizeNodeRevoke":            true,
}

// surfaceGateIdents are the identifiers that count as "this handler reaches a
// surface-level role check": a ControlGate method, gateControl, or a direct
// AuthorizeControl call, which the no_dispatch guard forbids here anyway.
var surfaceGateIdents = map[string]bool{
	"AuthorizeEnrollmentTokenMint":   true,
	"AuthorizeEnrollmentTokenRevoke": true,
	"AuthorizeNodeRevoke":            true,
	"gateControl":                    true,
	"AuthorizeControl":               true,
}

// TestControlGateMethodsAreTheSeam keeps controlGateMethods equal to the
// ControlGate interface, so the call-graph walk cannot go stale when a method
// is added to or removed from the seam.
func TestControlGateMethodsAreTheSeam(t *testing.T) {
	typ := reflect.TypeOf((*ControlGate)(nil)).Elem()
	got := map[string]bool{}
	for i := 0; i < typ.NumMethod(); i++ {
		got[typ.Method(i).Name] = true
	}
	if !reflect.DeepEqual(got, controlGateMethods) {
		t.Errorf("ControlGate methods = %v, controlGateMethods = %v; they must be the same set",
			sortedKeys(got), sortedKeys(controlGateMethods))
	}
}

// TestEveryRouteIsRoleClassified is the guard. Two directions, both
// mechanical: no route may be unclassified, and no classification may name a
// route the server does not serve.
func TestEveryRouteIsRoleClassified(t *testing.T) {
	served := map[string]bool{}
	for _, r := range Routes() {
		pattern := r.Pattern()
		served[pattern] = true
		if _, ok := routeFloors[pattern]; !ok {
			t.Errorf("route %q has no entry in routeFloors — decide its role floor (#397): "+
				"floorGate if the handler must call its ControlGate method, "+
				"floorCapability if the capability layer decides it, floorNone if any "+
				"authenticated Account may call it", pattern)
		}
	}

	var stale []string
	for pattern := range routeFloors {
		if !served[pattern] {
			stale = append(stale, pattern)
		}
	}
	sort.Strings(stale)
	for _, pattern := range stale {
		t.Errorf("routeFloors classifies %q, which Routes() does not serve — a stale entry "+
			"silently stops guarding anything", pattern)
	}
}

// TestGatedRoutesReachTheirOwnControlGate is the mechanical half: for every
// route classified floorGate, the handler's call graph within this package
// must reach the ControlGate method of its own act. Deleting the gate call
// from a handler fails here, which is exactly the regression #397 records.
func TestGatedRoutesReachTheirOwnControlGate(t *testing.T) {
	funcs := packageFuncs(t)

	checked := 0
	for _, r := range Routes() {
		if routeFloors[r.Pattern()] != floorGate {
			continue
		}
		checked++
		method, ok := routeGate[r.Pattern()]
		if !ok {
			t.Errorf("route %q is classified floorGate but has no routeGate entry naming its ControlGate method", r.Pattern())
			continue
		}
		entry := handlerFuncName(t, r)
		if _, ok := funcs[entry]; !ok {
			t.Errorf("route %q: handler %q not found among this package's top-level functions", r.Pattern(), entry)
			continue
		}
		if !reachesAny(entry, funcs, map[string]bool{method: true}) {
			t.Errorf("route %q is classified floorGate but its handler %q never reaches %s "+
				"— a route that authenticates and then proceeds is #397 all over again",
				r.Pattern(), entry, method)
		}
	}

	// Non-vacuity: if a refactor made every route capability-floored, the loop
	// above would pass by checking nothing.
	if checked == 0 {
		t.Fatal("checked 0 gated routes — the guard must actually inspect something")
	}
}

// TestCapabilityFlooredRoutesDoNotReachASurfaceGate is the INVERSE of
// TestGatedRoutesReachTheirOwnControlGate (#653 suggestion 11): for every route
// classified floorCapability, the handler's call graph within this package
// must NOT reach any surfaceGateIdents entry.
//
// Without this, "this surface re-derives nothing" (this file's own comment
// on the identity rows above) is a declaration nobody checks. This is what
// would fail if a future editor re-introduced a local role check beside a
// capability call that already refuses — a regression as real as the one
// TestGatedRoutesReachTheirOwnControlGate catches, just in the other direction.
func TestCapabilityFlooredRoutesDoNotReachASurfaceGate(t *testing.T) {
	funcs := packageFuncs(t)

	checked := 0
	for _, r := range Routes() {
		if routeFloors[r.Pattern()] != floorCapability {
			continue
		}
		checked++
		entry := handlerFuncName(t, r)
		if _, ok := funcs[entry]; !ok {
			t.Errorf("route %q: handler %q not found among this package's top-level functions", r.Pattern(), entry)
			continue
		}
		if reachesAny(entry, funcs, surfaceGateIdents) {
			t.Errorf("route %q is classified floorCapability but its handler %q reaches a surface-level role check "+
				"(%s) — the capability layer already decides this route's floor; a local check beside it is the "+
				"second control path invariant 10 forbids",
				r.Pattern(), entry, strings.Join(sortedKeys(surfaceGateIdents), " or "))
		}
	}

	// Non-vacuity: if a refactor classified every route floorGate/floorNone,
	// the loop above would pass by checking nothing.
	if checked == 0 {
		t.Fatal("checked 0 capability-floored routes — the guard must actually inspect something")
	}
}

// handlerFuncName resolves the top-level function backing r.Handler.
//
// Route.Handler is a func value, so its name comes from the runtime rather
// than the AST: "…/api.handleMintToken", or "…/api.enableAccount.func1" for a
// route whose handler is built by a closure. Both reduce to the top-level
// declaration the call-graph walk starts from.
func handlerFuncName(t *testing.T, r Route) string {
	t.Helper()
	fn := runtime.FuncForPC(reflect.ValueOf(r.Handler).Pointer())
	if fn == nil {
		t.Fatalf("route %q: cannot resolve its handler function", r.Pattern())
	}
	name := fn.Name()
	name = name[strings.LastIndex(name, "/")+1:] // drop the import path
	if i := strings.Index(name, "."); i >= 0 {
		name = name[i+1:] // drop the package name
	}
	beforeClosureSuffix := name
	if i := strings.Index(name, "."); i >= 0 {
		name = name[:i] // drop a ".funcN" closure suffix
	}
	// A resolution of "Routes" means the Go compiler inlined a
	// closure-returning function (like enableAccount) into Routes() at its
	// call site, which makes runtime.FuncForPC attribute the returned
	// closure to Routes itself rather than to the function that built it.
	// Routes' own body references literally every handler in the table as a
	// value, so reachesAny("Routes", …) walks into all of them — making the
	// FORWARD guard (TestGatedRoutesReachTheirOwnControlGate) trivially true
	// for that route regardless of whether ITS OWN handler reaches a gate
	// (a silent false pass), while the INVERSE guard
	// (TestCapabilityFlooredRoutesDoNotReachASurfaceGate) fails LOUDLY but
	// for the same wrong reason — a spurious failure, not a proof the
	// handler re-derives anything. Neither is acceptable, so this fails
	// the test outright with a message naming the fix: //go:noinline on the
	// function that returns this route's handler closure (see
	// enableAccount's own //go:noinline and its doc comment for why).
	if name == "Routes" || strings.HasPrefix(beforeClosureSuffix, "Routes.") {
		t.Fatalf("route %q: handler resolved to %q (from %q) — a closure-returning function "+
			"was inlined into Routes(), making this route's role-floor guard either trivially "+
			"true or spuriously false; add //go:noinline to the function that builds this "+
			"route's Handler", r.Pattern(), name, beforeClosureSuffix)
	}
	return name
}

// packageFuncs parses this package's non-test sources and returns every
// top-level function declaration by name.
func packageFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	funcs := map[string]*ast.FuncDecl{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			funcs[fd.Name.Name] = fd
		}
	}
	return funcs
}

// reachesAny walks the call graph from entry, within this package, looking for
// one of names. Identifiers inside nested closures count, because a closure's
// body is part of its enclosing declaration.
func reachesAny(entry string, funcs map[string]*ast.FuncDecl, names map[string]bool) bool {
	seen := map[string]bool{entry: true}
	queue := []string{entry}

	for len(queue) > 0 {
		fd := funcs[queue[0]]
		queue = queue[1:]
		if fd == nil {
			continue
		}
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if names[id.Name] {
				found = true
				return false
			}
			if _, isLocal := funcs[id.Name]; isLocal && !seen[id.Name] {
				seen[id.Name] = true
				queue = append(queue, id.Name)
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// TestReachesAny_Fixtures proves the walker actually discriminates, rather
// than answering true for everything — the failure mode that would make the
// guard above decorative.
func TestReachesAny_Fixtures(t *testing.T) {
	parse := func(src string) map[string]*ast.FuncDecl {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "fixture.go", src, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		out := map[string]*ast.FuncDecl{}
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				out[fd.Name.Name] = fd
			}
		}
		return out
	}

	cases := []struct {
		name  string
		src   string
		entry string
		want  bool
	}{
		{
			name: "gate called inside the returned closure",
			src: `package api
func handler() {
	_ = func() { g.AuthorizeNodeRevoke() }
}`,
			entry: "handler", want: true,
		},
		{
			name: "gate reached one hop away",
			src: `package api
func handler() { helper() }
func helper() { g.AuthorizeNodeRevoke() }`,
			entry: "handler", want: true,
		},
		{
			name: "authenticates and proceeds — the #397 shape",
			src: `package api
func handler() {
	_ = func() { principal() }
}`,
			entry: "handler", want: false,
		},
		{
			name: "a call cycle must not hang the walk",
			src: `package api
func handler() { helper() }
func helper() { handler() }`,
			entry: "handler", want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reachesAny(tc.entry, parse(tc.src), controlGateMethods); got != tc.want {
				t.Errorf("reachesAny() = %v, want %v", got, tc.want)
			}
		})
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
