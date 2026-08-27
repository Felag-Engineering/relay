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
// It is deliberately mechanical in the surface-gated direction (the handler's
// call graph really is walked, so deleting an authorizeControl call fails
// here) and deliberately declarative in the other two (a capability-layer
// floor cannot be proven from this package's AST). The declarative half still
// earns its keep: a NEW route cannot be added without someone writing down
// which of the three it is.

// floorKind classifies where a route's role floor is enforced.
type floorKind int

const (
	// floorSurface: the handler itself must reach a role check in this
	// package — requireAdmin (identity routes) or authorizeControl (#397's
	// administrative routes). Verified by walking the call graph.
	floorSurface floorKind = iota

	// floorCapability: the floor is enforced inside the capability layer, and
	// this surface only renders the refusal. Execution (authz.RoleGate via
	// capability.Service.Run), Freeze (AuthorizeControl via EngageFreeze/
	// ReleaseFreeze), and approvals (AuthorizeApprovalDecision) are all here.
	// A handler in this class must NOT re-derive the rule — that would be the
	// second control path invariant 10 forbids.
	floorCapability

	// floorNone: no role floor. Any authenticated Account may call it. Only
	// legitimate for reads, whose floor is `viewer` — which is to say, the
	// floor every authenticated caller already clears.
	floorNone
)

func (f floorKind) String() string {
	switch f {
	case floorSurface:
		return "floorSurface"
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
	"POST /api/v1/enrollment-tokens":        floorSurface,
	"DELETE /api/v1/enrollment-tokens/{id}": floorSurface,
	"POST /api/v1/nodes/{node_id}/revoke":   floorSurface,
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

	// Identity management (#297): admin in full, gated per handler.
	"POST /api/v1/accounts":                floorSurface,
	"GET /api/v1/accounts":                 floorSurface,
	"GET /api/v1/accounts/{id}":            floorSurface,
	"POST /api/v1/accounts/{id}/role":      floorSurface,
	"POST /api/v1/accounts/{id}/enable":    floorSurface,
	"POST /api/v1/accounts/{id}/disable":   floorSurface,
	"POST /api/v1/accounts/{id}/tokens":    floorSurface,
	"GET /api/v1/accounts/{id}/tokens":     floorSurface,
	"DELETE /api/v1/api-tokens/{token_id}": floorSurface,

	// Execution (#356): operator for a typed Operation, admin for Raw Exec —
	// authz.RoleGate, reached through capability.Service.Run/Plan.
	"POST /api/v1/operations": floorCapability,
	"POST /api/v1/raw-exec":   floorCapability,

	// Jobs (#357). Reading a Job is a read (audited, ADR-0025); cancelling one
	// goes through the capability layer.
	"GET /api/v1/jobs/{id}":         floorNone,
	"POST /api/v1/jobs/{id}/cancel": floorCapability,

	// Approvals (#270, ADR-0027). Listing and reading a parked request is a
	// read; deciding one is floored by AuthorizeApprovalDecision at the SAME
	// role the request itself needed, inside the capability layer.
	"GET /api/v1/approvals":                floorNone,
	"GET /api/v1/approvals/{id}":           floorNone,
	"POST /api/v1/approvals/{id}/decision": floorCapability,

	// Approval grants (#378). Requesting one creates an ordinary approval
	// Request, so the floor is the gate's, in the capability layer.
	"POST /api/v1/approval-grants":             floorCapability,
	"GET /api/v1/approval-grants":              floorNone,
	"GET /api/v1/approval-grants/{id}":         floorNone,
	"POST /api/v1/approval-grants/{id}/revoke": floorCapability,
}

// surfaceGateFuncs are the identifiers that count as "this handler reaches a
// role check in this package". Both take the ResponseWriter and refuse the
// request themselves, so reaching one is reaching a decision.
var surfaceGateFuncs = map[string]bool{
	"requireAdmin":     true,
	"authorizeControl": true,
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
				"floorSurface if the handler must call requireAdmin/authorizeControl, "+
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

// TestSurfaceGatedRoutesReachARoleCheck is the mechanical half: for every
// route classified floorSurface, the handler's call graph within this package
// must reach requireAdmin or authorizeControl. Deleting the gate call from a
// handler fails here, which is exactly the regression #397 records.
func TestSurfaceGatedRoutesReachARoleCheck(t *testing.T) {
	funcs := packageFuncs(t)

	checked := 0
	for _, r := range Routes() {
		if routeFloors[r.Pattern()] != floorSurface {
			continue
		}
		checked++
		entry := handlerFuncName(t, r)
		if _, ok := funcs[entry]; !ok {
			t.Errorf("route %q: handler %q not found among this package's top-level functions", r.Pattern(), entry)
			continue
		}
		if !reachesGate(entry, funcs) {
			t.Errorf("route %q is classified floorSurface but its handler %q never reaches a role check "+
				"(%s) — a route that authenticates and then proceeds is #397 all over again",
				r.Pattern(), entry, strings.Join(sortedKeys(surfaceGateFuncs), " or "))
		}
	}

	// Non-vacuity: if a refactor made every route capability-floored, the loop
	// above would pass by checking nothing.
	if checked == 0 {
		t.Fatal("checked 0 surface-gated routes — the guard must actually inspect something")
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
	if i := strings.Index(name, "."); i >= 0 {
		name = name[:i] // drop a ".funcN" closure suffix
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

// reachesGate walks the call graph from entry, within this package, looking
// for one of surfaceGateFuncs. Identifiers inside nested closures count,
// because a closure's body is part of its enclosing declaration.
func reachesGate(entry string, funcs map[string]*ast.FuncDecl) bool {
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
			if surfaceGateFuncs[id.Name] {
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

// TestReachesGate_Fixtures proves the walker actually discriminates, rather
// than answering true for everything — the failure mode that would make the
// guard above decorative.
func TestReachesGate_Fixtures(t *testing.T) {
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
	_ = func() { authorizeControl() }
}`,
			entry: "handler", want: true,
		},
		{
			name: "gate reached one hop away",
			src: `package api
func handler() { helper() }
func helper() { requireAdmin() }`,
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
			if got := reachesGate(tc.entry, parse(tc.src)); got != tc.want {
				t.Errorf("reachesGate() = %v, want %v", got, tc.want)
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
