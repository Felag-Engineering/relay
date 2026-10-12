package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest/astguard"
)

// no_dispatch_test.go is the Control API's structural half of invariant 10,
// added with the execution routes (#356) and mirroring
// mcp/no_dispatch_test.go: the ONLY path from a route to a dispatch is the
// injected Executor interface (execution.go). A file here that held a
// *capability.Service, called the exported capability.New constructor, or
// reached capability's internal newDispatch would be a second control path —
// the thing ADR-0009/0010 exist to prevent — so it fails this guard with an
// explicit message rather than passing review unnoticed.
//
// Unlike mcp's guard there is no read/exec partition. mcp needs one because
// its read tools must never name a capability identifier at all; every file in
// package api legitimately handles capability.Principal (it is how every route
// attributes its action), so the strict pure-read allowlist would be pure
// false positives here. The rules below are exactly mcp's UNCONDITIONAL ones,
// applied flat to every non-test file — which also means a new source file is
// covered automatically, with no classification map to forget to update.

const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
)

// bannedCapabilityServices maps every capability service type, and its
// constructor, to the narrowed seam an api file must use instead. They are
// banned by EXACT name beside capability.Service and capability.New: a prefix
// match would falsely flag unrelated identifiers such as
// capability.ControlAction and capability.AccountAdminEvent, which routes
// legitimately use.
var bannedCapabilityServices = map[string]string{
	"Recorder":        "the Recorder belongs to the composition root alone",
	"NewRecorder":     "the Recorder belongs to the composition root alone",
	"Control":         "use the Freezer interface",
	"NewControl":      "use the Freezer interface",
	"AccountAdmin":    "use the AccountAdmin interface",
	"NewAccountAdmin": "use the AccountAdmin interface",
	"ReadLane":        "use the NodeReader interface",
	"NewReadLane":     "use the NodeReader interface",
}

// dispatchViolations AST-inspects file (fileName is used only in messages) and
// returns one message per rule it catches:
//
//   - capability.Service (or an alias's .Service): the execution layer's entry
//     point. No api file may hold one directly — routes reach dispatch only
//     through the injected Executor.
//   - capability.New (or an alias's .New): the exported dispatch constructor;
//     holding its result is equivalent to holding a Service.
//   - the other capability services and their constructors
//     (bannedCapabilityServices): Control, AccountAdmin, ReadLane and
//     Recorder, by exact name. Each route holds the narrow interface it uses,
//     never the concrete service.
//   - the unexported newDispatch identifier: capability's internal constructor,
//     sealed to package capability. A reference here would not compile, but the
//     guard gives an explicit message instead of an opaque compiler error.
//   - a type assertion (or type-switch case) to registry.Repository: the
//     runtime path from a narrowed reader back to the full registry write
//     surface (Upsert/SetRelayLabels/Delete/...).
//   - G1 (#680): naming policyview.Cache, policyview.New, nodevocab.Cache or
//     nodevocab.New. Package api does not import either package today and
//     must not start — those are the types that carry Set (invariant 2,
//     ADR-0002).
//   - G2 (#680), same formulation as mcp's and the Console's: an interface
//     method declared in a non-test file whose RESULTS name registry.Node,
//     policyview.Snapshot or nodevocab.Snapshot and whose PARAMETERS contain
//     no context.Context — a read no lane could have recorded or
//     attributed (invariant 10, ADR-0025).
//   - a dot-import of capability, registry, policyview or nodevocab
//     (security review, cycle 2): it erases the package qualifier every
//     rule above matches on, so it is refused outright.
//
// This guard is flat by design — no read/exec partition, because every file
// in package api legitimately handles capability.Principal (see the file
// header) — so both new rules are unconditional, alongside the
// capability.Service/capability.New/newDispatch ones, and a new source file
// is covered automatically.
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, capImported := astguard.LocalImportAlias(file, capabilityImportPath)
	regAlias, regImported := astguard.LocalImportAlias(file, registryImportPath)
	pvAlias, pvImported := astguard.LocalImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := astguard.LocalImportAlias(file, nodevocabImportPath)

	// A dot-import of any of these four erases the package qualifier every
	// check in this function matches on: `import . ".../registry"` turns
	// `registry.Repository` into a bare `Repository` this guard cannot see,
	// and the same holds for capability/policyview/nodevocab. There is no
	// legitimate reason for one here, so it is a violation on its own.
	// Mirrors console/no_dispatch_test.go's identical rule (security review,
	// cycle 2).
	for _, banned := range []struct{ alias, pkg string }{
		{capAlias, "capability"}, {regAlias, "registry"}, {pvAlias, "policyview"}, {nvAlias, "nodevocab"},
	} {
		if banned.alias == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s — that erases the package qualifier this guard matches on, so "+
					"every check below silently stops working", fileName, banned.pkg))
		}
	}

	checkRepositoryAssertion := func(expr ast.Expr) {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !regImported || pkg.Name != regAlias || sel.Sel.Name != "Repository" {
			return
		}
		violations = append(violations, fmt.Sprintf(
			"%s: type-asserts to registry.Repository — the Control API must never recover the full registry write surface from a narrowed reader (no-dispatch structural guarantee)",
			fileName))
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if capImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == capAlias {
					switch v.Sel.Name {
					case "Service":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.Service — Control API routes must never hold a capability.Service directly, only the injected Executor interface (no-dispatch structural guarantee)",
							fileName))
					case "New":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.New — the exported dispatch constructor must never be called from a Control API route file (no-dispatch structural guarantee)",
							fileName))
					default:
						if advice := bannedCapabilityServices[v.Sel.Name]; advice != "" {
							violations = append(violations, fmt.Sprintf(
								"%s references capability.%s — a concrete capability service or its constructor; %s (no-dispatch structural guarantee)",
								fileName, v.Sel.Name, advice))
						}
					}
				}
			}
			if pvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == pvAlias && (v.Sel.Name == "Cache" || v.Sel.Name == "New") {
					violations = append(violations, fmt.Sprintf(
						"%s references policyview.%s — the Control API must never hold or construct a *policyview.Cache: Cache carries Set (ADR-0002, invariant 2; ADR-0011, invariant 12)",
						fileName, v.Sel.Name))
				}
			}
			if nvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == nvAlias && (v.Sel.Name == "Cache" || v.Sel.Name == "New") {
					violations = append(violations, fmt.Sprintf(
						"%s references nodevocab.%s — the Control API must never hold or construct a *nodevocab.Cache: Cache carries Set (ADR-0002, invariant 2; ADR-0011, invariant 12)",
						fileName, v.Sel.Name))
				}
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — Control API routes must never construct a dispatch (no-dispatch structural guarantee)",
					fileName))
			}
		case *ast.TypeAssertExpr:
			checkRepositoryAssertion(v.Type)
		case *ast.InterfaceType:
			violations = append(violations, astguard.SeamHandsBackUnauditedRead(fileName, v, file)...)
		case *ast.CaseClause:
			for _, expr := range v.List {
				checkRepositoryAssertion(expr)
			}
		}
		return true
	})

	return violations
}

// TestNoDispatchConstruction is #356's acceptance criterion ("a route that
// attempts to dispatch outside the capability layer does not compile"): every
// non-test .go file in this package is AST-parsed and checked. It is defense in
// depth over the interface boundary — Deps.Exec is an Executor, so the compiler
// already refuses a Service today — catching a future widening at `go test`
// time with a message that names the rule.
func TestNoDispatchConstruction(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, msg := range dispatchViolations(name, file) {
			t.Error(msg)
		}
		checked++
	}

	// Non-vacuity: if a refactor ever moved every route out of this directory,
	// the loop above would pass by checking nothing at all.
	if checked == 0 {
		t.Fatal("checked 0 files — the guard must actually inspect this package's sources")
	}
}

// TestDispatchViolations_BansConcreteCapabilityServices proves every capability
// service type and constructor is refused by exact name, and that similarly
// named identifiers routes legitimately use are not. The list is spelled out
// here rather than read from the map, so deleting a name from the map cannot
// delete its row.
func TestDispatchViolations_BansConcreteCapabilityServices(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	check := func(t *testing.T, src string) []string {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		return dispatchViolations("fixture.go", file)
	}
	mustContain := func(t *testing.T, violations []string, want string) {
		t.Helper()
		for _, v := range violations {
			if strings.Contains(v, want) {
				return
			}
		}
		t.Fatalf("dispatchViolations() = %v, want one containing %q", violations, want)
	}

	for _, name := range []string{
		"Recorder", "NewRecorder", "Control", "NewControl",
		"AccountAdmin", "NewAccountAdmin", "ReadLane", "NewReadLane",
	} {
		t.Run(name, func(t *testing.T) {
			src := "package api\nimport " + capImport + "\nvar _ = capability." + name + "\n"
			mustContain(t, check(t, src), "capability."+name+" — a concrete capability service")
		})
	}

	t.Run("an aliased import cannot dodge the ban", func(t *testing.T) {
		src := "package api\nimport c2 " + capImport + "\nvar _ *c2.ReadLane\n"
		mustContain(t, check(t, src), "capability.ReadLane — a concrete capability service")
	})

	t.Run("exact match leaves similarly-named identifiers alone", func(t *testing.T) {
		src := "package api\nimport " + capImport + `
var _ capability.ControlAction
var _ = capability.ControlFreezeEngage
var _ capability.AccountAdminEvent
var _ capability.IntentRecorder
`
		if violations := check(t, src); len(violations) != 0 {
			t.Fatalf("dispatchViolations() = %v, want none — the ban is by exact name, not prefix", violations)
		}
	})
}

// TestDispatchViolations_Fixtures runs dispatchViolations against synthetic
// snippets rather than this package's real files, proving each rule actually
// fires — and that the legitimate capability usage these routes depend on does
// not.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"`

	cases := []struct {
		name       string
		src        string
		wantSubstr string // "" = expect NO violations
	}{
		{
			name: "capability.Service held directly",
			src: `package api
import capability ` + capImport + `
var _ = capability.Service{}
`,
			wantSubstr: "capability.Service",
		},
		{
			name: "aliased capability import dodging the literal package name",
			src: `package api
import c2 ` + capImport + `
var _ = c2.Service{}
`,
			wantSubstr: "capability.Service",
		},
		{
			name: "exported capability.New dispatch constructor",
			src: `package api
import ` + capImport + `
func f() { capability.New(nil) }
`,
			wantSubstr: "capability.New",
		},
		{
			name: "exported capability.New via an alias",
			src: `package api
import cap ` + capImport + `
func f() { cap.New(nil) }
`,
			wantSubstr: "capability.New",
		},
		{
			name: "unexported newDispatch identifier",
			src: `package api
func f() { newDispatch() }
`,
			wantSubstr: "newDispatch",
		},
		{
			name: "type assertion recovering registry.Repository",
			src: `package api
import ` + regImport + `
func f(nodes any) { _ = nodes.(registry.Repository) }
`,
			wantSubstr: "registry.Repository",
		},
		{
			name: "type-switch case recovering registry.Repository",
			src: `package api
import ` + regImport + `
func f(nodes any) {
	switch nodes.(type) {
	case registry.Repository:
	}
}
`,
			wantSubstr: "registry.Repository",
		},
		{
			// The false-positive guard: this is exactly what execution.go does.
			name: "legitimate execution-route capability usage produces nothing",
			src: `package api
import ` + capImport + `
func f(p capability.Principal, s string) (capability.PlanResult, []capability.NodeResult, error) {
	sel, _ := capability.ParseSelector(s)
	_ = sel
	var fe *capability.FrozenError
	var ce *capability.CapExceededError
	_, _ = fe, ce
	return capability.PlanResult{}, nil, nil
}
`,
			wantSubstr: "",
		},
		{
			name: "constructing a policyview cache",
			src: `package api
import ` + pvImport + `
var _ = policyview.New()
`,
			wantSubstr: "policyview.New",
		},
		{
			name: "type assertion recovering the policyview cache",
			src: `package api
import ` + pvImport + `
func f(p any) { _ = p.(*policyview.Cache) }
`,
			wantSubstr: "policyview.Cache",
		},
		{
			name: "constructing a nodevocab cache",
			src: `package api
import ` + nvImport + `
var _ = nodevocab.New()
`,
			wantSubstr: "nodevocab.New",
		},
		{
			name: "type assertion recovering the nodevocab cache",
			src: `package api
import ` + nvImport + `
func f(v any) { _ = v.(*nodevocab.Cache) }
`,
			wantSubstr: "nodevocab.Cache",
		},
		{
			name: "the deleted Get-by-id NodeReader shape hands back a Node with no context",
			src: `package api
import ` + regImport + `
type NodeReader interface {
	Get(nodeID string) (registry.Node, bool)
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			name: "an interface method returning registry.Node WITH a context does not violate",
			src: `package api
import (
	"context"
	` + regImport + `
)
type NodeReader interface {
	Get(ctx context.Context, nodeID string) (registry.Node, bool)
}
`,
			wantSubstr: "",
		},
		{
			// LOW 3 (security review, cycle 2): a map result is one of the two
			// shapes namesBannedType did not walk before this guard was
			// hardened.
			name: "a seam handing back a map of registry.Node with no context",
			src: `package api
import ` + regImport + `
type NodeReader interface {
	ByID() map[string]registry.Node
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The other shape: a channel result.
			name: "a seam handing back a channel of nodevocab.Snapshot with no context",
			src: `package api
import ` + nvImport + `
type VocabReader interface {
	Stream() <-chan nodevocab.Snapshot
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The dot-import evasion (security review, cycle 2): erasing the
			// registry qualifier would otherwise let a map/chan/slice of Node
			// slip past namesBannedType silently.
			name: "dot-importing registry erases the qualifier G2 matches on",
			src: `package api
import . ` + regImport + `
`,
			wantSubstr: "dot-imports registry",
		},
		{
			name: "dot-importing policyview erases the qualifier G2 matches on",
			src: `package api
import . ` + pvImport + `
`,
			wantSubstr: "dot-imports policyview",
		},
		{
			name: "dot-importing nodevocab erases the qualifier G2 matches on",
			src: `package api
import . ` + nvImport + `
`,
			wantSubstr: "dot-imports nodevocab",
		},
		{
			name: "dot-importing capability erases the qualifier this guard matches on",
			src: `package api
import . ` + capImport + `
`,
			wantSubstr: "dot-imports capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile: %v", err)
			}

			violations := dispatchViolations("fixture.go", file)

			if tc.wantSubstr == "" {
				if len(violations) != 0 {
					t.Fatalf("dispatchViolations() = %v, want none (this is legitimate execution-route usage)", violations)
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("dispatchViolations() = empty, want a violation containing %q", tc.wantSubstr)
			}
			for _, v := range violations {
				if strings.Contains(v, tc.wantSubstr) {
					return
				}
			}
			t.Fatalf("dispatchViolations() = %v, want one containing %q", violations, tc.wantSubstr)
		})
	}
}

// TestNoAdapterSetsARiskClass is the structural half of invariant 13 for this
// surface (ADR-0012, ADR-0042, #878): no adapter sets an Action's risk class.
// The capability layer derives it and refuses an Action that arrives with one;
// this guard (astguard.RiskClassViolations) makes the attempt fail go test.
// What this surface may do beyond comparing a class is the allowlist below, by
// file and function, each with its reason; an entry that no longer names a
// class constant fails the test so the list cannot quietly widen.
func TestNoAdapterSetsARiskClass(t *testing.T) {
	allowed := map[string]map[string]string{
		"approval_grants.go": {
			"parseRiskClass": "maps an operator's grant-scope risk_class wire name onto approval.GrantScope's match criterion (ADR-0027); it builds no Action, and the capability layer validates the scope",
		},
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	usesConstant := map[string]map[string]bool{} // file -> function -> names a class constant
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		checked++
		for _, msg := range astguard.RiskClassViolations(name, file, allowed[name]) {
			t.Error(msg)
		}
		usesConstant[name] = map[string]bool{}
		for _, fn := range astguard.RiskClassConstantFuncs(file) {
			usesConstant[name][fn] = true
		}
	}
	if checked == 0 {
		t.Fatal("no non-test .go files checked: the guard is vacuous")
	}
	for file, funcs := range allowed {
		for fn, reason := range funcs {
			if reason == "" {
				t.Errorf("allowlist entry %s %s has no reason", file, fn)
			}
			if !usesConstant[file][fn] {
				t.Errorf("allowlist entry %s %s no longer names a risk class constant outside a comparison; remove it", file, fn)
			}
		}
	}
}
