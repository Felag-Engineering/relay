package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
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
	contextImportPath    = "context"
)

// localImportAlias resolves the local identifier file uses for importPath: the
// explicit alias when the import has one, otherwise the last path segment
// (Go's default). Resolving by import PATH rather than an assumed package name
// is what stops an aliased import (`import c2 ".../capability"`) from dodging
// the check. ok is false when file does not import importPath at all.
func localImportAlias(file *ast.File, importPath string) (alias string, ok bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return path[strings.LastIndex(path, "/")+1:], true
	}
	return "", false
}

// dispatchViolations AST-inspects file (fileName is used only in messages) and
// returns one message per rule it catches:
//
//   - capability.Service (or an alias's .Service): the execution layer's entry
//     point. No api file may hold one directly — routes reach dispatch only
//     through the injected Executor.
//   - capability.New (or an alias's .New): the exported dispatch constructor;
//     holding its result is equivalent to holding a Service.
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

	capAlias, capImported := localImportAlias(file, capabilityImportPath)
	regAlias, regImported := localImportAlias(file, registryImportPath)
	pvAlias, pvImported := localImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := localImportAlias(file, nodevocabImportPath)

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
			violations = append(violations, seamHandsBackUnauditedRead(fileName, v, file)...)
		case *ast.CaseClause:
			for _, expr := range v.List {
				checkRepositoryAssertion(expr)
			}
		}
		return true
	})

	return violations
}

// seamHandsBackUnauditedRead is G2: an interface method declared in a
// non-test file whose RESULTS name registry.Node, policyview.Snapshot or
// nodevocab.Snapshot (bare, pointer, or slice) and whose PARAMETERS contain
// no context.Context is a violation — it declares a seam that hands back a
// Node or a display-only snapshot with no context, which is a read no lane
// could have recorded or attributed (invariant 10, ADR-0025). Phrased as a
// property, not a type denylist: it fires on the deleted Get-by-id
// NodeReader shape and does not fire on the lane-shaped one, whose
// DescribeNode takes a context.Context. Mirrors mcp/no_dispatch_test.go's
// and console/no_dispatch_test.go's identically-formulated rule.
//
// This closes the obvious door, not every door (security review, cycle 2):
// MapType/ChanType below catch a map or channel of one of the three banned
// types, but a local type alias for one of them, a generic type parameter
// shaped like one, or an anonymous struct embedding one would not be. The
// real bar is the composition-root guard
// (TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache,
// cmd/relay/control_surfaces_test.go) plus no surface being handed a
// registry or cache at all.
func seamHandsBackUnauditedRead(fileName string, iface *ast.InterfaceType, file *ast.File) []string {
	if iface.Methods == nil {
		return nil
	}
	regAlias, regImported := localImportAlias(file, registryImportPath)
	pvAlias, pvImported := localImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := localImportAlias(file, nodevocabImportPath)
	ctxAlias, ctxImported := localImportAlias(file, contextImportPath)

	var namesBannedType func(expr ast.Expr) bool
	namesBannedType = func(expr ast.Expr) bool {
		switch t := expr.(type) {
		case *ast.StarExpr:
			return namesBannedType(t.X)
		case *ast.ArrayType:
			return namesBannedType(t.Elt)
		case *ast.MapType:
			return namesBannedType(t.Key) || namesBannedType(t.Value)
		case *ast.ChanType:
			return namesBannedType(t.Value)
		case *ast.SelectorExpr:
			pkg, ok := t.X.(*ast.Ident)
			if !ok {
				return false
			}
			switch {
			case regImported && pkg.Name == regAlias && t.Sel.Name == "Node":
				return true
			case pvImported && pkg.Name == pvAlias && t.Sel.Name == "Snapshot":
				return true
			case nvImported && pkg.Name == nvAlias && t.Sel.Name == "Snapshot":
				return true
			}
		}
		return false
	}

	hasContextParam := func(ft *ast.FuncType) bool {
		if !ctxImported || ft.Params == nil {
			return false
		}
		for _, p := range ft.Params.List {
			sel, ok := p.Type.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == ctxAlias && sel.Sel.Name == "Context" {
				return true
			}
		}
		return false
	}

	var violations []string
	for _, m := range iface.Methods.List {
		ft, ok := m.Type.(*ast.FuncType)
		if !ok || ft.Results == nil {
			continue
		}
		bannedResult := false
		for _, r := range ft.Results.List {
			if namesBannedType(r.Type) {
				bannedResult = true
				break
			}
		}
		if !bannedResult || hasContextParam(ft) {
			continue
		}
		methodName := "<unnamed>"
		if len(m.Names) > 0 {
			methodName = m.Names[0].Name
		}
		violations = append(violations, fmt.Sprintf(
			"%s: interface method %s declares a seam that hands back a Node or a display-only snapshot with no context — a read no lane could have recorded or attributed (invariant 10, ADR-0025); read through the capability read lane",
			fileName, methodName))
	}
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
