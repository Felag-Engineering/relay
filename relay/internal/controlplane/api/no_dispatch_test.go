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
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, capImported := localImportAlias(file, capabilityImportPath)
	regAlias, regImported := localImportAlias(file, registryImportPath)

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
			if !capImported {
				break
			}
			pkg, ok := v.X.(*ast.Ident)
			if !ok || pkg.Name != capAlias {
				break
			}
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
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — Control API routes must never construct a dispatch (no-dispatch structural guarantee)",
					fileName))
			}
		case *ast.TypeAssertExpr:
			checkRepositoryAssertion(v.Type)
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

// TestDispatchViolations_Fixtures runs dispatchViolations against synthetic
// snippets rather than this package's real files, proving each rule actually
// fires — and that the legitimate capability usage these routes depend on does
// not.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`

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
