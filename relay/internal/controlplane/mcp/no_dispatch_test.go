package mcp

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

// capabilityImportPath and registryImportPath are the fully-qualified import
// paths this guard treats as "the capability layer" and "the registry",
// resolved by import PATH rather than by an assumed local package name — so
// an aliased import (e.g. `import c2 "…/internal/capability"`) cannot dodge
// the check.
const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capabilityReadAllowlist is the exhaustive set of capability-package
// identifiers this package may reference: pure, stateless Selector/Predicate
// parsing helpers with no path to a *capability.Service or dispatch.
// Everything else on the capability import — including capability.Service
// and the exported capability.New dispatch constructor — is a violation.
var capabilityReadAllowlist = map[string]bool{
	"ParseSelector":        true,
	"Selector":             true,
	"Predicate":            true,
	"Namespace":            true,
	"NamespaceUnspecified": true,
	"NamespaceNode":        true,
	"NamespaceRelay":       true,
}

// localImportAlias resolves the local identifier file uses to refer to
// importPath: the explicit alias if the import declaration has one,
// otherwise the conventional last path segment (Go's default when no alias
// is given). ok is false if file doesn't import importPath at all.
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

// dispatchViolations AST-inspects file (whose source came from fileName,
// used only in messages) and returns one message per rule it catches:
//
//   - capability.Service (or an alias's .Service): the execution layer's
//     entry point. A read tool must never hold one.
//   - capability.New (or an alias's .New): the exported dispatch
//     constructor. Holding its result is equivalent to holding a Service.
//   - any other selector on the capability import that isn't in
//     capabilityReadAllowlist: closes the gap where a future capability
//     export we haven't audited yet would silently be allowed through.
//   - the unexported newDispatch identifier: capability's internal
//     constructor, sealed to package capability by dispatch_construction_test.go
//     (a reference here wouldn't even compile, but this gives an explicit
//     failure message instead of an opaque compiler error).
//   - a type assertion (or type-switch case) to registry.Repository: the
//     runtime path back from a narrowed NodeReader to the full registry
//     interface (Upsert/SetRelayLabels/Delete/…), even though mcp.New's
//     adapters (mcp.go) make this fail at runtime today, this guard catches
//     the attempt at test time with a clear message.
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
			"%s: type-asserts to registry.Repository — this package must never recover the full registry write surface from a narrowed NodeReader (no-dispatch structural guarantee)",
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
			switch {
			case v.Sel.Name == "Service":
				violations = append(violations, fmt.Sprintf(
					"%s references capability.Service — mcp tools must stay read-only and never hold a capability.Service (no-dispatch structural guarantee)",
					fileName))
			case v.Sel.Name == "New":
				violations = append(violations, fmt.Sprintf(
					"%s references capability.New — the exported dispatch constructor must never be called from a read tool (no-dispatch structural guarantee)",
					fileName))
			case !capabilityReadAllowlist[v.Sel.Name]:
				violations = append(violations, fmt.Sprintf(
					"%s references capability.%s, which is not on the pure-read allow-list (%v) — audit it before allowing it here (no-dispatch structural guarantee)",
					fileName, v.Sel.Name, capabilityReadAllowlist))
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — mcp tools must never construct a dispatch (no-dispatch structural guarantee)",
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

// TestNoDispatchConstruction is the ROADMAP acceptance criterion for this
// issue ("no read tool can reach dispatch"): AST-parse every non-test .go
// file in this package and fail on any dispatchViolations (see its doc
// comment for the exact rules).
//
// This mirrors capability/dispatch_construction_test.go's own AST guard and
// jobs.TestNoDatabaseSQLImport's parse-and-inspect style. The structural
// guarantee it defends is the read-only interfaces in mcp.go (NodeReader /
// PolicyReader / OperationLister — Get/List/Operations only, never Run) and
// their runtime narrowing via nodeReaderAdapter/policyReaderAdapter/
// operationListerAdapter in New (mcp.go): this package holds no
// *capability.Service, cannot call newDispatch or capability.New, and cannot
// recover registry.Repository from a NodeReader. This test is defense in
// depth that catches the mistake at `go test` time with an explicit message,
// rather than an opaque compiler error or runtime panic.
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
	}
}

// TestDispatchViolations_Fixtures runs dispatchViolations against small,
// synthetic source snippets rather than this package's real files, proving
// each rule actually fires (and that legitimate read-only usage doesn't).
// Each subtest is a negative fixture: source that TestNoDispatchConstruction
// would reject if it ever appeared in this package for real.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`

	cases := []struct {
		name       string
		src        string
		wantSubstr string // substring expected in one of the returned violations
	}{
		{
			name: "literal capability.Service selector",
			src: `package mcp
import capability ` + capImport + `
var _ = capability.Service{}
`,
			wantSubstr: "capability.Service",
		},
		{
			name: "aliased capability import dodging the literal package name",
			src: `package mcp
import c2 ` + capImport + `
var _ = c2.Service{}
`,
			wantSubstr: "capability.Service",
		},
		{
			name: "exported capability.New dispatch constructor, default import name",
			src: `package mcp
import ` + capImport + `
func f() { capability.New(nil) }
`,
			wantSubstr: "capability.New",
		},
		{
			name: "exported capability.New via an alias",
			src: `package mcp
import cap ` + capImport + `
func f() { cap.New(nil) }
`,
			wantSubstr: "capability.New",
		},
		{
			name: "capability selector not on the pure-read allow-list",
			src: `package mcp
import ` + capImport + `
var _ = capability.NewBlastCap(0, 0)
`,
			wantSubstr: "not on the pure-read allow-list",
		},
		{
			name: "unexported newDispatch identifier (would also fail to compile outside package capability)",
			src: `package mcp
func f() { newDispatch() }
`,
			wantSubstr: "newDispatch",
		},
		{
			name: "type assertion recovering registry.Repository from a narrowed NodeReader",
			src: `package mcp
import ` + regImport + `
func f(nodes NodeReader) {
	_ = nodes.(registry.Repository)
}
`,
			wantSubstr: "registry.Repository",
		},
		{
			name: "type-switch case recovering registry.Repository",
			src: `package mcp
import ` + regImport + `
func f(nodes NodeReader) {
	switch nodes.(type) {
	case registry.Repository:
	}
}
`,
			wantSubstr: "registry.Repository",
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

// TestDispatchViolations_AllowsReadHelpers proves the allow-list itself
// isn't so strict it would flag this package's actual, legitimate use of
// capability.ParseSelector (tools_nodes.go) — a false positive here would be
// as bad as a false negative on the fixtures above.
func TestDispatchViolations_AllowsReadHelpers(t *testing.T) {
	const src = `package mcp
import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"

func f(s string) {
	sel, _ := capability.ParseSelector(s)
	var p capability.Predicate
	p.Namespace = capability.NamespaceNode
	_ = sel
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v", err)
	}

	if violations := dispatchViolations("fixture.go", file); len(violations) != 0 {
		t.Fatalf("dispatchViolations() = %v, want none (this is legitimate pure-read Selector usage)", violations)
	}
}
