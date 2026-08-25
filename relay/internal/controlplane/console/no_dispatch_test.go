package console

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// no_dispatch_test.go is the Console's structural half of invariant 10,
// mirroring api/no_dispatch_test.go and mcp/no_dispatch_test.go.
//
// ADR-0026 decision 1 requires it in those words: "The `no_dispatch`-style
// structural guard extends to the Console package: a Console file that holds a
// `*capability.Service`, calls `capability.New`, or reaches capability's
// internal dispatch fails to compile the test suite. The guard is extended,
// never dropped — a new execution surface is exactly when the temptation to
// shortcut appears."
//
// The guard exists at package creation rather than arriving with the composer
// (issue #438). Adding it later would mean the window in which the shortcut is
// cheapest is the window in which nothing is watching, and a guard that arrives
// after the code it guards has only ever proved that the code passing it today
// passes it today.
//
// Like the Control API's guard and unlike the MCP surface's, there is no
// read/exec partition: every file here legitimately handles
// capability.Principal, since that is how a page attributes what it renders.

const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// localImportAlias resolves the local identifier file uses for importPath: the
// explicit alias when the import has one, otherwise the last path segment.
// Resolving by import PATH rather than an assumed package name is what stops an
// aliased import (`import c2 ".../capability"`) from dodging the check.
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

// dispatchViolations AST-inspects file and returns one message per rule caught.
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
			"%s: type-asserts to registry.Repository — the Console must never recover the full registry write surface from a narrowed reader (no-dispatch structural guarantee)",
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
							"%s references capability.Service — Console handlers must never hold a capability.Service directly, only an injected interface (no-dispatch structural guarantee, ADR-0026 decision 1)",
							fileName))
					case "New":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.New — the exported dispatch constructor must never be called from a Console file (no-dispatch structural guarantee, ADR-0026 decision 1)",
							fileName))
					}
				}
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — the Console must never construct a dispatch (no-dispatch structural guarantee, ADR-0026 decision 1)",
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

func TestConsole_NoDispatchOutsideCapabilityLayer(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, v := range dispatchViolations(name, file) {
			t.Error(v)
		}
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package.
	if checked == 0 {
		t.Fatal("no_dispatch guard inspected zero files — the guard is not running")
	}
}
