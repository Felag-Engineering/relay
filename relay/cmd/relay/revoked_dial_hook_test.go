package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestControlSurfaces_TestOnlyRevokedDialClockIsNilInProduction pins that the
// revoked-dial recorder's clock seam is a test-only hook: the production entry
// point leaves it nil, and no production file sets it.
func TestControlSurfaces_TestOnlyRevokedDialClockIsNilInProduction(t *testing.T) {
	t.Run("runtime: nil on the production entry point", func(t *testing.T) {
		cfg := baseTestConfig(t)
		_, deps, err := newServer(cfg, testStartupFiles(t, cfg))
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		t.Cleanup(func() { deps.store.Close() })

		if deps.hooks.testRevokedDialClock != nil {
			t.Error("newServer populated serverHooks.testRevokedDialClock; the production entry point must leave test-only hooks unset")
		}
	})

	t.Run("static: no production file sets the hook", func(t *testing.T) {
		assertNoProductionFileSetsHook(t, "testRevokedDialClock")
	})
}

// TestControlSurfaces_TestOnlyConnectionClockIsNilInProduction is the same pin
// for the Node connection recorder's clock.
func TestControlSurfaces_TestOnlyConnectionClockIsNilInProduction(t *testing.T) {
	t.Run("runtime: nil on the production entry point", func(t *testing.T) {
		cfg := baseTestConfig(t)
		_, deps, err := newServer(cfg, testStartupFiles(t, cfg))
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		t.Cleanup(func() { deps.store.Close() })

		if deps.hooks.testConnectionClock != nil {
			t.Error("newServer populated serverHooks.testConnectionClock; the production entry point must leave test-only hooks unset")
		}
	})

	t.Run("static: no production file sets the hook", func(t *testing.T) {
		assertNoProductionFileSetsHook(t, "testConnectionClock")
	})
}

// assertNoProductionFileSetsHook fails for every non-test file in this package
// that assigns the serverHooks field, directly or in a literal.
func assertNoProductionFileSetsHook(t *testing.T, field string) {
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
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == field {
						t.Errorf("%s assigns %s; only a test may set it", name, field)
					}
				}
			case *ast.KeyValueExpr:
				if id, ok := v.Key.(*ast.Ident); ok && id.Name == field {
					t.Errorf("%s sets %s in a literal; only a test may set it", name, field)
				}
			}
			return true
		})
	}
}
