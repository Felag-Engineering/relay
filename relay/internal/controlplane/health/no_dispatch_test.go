package health

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// allowedImports is the closed set the health route may import. Anything else
// could reach a capability method, the store or a Node from a route that
// answers without a credential.
var allowedImports = map[string]bool{
	"net/http":    true,
	"sync/atomic": true,
}

// disallowedImports returns every import path in src that is not allowed.
func disallowedImports(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var bad []string
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s: %v", imp.Path.Value, err)
		}
		if !allowedImports[path] {
			bad = append(bad, path)
		}
	}
	return bad
}

func TestNoDispatch_HealthImportsOnlyTheStandardLibrary(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	inspected := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		inspected++
		for _, path := range disallowedImports(t, filepath.Join(dir, name), nil) {
			t.Errorf("%s imports %q: the unauthenticated health route reaches no capability method, store or Node (invariant 10)", name, path)
		}
	}
	if inspected == 0 {
		t.Fatal("inspected zero non-test .go files: the guard would silently check nothing")
	}

	t.Run("negative control sees a capability import", func(t *testing.T) {
		src := "package health\n\nimport \"github.com/Felag-Engineering/relay/relay/internal/capability\"\n"
		if bad := disallowedImports(t, "snippet.go", src); len(bad) != 1 {
			t.Fatalf("guard reported %v for a capability import, want exactly one violation", bad)
		}
	})
}
