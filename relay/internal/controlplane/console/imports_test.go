package console

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// imports_test.go is the structural half of issue #441's acceptance line 19
// ("the Console package never imports store"), in the same AST-guard shape
// as no_dispatch_test.go: no non-test file in package console may import
// internal/store or database/sql. Invariant 10 says there is ONE capability
// layer and three thin surfaces — a Console file that reached the store
// directly would be a second control path around the seams in seams.go, no
// matter how the query itself were written.
const (
	storeImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
	sqlImportPath   = "database/sql"
)

func TestConsole_NeverImportsStore(t *testing.T) {
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
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		checked++
		for _, imp := range file.Imports {
			path, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, unquoteErr)
			}
			if path == storeImportPath || path == sqlImportPath {
				t.Errorf("%s imports %q — the Console must never hold a path to the store (invariant 10); "+
					"read through the capability layer's seams (seams.go) instead", name, path)
			}
		}
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package.
	if checked == 0 {
		t.Fatal("imports guard inspected zero files — the guard is not running")
	}
}
