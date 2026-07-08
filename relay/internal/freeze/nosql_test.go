package freeze

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoDatabaseSQLImport is a compile-boundary guard: internal/freeze must
// never import database/sql. Keeping this package SQL-free is what makes
// internal/store's SQLite implementation (and any future Postgres swap) a
// single-package change, rather than a change to every caller of Repository.
func TestNoDatabaseSQLImport(t *testing.T) {
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
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, imp := range file.Imports {
			if imp.Path.Value == `"database/sql"` {
				t.Errorf("%s imports database/sql — this package must stay SQL-free (internal/store owns all SQL)", e.Name())
			}
		}
	}
}
