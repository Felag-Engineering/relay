package nodevocab

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

// TestNodeVocabImportsStayNarrow is the boundary guard that earns this
// package its place on package capability's import allowlist (#680),
// modelled on accounts.TestAccountsImportsStayNarrow and
// capability.TestCapabilityImportsOnlyRegistryAndJobs.
//
// capability's own guard exists to keep the wire proto and raw SQL out of the
// capability layer. Admitting internal/nodevocab to that allowlist would be
// pointless if nodevocab could itself import either one — capability would
// reach them transitively and the guard would be enforcing a boundary that no
// longer exists. The allowlist entry for this package is guarded by its own
// import test so widening does not create a transitive back door into the
// wire types.
func TestNodeVocabImportsStayNarrow(t *testing.T) {
	allowed := map[string]bool{
		"sync": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1": true,
		"database/sql": true,
	}

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
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if forbidden[path] {
				t.Errorf("%s imports %q — package nodevocab must stay free of the wire proto and raw SQL, "+
					"or capability's own import guard becomes meaningless", name, path)
			}
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not in the nodevocab package's import allowlist", name, path)
			}
		}
	}

	// Non-vacuity: if this package were ever emptied down to a single
	// _test.go file, the loop above would pass by checking nothing.
	if checked == 0 {
		t.Fatal("checked 0 non-test .go files — the guard must actually inspect something")
	}
}
