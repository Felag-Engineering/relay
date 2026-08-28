package approval

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

// TestApprovalImportsStayNarrow is the boundary guard that earns this package
// its place on the capability layer's import allowlist (#269, ADR-0027).
//
// capability's own guard (TestCapabilityImportsOnlyRegistryAndJobs) exists to
// keep the wire proto and raw SQL out of the capability layer. Admitting
// internal/approval to that allowlist would be pointless if approval could
// itself import either one — capability would reach them transitively and the
// guard would be enforcing a boundary that no longer exists.
//
// So this package accepts the same discipline as internal/jobs: a small stdlib
// allowlist plus internal/jobs, and never relayv1 or database/sql. The SQLite
// implementation of Repository lives in internal/store, which is what keeps a
// later Postgres swap a single-package change.
func TestApprovalImportsStayNarrow(t *testing.T) {
	allowed := map[string]bool{
		"bytes":         true,
		"context":       true,
		"crypto/sha256": true,
		"encoding/hex":  true,
		"encoding/json": true,
		"errors":        true,
		"fmt":           true,
		"io":            true,
		"io/fs":         true,
		"os":            true,
		"sort":          true,
		"strings":       true,
		"syscall":       true,
		"time":          true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs": true,
		// internal/opvocab joined with #415, on exactly the terms jobs is
		// admitted: it imports only fmt, sort, strings and internal/jobs, has
		// no proto and no database/sql, so admitting it opens no transitive
		// back door into the wire types. It is admitted precisely so
		// shape-vs-scale (opvocab.ArgClass) has exactly ONE declaration site —
		// a copy of that table in this package is a copy that can disagree with
		// the Operation vocabulary it describes.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1": true,
		"database/sql": true,
		// capability imports this package; importing it back would be an
		// import cycle, but naming it here makes the direction a stated rule
		// rather than something the compiler happens to catch.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability": true,
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
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
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
				t.Errorf("%s imports %q — package approval must stay free of the wire proto and raw SQL, "+
					"or capability's own import guard becomes meaningless", name, path)
			}
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not in the approval package's import allowlist", name, path)
			}
		}
	}
}
