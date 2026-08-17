package mcptask

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

// TestMCPTaskImportsStayNarrow keeps this package a domain package, on the same
// terms as internal/jobs and internal/approval.
//
// Two boundaries matter here, and they point in different directions.
//
// Downward: no database/sql. The SQLite implementation lives in internal/store,
// which is what keeps a later Postgres swap a single-package change.
//
// Upward, and this is the one specific to ADR-0028: **no MCP SDK, and no wire
// types.** The whole argument for shimming SEP-2663 rather than forking the
// go-sdk is that the shim is a bounded, deletable piece of our own code with a
// written removal condition. If the SDK's types leaked down into the domain,
// deleting the shim when go-sdk#626 lands would stop being a deletion and start
// being a refactor of everything that touched a handle — which is precisely how
// a temporary shim becomes a permanent one.
func TestMCPTaskImportsStayNarrow(t *testing.T) {
	allowed := map[string]bool{
		"context": true,
		"errors":  true,
		"fmt":     true,
		"strings": true,
		"time":    true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval": true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs":     true,
	}
	forbidden := map[string]string{
		"database/sql": "the SQLite implementation belongs in internal/store",
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1":   "a task handle is not a wire type",
		"github.com/modelcontextprotocol/go-sdk/mcp":                            "ADR-0028: the SDK stays above this package, or the shim stops being deletable",
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability": "capability imports this package; the dependency runs one way",
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
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q — %s", name, path, why)
			}
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not in the mcptask package's import allowlist", name, path)
			}
		}
	}
}
