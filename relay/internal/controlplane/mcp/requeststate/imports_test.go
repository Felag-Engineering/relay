package requeststate

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

// TestRequestStateImportsStayNarrow keeps this package a crypto primitive
// that decides nothing, in the shape of mcptask's import guard
// (mcptask/imports_test.go) plus the "checked == 0 means t.Fatal" non-vacuity
// guard from console/imports_test.go.
//
// Downward: no database/sql or internal/store. R27 (a restart or another
// replica strands an outstanding request state) is deliberately left
// unsolved in this issue; persisting the key would be the fix, and it is not
// taken here.
//
// Upward: no internal/controlplane/mcp (its own parent package — the
// dependency runs one way), and no internal/approval or internal/capability.
// ADR-0029 decision 5 keeps every decision in one file; a package that only
// seals and opens bytes must not import the packages that decide anything.
//
// No MCP SDK types: the go-sdk package has no business inside a primitive
// that never sees a tool call.
//
// No crypto/subtle: MAC comparison goes through hmac.Equal via the equalMAC
// seam only (see requeststate_test.go's AST scan for the stronger,
// code-shape half of this rule).
func TestRequestStateImportsStayNarrow(t *testing.T) {
	allowed := map[string]bool{
		"bytes":           true,
		"crypto/hmac":     true,
		"crypto/rand":     true,
		"crypto/sha256":   true,
		"encoding/base64": true,
		"encoding/hex":    true,
		"encoding/json":   true,
		"errors":          true,
		"fmt":             true,
		"io":              true,
		"log/slog":        true,
		"strings":         true,
		"time":            true,
		"unicode/utf8":    true,
	}
	forbidden := map[string]string{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp": "its own parent package; the parent consumes this package, never the reverse",
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval":         "a crypto primitive decides nothing (ADR-0029 decision 5 keeps decisions in one file)",
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability":       "a crypto primitive decides nothing (ADR-0029 decision 5 keeps decisions in one file)",
		"github.com/modelcontextprotocol/go-sdk/mcp":                                  "no SDK types in the primitive",
		"database/sql": "the key is never persisted (R27 left unsolved by owner decision)",
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store": "the key is never persisted (R27 left unsolved by owner decision)",
		"crypto/subtle": "mac comparison goes through hmac.Equal via equalMAC only",
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
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		checked++
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q — %s", name, path, why)
			}
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not in the requeststate package's import allowlist", name, path)
			}
		}
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package.
	if checked == 0 {
		t.Fatal("imports guard inspected zero files — the guard is not running")
	}
}
