package accounts

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

// TestAccountsImportsStayNarrow is the boundary guard that earns this
// package its place on the capability layer's import allowlist (#653),
// modelled on approval.TestApprovalImportsStayNarrow.
//
// capability's own guard (TestCapabilityImportsOnlyRegistryAndJobs) exists to
// keep the wire proto and raw SQL out of the capability layer. Admitting
// internal/accounts to that allowlist would be pointless if accounts could
// itself import either one — capability would reach them transitively and the
// guard would be enforcing a boundary that no longer exists.
//
// So this package accepts the same discipline as approval, mcptask, and
// nodestate: a small stdlib allowlist, and never relayv1 or database/sql. The
// SQLite implementation of Repository lives in internal/store, which is what
// keeps a later Postgres swap a single-package change.
func TestAccountsImportsStayNarrow(t *testing.T) {
	allowed := map[string]bool{
		"context":                    true,
		"crypto/rand":                true,
		"crypto/sha256":              true,
		"crypto/subtle":              true,
		"encoding/base64":            true,
		"encoding/hex":               true,
		"encoding/json":              true,
		"errors":                     true,
		"fmt":                        true,
		"log/slog":                   true,
		"strings":                    true,
		"sync":                       true,
		"time":                       true,
		"golang.org/x/crypto/argon2": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1": true,
		"database/sql": true,
		// capability imports this package (#653); importing it back would be
		// an import cycle, but naming it here makes the direction a stated
		// rule rather than something the compiler happens to catch.
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
				t.Errorf("%s imports %q — package accounts must stay free of the wire proto and raw SQL, "+
					"or capability's own import guard becomes meaningless", name, path)
			}
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not in the accounts package's import allowlist", name, path)
			}
		}
	}

	// Non-vacuity: if this package were ever emptied down to a single
	// _test.go file, the loop above would pass by checking nothing.
	if checked == 0 {
		t.Fatal("checked 0 non-test .go files — the guard must actually inspect something")
	}
}
