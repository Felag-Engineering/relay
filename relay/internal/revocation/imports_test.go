package revocation

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

// TestRevocationImportsExcludeAuditAndCapability is an import-boundary AST
// guard (mirrors capability.TestCapabilityImportsOnlyRegistryAndJobs and
// api.TestAPIImportsAreAllowlisted): package revocation's non-test files must
// never import internal/audit or internal/capability.
//
// This is the STRUCTURAL half of #557's RevocationRecorder design. The
// recorder is caller-supplied precisely because RevokeNode has nowhere to
// acquire an audit sink from: enroll.Service calls it as internal cleanup
// after a failed enrollment, through the NodeDenylister interface whose only
// method is RevokeNode(string) — no Principal, no audit.Record, no caller to
// ask. A future "just add an audit field to Service" would start filing the
// Relay's own cleanup as an operator act, which is exactly backwards; this
// test refuses that change at compile time rather than relying on a reviewer
// to catch it in a diff.
func TestRevocationImportsExcludeAuditAndCapability(t *testing.T) {
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit":      true,
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
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, imp := range file.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if forbidden[importPath] {
				t.Errorf("%s imports %q — package revocation must never learn what a "+
					"Principal or an audit.Record is; the cascade's per-Node record is "+
					"authored by a caller-supplied RevocationRecorder instead (#557)",
					name, importPath)
			}
		}
	}
}
