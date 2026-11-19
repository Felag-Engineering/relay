package jobs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

// policyRuleReaders is every non-test file under relay/ that may select a
// PolicyRule field: the sites that copy the daemon's rule reference from the
// wire to the audit trail and back out to the read lane. Nothing else may read
// it, because no Relay decision may depend on it (invariant 12).
var policyRuleReaders = []string{
	"internal/audit/chain.go",
	"internal/auditquery/auditquery.go",
	"internal/auditsink/auditsink.go",
	"internal/capability/execution.go",
	"internal/dispatch/convert.go",
	"internal/store/audit.go",
}

func policyRuleSelectors(root string) ([]string, error) {
	fset := token.NewFileSet()
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// The generated wire code names the field in its own getters.
		if strings.HasPrefix(rel, "internal/relay/v1/") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "PolicyRule" || sel.Sel.Name == "GetPolicyRule") {
				found = true
			}
			return !found
		})
		if found {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

// The daemon's rule reference is copied and recorded, never read to decide
// anything. Matching by selector name mirrors the other structural guards: a
// new reader has to argue with this test.
// Proves EX-70.
func TestPolicyRuleRef_IsReadOnlyWhereItIsRecorded(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// This file is relay/internal/jobs/policyrule_guard_test.go; the module root
	// is two directories up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	got, err := policyRuleSelectors(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, f := range got {
		if !slices.Contains(policyRuleReaders, f) {
			t.Errorf("%s selects .PolicyRule but is not a copy or record site: the rule reference is display-only, so no Relay decision may read it (EX-70, invariant 12). If this is a new copy or record site, add it to policyRuleReaders", f)
		}
	}
	for _, f := range policyRuleReaders {
		if !slices.Contains(got, f) {
			t.Errorf("%s is on the allowlist but no longer selects .PolicyRule: remove it, so the list stays the exact set of sites", f)
		}
	}
}
