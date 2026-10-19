package capability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestPolicyAliases_ReachOnlyTheAliasAdminAndTheReadLane proves structurally
// that a Policy alias is display data and never an input to a decision: every
// identifier that reads or writes one occurs only in the three files that
// declare and serve them, so Selector resolution, Plan, dispatch, the blast
// cap and approval cannot reference an alias.
//
// It scans this package's non-test source only. The test files reference these
// identifiers by design; the guard is about shipped decision code.
func TestPolicyAliases_ReachOnlyTheAliasAdminAndTheReadLane(t *testing.T) {
	allowed := map[string]bool{"policyalias.go": true, "seams.go": true, "readlane_registry.go": true}
	idents := map[string]bool{
		"aliases": true, "PolicyAliasSource": true, "PolicyAliasRecorder": true,
		"RecordPolicyAlias": true, "PolicyAliases": true,
		"SetPolicyAlias": true, "ClearPolicyAlias": true,
	}
	seen := map[string]int{}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || !idents[id.Name] {
				return true
			}
			seen[id.Name]++
			if !allowed[name] {
				t.Errorf("%s: %s references %q; a Policy alias is reached only from policyalias.go, seams.go and readlane_registry.go", fset.Position(id.Pos()), name, id.Name)
			}
			return true
		})
	}

	var missing []string
	for id := range idents {
		if seen[id] == 0 {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("identifiers never found, so the guard proves nothing about them: %v", missing)
	}
}
