package accounts_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func TestRole_DescriptionIsGlossaryWording(t *testing.T) {
	raw, err := os.ReadFile("../../../GLOSSARY.md")
	if err != nil {
		t.Fatalf("read GLOSSARY.md: %v", err)
	}
	// The glossary wraps mid-sentence.
	glossary := strings.Join(strings.Fields(string(raw)), " ")

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin} {
		d := role.Description()
		if d == "" {
			t.Errorf("%s: empty Description", role)
			continue
		}
		want := "**`" + string(role) + "`** " + d
		if !strings.Contains(glossary, want) {
			t.Errorf("GLOSSARY.md does not say %q", want)
		}
	}
	if got := accounts.Role("root").Description(); got != "" {
		t.Errorf("an invalid role described %q, want nothing", got)
	}
}

// A role description that permission code reads becomes a second
// authorization model (invariant 10, ADR-0010). The AST is untyped, so the
// rule is stricter than "a selector on a Role": the whole relay module holds
// exactly one selector named Description in non-test code, and it is the
// Console's role panel.
func TestRole_DescriptionIsReadOnlyByTheConsolePanel(t *testing.T) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the relay module root is not two directories up: %v", err)
	}

	const allowed = "internal/controlplane/console/accounts_page.go"
	areas := []string{"internal/authz/", "internal/capability/", "internal/controlplane/"}
	fset := token.NewFileSet()
	parsed := 0
	reached := map[string]bool{}
	var sites []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		parsed++
		slash := filepath.ToSlash(path)
		for _, area := range areas {
			if strings.Contains(slash, area) {
				reached[area] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "Description" {
				sites = append(sites, fset.Position(sel.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if parsed == 0 {
		t.Fatal("parsed no files; the guard is vacuous")
	}
	for _, area := range areas {
		if !reached[area] {
			t.Fatalf("the walk never reached %s; the guard does not cover the permission code", area)
		}
	}

	for _, site := range sites {
		if !strings.Contains(filepath.ToSlash(site), allowed) {
			t.Errorf("%s selects .Description outside %s. A role description that permission code "+
				"reads becomes a second authorization model (invariant 10, ADR-0010). If this is an "+
				"unrelated field, allow that one site by file and line; never widen the allowance "+
				"to a permission package.", site, allowed)
		}
	}
	if len(sites) != 1 {
		t.Errorf("want exactly one .Description selector (in %s), found %d: %v", allowed, len(sites), sites)
	}
}
