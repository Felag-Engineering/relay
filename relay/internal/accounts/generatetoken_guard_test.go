package accounts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestGenerateToken_CallSitesAreEnumerated: GenerateToken makes a credential without
// Mint's check that the Account exists and is enabled, so where it is called is a
// checked fact rather than a convention. Mint itself, and the first admin that
// `relay init` creates in the same transaction as its token, are the only callers;
// a new one is a reviewed decision, and a stale entry fails too.
func TestGenerateToken_CallSitesAreEnumerated(t *testing.T) {
	permitted := map[string]bool{
		"internal/accounts/tokenservice.go": true,
		"cmd/relay/init.go":                 true,
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	const accountsPath = "github.com/Felag-Engineering/relay/relay/internal/accounts"

	found := map[string]bool{}
	fset := token.NewFileSet()
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
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inAccounts := f.Name.Name == "accounts" && filepath.Base(filepath.Dir(path)) == "accounts"
		var local string // the name this file imports the accounts package under
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == accountsPath {
				local = "accounts"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		hit := false
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && x.Sel.Name == "GenerateToken" {
					hit = true
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && inAccounts && id.Name == "GenerateToken" {
					hit = true
				}
			}
			return true
		})
		if hit {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for f := range found {
		if !permitted[f] {
			t.Errorf("%s calls accounts.GenerateToken, which skips Mint's existence and enabled checks; "+
				"a new call site must be a deliberate, reviewed decision added to this list", f)
		}
	}
	for f := range permitted {
		if !found[f] {
			t.Errorf("%s is permitted to call accounts.GenerateToken but does not; remove the stale entry", f)
		}
	}
}
