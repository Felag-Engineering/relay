package policyalias_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyAlias_NoWireOrResolutionPackageImportsIt proves a Policy alias is
// never sent to a Node and never part of resolution: none of the packages that
// speak the wire protocol or resolve a Selector imports internal/policyalias.
func TestPolicyAlias_NoWireOrResolutionPackageImportsIt(t *testing.T) {
	const aliasPath = "github.com/Felag-Engineering/relay/relay/internal/policyalias"
	for _, dir := range []string{
		"../transport", "../dispatch", "../registry", "../nodestate", "../jobs", "../relay/v1",
	} {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(dir, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			parsed := 0
			fset := token.NewFileSet()
			for _, name := range files {
				if strings.HasSuffix(name, "_test.go") {
					continue
				}
				src, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
				if err != nil {
					t.Fatal(err)
				}
				parsed++
				for _, imp := range f.Imports {
					if strings.Trim(imp.Path.Value, `"`) == aliasPath {
						t.Errorf("%s imports internal/policyalias; an alias never reaches a Node or Selector resolution", name)
					}
				}
			}
			if parsed == 0 {
				t.Fatalf("no non-test .go file found under %s; the guard would inspect nothing", dir)
			}
		})
	}
}
