package capability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestForeignPackageCannotConstructDispatch is the ROADMAP acceptance
// criterion for this issue: a package outside capability that tries to
// build a dispatch value or call newDispatch must fail to compile, not
// merely fail review. testdata/foreign/foreign.go attempts both. Building
// it with `go build -o <tempdir>/foreign` (rather than in the package
// directory) means an accidental future success never leaves a stray
// binary behind.
func TestForeignPackageCannotConstructDispatch(t *testing.T) {
	out := filepath.Join(t.TempDir(), "foreign")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/foreign")
	stderr, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("go build ./testdata/foreign unexpectedly succeeded; the capability layer's sealing is broken:\n%s", stderr)
	}

	// Assert the failure is specifically about the unexported symbols, not
	// some unrelated build break (e.g. a bad import path), so this test
	// can't false-pass.
	for _, symbol := range []string{"dispatch", "newDispatch"} {
		if !strings.Contains(string(stderr), symbol) {
			t.Errorf("go build ./testdata/foreign failed, but stderr does not mention %q as expected; got:\n%s", symbol, stderr)
		}
	}
}

// TestDispatchSymbolsUnexported is a defense-in-depth AST guard (mirrors
// jobs.TestNoDatabaseSQLImport's parse-and-inspect style): even if the
// testdata build above were ever skipped, this catches an accidental future
// export of the dispatch type or its constructor by name.
func TestDispatchSymbolsUnexported(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "dispatch.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	var foundDispatchType, foundNewDispatchFunc bool
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				switch ts.Name.Name {
				case "dispatch":
					foundDispatchType = true
				case "Dispatch":
					t.Error("dispatch.go defines an exported type Dispatch — the dispatch type must stay unexported so foreign packages cannot construct one")
				}
			}
		case *ast.FuncDecl:
			switch d.Name.Name {
			case "newDispatch":
				foundNewDispatchFunc = true
			case "NewDispatch":
				t.Error("dispatch.go defines an exported func NewDispatch — the constructor must stay unexported so foreign packages cannot construct one")
			}
		}
	}

	if !foundDispatchType {
		t.Error("dispatch.go no longer defines an unexported dispatch type")
	}
	if !foundNewDispatchFunc {
		t.Error("dispatch.go no longer defines an unexported newDispatch func")
	}
}
