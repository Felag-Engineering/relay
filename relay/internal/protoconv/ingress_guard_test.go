package protoconv_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// ingress_guard_test.go pins (#504) that exactly two files under relay/ may
// populate a registry.Report's node-space label map, so a third writer has to
// argue with a test rather than slip past review.
//
// This is a backstop. registry.Report.nodeLabels is unexported, so a field
// assignment from another package is a compile error; what Go's export rules
// cannot restrict to a caller list is the WithNodeLabels call itself, which is
// what this walks: every non-test .go file under relay/ containing a call
// whose selector is named WithNodeLabels. Matching by name mirrors the
// no_dispatch guards.
func withNodeLabelsCallers(root string) (files []string, err error) {
	fset := token.NewFileSet()
	seen := map[string]bool{}

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "WithNodeLabels" && !seen[rel] {
				seen[rel] = true
				files = append(files, rel)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(files)
	return files, nil
}

// TestReportNodeLabelsHasTwoWriters walks relay/ and asserts that exactly
// cmd/relay/tunnel.go and internal/enroll/handler.go call WithNodeLabels — the
// only two places a Node's self-reported labels are legitimately allowed to
// enter the registry (ADR-0006's two-namespace label authority; D4 in the
// #504 plan).
//
// MUTATION: add a third call to WithNodeLabels anywhere else under relay/
// (composite-literal style OR the post-construction field-assignment style
// this guard exists to catch) and this test goes red.
func TestReportNodeLabelsHasTwoWriters(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// this file is relay/internal/protoconv/ingress_guard_test.go; the module
	// root ("relay/") is two directories up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	got, err := withNodeLabelsCallers(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	want := []string{"cmd/relay/tunnel.go", "internal/enroll/handler.go"}
	if len(got) != len(want) {
		t.Fatalf("WithNodeLabels callers: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("WithNodeLabels callers: got %v, want %v", got, want)
		}
	}
}

// TestWithNodeLabelsCallers_Fixtures exercises the guard's scanning logic
// against sources outside the real tree, mirroring the fixture pattern in
// console/no_dispatch_test.go: a guard nobody has ever seen fail is a guard
// that might not run.
func TestWithNodeLabelsCallers_Fixtures(t *testing.T) {
	dir := t.TempDir()

	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// A composite-literal-only guard would catch this one...
	write("a.go", `package a

import "github.com/Felag-Engineering/relay/relay/internal/registry"

func f() {
	_ = registry.Report{NodeID: "x"}.WithNodeLabels(map[string]string{"role": "web"})
}
`)
	// ...but this is the shape that defeated the composite-literal-only
	// version of this guard: build the Report first, then call
	// WithNodeLabels on it. The unexported field makes the OLDER
	// `rep.NodeLabels = someMap` idiom this comment describes a compile
	// error; this is what the language still allows a second writer to
	// spell, and it must be caught exactly like a.go.
	write("b.go", `package b

import "github.com/Felag-Engineering/relay/relay/internal/registry"

func g() {
	rep := registry.Report{NodeID: "y"}
	rep = rep.WithNodeLabels(map[string]string{"role": "db"})
	_ = rep
}
`)
	// A _test.go file must never count — every fixture and hermetic test
	// legitimately calls WithNodeLabels to seed a registry.
	write("c_test.go", `package c

import "github.com/Felag-Engineering/relay/relay/internal/registry"

func h() {
	_ = registry.Report{NodeID: "z"}.WithNodeLabels(nil)
}
`)
	// A file that never mentions WithNodeLabels must never appear.
	write("d.go", `package d

func noop() {}
`)

	got, err := withNodeLabelsCallers(dir)
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	want := []string{"a.go", "b.go"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
