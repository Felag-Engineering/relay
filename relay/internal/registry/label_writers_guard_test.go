package registry_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// label_writers_guard_test.go pins, for each label namespace that has a
// writer, the files that may call it (invariant 7, ADR-0006, ADR-0050), so a
// new writer has to argue with a test rather than slip past review. It is a
// backstop: the structural enforcement is that registry.Report has no tag field
// and registry.Repository has no tag method (tags_test.go). What Go's export
// rules cannot restrict to a caller list is the call itself, so this walks every
// non-test .go file of the module and matches selectors BY EXACT NAME, the way
// the no_dispatch guards and protoconv's ingress guard do.
//
// node: is pinned by protoconv's TestReportNodeLabelsHasTwoWriters, and state:
// by TestNode_HasNoStateLabelField and TestRepository_HasNoStateLabelWriter.

// selectorUses walks every non-test .go file under root and returns, for each
// name in names, the sorted slash-separated files that contain a selector
// expression ending in it.
func selectorUses(root string, names ...string) (map[string][]string, error) {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	fset := token.NewFileSet()
	found := map[string]map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !want[sel.Sel.Name] {
				return true
			}
			if found[sel.Sel.Name] == nil {
				found[sel.Sel.Name] = map[string]bool{}
			}
			found[sel.Sel.Name][rel] = true
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(names))
	for _, n := range names {
		for f := range found[n] {
			out[n] = append(out[n], f)
		}
		sort.Strings(out[n])
	}
	return out, nil
}

// TestLabelWriters_EachHasOnlyItsDefiningCallers walks the module and asserts
// who may call each label writer.
//
// MUTATION: call SetRelayLabels, AppendWithTagWrite, RecordTagWrite, WriteTag or
// ApplyTagChanges from any other non-test file and this test goes red. The
// registrytest package is the shared conformance suite that seeds relay: labels
// for the implementations under test.
func TestLabelWriters_EachHasOnlyItsDefiningCallers(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// this file is relay/internal/registry/label_writers_guard_test.go; the
	// module root ("relay/") is three directories up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	want := map[string][]string{
		"SetRelayLabels": {
			"internal/enroll/handler.go",
			"internal/eventsink/eventsink.go",
			"internal/registry/registrytest/conformance.go",
		},
		"AppendWithTagWrite": {"internal/auditsink/auditsink.go"},
		"RecordTagWrite":     {"internal/capability/tags.go"},
		// The Control API and the Console are the two surfaces a human Account
		// writes tags through, both via the capability layer's TagWriter
		// (ADR-0050, invariants 7 and 10).
		"WriteTag": {
			"internal/controlplane/api/tags.go",
			"internal/controlplane/console/tags.go",
		},
		"ApplyTagChanges": nil,
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	got, err := selectorUses(root, names...)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, n := range names {
		if !reflect.DeepEqual(got[n], want[n]) {
			t.Errorf("%s callers: got %v, want %v", n, got[n], want[n])
		}
	}
}

// TestLabelWriters_Fixtures arms the scanner: a guard nobody has seen fail is
// one that might not run.
func TestLabelWriters_Fixtures(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("a.go", `package a

func f(r interface{ SetRelayLabels(string, map[string]string) error }) {
	_ = r.SetRelayLabels("n", nil)
}
`)
	// A method value is a use too, not only a call.
	write("b.go", `package b

func g(w interface{ ApplyTagChanges(int) error }) {
	h := w.ApplyTagChanges
	_ = h
}
`)
	// A _test.go file never counts.
	write("c_test.go", `package c

func h(r interface{ SetRelayLabels() }) { r.SetRelayLabels() }
`)
	// Matching is by exact name: a longer name is a different method.
	write("d.go", `package d

func k(r interface{ SetRelayLabelsAll() }) { r.SetRelayLabelsAll() }
`)

	got, err := selectorUses(dir, "SetRelayLabels", "ApplyTagChanges", "WriteTag")
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if want := []string{"a.go"}; !reflect.DeepEqual(got["SetRelayLabels"], want) {
		t.Errorf("SetRelayLabels = %v, want %v", got["SetRelayLabels"], want)
	}
	if want := []string{"b.go"}; !reflect.DeepEqual(got["ApplyTagChanges"], want) {
		t.Errorf("ApplyTagChanges = %v, want %v", got["ApplyTagChanges"], want)
	}
	if len(got["WriteTag"]) != 0 {
		t.Errorf("WriteTag = %v, want none", got["WriteTag"])
	}
}
