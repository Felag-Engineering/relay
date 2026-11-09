package transport_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/descriptorpb"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// TestHello_NodeIDIsDeprecatedInTheContract pins that Hello.node_id stays in
// /proto, under its number, marked deprecated: buf's FILE breaking rules forbid
// deleting it, and the relay-daemon never sets it and the Relay never reads it.
//
// Proves NC-38.
func TestHello_NodeIDIsDeprecatedInTheContract(t *testing.T) {
	fd := (&relayv1.Hello{}).ProtoReflect().Descriptor().Fields().ByNumber(1)
	if fd == nil || fd.Name() != "node_id" {
		t.Fatalf("Hello field 1 = %v, want node_id: the field is kept, not deleted or renumbered (NC-38)", fd)
	}
	opts, _ := fd.Options().(*descriptorpb.FieldOptions)
	if !opts.GetDeprecated() {
		t.Error("Hello.node_id is not marked [deprecated = true] in /proto (NC-38)")
	}
}

// TestRelay_NoFileSelectsTheHelloNodeID is an absence asserted over the Relay's
// source: no non-test, non-generated file selects NodeId or GetNodeId, so a
// Node's identity can come only from its verified client certificate
// (invariant 6, ADR-0006). The empty allowlist is deliberate. The match is by
// name on any type, so it bans a selector read of NodeId or GetNodeId on the
// enrollment messages and the apiclient types as well as on Hello; building a
// message with a composite-literal key is not a selection and stays legal.
//
// Proves NC-38.
func TestRelay_NoFileSelectsTheHelloNodeID(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")
	hits, err := nodeIDSelections(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hits) > 0 {
		t.Errorf("non-test Relay code selects NodeId or GetNodeId, which reads a Node ID off the wire (NC-38, invariant 6, ADR-0006): identity comes only from the verified client certificate. The ban covers any non-test, non-generated selection of a field or method named exactly NodeId or GetNodeId, on any type (enrollment messages and apiclient types included).\n  %s", strings.Join(hits, "\n  "))
	}
}

// TestNodeIDSelections_Fixtures arms the scanner: it must report a read and a
// method value and nothing else.
func TestNodeIDSelections_Fixtures(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go":                   "package p\nfunc f(h T) { _ = h.NodeId }\n",
		"b.go":                   "package p\nfunc f(h T) { g := h.GetNodeId; _ = g }\n",
		"c_test.go":              "package p\nfunc f(h T) { _ = h.NodeId }\n",
		"d.go":                   "package p\nvar _ = T{NodeId: \"x\"}\n",
		"e.go":                   "package p\nfunc f(h T) { _ = h.NodeIdx }\n",
		"internal/relay/v1/g.go": "package v1\nfunc f(h T) { _ = h.NodeId }\n",
	}
	for name, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hits, err := nodeIDSelections(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.go:2: .NodeId", "b.go:2: .GetNodeId"}
	if strings.Join(hits, "|") != strings.Join(want, "|") {
		t.Errorf("hits = %v, want %v", hits, want)
	}
}

// nodeIDSelections lists "rel/path.go:line: .Name" for every selection of
// NodeId or GetNodeId in the non-test Go files under root, skipping the
// generated package.
func nodeIDSelections(root string) ([]string, error) {
	fset := token.NewFileSet()
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "internal/relay/v1" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && (sel.Sel.Name == "NodeId" || sel.Sel.Name == "GetNodeId") {
				hits = append(hits, rel+":"+strconv.Itoa(fset.Position(sel.Pos()).Line)+": ."+sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	sort.Strings(hits)
	return hits, err
}
