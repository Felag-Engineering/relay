package capability_test

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

// approval_routes_guard_test.go pins the functions that may reach an approval
// decision: a decision enters the store only through the Control API's
// decision endpoint and the in-band elicited answer, and Relay integrates no
// other decision path (invariant 10, ADR-0047). What Go's export rules cannot
// restrict to a caller list is the call itself, so this walks every non-test
// .go file of the module and matches selectors BY EXACT NAME, as the label
// writers guard does. The guard is per enclosing function: a second caller in
// an allowlisted file changes the set and fails. The match is by name only: an unrelated method called
// decide added elsewhere also trips it, which is loud and cheap to inspect.
// The walker is a copy of the label writers guard's walker.

// outsideFunc marks a use that sits outside any top-level function, such as a
// package-level var holding a func literal, so it cannot pass as an allowed
// function.
const outsideFunc = "<outside-func>"

// funcName names a top-level function, or a method as Type.name.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.Ident:
			return x.Name + "." + fn.Name.Name
		default:
			return "?." + fn.Name.Name
		}
	}
}

// decisionSelectorUses returns, for each name, the sorted "file:Func" sites
// under root, test files excluded, that contain a selector expression ending in
// it: the slash-separated file and its enclosing top-level function (a method
// is Type.name). A method value counts; a comment does not.
func decisionSelectorUses(root string, names ...string) (map[string][]string, error) {
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// The gitignored output of the apiclient generator: an HTTP client of
		// the Control API's decision route, not a second decision path.
		if rel == "internal/apiclient/client.gen.go" {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			site := rel + ":" + outsideFunc
			if fn, ok := decl.(*ast.FuncDecl); ok {
				site = rel + ":" + funcName(fn)
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !want[sel.Sel.Name] {
					return true
				}
				if found[sel.Sel.Name] == nil {
					found[sel.Sel.Name] = map[string]bool{}
				}
				found[sel.Sel.Name][site] = true
				return true
			})
		}
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

// TestApprovalDecisions_ArriveByOnlyTheTwoRoutes walks the module and asserts
// which function may call each step of recording a decision: the two exported
// routes, the one shared body behind them, and the store write.
//
// MUTATION: call DecideApproval, AnswerElicited, decide, RecordDecision or Decide from
// any other non-test function and this test goes red.
//
// Proves AP-18.
func TestApprovalDecisions_ArriveByOnlyTheTwoRoutes(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// this file is relay/internal/capability/approval_routes_guard_test.go; the
	// module root ("relay/") is three directories up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	want := map[string][]string{
		"DecideApproval": {"internal/controlplane/api/approvals.go:handleDecideApproval"},
		"AnswerElicited": {
			"internal/controlplane/mcp/tools_approval.go:acceptElicitedAnswer",
			"internal/controlplane/mcp/tools_approval.go:approvalAnswererAdapter.AnswerElicited",
		},
		"decide": {
			"internal/capability/approval_decide.go:Approvals.AnswerElicited",
			"internal/capability/approval_decide.go:Approvals.DecideApproval",
		},
		"RecordDecision": {"internal/capability/approval_decide.go:Approvals.decide"},
		"Decide":         {"internal/store/approvals.go:sqliteApprovals.RecordDecision"},
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	got, err := decisionSelectorUses(root, names...)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, n := range names {
		if !reflect.DeepEqual(got[n], want[n]) {
			t.Errorf("%s callers: got %v, want %v", n, got[n], want[n])
		}
	}
}

// TestApprovalDecisionsGuard_Fixtures arms the scanner: a guard nobody has seen
// fail is one that might not run.
func TestApprovalDecisionsGuard_Fixtures(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("a.go", `package a

func f(r interface{ DecideApproval(int) error }) {
	_ = r.DecideApproval(1)
}
`)
	// A method value is a use too, not only a call.
	write("b.go", `package b

func g(r interface{ AnswerElicited(int) error }) {
	h := r.AnswerElicited
	_ = h
}
`)
	// Only the generated client file is excluded, not its directory.
	const decide = `package x

func f(r interface{ DecideApproval(int) error }) { _ = r.DecideApproval(1) }
`
	write("internal/apiclient/client.gen.go", decide)
	write("internal/apiclient/other.go", decide)
	// A _test.go file never counts.
	write("c_test.go", `package c

func h(r interface{ RecordDecision() }) { r.RecordDecision() }
`)

	// Two functions in one file are two sites: a second handler in an
	// allowlisted file changes the set. A use outside any function is marked.
	write("d.go", `package d

func first(r interface{ Decide() }) { r.Decide() }

func (s *S) second(r interface{ Decide() }) { r.Decide() }

var lit = func(r interface{ Decide() }) { r.Decide() }
`)

	got, err := decisionSelectorUses(dir, "DecideApproval", "AnswerElicited", "RecordDecision", "Decide")
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if want := []string{"a.go:f", "internal/apiclient/other.go:f"}; !reflect.DeepEqual(got["DecideApproval"], want) {
		t.Errorf("DecideApproval = %v, want %v", got["DecideApproval"], want)
	}
	if want := []string{"b.go:g"}; !reflect.DeepEqual(got["AnswerElicited"], want) {
		t.Errorf("AnswerElicited = %v, want %v", got["AnswerElicited"], want)
	}
	if want := []string{"d.go:" + outsideFunc, "d.go:S.second", "d.go:first"}; !reflect.DeepEqual(got["Decide"], want) {
		t.Errorf("Decide = %v, want %v", got["Decide"], want)
	}
	if len(got["RecordDecision"]) != 0 {
		t.Errorf("RecordDecision = %v, want none", got["RecordDecision"])
	}
}
