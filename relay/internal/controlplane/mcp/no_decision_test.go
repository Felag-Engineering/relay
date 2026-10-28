package mcp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// no_decision_test.go is the structural guard on package mcp's decision path
// (ADR-0027). It covers the WHOLE package: no non-test file may name a
// decision identifier or an approval channel.
//
// The MCP surface may surface a pending approval and may accept an MRTR answer
// on the retried call (ADR-0029 decision 6). It may not record a decision any
// other way. A tool call is the model's own output, so a decision sent that way
// could be the AI-agent approving itself; approve_request is retired and its
// one-file exemption with it (ADR-0047 decision 4, which supersedes ADR-0029
// decision 5).
//
// The elicited answer reaches the capability layer only through
// AnswerElicited, which sets the channel itself. The package renders the
// channel the capability layer recorded and never names one.
//
// "We just won't call it from here" is a convention, and conventions are what
// get forgotten when someone wires a decision tool to close a loop. This test
// makes it a build failure instead. Reading is untouched: PendingApprovals and
// Approval stay callable, because surfacing what is waiting is exactly what
// the delivery envelopes are for.
//
// It deliberately does NOT live beside the API's approval routes: a guard on
// the surface that has the power is worth nothing if the surface that must not
// have it is unguarded.

// forbiddenDecisionIdents are the identifiers that would let this package
// record an approval decision or name a decision channel. Matched as selector
// expressions (pkg.Ident) and as bare identifiers, so neither an import alias
// nor a dot-import evades them. Reading a recorded Decision's Channel field is
// not naming a channel value, and stays permitted.
var forbiddenDecisionIdents = map[string]string{
	"DecideApproval":   "records an approval decision; the only in-band entry point is the capability layer's AnswerElicited (ADR-0047 decision 4)",
	"ApprovalDecision": "is the capability layer's decision input; constructing one here would mean this surface intends to decide, not to notify (ADR-0027)",
	"RecordDecision":   "is the approval store's decision write; the AI channel must never reach it (ADR-0027)",
	"ChannelInBand":    "names a decision channel. Channel strength is set by the capability layer's entry point, and this package renders what was recorded (ADR-0047 decision 4)",
	"ChannelOutOfBand": "names a decision channel. Only the out-of-band endpoint stamps one, and it is not this package (ADR-0027)",
}

// forbiddenDecisionMethods are JSON-RPC methods this package must never serve.
// Matched as string LITERALS rather than identifiers: a method name reaches the
// wire as a string, so that is where the guard has to look.
var forbiddenDecisionMethods = map[string]string{
	"tasks/update": "answers an inputRequests elicitation over the AI's own session with nobody in the path (ADR-0029)",
	"tasks/get":    "is an MCP Tasks method; a parked request is never an MCP task handle (ADR-0047 decision 8)",
	"tasks/cancel": "is an MCP Tasks method; a parked request is never an MCP task handle (ADR-0047 decision 8)",
}

func packageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

func TestMCPCannotAcceptAnApprovalDecision(t *testing.T) {
	findings, _ := scanForDecisionPaths(t, packageDir(t))
	for _, finding := range findings {
		t.Error(finding)
	}
}

// TestDecisionGuardScansEveryNonTestFile pins the guard's coverage: the files
// it parsed are exactly the package's non-test Go files, so no file is exempt.
func TestDecisionGuardScansEveryNonTestFile(t *testing.T) {
	dir := packageDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	var want []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			want = append(want, name)
		}
	}
	_, scanned := scanForDecisionPaths(t, dir)
	slices.Sort(want)
	slices.Sort(scanned)

	if len(want) == 0 || len(scanned) == 0 {
		t.Fatalf("empty file set: want %v, scanned %v", want, scanned)
	}
	if !slices.Equal(want, scanned) {
		t.Errorf("the guard scanned %v, want every non-test file %v", scanned, want)
	}
}

// TestNoDecisionGuardActuallyFires guards the guard.
//
// A structural test that has never been seen to fail is indistinguishable from
// one that scans nothing — a wrong directory, a filter that skips every file, a
// refactor that quietly stopped matching. This plants each forbidden form in a
// throwaway package and asserts the scanner catches it, so the passing result
// above means "these packages are clean" rather than "the scanner found no
// files".
func TestNoDecisionGuardActuallyFires(t *testing.T) {
	cases := map[string]struct {
		file string
		src  string
	}{
		"a qualified decision call": {"planted.go", `package planted
func f(s Store) { s.DecideApproval(nil, nil) }
type Store interface{ DecideApproval(a, b any) }`},

		"a bare decision identifier": {"planted.go", `package planted
type Store interface{ RecordDecision(a any) }`},

		"a channel constant": {"planted.go", `package planted
import "x"
var _ = x.ChannelInBand`},

		"the tasks/update method literal": {"planted.go", `package planted
const method = "tasks/update"`},

		"the tasks/get method literal": {"planted.go", `package planted
const method = "tasks/get"`},

		"the tasks/cancel method literal": {"planted.go", `package planted
const method = "tasks/cancel"`},

		"an answer call outside acceptElicitedAnswer": {"planted.go", `package planted
func newTool(a Answerer) { a.AnswerElicited(nil, nil, "id", "hash", true) }
type Answerer interface{ AnswerElicited(a, b any, c, d string, e bool) }`},

		// The file the old exemption named: it is scanned like any other.
		"a decision call in the formerly exempt file": {"tools_approval.go", `package planted
func f(s Store) { s.DecideApproval(nil, nil) }
type Store interface{ DecideApproval(a, b any) }`},

		"a channel name in the formerly exempt file": {"tools_approval.go", `package planted
import "approval"
var _ = approval.ChannelInBand.String()`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o600); err != nil {
				t.Fatalf("write planted source: %v", err)
			}
			findings, scanned := scanForDecisionPaths(t, dir)
			if len(findings) == 0 {
				t.Errorf("the guard did not catch a planted decision path:\n%s", tc.src)
			}
			if !slices.Contains(scanned, tc.file) {
				t.Errorf("the guard did not scan %s (scanned %v)", tc.file, scanned)
			}
		})
	}

	// And it does not fire on the shapes it must permit: SURFACING a pending
	// approval is exactly what the delivery envelopes are for, and reading the
	// channel a Decision recorded is not naming a channel.
	permitted := map[string]string{
		"reading approvals is permitted": `package planted
func f(s Store) { s.PendingApprovals(nil); s.Approval(nil, "id") }
type Store interface {
	PendingApprovals(a any)
	Approval(a any, id string)
}`,
		"the answer call inside acceptElicitedAnswer is permitted": `package planted
func acceptElicitedAnswer(a Answerer) { a.AnswerElicited(nil, nil, "id", "hash", true) }
type Answerer interface{ AnswerElicited(a, b any, c, d string, e bool) }`,
		"the adapter's pass-through is permitted": `package planted
type approvalAnswererAdapter struct{ r Answerer }
func (a approvalAnswererAdapter) AnswerElicited(x, y any, c, d string, e bool) { a.r.AnswerElicited(x, y, c, d, e) }
type Answerer interface{ AnswerElicited(a, b any, c, d string, e bool) }`,
		"reading a recorded Decision's Channel is permitted": `package planted
func recordedChannel(req approval.Request) string { return req.Decisions[0].Channel.String() }`,
	}
	for name, src := range permitted {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
				t.Fatalf("write planted source: %v", err)
			}
			if findings, _ := scanForDecisionPaths(t, dir); len(findings) != 0 {
				t.Errorf("the guard refused a permitted shape: %v", findings)
			}
		})
	}
}

// scanForDecisionPaths returns one finding per forbidden reference in dir's
// non-test Go files, and the base name of every file it parsed. It returns
// rather than fails so the guard can be tested against planted source (see
// TestNoDecisionGuardActuallyFires).
func scanForDecisionPaths(t *testing.T, dir string) (findings, scanned []string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		scanned = append(scanned, name)

		for _, decl := range file.Decls {
			owner := declOwner(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == answerEntryPoint && !slices.Contains(answerCallSites, owner) {
						findings = append(findings, fmt.Sprintf("%s calls %s from %q; the only call sites are %v, "+
							"which run after the sealed state opens (ADR-0047 decision 4)", name, answerEntryPoint, owner, answerCallSites))
					}
				case *ast.SelectorExpr:
					if why, bad := forbiddenDecisionIdents[node.Sel.Name]; bad {
						findings = append(findings, fmt.Sprintf("%s references %q, which %s", name, node.Sel.Name, why))
					}
				case *ast.Ident:
					if why, bad := forbiddenDecisionIdents[node.Name]; bad {
						findings = append(findings, fmt.Sprintf("%s references %q, which %s", name, node.Name, why))
					}
				case *ast.BasicLit:
					if node.Kind != token.STRING {
						return true
					}
					lit, err := strconv.Unquote(node.Value)
					if err != nil {
						return true
					}
					if why, bad := forbiddenDecisionMethods[lit]; bad {
						findings = append(findings, fmt.Sprintf("%s contains the literal %q, which %s. Serving it requires "+
							"amending the ADR that forbids it and this guard, in front of a human.", name, lit, why))
					}
				}
				return true
			})
		}
	}
	return findings, scanned
}

// answerEntryPoint is the capability layer's in-band entry point. It is a
// decision write, so the guard pins where this package may call it: only from
// acceptElicitedAnswer, which runs after the sealed state opens and binds to
// the call, and from the adapter's one-line pass-through. A tool that took a
// request id and plan hash and called it directly would re-create the retired
// decision tool.
const answerEntryPoint = "AnswerElicited"

var answerCallSites = []string{"acceptElicitedAnswer", "approvalAnswererAdapter.AnswerElicited"}

// declOwner names the function a declaration defines ("Recv.Name" for a
// method), or "" for anything else.
func declOwner(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// scanForStaleToolPointers returns one finding per string literal in dir's
// non-test Go files that names the retired approve_request tool.
func scanForStaleToolPointers(t *testing.T, dir string) []string {
	t.Helper()
	var findings []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(v, "approve_request") {
				findings = append(findings, fmt.Sprintf("%s has a string literal naming approve_request: %q", name, v))
			}
			return true
		})
	}
	return findings
}

// Proves AP-83.
func TestNoMCPTextPointsAtApproveRequest(t *testing.T) {
	for _, finding := range scanForStaleToolPointers(t, packageDir(t)) {
		t.Error(finding)
	}

	t.Run("the scan fires on a planted literal", func(t *testing.T) {
		dir := t.TempDir()
		src := "package planted\nconst next = \"answer it with approve_request\"\n"
		if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
			t.Fatalf("write planted source: %v", err)
		}
		if len(scanForStaleToolPointers(t, dir)) == 0 {
			t.Error("the scan did not catch a planted approve_request literal")
		}
	})
}
