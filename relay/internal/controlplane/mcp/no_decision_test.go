package mcp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// no_decision_test.go is the structural half of ADR-0027's core decision
// (#270): **notify via MCP, decide out-of-band.**
//
// The MCP surface may surface a pending approval — that is [4/6]/[5/6]'s whole
// job — and it must never accept a decision. The reason is the one property the
// whole mechanism rests on: elicitation and the Tasks extension travel over the
// MCP session, which is the AI's channel and the client's responsibility. A
// naive client can feed an approval prompt to its model and a compromised one
// can answer it outright, and the Relay cannot tell the difference. So the
// answer has to arrive somewhere the requesting session cannot reach: the
// authenticated /api/v1 decision endpoint, carrying a credential that session
// does not hold.
//
// "We just won't call it from here" is not that guarantee — it is a convention,
// and conventions are what get forgotten when someone wires an approval tool to
// close a loop. This test makes it a build failure instead: no file in package
// mcp may name DecideApproval, capability.ApprovalDecision, or an approval
// Channel constant. Reading is untouched — PendingApprovals and Approval stay
// callable, because surfacing what is waiting is exactly what the delivery
// envelopes are for.
//
// It deliberately does NOT live beside the API's approval routes: a guard on
// the surface that has the power is worth nothing if the surface that must not
// have it is unguarded.
//
// # What #376 added
//
// The scan now covers internal/mcptask as well. A task handle is the Tasks
// extension's delivery envelope, and an envelope that could record a decision
// would be the same hole one package over.
//
// It also forbids the string "tasks/update" outright. That is ADR-0028's stated
// boundary made structural: tasks/update is how a client answers an
// `inputRequests` elicitation, which is an approval decision arriving over the
// AI's own session — precisely the open rung-2 question on #272. Serving it
// requires naming it, so naming it fails the build. Somebody "completing the
// extension" is the exact failure mode the ADR predicted, and prose in an ADR
// does not stop it.

// forbiddenDecisionIdents are the identifiers that would let this package
// record an approval decision. Matched as selector expressions (pkg.Ident) and
// as bare identifiers, so neither an import alias nor a dot-import evades them.
var forbiddenDecisionIdents = map[string]string{
	"DecideApproval":   "records an approval decision; decisions must arrive out-of-band on /api/v1, never over the MCP session (ADR-0027)",
	"ApprovalDecision": "is the capability layer's decision input; constructing one here would mean this surface intends to answer, not to notify (ADR-0027)",
	"RecordDecision":   "is the approval store's decision write; the AI channel must never reach it (ADR-0027)",
	"ChannelInBand":    "names a decision channel. Channel strength is set by the surface that RECEIVES a decision, and this surface receives none (ADR-0027)",
	"ChannelOutOfBand": "names a decision channel. Only the out-of-band endpoint stamps one, and it is not this package (ADR-0027)",
}

// forbiddenDecisionMethod is the JSON-RPC method that would open an in-band
// decision channel. Matched as a string LITERAL rather than as an identifier:
// a method name reaches the wire as a string, so that is where the guard has to
// look.
const forbiddenDecisionMethod = "tasks/update"

func TestMCPCannotAcceptAnApprovalDecision(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	// The Tasks extension spans two packages; both are the AI's channel.
	for _, target := range []string{dir, filepath.Join(dir, "..", "..", "mcptask")} {
		for _, finding := range scanForDecisionPaths(t, target) {
			t.Error(finding)
		}
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
	cases := map[string]string{
		"a qualified decision call": `package planted
func f(s Store) { s.DecideApproval(nil, nil) }
type Store interface{ DecideApproval(a, b any) }`,

		"a bare decision identifier": `package planted
type Store interface{ RecordDecision(a any) }`,

		"a channel constant": `package planted
import "x"
var _ = x.ChannelInBand`,

		"the tasks/update method literal": `package planted
const method = "tasks/update"`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
				t.Fatalf("write planted source: %v", err)
			}
			if findings := scanForDecisionPaths(t, dir); len(findings) == 0 {
				t.Errorf("the guard did not catch a planted decision path:\n%s", src)
			}
		})
	}

	// And it does not fire on the shape it must permit: SURFACING a pending
	// approval is exactly what the delivery envelopes are for.
	t.Run("reading approvals is permitted", func(t *testing.T) {
		dir := t.TempDir()
		src := `package planted
func f(s Store) { s.PendingApprovals(nil); s.Approval(nil, "id") }
type Store interface {
	PendingApprovals(a any)
	Approval(a any, id string)
}`
		if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
			t.Fatalf("write planted source: %v", err)
		}
		if findings := scanForDecisionPaths(t, dir); len(findings) != 0 {
			t.Errorf("the guard refused a read-only approval surface: %v", findings)
		}
	})
}

// scanForDecisionPaths returns one finding per forbidden reference in dir's
// non-test Go files. It returns rather than fails so the guard can be tested
// against planted source (see TestNoDecisionGuardActuallyFires).
func scanForDecisionPaths(t *testing.T, dir string) []string {
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
			switch node := n.(type) {
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
				if lit == forbiddenDecisionMethod {
					findings = append(findings, fmt.Sprintf("%s contains the literal %q. That method answers an inputRequests "+
						"elicitation, which is an approval decision arriving over the AI's own session — "+
						"out of scope until #272 settles whether an in-band answer can ever count "+
						"(ADR-0028). Serving it requires amending both that ADR and this guard, in front "+
						"of a human.", name, forbiddenDecisionMethod))
				}
			}
			return true
		})
	}
	return findings
}
