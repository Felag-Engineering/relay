package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
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

func TestMCPCannotAcceptAnApprovalDecision(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

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
					t.Errorf("%s references %q, which %s", name, node.Sel.Name, why)
				}
			case *ast.Ident:
				if why, bad := forbiddenDecisionIdents[node.Name]; bad {
					t.Errorf("%s references %q, which %s", name, node.Name, why)
				}
			}
			return true
		})
	}
}
