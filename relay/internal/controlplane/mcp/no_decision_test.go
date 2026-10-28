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
// whole mechanism rests on: elicitation travels over the MCP session, which is the AI's channel and the client's
// responsibility. A naive client can feed an approval prompt to its model and a
// compromised one can answer it outright, and the Relay cannot tell the
// difference. So the answer has to arrive somewhere the requesting session
// cannot reach: the authenticated /api/v1 decision endpoint, carrying a
// credential that session does not hold.
//
// "We just won't call it from here" is not that guarantee — it is a convention,
// and conventions are what get forgotten when someone wires an approval tool to
// close a loop. This test makes it a build failure instead: no file in package
// mcp may name DecideApproval, capability.ApprovalDecision, or an approval
// Channel constant. Reading is untouched — PendingApprovals and Approval stay
// callable, because surfacing what is waiting is exactly what the delivery
// envelopes are for.
//
// # Amended by ADR-0029
//
// One file — inBandDecisionFile — is now exempt, because the in-band rung was
// ratified as a TOOL CALL. That is a different shape from what this guard was
// written against: tasks/update answers an elicitation over the AI's own
// session with nobody in the path, whereas a tool call is surfaced by every
// client's confirmation UX to a human who answers it. The exemption is one
// filename, and two further tests below pin it — that it is used, that the file
// exists, and that it still may not name tasks/update.
//
// What did NOT change: the decision is still evaluated by package approval, an
// in-band answer still cannot satisfy an out-of-band rule (ErrWeakChannel), and
// the approver it names is asserted rather than verified.
//
// It deliberately does NOT live beside the API's approval routes: a guard on
// the surface that has the power is worth nothing if the surface that must not
// have it is unguarded.
//
// # What #376 added
//
// It forbids the string "tasks/update" outright. That is ADR-0029's stated
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

// inBandDecisionFile is the single file exempted from the scan above, per
// ADR-0029's decision to make the in-band rung reachable through the tool
// surface.
//
// It is a filename rather than a build tag or a package split because the
// exemption should be trivially visible: `git log -p` on this constant shows
// every time the hole changed shape, and TestInBandDecisionExemptionIsExactlyOneFile
// below fails if the file it names ever stops existing — so the exemption
// cannot be widened by renaming and cannot be left dangling by deletion.
const inBandDecisionFile = "tools_approval.go"

func TestMCPCannotAcceptAnApprovalDecision(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	for _, finding := range scanForDecisionPaths(t, dir) {
		t.Error(finding)
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
		if name == inBandDecisionFile {
			// ADR-0029: exactly one file may record a decision, and this is
			// the whole of that exemption. Everything else in both packages
			// stays guarded, so a second decision path cannot appear by
			// accident and this hole is auditable by opening one file.
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
						"(ADR-0029). Serving it requires amending both that ADR and this guard, in front "+
						"of a human.", name, forbiddenDecisionMethod))
				}
			}
			return true
		})
	}
	return findings
}

// TestInBandDecisionExemptionIsExactlyOneFile pins the exemption itself.
//
// The guard above is only as good as the narrowness of what it skips. This
// asserts the exempted file exists (so a rename cannot silently turn the
// exemption into a no-op that leaves a decision path unguarded elsewhere) and
// that it is the ONLY file in either scanned package naming a decision
// identifier — which is the same claim the guard makes, restated from the
// other direction so a reviewer can check it without reading the scanner.
func TestInBandDecisionExemptionIsExactlyOneFile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	if _, err := os.Stat(filepath.Join(dir, inBandDecisionFile)); err != nil {
		t.Fatalf("the exempted file %q does not exist (%v). Either it was renamed — in which case "+
			"the exemption now protects nothing and some other file may be recording decisions unnoticed — "+
			"or the in-band tool was removed, in which case delete the exemption too.", inBandDecisionFile, err)
	}

	// Count the exempted file's own references, so "we exempted a file that
	// does not actually need it" is also a failure: an exemption nobody uses
	// is an exemption waiting to be used by something else.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(dir, inBandDecisionFile), nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", inBandDecisionFile, err)
	}
	var refs int
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if _, bad := forbiddenDecisionIdents[node.Sel.Name]; bad {
				refs++
			}
		case *ast.Ident:
			if _, bad := forbiddenDecisionIdents[node.Name]; bad {
				refs++
			}
		}
		return true
	})
	if refs == 0 {
		t.Errorf("%s is exempted from the decision guard but names no decision identifier. "+
			"Remove the exemption rather than leaving an unguarded file in the package.", inBandDecisionFile)
	}
}

// TestInBandDecisionCannotNameTasksUpdate keeps the one exempted file honest
// about the boundary that did NOT move.
//
// ADR-0029 made the in-band rung reachable through a tool call, where a client
// with a human in front of it is the surface. It did not sanction tasks/update,
// where an answer arrives with no human anywhere in the path (ADR-0029). The
// exemption above skips the whole file, so without this the one file allowed to
// record decisions would also be the one file allowed to serve tasks/update.
func TestInBandDecisionCannotNameTasksUpdate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), inBandDecisionFile)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", inBandDecisionFile, err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, isLit := n.(*ast.BasicLit)
		if !isLit || lit.Kind != token.STRING {
			return true
		}
		if v, err := strconv.Unquote(lit.Value); err == nil && v == forbiddenDecisionMethod {
			t.Errorf("%s contains the literal %q. The in-band exemption covers a TOOL CALL, where the client "+
				"puts a human in front of the decision. It does not extend to %s, which answers an elicitation "+
				"over the AI's own session with nobody in the path (ADR-0029).",
				inBandDecisionFile, forbiddenDecisionMethod, forbiddenDecisionMethod)
		}
		return true
	})
}
