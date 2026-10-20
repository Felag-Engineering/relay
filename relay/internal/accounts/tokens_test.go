package accounts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mintLikeSelectors are the method names known to return a Plaintext as
// their second value: TokenService.Mint (tokenservice.go, this package) and
// capability.AccountAdmin.MintAPIToken (its capability-layer counterpart, #653,
// which this package must not import — see .golangci.yml's accounts-imports rule — so it is named
// here rather than referenced).
var mintLikeSelectors = map[string]bool{"Mint": true, "MintAPIToken": true}

// fileCallsPlaintextReveal reports whether path calls Plaintext.Reveal(),
// distinguished from every OTHER type's Reveal() method in this codebase
// (consoleauth.SessionID, console's CSRFToken, accounts.Password) by tracking
// which local variables were bound, anywhere in the file, from a call shaped
// like a Plaintext producer: the second value of a `mintLikeSelectors` call,
// or the result of NewPlaintext directly.
//
// This is file-scoped rather than function-scoped — deliberately the coarser
// of the two options for FALSE POSITIVES: a false positive (an unrelated
// variable elsewhere in the same file happening to match one of these
// shapes) only ever makes this guard MORE inclusive, never less — it would
// add a file to the found set, and TestPlaintext_RevealCallSitesAreEnumerated
// compares that set for EQUALITY with the permitted list, so an over-broad
// match fails loud rather than silently passing.
//
// FALSE NEGATIVES this guard CANNOT see, stated plainly rather than left
// implicit — this repo has shipped guards that claimed more than they
// enforced, and this one is narrower than its name suggests:
//   - a Plaintext arriving as a FUNCTION PARAMETER (`func f(p Plaintext)`)
//     rather than bound by a local assignment;
//   - a Plaintext held in a STRUCT FIELD and reached via `x.field.Reveal()`;
//   - a CHAINED call, `mint(...).Reveal()` or `NewPlaintext(...).Reveal()`,
//     with no intermediate variable at all;
//   - a 2-VALUE mint shape (`tok, err := ...`) where Plaintext is folded into
//     a wrapper struct rather than returned as the literal second value of a
//     3-value assignment.
//
// A new call site introduced through any of these shapes would NOT be
// caught by this test. It is a guard against the three known, currently-real
// call sites drifting or a fourth being added in the SAME shape as those
// three — not a general static-analysis proof that Reveal() is called nowhere
// else.
func fileCallsPlaintextReveal(fset *token.FileSet, path string) (bool, error) {
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return false, err
	}

	plaintextVars := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if mintLikeSelectors[sel.Sel.Name] && len(assign.Lhs) == 3 {
				if id, ok := assign.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
					plaintextVars[id.Name] = true
				}
			}
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "NewPlaintext" && len(assign.Lhs) == 1 {
			if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
				plaintextVars[lhs.Name] = true
			}
		}
		return true
	})

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Reveal" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if ok && plaintextVars[id.Name] {
			found = true
		}
		return true
	})
	return found, nil
}

// TestPlaintext_RevealCallSitesAreEnumerated makes Plaintext.Reveal's
// permitted call sites a checked fact (#653): the doc comment on Reveal
// claimed "there should be exactly one" and there were already two. Skips
// every _test.go file — Reveal is called throughout this repo's tests purely
// to get a string to put in an HTTP request, which is not the "the plaintext
// escapes production code" property this guards. See
// fileCallsPlaintextReveal's doc comment for the call SHAPES this cannot
// see — it enumerates the three known real call sites, it does not prove
// there is no fourth in a different shape.
func TestPlaintext_RevealCallSitesAreEnumerated(t *testing.T) {
	permitted := map[string]bool{
		"internal/controlplane/api/accounts.go":           true,
		"cmd/relay/init.go":                               true,
		"internal/controlplane/console/accounts_write.go": true,
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile is relay/internal/accounts/tokens_test.go; root is relay/.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")

	found := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		hasReveal, err := fileCallsPlaintextReveal(fset, path)
		if err != nil {
			return err
		}
		if hasReveal {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	for f := range found {
		if !permitted[f] {
			t.Errorf("%s calls Plaintext.Reveal() but is not in the permitted list — "+
				"a new call site is a place the plaintext escapes and must be a deliberate, reviewed decision", f)
		}
	}
	for f := range permitted {
		if !found[f] {
			t.Errorf("%s is permitted to call Plaintext.Reveal() but does not — a stale entry stops guarding anything", f)
		}
	}
	if len(found) == 0 {
		t.Fatal("found 0 Plaintext.Reveal() call sites — the guard must actually inspect something")
	}
}
