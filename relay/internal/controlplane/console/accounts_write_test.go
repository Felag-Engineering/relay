package console

// accounts_write_test.go covers the Accounts screen's write half (#655):
// the five routes, the per-action step-up, the reveal-once mint, and the two
// source-level guards that keep this file from acquiring a second opinion
// about authority.
//
// The two guards at the top are here rather than in accounts_test.go for the
// same reason accounts_write.go is its own file: they are about the WRITE
// half, and accounts.go keeps its own, stricter, exception-free version.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// accountsWriteFile is the one file both guards below inspect. A base name, so
// renaming the file fails these guards loudly rather than silently disabling
// them — the same base-name check no_dispatch_test.go makes.
const accountsWriteFile = "accounts_write.go"

// accountsConfirmFile is the confirmation pages' file, held to the same
// caller-role rules. A base name, for the same rename-fails-loudly reason.
const accountsConfirmFile = "accounts_confirm.go"

// ---------------------------------------------------------------------------
// Guard A — the write half reads no caller role, by two independent mechanisms
// ---------------------------------------------------------------------------

// parseWriteHalf parses accounts_write.go, WITHOUT comments.
//
// Without comments deliberately, and it is load-bearing for Layer 1 below: a
// doc comment that names a shape in order to EXPLAIN it — roleChangeCouldGrant's
// comment names the fail-open spelling precisely so nobody writes it — is not
// the violation. TestAccounts_NoConsoleFileNamesSecretHash takes the same
// position for the same reason.
func parseWriteHalf(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	return parseGuardedFile(t, accountsWriteFile)
}

// parseGuardedFile is parseWriteHalf for any file the caller-role guards cover.
func parseGuardedFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fset, file
}

// writeHalfCode renders accounts_write.go back to source with every comment
// dropped, so Layer 1's string bans scan CODE and not prose.
func writeHalfCode(t *testing.T) string {
	t.Helper()
	return guardedFileCode(t, accountsWriteFile)
}

func guardedFileCode(t *testing.T, name string) string {
	t.Helper()
	fset, file := parseGuardedFile(t, name)
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, file); err != nil {
		t.Fatalf("print %s: %v", name, err)
	}
	return buf.String()
}

// callerAuthorityProducers are this package's functions that RETURN a
// caller-authority value: principal() reads the Principal the authentication
// boundary injected (console.go), page() carries the caller's role on Page
// (layout.go), and writePrelude (accounts_write.go) and confirmPrelude
// (accounts_confirm.go) return both.
//
// A local bound from any of them holds the CALLER's authority whatever it is
// named, which is the whole point of Layer 2: the spelling bans in Layer 1
// only catch the spellings somebody thought of, and a plan reviewer broke the
// first cut of this guard by renaming the local.
//
// WHAT THIS LIST IS, AND WHAT IT THEREFORE CANNOT DO. It is a PROVENANCE
// ALLOWLIST: Layer 2 flags a .Role read only on an identifier it can see the
// caller's authority arriving in. A caller obtained any OTHER way is invisible
// to it, and nothing else in this file compensates — a code reviewer found
// exactly that hole by calling controlplane.PrincipalFromContext directly,
// whose Principal.Role is a plain string and so trips none of Layer 1's
// spellings either. That is why the selector form below is matched as well,
// and why a new way to reach the caller MUST be added here: no other guard in
// this file will notice its absence.
var callerAuthorityProducers = map[string]bool{
	"principal":    true,
	"page":         true,
	"writePrelude": true,
	// confirmPrelude returns the caller and Page just as writePrelude does.
	"confirmPrelude": true,
}

// callerAuthoritySelectors are the same thing reached through a package
// qualifier — controlplane.PrincipalFromContext returns the Principal the
// authentication boundary put in the request context, which is the caller's
// authority by definition.
//
// Matched on the SELECTOR NAME alone, deliberately: a renamed import, an alias
// or a local wrapper type would all hide a qualifier-based match, and the
// method name is the part that cannot change without the call changing too.
var callerAuthoritySelectors = map[string]bool{
	"PrincipalFromContext": true,
}

// callerAuthorityIdents collects every identifier in scope known to hold a
// caller-authority value: a parameter or result typed Page or
// capability.Principal, and a local bound from a callerAuthorityProducers or
// callerAuthoritySelectors call.
//
// It takes a NODE rather than the file, because the set is per-declaration:
// see callerAuthorityReads.
func callerAuthorityIdents(scope ast.Node) map[string]bool {
	out := map[string]bool{}

	isAuthorityType := func(e ast.Expr) bool {
		switch t := e.(type) {
		case *ast.Ident:
			return t.Name == "Page"
		case *ast.SelectorExpr:
			x, ok := t.X.(*ast.Ident)
			return ok && x.Name == "capability" && t.Sel.Name == "Principal"
		}
		return false
	}
	collectFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			if !isAuthorityType(f.Type) {
				continue
			}
			for _, name := range f.Names {
				if name.Name != "_" {
					out[name.Name] = true
				}
			}
		}
	}

	// producesAuthority reports whether a call hands back the caller's own
	// authority — a bare call to one of this package's prelude helpers, or a
	// qualified call to one of the context readers.
	producesAuthority := func(call *ast.CallExpr) bool {
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			return callerAuthorityProducers[fn.Name]
		case *ast.SelectorExpr:
			return callerAuthoritySelectors[fn.Sel.Name]
		}
		return false
	}

	ast.Inspect(scope, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			collectFields(v.Type.Params)
			collectFields(v.Type.Results)
		case *ast.FuncLit:
			collectFields(v.Type.Params)
			collectFields(v.Type.Results)
		case *ast.AssignStmt:
			if len(v.Rhs) != 1 {
				return true
			}
			call, ok := v.Rhs[0].(*ast.CallExpr)
			if !ok || !producesAuthority(call) {
				return true
			}
			for _, lhs := range v.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
					out[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			// `var who, _ = controlplane.PrincipalFromContext(ctx)` binds an
			// allowlisted producer with a different keyword, and a ValueSpec
			// is not an AssignStmt. Without this arm the binding FORM decided
			// whether the guard saw a caller — which is not a property anyone
			// would think to check, and exactly the kind of hole that reads
			// as covered to someone trusting the doc comment above.
			if len(v.Values) != 1 {
				return true
			}
			call, ok := v.Values[0].(*ast.CallExpr)
			if !ok || !producesAuthority(call) {
				return true
			}
			for _, name := range v.Names {
				if name.Name != "_" {
					out[name.Name] = true
				}
			}
		}
		return true
	})
	return out
}

// callerAuthorityReads reports every .Role read on an identifier holding
// caller authority, named, in source order — collecting the
// identifier set PER TOP-LEVEL DECLARATION rather than once for the whole
// file.
//
// Per declaration because a file-global set is a false-positive waiting to
// happen: one handler writing `target, pg, ok := writePrelude(...)` would make
// `target` a caller-authority name EVERYWHERE, and roleChangeCouldGrant's
// legitimate `target.Role` — the TARGET Account's role, which this file must
// read — would fail the guard in an unrelated function. A guard that cries
// wolf is a guard someone deletes.
//
// Go's scoping makes this safe in the other direction too: a name can only
// hold what its own declaration put there, and a nested closure is inside the
// declaration that encloses it.
func callerAuthorityReads(file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		idents := callerAuthorityIdents(decl)
		if len(idents) == 0 {
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Role" {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !idents[id.Name] {
				return true
			}
			out = append(out, id.Name)
			return true
		})
	}
	return out
}

// callerAuthorityNames is the union of the per-declaration sets, for the
// vacuity pins alone. Nothing is flagged from it.
func callerAuthorityNames(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range file.Decls {
		for name := range callerAuthorityIdents(decl) {
			out[name] = true
		}
	}
	return out
}

// callerRoleSpellings are the source spellings of a caller-role comparison,
// banned in every file the caller-role guards cover.
var callerRoleSpellings = []string{
	"ReachableBy(", "== accounts.Role", "!= accounts.Role",
	"RoleGate", "requiredRole", "caller.Role", "pg.Role",
}

// TestAccountsWrite_NoCallerRoleComparisonLivesInTheWriteHalf is invariant 10
// as a source fact: accounts_write.go must interpret NO caller role. The
// route's MinRole subtracts reach at mount time and the capability layer
// authorizes; a comparison here would be a third, unreviewed answer.
//
// TWO INDEPENDENT LAYERS, because one is not enough and this package has the
// scar to prove it. A plan reviewer defeated the first cut of this guard with
// `if pg.Role != accounts.RoleAdmin { /* skip the password */ }` — a step-up
// bypass that passed both halves as they were then written.
//
//   - Layer 1 bans the spellings, including the two that let that bypass
//     through. `.AtLeast(` is banned here TOO, with a COUNTED, LOCATED
//     exception: this layer requires exactly one occurrence and Guard B
//     requires that one to be inside roleChangeCouldGrant. A ban with a
//     counted exception is falsifiable; a ban that was simply deleted is not.
//   - Layer 2 is an AST rule that does not care what the local is called: any
//     `.Role` selector on an identifier KNOWN to hold caller authority fails,
//     whatever its name, which catches `string(who.Role) != "admin"` — a hole
//     accounts.go's own comment admits its spelling bans do not close.
func TestAccountsWrite_NoCallerRoleComparisonLivesInTheWriteHalf(t *testing.T) {
	code := writeHalfCode(t)

	const message = "%s reads or re-derives the CALLER's authority (%s) — the write half must " +
		"interpret no caller role. The route's MinRole subtracts reach at mount time and the " +
		"capability layer authorizes; a comparison here is a third, unreviewed answer (invariant 10)."

	// --- Layer 1: the spelling bans, accounts.go's list in full ------------
	for _, banned := range callerRoleSpellings {
		if strings.Contains(code, banned) {
			t.Errorf(message, accountsWriteFile, banned)
		}
	}

	// `.AtLeast(` is banned with one counted, located exception. Zero would
	// mean roleChangeCouldGrant was renamed or deleted and Guard B is now
	// asserting nothing; more than one means an occurrence slipped in.
	if got := strings.Count(code, ".AtLeast("); got != 1 {
		t.Errorf("%s calls AtLeast %d times, want exactly 1 (roleChangeCouldGrant's, on the "+
			"TARGET Account's own old and new role). Zero means this guard and Guard B are "+
			"asserting nothing; more than one means a second role comparison appeared.",
			accountsWriteFile, got)
	}

	// --- Layer 2: the AST rule ---------------------------------------------
	_, file := parseWriteHalf(t)
	authority := callerAuthorityNames(file)

	// Vacuity pins. An empty set means the collection pass stopped working,
	// not that the file got safer — every handler here takes a Principal and
	// a Page. The two names are asserted explicitly because Layer 1's
	// "caller.Role"/"pg.Role" bans are only load-bearing while those ARE the
	// spellings in use; if someone renames them, this fails and the rename
	// has to be a deliberate act that also revisits Layer 1.
	if len(authority) == 0 {
		t.Fatal("the caller-authority identifier set is empty — the collection pass is not running, " +
			"so Layer 2 is inspecting nothing")
	}
	for _, want := range []string{"caller", "pg"} {
		if !authority[want] {
			t.Errorf("the caller-authority set does not contain %q. Either the collection pass "+
				"broke, or the locals were renamed — in which case Layer 1's spelling bans "+
				"(%q, %q) are no longer load-bearing and must be revisited deliberately.",
				want, "caller.Role", "pg.Role")
		}
	}

	for _, ident := range callerAuthorityReads(file) {
		t.Errorf(message, accountsWriteFile, ident+".Role")
	}
}

// ---------------------------------------------------------------------------
// Guard B — the one AtLeast call is roleChangeCouldGrant's
// ---------------------------------------------------------------------------

// atLeastSite is one occurrence of an AtLeast selector and the function it sits
// in. enclosing is "" for PACKAGE SCOPE — a var initialiser or a package-level
// func literal, which is precisely how a caller-role comparison hides from a
// guard that only walks f.Decls looking for *ast.FuncDecl.
type atLeastSite struct {
	enclosing string
	pos       token.Pos
}

// atLeastCallSites walks the WHOLE file, maintaining the node stack, so a
// package-scope occurrence is found rather than skipped.
//
// The first cut of this guard iterated f.Decls and `continue`d on anything
// that was not an *ast.FuncDecl, which made
// `var callerOutranks = func(a, b accounts.Role) bool { return a.AtLeast(b) }`
// invisible to it — AtLeast on a caller's role, at package scope, passing
// clean, under a failure message asserting the only comparison in the file was
// roleChangeCouldGrant's. The third fixture below is that shape.
func atLeastCallSites(file *ast.File) []atLeastSite {
	var sites []atLeastSite
	var stack []ast.Node

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			// Post-visit. Every non-nil push above returns true, so pushes
			// and pops are balanced.
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)

		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "AtLeast" {
			return true
		}
		enclosing := ""
		for i := len(stack) - 1; i >= 0; i-- {
			if fd, ok := stack[i].(*ast.FuncDecl); ok {
				enclosing = fd.Name.Name
				break
			}
		}
		sites = append(sites, atLeastSite{enclosing: enclosing, pos: sel.Pos()})
		return true
	})
	return sites
}

// atLeastViolations reports the sites that are not roleChangeCouldGrant's,
// each with the message its own shape deserves.
func atLeastViolations(sites []atLeastSite) []string {
	var out []string
	for _, s := range sites {
		switch s.enclosing {
		case "roleChangeCouldGrant":
			// The one permitted occurrence.
		case "":
			out = append(out, fmt.Sprintf(
				"%s calls AtLeast at PACKAGE SCOPE (a var initialiser or a package-level func "+
					"literal). That is outside every function this guard names, which is precisely "+
					"how a caller-role comparison hides from it.", accountsWriteFile))
		default:
			out = append(out, fmt.Sprintf(
				"%s calls AtLeast in %s — the only role comparison this file may make is "+
					"roleChangeCouldGrant's, on the TARGET Account's own old and new role. A "+
					"comparison anywhere else is a second opinion about authority (invariant 10).",
				accountsWriteFile, s.enclosing))
		}
	}
	return out
}

func TestAccountsWrite_AtLeastIsCalledOnlyInRoleChangeCouldGrant(t *testing.T) {
	_, file := parseWriteHalf(t)
	sites := atLeastCallSites(file)

	// The vacuity assert, in the same shape as the Reveal guard below. Zero
	// means the function was renamed or deleted and this guard now asserts
	// nothing; more than one means an occurrence slipped in even if it
	// happened to sit in the right function.
	if len(sites) != 1 {
		t.Fatalf("%s contains %d AtLeast selectors, want exactly 1 — this guard carves ONE "+
			"exception out of Guard A's ban, and it is only meaningful while there is exactly "+
			"one occurrence to locate", accountsWriteFile, len(sites))
	}
	for _, v := range atLeastViolations(sites) {
		t.Error(v)
	}
}

// TestAccountsWriteGuard_AtLeastFixtures runs Guard B's machinery over sources
// that are not this package — a guard nobody has ever seen fail is a guard
// that might not run. The `no_dispatch` fixture idiom: every case asserted in
// both directions.
func TestAccountsWriteGuard_AtLeastFixtures(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		wantSubstr string // "" = expect NO violation
		wantSites  int
	}{
		{
			name: "the real roleChangeCouldGrant is clean",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func roleChangeCouldGrant(from, to accounts.Role) bool {
	if !from.Valid() || !to.Valid() {
		return true
	}
	return to != from && to.AtLeast(from)
}
`,
			wantSubstr: "",
			wantSites:  1,
		},
		{
			name: "a second function calling AtLeast violates",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func roleChangeCouldGrant(from, to accounts.Role) bool { return to != from && to.AtLeast(from) }
func callerOutranks(pg Page, want accounts.Role) bool { return pg.Role.AtLeast(want) }
`,
			wantSubstr: "calls AtLeast in callerOutranks",
			wantSites:  2,
		},
		{
			// THE FIXTURE THAT FAILS AGAINST THE f.Decls SHAPE. A package-level
			// func literal is not an *ast.FuncDecl, so a guard that filtered
			// f.Decls never saw it.
			name: "a package-level func literal calling AtLeast violates",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func roleChangeCouldGrant(from, to accounts.Role) bool { return to != from && to.AtLeast(from) }
var callerOutranks = func(a, b accounts.Role) bool { return a.AtLeast(b) }
`,
			wantSubstr: "at PACKAGE SCOPE",
			wantSites:  2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			sites := atLeastCallSites(file)
			if len(sites) != tc.wantSites {
				t.Fatalf("atLeastCallSites found %d sites, want %d — the walk itself is wrong",
					len(sites), tc.wantSites)
			}
			violations := atLeastViolations(sites)
			if tc.wantSubstr == "" {
				if len(violations) != 0 {
					t.Fatalf("atLeastViolations = %v, want none (this is the legitimate shape)", violations)
				}
				return
			}
			for _, v := range violations {
				if strings.Contains(v, tc.wantSubstr) {
					return
				}
			}
			t.Fatalf("atLeastViolations = %v, want one containing %q", violations, tc.wantSubstr)
		})
	}
}

// TestAccountsWriteGuard_CallerAuthorityFixtures is Guard A Layer 2's own
// both-directions fixture table, including the EXACT bypass a plan reviewer
// used against the first cut of this guard.
func TestAccountsWriteGuard_CallerAuthorityFixtures(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantIDs []string // identifiers whose .Role must be flagged; empty = none
	}{
		{
			// The reviewer's bypass, verbatim in shape: a step-up skipped on
			// the CALLER's own role.
			name: "pg.Role on a Page parameter is flagged",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func f(pg Page) bool {
	if pg.Role != accounts.RoleAdmin {
		return false
	}
	return true
}
`,
			wantIDs: []string{"pg"},
		},
		{
			// The same bypass with the local renamed — Layer 1's spelling
			// bans cannot see this one at all.
			name: "a renamed Page local is still flagged",
			src: `package console
func f(w any, r any) {
	who, thePage, ok := writePrelude(nil, w, r, "Accounts")
	_, _ = who, ok
	if string(thePage.Role) != "admin" {
		return
	}
}
`,
			wantIDs: []string{"thePage"},
		},
		{
			// The hole a code reviewer found in the first cut of Layer 2: the
			// caller reached through a SELECTOR call rather than one of this
			// package's bare prelude helpers. capability.Principal.Role is a
			// plain string, so comparing it to a literal trips no Layer 1
			// spelling either — this fixture is the only thing standing
			// between that bypass and a green package.
			name: "a Principal from controlplane.PrincipalFromContext is flagged",
			src: `package console
func f(ctx any) bool {
	who, _ := controlplane.PrincipalFromContext(ctx)
	return who.Role == "admin"
}
`,
			wantIDs: []string{"who"},
		},
		{
			// The SAME allowlisted producer, bound with `var` instead of `:=`.
			// A ValueSpec is not an AssignStmt, so before this arm existed the
			// BINDING FORM decided whether the guard saw a caller at all —
			// which is not a property anyone would think to check, and which
			// read as covered to anyone trusting the doc comment.
			name: "a var-bound Principal from a producer is flagged",
			src: `package console
func f(ctx any) bool {
	var who, _ = controlplane.PrincipalFromContext(ctx)
	return who.Role == "admin"
}
`,
			wantIDs: []string{"who"},
		},
		{
			// Per-declaration scoping: a prelude local in ONE function must
			// not make the same name caller-authority in another, where it is
			// the TARGET Account whose role this file legitimately reads.
			// Against a file-global set this fixture flags "target" and fails.
			name: "a prelude local does not taint the same name in another function",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func handler(w any, r any) {
	target, pg, ok := writePrelude(nil, w, r, "Accounts")
	_, _, _ = target, pg, ok
}
func decide(target accounts.Account, to accounts.Role) bool {
	return roleChangeCouldGrant(target.Role, to)
}
`,
			wantIDs: nil,
		},
		{
			name: "a capability.Principal parameter's Role is flagged",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/capability"
func f(anybody capability.Principal) string { return anybody.Role }
`,
			wantIDs: []string{"anybody"},
		},
		{
			// The false-positive control: a TARGET Account's role is what
			// roleChangeCouldGrant legitimately reads. It must not be
			// mistaken for the caller's.
			name: "a target Account's Role is not flagged",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/accounts"
func f(target accounts.Account, to accounts.Role) bool {
	return roleChangeCouldGrant(target.Role, to)
}
`,
			wantIDs: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			flagged := callerAuthorityReads(file)
			if !reflect.DeepEqual(flagged, tc.wantIDs) {
				t.Fatalf("flagged %v, want %v", flagged, tc.wantIDs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The plaintext's structural containment
// ---------------------------------------------------------------------------

// TestAccountsWrite_RevealIsCalledExactlyOnceInTheMintFile counts the Reveal
// selectors in accounts_write.go.
//
// Scoped to that ONE file and deliberately not a package-wide ban, because
// three legitimate unrelated Reveal() calls exist in this package —
// login.go's consoleauth.SessionID and security.go's two console.CSRFToken
// comparisons. A package-wide ban would false-positive on the session cookie
// and the CSRF check, and a guard suppressed on its first run is a guard
// nobody trusts.
//
// WHAT THIS DOES NOT PROVE: that the revealed string never escapes. A helper
// taking the revealed value would pass this. The properties carrying that are
// the no-redirect / no-Location / no-store / absent-from-every-later-render
// tests below, mintedView.LogValue, and TestPlaintext_RevealCallSitesAreEnumerated
// upstream in internal/accounts.
func TestAccountsWrite_RevealIsCalledExactlyOnceInTheMintFile(t *testing.T) {
	_, file := parseWriteHalf(t)
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Reveal" {
			count++
		}
		return true
	})
	if count != 1 {
		t.Errorf("%s calls Reveal %d times, want exactly 1 — the mint response is the only "+
			"place in this package a token plaintext may be unwrapped", accountsWriteFile, count)
	}
}

// TestAccountsWrite_NoConsoleFileNamesPlaintextOutsideTheMint is the
// source-level companion: accounts_write.go legitimately names
// accounts.Plaintext, and no other file in this package may.
//
// Parsed without comments, deliberately — a doc comment naming the type in
// order to say it is absent (seams.go and accounts.go both do) is not the
// violation. The shape is TestAccounts_NoConsoleFileNamesSecretHash's.
func TestAccountsWrite_NoConsoleFileNamesPlaintextOutsideTheMint(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	checked, sawTheMintFile := 0, false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == accountsWriteFile {
			sawTheMintFile = true
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if v.Name == "Plaintext" {
					t.Errorf("%s names Plaintext. Only %s's mint response may hold a token's "+
						"plaintext; naming the type anywhere else is the first half of giving it "+
						"a second rendering.", name, accountsWriteFile)
				}
			case *ast.BasicLit:
				if strings.Contains(v.Value, "Plaintext") {
					t.Errorf("%s has a string literal naming Plaintext (%.60s…) — a template that "+
						"names it renders it", name, v.Value)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("the guard inspected zero files — it is not running")
	}
	if !sawTheMintFile {
		t.Fatalf("%s was not found in this package — the allowlisted file was renamed, which "+
			"silently widens this guard's exception to nothing at all", accountsWriteFile)
	}
}

// TestAccountsWrite_OnlyTheMintViewHasAFieldASecretCouldOccupy is the
// structural claim in both directions: the screen's view types have nowhere to
// put a secret, and mintedView has exactly one place — which is what makes
// "the plaintext lands in one field" a fact about the types.
//
// CSRFToken is deliberately NOT banned by name: a CSRF token is a per-session
// derived value the layout already renders into every form, and banning the
// word would ban the control rather than the secret. What is banned is
// Secret/Hash/Plaintext, exactly as TestAccounts_ATokenRowHasNoFieldASecretCouldOccupy
// bans them on tokenRow.
func TestAccountsWrite_OnlyTheMintViewHasAFieldASecretCouldOccupy(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(accountsView{}),
		reflect.TypeOf(accountRow{}),
		reflect.TypeOf(tokenRow{}),
		reflect.TypeOf(accountsWriteControls{}),
		reflect.TypeOf(accountCreateForm{}),
		reflect.TypeOf(accountsWriteResultView{}),
	} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s.%s is a []byte — no screen type may have somewhere to put a SecretHash",
					typ.Name(), f.Name)
			}
			for _, word := range []string{"Secret", "Hash", "Plaintext"} {
				if strings.Contains(f.Name, word) {
					t.Errorf("%s.%s names %q — a token's secret exists once, at mint, and reaches "+
						"exactly one render", typ.Name(), f.Name, word)
				}
			}
		}
	}

	// The create form is re-drawn with the caller's submission echoed back, so
	// the password having no field is a fact about the type.
	create := reflect.TypeOf(accountCreateForm{})
	for i := range create.NumField() {
		if strings.Contains(create.Field(i).Name, "Password") {
			t.Errorf("accountCreateForm.%s could hold the password the form is never to echo", create.Field(i).Name)
		}
	}

	// The positive half: mintedView has EXACTLY ONE string field named Token.
	typ := reflect.TypeOf(mintedView{})
	tokenFields := 0
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Name == "Token" {
			if f.Type.Kind() != reflect.String {
				t.Errorf("mintedView.Token is %s, want a string", f.Type.Kind())
			}
			tokenFields++
		}
	}
	if tokenFields != 1 {
		t.Errorf("mintedView has %d fields named Token, want exactly 1 — 'the one place a secret "+
			"can land' must be a fact about the type", tokenFields)
	}
}

// TestAccountsWrite_MintedViewRedactsItsTokenWhenLogged is the structural half
// of "the plaintext never reaches a log".
//
// mintedView.Token is a PLAIN STRING: by the time it lands there, Reveal() has
// run and every redaction accounts.Plaintext provides — String, GoString,
// LogValue, MarshalJSON — is gone. LogValue is what puts one of them back, and
// it survives a future handler edit in a way a buffer assertion on today's
// handler does not.
func TestAccountsWrite_MintedViewRedactsItsTokenWhenLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	v := mintedView{
		AccountName: "gleipnir-prod",
		TokenID:     sweepMintedTokenID,
		TokenName:   "ci-deploy",
		Token:       sweepMintedPlaintext,
		Back:        backLink{Href: "/console/accounts", Label: "Back to Accounts"},
	}
	logger.Info("minted", slog.Any("view", v))

	out := buf.String()
	if strings.Contains(out, sweepMintedPlaintext) {
		t.Errorf("logging a mintedView emitted the plaintext:\n%s", out)
	}
	if !strings.Contains(out, sweepMintedTokenID) {
		t.Errorf("logging a mintedView emitted no token id — the operator's only handle:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// The five routes' targets, taken from sweepAccounts (fakes_test.go) so a
// fixture and an assertion cannot drift. None is the signed-in Account, so
// nothing here is masked by capability.ErrSelfTargeted.
const (
	targetViewerID   = "acct-ana"      // a viewer: raising it is a grant
	targetAdminID    = "acct-mike"     // an admin: lowering it is not
	targetOperatorID = "acct-gleipnir" // an operator, with tokens
	targetDisabledID = "acct-retired"  // disabled: enabling it is a grant
	targetLiveToken  = "tok-live"      // a live token on targetOperatorID
)

// writeFix is a REAL browser session over a real consoleauth.Service, with the
// write seams the test controls.
//
// A real session is not optional: stepUpProved resolves
// controlplane.ConsoleSessionFromContext, and the CSRF middleware refuses
// every bearer-lane POST before routing. The seams are fakes because the
// refusal branches (throttled, bad credential, no session) are what these
// tests are about, and a real store would only obscure what the handler does
// with the error it gets back. A shared order recorder lets a test assert
// StepUp happened strictly before the capability call.
type writeFix struct {
	f       *loginFixture
	session *http.Cookie
	csrf    string
	admin   *fakeAccountAdmin
	auth    *fakeAuth
}

func newWriteFix(t *testing.T, mutate func(*Deps)) *writeFix {
	t.Helper()
	admin := &fakeAccountAdmin{}
	auth := &fakeAuth{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Accounts = sweepAccounts()
		d.AccountAdmin = admin
		d.Auth = auth
		if mutate != nil {
			mutate(d)
		}
	})
	id, _, err := f.svc.Login(context.Background(), consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword(consolePassword), Source: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	csrf := f.sessions.CSRFToken(id).Reveal()
	// Without a rotation the fake reports the page's own token, so a seam test
	// sees no phantom token change.
	auth.csrf = csrf
	return &writeFix{
		f:       f,
		session: &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()},
		csrf:    csrf,
		admin:   admin,
		auth:    auth,
	}
}

// get fetches path over the fixture's session. A GET needs no CSRF token.
func (x *writeFix) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return x.f.do(t, httptest.NewRequest(http.MethodGet, path, nil), x.session)
}

// post submits form to path over the fixture's session, adding the session's
// own CSRF token. A test that wants the token absent or wrong builds the
// request itself.
func (x *writeFix) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{"csrf_token": {x.csrf}}
	for k, vs := range form {
		body[k] = vs
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return x.f.do(t, req, x.session)
}

// writeAct is one act a write route can perform, in one direction.
//
// pattern is the ROUTE it drives, and it is what
// TestAccountsWrite_EveryWriteRouteIsClassifiedAsGrantingOrReducing checks the
// two tables below against a set DERIVED from Routes — so a write route that nobody classified
// as granting or reducing cannot exist quietly. The two tables do not
// partition the routes: the role and the enabled routes appear in both,
// because the same route raises or lowers depending on what was submitted,
// and that duality is itself pinned below.
type writeAct struct {
	name    string
	pattern string
	path    func() string
	form    url.Values
	// called reports how many times THIS act's capability verb was called.
	called func(*fakeAccountAdmin) int
}

// grantingAct is a writeAct in the granting direction. The alias keeps the
// name the refusal sweeps read by.
type grantingAct = writeAct

// grantingActs are the four acts that cost a password.
func grantingActs() []grantingAct {
	return []grantingAct{
		{
			name:    "create an Account",
			pattern: createAccountPattern,
			path:    createAccountAction,
			form:    url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.creates) },
		},
		{
			name:    "raise a role",
			pattern: setAccountRolePattern,
			path:    func() string { return setAccountRoleAction(targetViewerID) },
			form:    url.Values{"role": {"admin"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.roles) },
		},
		{
			name:    "re-enable a disabled Account",
			pattern: setAccountEnabledPattern,
			path:    func() string { return setAccountEnabledAction(targetDisabledID) },
			form:    url.Values{"enabled": {"true"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.enables) },
		},
		{
			name:    "mint an API Token",
			pattern: mintAPITokenPattern,
			path:    func() string { return mintAPITokenAction(targetOperatorID) },
			form:    url.Values{"name": {"ci-deploy"}, "ttl": {"90d"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.mints) },
		},
	}
}

// reducingActs are the acts that can only REDUCE what some principal may do,
// and therefore cost no password (owner decision, 2026-09-19).
func reducingActs() []writeAct {
	return []writeAct{
		{
			name:    "disable an Account",
			pattern: setAccountEnabledPattern,
			path:    func() string { return setAccountEnabledAction(targetViewerID) },
			form:    url.Values{"enabled": {"false"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.enables) },
		},
		{
			// admin -> operator, deliberately NOT the floor case, so the
			// assertion is not quietly satisfied by a change to viewer alone.
			name:    "lower a role from admin to operator",
			pattern: setAccountRolePattern,
			path:    func() string { return setAccountRoleAction(targetAdminID) },
			form:    url.Values{"role": {"operator"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.roles) },
		},
		{
			name:    "lower a role from operator to viewer",
			pattern: setAccountRolePattern,
			path:    func() string { return setAccountRoleAction(targetOperatorID) },
			form:    url.Values{"role": {"viewer"}},
			called:  func(a *fakeAccountAdmin) int { return len(a.roles) },
		},
		{
			name:    "revoke a token",
			pattern: revokeAPITokenPattern,
			path:    func() string { return revokeAPITokenAction(targetLiveToken) },
			form:    url.Values{},
			called:  func(a *fakeAccountAdmin) int { return len(a.revokes) },
		},
	}
}

// consoleWriteRoutePatterns derives the write-route set from the route table
// itself: every UNSAFE-METHOD route Routes mounts under /console/accounts or
// /console/api-tokens.
//
// DERIVED, not restated, and that is the whole point. The first cut of the
// classification guard below compared a hardcoded table against its own
// length, so a code reviewer could add a sixth write route — one calling
// SetAccountRole(..., RoleAdmin) with no step-up at all, an unconditional
// grant of admin from any admin session with no password — and watch the
// whole package go green. Routes is the thing a request actually reaches, so
// it is the thing the classification has to be checked against.
//
// Execution is forced on because Routes returns a SMALLER slice when it is
// off; a future write route gated behind that flag must still be classified.
//
// "Write" is isSafeMethod's complement, deliberately: that is the same
// predicate Secure (security.go) uses to decide what needs a CSRF token, so
// this guard and the middleware cannot drift apart on what counts as a write.
// Requiring POST was narrower than both — a PUT route registers cleanly and
// Secure treats it as unsafe, while this derivation, accountsWriteRoutes(),
// the below-admin reach sweep and the CSRF sweeps would every one have
// skipped it.
//
// THE SCOPE LIMIT, said out loud: this derivation is by PATH PREFIX, so a
// write route belonging to this screen but mounted on a fourth path would
// escape it — and nothing forces the prefix. Create lives on a third prefix
// (/console/new-account), which this filter includes. A further path registers
// cleanly (only two shapes panic, and console.go records both); what the
// prefix rests on is that choosing one is a deliberate act, and the person
// taking it owns widening this filter with it. The METHOD dimension is closed above; the
// PATH dimension is not, and this paragraph is the whole of what stands in
// for it.
func consoleWriteRoutePatterns() []string {
	d := sweepFixture()
	d.Execution = true

	var out []string
	for _, r := range Routes(d) {
		if isSafeMethod(r.Method) {
			continue
		}
		if !strings.HasPrefix(r.Path, "/console/accounts") && !strings.HasPrefix(r.Path, "/console/api-tokens") &&
			!strings.HasPrefix(r.Path, "/console/new-account") {
			continue
		}
		out = append(out, r.Pattern())
	}
	return out
}

// TestAccountsWrite_EveryWriteRouteIsClassifiedAsGrantingOrReducing is the
// guard that makes "adding a write route without classifying it fails here"
// a fact rather than a comment.
//
// Every mounted write route must appear in grantingActs() or reducingActs().
// A granting entry is swept by
// TestAccountsWrite_EveryGrantingActRefusesWithoutACorrectPassword, which
// proves the route refuses without a correct password and never reaches the
// capability seam; a reducing entry is swept by
// TestAccountsWrite_AReducingActNeedsNoPassword, which proves the opposite
// deliberately. An UNCLASSIFIED route is one that no test has ever asked
// either question of — which is exactly how a route that grants admin with no
// password passes a green package.
//
// The two tables are not a partition, and the dual set is pinned rather than
// waved at: the role route and the enabled route each appear in BOTH, because
// one route raises or lowers depending on what was submitted, and that is the
// only reason either may be classified twice.
func TestAccountsWrite_EveryWriteRouteIsClassifiedAsGrantingOrReducing(t *testing.T) {
	mounted := consoleWriteRoutePatterns()
	if len(mounted) == 0 {
		t.Fatal("Routes mounts no write routes under /console/accounts, /console/new-account or /console/api-tokens — " +
			"the derivation is not running, so this guard is asserting nothing")
	}

	granting := map[string][]string{}
	for _, act := range grantingActs() {
		granting[act.pattern] = append(granting[act.pattern], act.name)
	}
	reducing := map[string][]string{}
	for _, act := range reducingActs() {
		reducing[act.pattern] = append(reducing[act.pattern], act.name)
	}

	for _, pattern := range mounted {
		_, isGranting := granting[pattern]
		_, isReducing := reducing[pattern]
		if !isGranting && !isReducing {
			t.Errorf("Routes mounts %q and neither grantingActs() nor reducingActs() names it. "+
				"Every write route on this screen must be classified: a granting act is proved to "+
				"refuse without a correct password and never reach the capability seam, a reducing "+
				"act is proved to need none. An unclassified write route is one nobody ever asked "+
				"either question of.", pattern)
		}
	}

	// The other direction: a table entry naming a route that is not mounted is
	// a sweep driving a path no request can reach, which reads as coverage and
	// is not.
	for _, table := range []map[string][]string{granting, reducing} {
		for pattern, names := range table {
			if !slices.Contains(mounted, pattern) {
				t.Errorf("the act table names %q (%v), which Routes does not mount — a sweep over "+
					"a route no request reaches is not coverage", pattern, names)
			}
		}
	}

	// The dual routes, pinned by name. A THIRD route claiming to be both would
	// mean some act is classified in two directions at once, which for
	// anything but a raise-or-lower pair is a contradiction, not a nuance.
	var dual []string
	for pattern := range granting {
		if _, ok := reducing[pattern]; ok {
			dual = append(dual, pattern)
		}
	}
	slices.Sort(dual)
	want := []string{setAccountEnabledPattern, setAccountRolePattern}
	slices.Sort(want)
	if !slices.Equal(dual, want) {
		t.Errorf("the routes classified BOTH ways are %v, want %v — only a route whose direction "+
			"depends on what was submitted (raise or lower, enable or disable) may be both",
			dual, want)
	}

	// And the reach sweep's own table, which is hand-maintained for the same
	// reason and would otherwise go stale silently.
	var swept []string
	for _, r := range accountsWriteRoutes() {
		swept = append(swept, r.pattern)
	}
	for _, pattern := range mounted {
		if !slices.Contains(swept, pattern) {
			t.Errorf("accountsWriteRoutes() does not name %q, so the below-admin reach sweep and "+
				"the CSRF sweeps never drive it", pattern)
		}
	}
}

// ---------------------------------------------------------------------------
// "Every granting act refuses without a correct password — and on refusal the
// capability seam is never called."
// ---------------------------------------------------------------------------

func TestAccountsWrite_EveryGrantingActRefusesWithoutACorrectPassword(t *testing.T) {
	refusals := []struct {
		name         string
		stepUpErr    error
		omitPassword bool
		wantStatus   int
	}{
		{name: "no password at all", omitPassword: true, wantStatus: http.StatusUnauthorized},
		{name: "a wrong password", stepUpErr: consoleauth.ErrBadCredentials, wantStatus: http.StatusUnauthorized},
		{name: "a throttled attempt", stepUpErr: &consoleauth.ThrottledError{RetryAfter: 30 * time.Second}, wantStatus: http.StatusTooManyRequests},
		{name: "an ended session", stepUpErr: consoleauth.ErrNoSession, wantStatus: http.StatusUnauthorized},
	}

	// A vacuity pin on THIS sweep's width, and nothing more: it re-reads the
	// table it drives, so it cannot notice a route missing from that table.
	// TestAccountsWrite_EveryWriteRouteIsClassifiedAsGrantingOrReducing is
	// what proves the table covers every write route Routes mounts.
	acts := grantingActs()
	if len(acts) != 4 {
		t.Fatalf("the granting-act table has %d entries, want 4 — four acts cost a password "+
			"(create, raise a role, re-enable, mint) and this sweep is only as wide as the table",
			len(acts))
	}

	for _, act := range acts {
		for _, refusal := range refusals {
			t.Run(act.name+"/"+refusal.name, func(t *testing.T) {
				x := newWriteFix(t, nil)
				x.auth.stepUpErr = refusal.stepUpErr

				form := url.Values{}
				for k, vs := range act.form {
					form[k] = vs
				}
				if !refusal.omitPassword {
					form.Set("password", "whatever the fake rejects")
				}

				rec := x.post(t, act.path(), form)
				if rec.Code != refusal.wantStatus {
					t.Errorf("status = %d, want %d; body %s", rec.Code, refusal.wantStatus, rec.Body.String())
				}
				if got := act.called(x.admin); got != 0 {
					t.Errorf("the capability seam was called %d times — a refused step-up must "+
						"never reach it", got)
				}
			})
		}
	}
}

func TestAccountsWrite_AThrottledStepUpSaysSoAndSaysWhen(t *testing.T) {
	// The mechanics over the fake: Retry-After is present and parseable, and
	// the seam is untouched.
	x := newWriteFix(t, nil)
	x.auth.stepUpErr = &consoleauth.ThrottledError{RetryAfter: 42 * time.Second}

	rec := x.post(t, createAccountAction(), url.Values{
		"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"anything"},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want %q", got, "42")
	}
	if !strings.Contains(rec.Body.String(), "Too many recent attempts") {
		t.Errorf("the throttle does not say what happened: %s", contentOf(rec.Body.String()))
	}
	if len(x.admin.creates) != 0 {
		t.Errorf("CreateAccount was called %d times on a throttled step-up", len(x.admin.creates))
	}

	// And once over the REAL consoleauth.Service and its real throttle, so
	// the number in Retry-After is the real throttle's rather than a fake's.
	realFix := newLoginFixtureWith(t, func(d *Deps) {
		d.Accounts = sweepAccounts()
		d.AccountAdmin = &fakeAccountAdmin{}
		// d.Auth is left as the fixture's REAL consoleauth.Service.
	})
	id, _, err := realFix.svc.Login(context.Background(), consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword(consolePassword), Source: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	session := &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()}
	csrf := realFix.sessions.CSRFToken(id).Reveal()

	post := func(password string) *httptest.ResponseRecorder {
		body := url.Values{
			"csrf_token": {csrf}, "name": {"newbie"}, "kind": {"human"},
			"role": {"viewer"}, "password": {password},
		}
		req := httptest.NewRequest(http.MethodPost, createAccountAction(), strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return realFix.do(t, req, session)
	}

	if rec := post("wrong once"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first wrong password status = %d, want 401", rec.Code)
	}
	// Service.StepUp shares the sign-in throttle keyed by (source, Account):
	// one failure throttles the very next attempt.
	throttled := post(consolePassword)
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body %s", throttled.Code, throttled.Body.String())
	}
	if _, convErr := time.ParseDuration(throttled.Header().Get("Retry-After") + "s"); convErr != nil {
		t.Errorf("Retry-After = %q, which does not parse as a number of seconds", throttled.Header().Get("Retry-After"))
	}
	// throttleMessage (login.go) is the one renderer of this sentence on every
	// Console surface, and it drops the "your password was not checked" clause
	// when the wait rounds to a single second — so the assertion is on what it
	// always says, not on the clause it sometimes adds.
	if !strings.Contains(throttled.Body.String(), "Too many recent attempts") {
		t.Errorf("the throttle does not say what happened: %s", contentOf(throttled.Body.String()))
	}
	if !strings.Contains(throttled.Body.String(), "Nothing was created") {
		t.Errorf("the throttle page does not say the act did not happen: %s", contentOf(throttled.Body.String()))
	}
	admin, _ := realFix.deps.AccountAdmin.(*fakeAccountAdmin)
	if admin == nil || len(admin.creates) != 0 {
		t.Error("the capability seam was reached during a throttled step-up")
	}
}

func TestAccountsWrite_StepUpHappensBeforeTheCapabilityCall(t *testing.T) {
	for _, act := range grantingActs() {
		t.Run(act.name, func(t *testing.T) {
			var order []string
			x := newWriteFix(t, nil)
			x.admin.order = &order
			x.auth.order = &order

			form := url.Values{"password": {"whatever the fake accepts"}}
			for k, vs := range act.form {
				form[k] = vs
			}
			rec := x.post(t, act.path(), form)
			if rec.Code >= 400 {
				t.Fatalf("status = %d, want a success; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			if len(order) != 2 || order[0] != "StepUp" {
				t.Fatalf("call order = %v, want StepUp first then the capability verb", order)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// "Reducing acts succeed without a password — asserted, not assumed."
// ---------------------------------------------------------------------------

func TestAccountsWrite_AReducingActNeedsNoPassword(t *testing.T) {
	for _, tc := range reducingActs() {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			// No password field AT ALL, and a step-up that would fail if one
			// were checked — so a handler that asked would be caught.
			x.auth.stepUpErr = consoleauth.ErrBadCredentials

			rec := x.post(t, tc.path(), tc.form)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			if got := tc.called(x.admin); got != 1 {
				t.Errorf("the capability seam was called %d times, want 1", got)
			}
			if got := len(x.auth.stepUpCalls); got != 0 {
				t.Errorf("StepUp was called %d times on an act that can only reduce — an "+
					"emergency brake that costs a password is one people route around", got)
			}
			if x.auth.requireCalls != 0 {
				t.Errorf("the step-up window was consulted %d times on an act that needs no step-up", x.auth.requireCalls)
			}
		})
	}
}

// TestAccountsWrite_RoleChangeCouldGrantIsExhaustiveAndFailsClosed pins the
// unit that decides a security control, directly rather than only through
// HTTP.
//
// The five invalid spellings are the ones a plan reviewer used to prove the
// property: accounts.Role.AtLeast returns false when EITHER side is invalid,
// so the "natural" spelling (to.AtLeast(from) && to != from) is fail-OPEN in
// every one of these cells — it would read "not a raise" on a corrupt stored
// role and skip the password.
func TestAccountsWrite_RoleChangeCouldGrantIsExhaustiveAndFailsClosed(t *testing.T) {
	valid := []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}
	invalid := []accounts.Role{"", "superadmin", "Admin", "VIEWER", "root"}

	// The nine ordered valid pairs, by hand so the expectation is stated and
	// not re-derived from the implementation.
	wantValid := map[string]bool{
		"viewer->viewer": false, "viewer->operator": true, "viewer->admin": true,
		"operator->viewer": false, "operator->operator": false, "operator->admin": true,
		"admin->viewer": false, "admin->operator": false, "admin->admin": false,
	}
	for _, from := range valid {
		for _, to := range valid {
			key := string(from) + "->" + string(to)
			if got := roleChangeCouldGrant(from, to); got != wantValid[key] {
				t.Errorf("roleChangeCouldGrant(%q, %q) = %v, want %v", from, to, got, wantValid[key])
			}
		}
	}

	all := append(append([]accounts.Role{}, valid...), invalid...)
	invalidCells := 0
	for _, from := range all {
		for _, to := range all {
			if from.Valid() && to.Valid() {
				continue
			}
			invalidCells++
			if !roleChangeCouldGrant(from, to) {
				t.Errorf("roleChangeCouldGrant(%q, %q) = false — an unknown role on either side "+
					"must be treated as a RAISE and cost a password, or a corrupt stored role "+
					"silently skips step-up", from, to)
			}
		}
	}
	if invalidCells != 55 {
		t.Fatalf("the invalid-role sweep covered %d cells, want 55 — the table is not what it claims", invalidCells)
	}
}

func TestAccountsWrite_ARoleReadFailureStillDemandsAPassword(t *testing.T) {
	x := newWriteFix(t, func(d *Deps) {
		a := sweepAccounts()
		a.accountErr = errors.New("the account store is unreachable")
		d.Accounts = a
	})
	x.auth.stepUpErr = consoleauth.ErrBadCredentials

	// A LOWER, which would normally need no password: with the current role
	// unknown the handler must fail closed in the FRICTION direction.
	rec := x.post(t, setAccountRoleAction(targetAdminID), url.Values{
		"role": {"operator"}, "password": {"wrong"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — an unreadable current role must demand a password "+
			"rather than skip it; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if len(x.admin.roles) != 0 {
		t.Error("SetAccountRole was reached despite a failed step-up")
	}

	// It must NOT refuse the act outright: with a correct password the demote
	// still goes through, because a demote during an incident must not be
	// blocked by an unrelated read failure.
	y := newWriteFix(t, func(d *Deps) {
		a := sweepAccounts()
		a.accountErr = errors.New("the account store is unreachable")
		d.Accounts = a
	})
	rec = y.post(t, setAccountRoleAction(targetAdminID), url.Values{
		"role": {"operator"}, "password": {"whatever the fake accepts"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 — a read failure must cost a password, not the act; body %s",
			rec.Code, contentOf(rec.Body.String()))
	}
	if len(y.admin.roles) != 1 {
		t.Errorf("SetAccountRole calls = %d, want 1", len(y.admin.roles))
	}
	// The read failed, so there is no observed role to compare against: this
	// is the one unconditional write, and it is stepped.
	if got := y.admin.roles[0]; got.Conditional {
		t.Errorf("the read-failure write was a compare-and-set %+v, want the unconditional SetAccountRole", got)
	}
}

// The role write is a compare-and-set against the role the handler classified
// from (#912), not an unconditional write.
func TestAccountsWrite_TheRoleWriteComparesAgainstTheRoleItClassifiedFrom(t *testing.T) {
	x := newWriteFix(t, nil)

	rec := x.post(t, setAccountRoleAction(targetAdminID), url.Values{"role": {"operator"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if len(x.admin.roles) != 1 {
		t.Fatalf("role writes = %d, want exactly 1", len(x.admin.roles))
	}
	got := x.admin.roles[0]
	if !got.Conditional || got.From != accounts.RoleAdmin || got.Role != accounts.RoleOperator {
		t.Errorf("role write = %+v, want a compare-and-set from admin to operator", got)
	}
}

func TestAccountsWrite_ARoleChangedRefusalSaysReviewAndRetry(t *testing.T) {
	x := newWriteFix(t, nil)
	x.admin.roleErr = accounts.ErrRoleChanged

	rec := x.post(t, setAccountRoleAction(targetAdminID), url.Values{"role": {"operator"}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	body := contentOf(rec.Body.String())
	if !strings.Contains(body, roleChangedRefusal) {
		t.Errorf("body does not carry the role-changed refusal: %s", body)
	}
	if !strings.Contains(body, "The role was not changed.") {
		t.Errorf("body does not say the role was not changed: %s", body)
	}
	if strings.Contains(body, "could not confirm") {
		t.Errorf("a role-changed refusal fell into the audit-confirmation default: %s", body)
	}
}

// interleavingReader runs afterRead synchronously once the real read has
// returned and before its result reaches the handler: the deterministic
// stand-in for a second admin's committed write landing between the handler's
// classification read and its write.
type interleavingReader struct {
	AccountReader
	afterRead func()
}

func (i *interleavingReader) Account(ctx context.Context, p capability.Principal, id string) (accounts.Account, error) {
	a, err := i.AccountReader.Account(ctx, p, id)
	if f := i.afterRead; f != nil {
		i.afterRead = nil
		f()
	}
	return a, err
}

// TestAccountsWrite_AConcurrentDemotionBetweenClassifyAndWriteIsRefused is the
// acceptance test of #912, on the real chain. The handler reads the target as
// admin, so operator is a LOWER and no password is taken; a second admin then
// demotes the target to viewer; the write that follows would be a raise from
// viewer with no step-up. It must be refused instead.
//
// It also proves the handler calls the compare-and-set: the unconditional path
// would read viewer and write operator, and land.
func TestAccountsWrite_AConcurrentDemotionBetweenClassifyAndWriteIsRefused(t *testing.T) {
	ctx := context.Background()
	var reader *interleavingReader
	x := newRealWriteFix(t, func(d *Deps) {
		reader = &interleavingReader{AccountReader: d.Accounts}
		d.Accounts = reader
	})
	// Three enabled admins, so the last-admin rule cannot interfere.
	if err := x.trail.Accounts().SetRole(ctx, x.target.ID, accounts.RoleOperator, accounts.RoleAdmin); err != nil {
		t.Fatalf("raise the target to admin: %v", err)
	}
	ran := false
	reader.afterRead = func() {
		ran = true
		if err := x.trail.Accounts().SetRole(ctx, x.target.ID, accounts.RoleAdmin, accounts.RoleViewer); err != nil {
			t.Errorf("the concurrent demotion: %v", err)
		}
	}

	// A lower from admin: no password field.
	rec := x.post(t, setAccountRoleAction(x.target.ID), url.Values{"role": {"operator"}})

	if !ran {
		t.Fatal("the interleaved demotion never ran, so this test proved nothing")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if !strings.Contains(contentOf(rec.Body.String()), "changed while you were editing") {
		t.Errorf("body does not say the Account changed: %s", contentOf(rec.Body.String()))
	}
	got, err := x.trail.Accounts().Get(ctx, x.target.ID)
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	if got.Role != accounts.RoleViewer {
		t.Errorf("stored role = %q, want viewer: an unstepped raise landed", got.Role)
	}
	kinds := x.kinds(t)
	for _, k := range []string{audit.KindAccountRole, audit.KindStepUp} {
		if containsKind(kinds, k) {
			t.Errorf("the trail has a %q row after a refused, unstepped write: %v", k, kinds)
		}
	}
}

// TestAccountsWrite_AnUnwiredAccountReaderOffersNothingAndPanicsNowhere is the
// composition-root trap: a Deps with AccountAdmin and Auth wired and Accounts
// NIL is constructible, and the role route is the one that would dereference
// it.
func TestAccountsWrite_AnUnwiredAccountReaderOffersNothingAndPanicsNowhere(t *testing.T) {
	d := renderableDeps()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	d.Accounts = nil

	if accountsOffered(d) {
		t.Error("accountsOffered is true with a nil Accounts seam — the role route reads through it")
	}

	// Each probe carries a VALID body, so the handler is not turned back by
	// its own input validation before it reaches the seam. Without this the
	// role route answers 400 on an empty body, the dereference is never
	// reached, and this test would pass while proving nothing about the
	// panic it is named for — which is the guard-that-under-enforces failure
	// mode this package keeps finding.
	h := newTestHandlerSkippingCSRF(d, accounts.RoleAdmin)
	probes := []struct {
		path string
		form url.Values
	}{
		{createAccountAction(), url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"p"}}},
		{setAccountRoleAction(targetViewerID), url.Values{"role": {"operator"}, "password": {"p"}}},
		{setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}}},
		{mintAPITokenAction(targetOperatorID), url.Values{"name": {"t"}, "ttl": {"30d"}, "password": {"p"}}},
		{revokeAPITokenAction(targetLiveToken), url.Values{}},
	}
	for _, p := range probes {
		rec := postFormSkippingCSRF(t, h, p.path, p.form)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("POST %s = %d, want 500 (unavailable)", p.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "was not wired into this Relay") {
			t.Errorf("POST %s does not render the unwired-seam explanation: %s", p.path, rec.Body.String())
		}
	}

	// The role route by name, with a body that DOES reach the read: it is the
	// one that would nil-dereference if the guard lived only in
	// accountsOffered and not in the handler.
	rec := postFormSkippingCSRF(t, h, setAccountRoleAction(targetViewerID),
		url.Values{"role": {"admin"}, "password": {"p"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("the role route with a nil Accounts seam answered %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "was not wired into this Relay") {
		t.Fatalf("the role route did not render the unwired-seam explanation: %s", rec.Body.String())
	}
}

// postFormSkippingCSRF is postSkippingCSRF with a body, so a probe reaches
// past a handler's own field validation.
func postFormSkippingCSRF(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// "The plaintext appears in the mint response and nowhere else."
// ---------------------------------------------------------------------------

// TestAccountsWrite_TheMintedPlaintextAppearsExactlyOnceAndIsNotCacheable
// covers the SUCCESS path, where the secret actually exists as a plain string.
//
// It captures slog for the duration, because mintedView.LogValue protects the
// VIEW and not the revealed string: a code reviewer added
// `slog.Info(..., "token", secret)` to this branch and every structural guard
// in this file — the exactly-once Reveal count, the LogValue redaction, the
// no-Plaintext-outside-this-file sweep — stayed green. Acceptance criterion 4
// says the plaintext is absent from logs, and this is the only assertion that
// reads a log.
//
// The buffer is legitimately EMPTY today: a successful mint logs nothing. The
// claim is not "something was logged", it is "whatever this request logs, it
// is not the secret" — which is what makes it survive a handler that starts
// logging.
func TestAccountsWrite_TheMintedPlaintextAppearsExactlyOnceAndIsNotCacheable(t *testing.T) {
	var logged bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	x := newWriteFix(t, nil)
	rec := x.post(t, mintAPITokenAction(targetOperatorID), url.Values{
		"name": {"ci-deploy"}, "ttl": {"90d"}, "password": {"whatever the fake accepts"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — mint is the one write route that must NOT "+
			"post-redirect-get, because the plaintext must never enter a URL; body %s",
			rec.Code, contentOf(rec.Body.String()))
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("the mint response carries Location: %q — the plaintext must never enter a URL", loc)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q — this response must not sit in a shared cache "+
			"or come back on a back button", got, "no-store")
	}
	if got := strings.Count(rec.Body.String(), sweepMintedPlaintext); got != 1 {
		t.Errorf("the plaintext appears %d times in the mint response, want exactly 1", got)
	}
	if strings.Contains(logged.String(), sweepMintedPlaintext) {
		t.Errorf("a successful mint wrote the plaintext to the log. The rendered page is the "+
			"ONE place it may appear, and a log line is the one copy nobody revokes:\n%s",
			logged.String())
	}
}

func TestAccountsWrite_TheMintedPlaintextIsAbsentFromEveryLaterRender(t *testing.T) {
	x := newWriteFix(t, nil)
	mint := x.post(t, mintAPITokenAction(targetOperatorID), url.Values{
		"name": {"ci-deploy"}, "ttl": {"never"}, "password": {"whatever the fake accepts"},
	})
	if mint.Code != http.StatusOK {
		t.Fatalf("mint status = %d, want 200; body %s", mint.Code, contentOf(mint.Body.String()))
	}
	if !strings.Contains(mint.Body.String(), sweepMintedPlaintext) {
		t.Fatal("the mint response did not carry the plaintext, so the absence assertion below proves nothing")
	}

	later := x.f.do(t, httptest.NewRequest(http.MethodGet,
		accountPagePath("gleipnir-prod"), nil), x.session)
	body := later.Body.String()
	if later.Code != http.StatusOK {
		t.Fatalf("the later render = %d, want 200", later.Code)
	}
	// Non-vacuity: the page that lists this Account's tokens rendered, so the
	// absences below are absences from a page that could have carried them.
	if !strings.Contains(body, targetLiveToken) {
		t.Fatalf("the later render does not list the live token %s, so the absence checks prove nothing", targetLiveToken)
	}
	if strings.Contains(body, sweepMintedPlaintext) {
		t.Error("the minted plaintext reached a later render of the Accounts screen")
	}
	// The #654 guard, still live on a page that now has forms.
	if strings.Contains(body, sweepTokenSecretHash) {
		t.Error("a token's SecretHash reached the rendered page")
	}
}

// TestAccountsWrite_AFailedMintRendersNoSecretButNamesTheTokenId covers the
// branch that actually occurs: capability.MintAPIToken returns a LIVE token
// and a LIVE plaintext together with a non-nil error when the mint succeeded
// and the audit append failed. fakeAccountAdmin models exactly that — a fake
// returning a zero Plaintext here would prove nothing.
func TestAccountsWrite_AFailedMintRendersNoSecretButNamesTheTokenId(t *testing.T) {
	var logged bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	x := newWriteFix(t, nil)
	x.admin.mintErr = errors.New("capability: record audit entry: the trail is full")

	rec := x.post(t, mintAPITokenAction(targetOperatorID), url.Values{
		"name": {"ci-deploy"}, "ttl": {"30d"}, "password": {"whatever the fake accepts"},
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	body := rec.Body.String()
	if strings.Contains(body, sweepMintedPlaintext) {
		t.Error("a failed mint rendered the plaintext — it must be dropped unrendered")
	}
	if !strings.Contains(body, sweepMintedTokenID) {
		t.Errorf("the failure page does not name the token id, which is the operator's only "+
			"handle on a token that may be live: %s", contentOf(body))
	}
	if !strings.Contains(body, "A token may have been created") {
		t.Errorf("the failure page does not say a token may exist and to check the list: %s", contentOf(body))
	}
	if strings.Contains(body, "Nothing was minted") {
		t.Error("the failure page claims nothing was minted, which this branch cannot back")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q — this page names a token id", got, "no-store")
	}

	out := logged.String()
	if strings.Contains(out, sweepMintedPlaintext) {
		t.Errorf("the plaintext reached the log:\n%s", out)
	}
	if !strings.Contains(out, sweepMintedTokenID) {
		t.Errorf("the token id was not logged — it is the only handle on a live token whose "+
			"secret is gone:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Route shape and reach
// ---------------------------------------------------------------------------

// accountsWriteRoutes is the five patterns paired with a concrete path, so a
// sweep can drive them.
func accountsWriteRoutes() []struct {
	pattern string
	path    string
	method  string
} {
	return []struct {
		pattern string
		path    string
		method  string
	}{
		{createAccountPattern, createAccountAction(), http.MethodPost},
		{setAccountRolePattern, setAccountRoleAction(targetViewerID), http.MethodPost},
		{setAccountEnabledPattern, setAccountEnabledAction(targetViewerID), http.MethodPost},
		{mintAPITokenPattern, mintAPITokenAction(targetOperatorID), http.MethodPost},
		{revokeAPITokenPattern, revokeAPITokenAction(targetLiveToken), http.MethodPost},
	}
}

func TestAccountsWrite_EveryWriteRouteIsAbsentBelowAdmin(t *testing.T) {
	admin := &fakeAccountAdmin{}
	d := sweepFixture()
	d.AccountAdmin = admin
	d.Auth = &fakeAuth{}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		h := newTestHandlerSkippingCSRF(d, role)
		miss := postSkippingCSRF(t, h, "/console/no-such-route")
		missOptions := request(t, h, http.MethodOptions, "/console/no-such-route")

		for _, r := range accountsWriteRoutes() {
			rec := postSkippingCSRF(t, h, r.path)
			if rec.Code != http.StatusNotFound {
				t.Errorf("role %s: POST %s = %d, want 404 (absent, not forbidden)", role, r.path, rec.Code)
				continue
			}
			if got, want := rec.Body.String(), miss.Body.String(); got != want {
				t.Errorf("role %s: POST %s body differs from an unmounted path — the 404 is a "+
					"status-code coincidence rather than byte-identical absence", role, r.path)
			}

			opt := request(t, h, http.MethodOptions, r.path)
			if opt.Code != http.StatusNotFound {
				t.Errorf("role %s: OPTIONS %s = %d, want 404 — the method oracle must not confirm "+
					"the route exists", role, r.path, opt.Code)
				continue
			}
			if got, want := opt.Body.String(), missOptions.Body.String(); got != want {
				t.Errorf("role %s: OPTIONS %s body differs from an unmounted path", role, r.path)
			}
		}
	}

	if n := len(admin.creates) + len(admin.roles) + len(admin.enables) + len(admin.mints) + len(admin.revokes); n != 0 {
		t.Errorf("the capability seam was called %d times by a session below admin", n)
	}
}

func TestAccountsWrite_ABearerLanePostIsRefusedAndNeverWrites(t *testing.T) {
	admin := &fakeAccountAdmin{}
	d := sweepFixture()
	d.AccountAdmin = admin
	d.Auth = &fakeAuth{}
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, r := range accountsWriteRoutes() {
		rec := request(t, h, http.MethodPost, r.path)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s on the bearer lane = %d, want 403", r.path, rec.Code)
		}
	}
	if n := len(admin.creates) + len(admin.roles) + len(admin.enables) + len(admin.mints) + len(admin.revokes); n != 0 {
		t.Errorf("the capability seam was called %d times by a bearer-lane POST", n)
	}
}

func TestAccountsWrite_ARealSessionPostWithNoCSRFTokenIsRefused(t *testing.T) {
	x := newWriteFix(t, nil)
	for _, r := range accountsWriteRoutes() {
		req := httptest.NewRequest(http.MethodPost, r.path, strings.NewReader("role=viewer&enabled=false"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := x.f.do(t, req, x.session)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with no CSRF token = %d, want 403", r.path, rec.Code)
		}
	}
	if n := len(x.admin.creates) + len(x.admin.roles) + len(x.admin.enables) + len(x.admin.mints) + len(x.admin.revokes); n != 0 {
		t.Errorf("the capability seam was called %d times without a CSRF token", n)
	}
}

func TestAccountsWrite_ARealSessionPostWithTheWrongCSRFTokenIsRefused(t *testing.T) {
	x := newWriteFix(t, nil)
	for _, r := range accountsWriteRoutes() {
		body := url.Values{"csrf_token": {"not-this-session-s-token"}, "role": {"viewer"}, "enabled": {"false"}}
		req := httptest.NewRequest(http.MethodPost, r.path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := x.f.do(t, req, x.session)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with the wrong CSRF token = %d, want 403", r.path, rec.Code)
		}
	}
	if n := len(x.admin.creates) + len(x.admin.roles) + len(x.admin.enables) + len(x.admin.mints) + len(x.admin.revokes); n != 0 {
		t.Errorf("the capability seam was called %d times with the wrong CSRF token", n)
	}
}

// TestAccountsWrite_MissingConsoleSessionFailsClosed pins stepUpProved's own
// ConsoleSessionFromContext branch directly.
//
// In a production-shaped mux this branch is unreachable: Secure refuses every
// bearer-lane POST before routing, which the test above proves. This one
// therefore goes AROUND Secure, via newTestHandlerSkippingCSRF, which never
// wires console sessions into its Authenticator at all. It must NOT be
// "fixed" by routing through the CSRF-checked handler, which would make it
// stop testing this branch.
func TestAccountsWrite_MissingConsoleSessionFailsClosed(t *testing.T) {
	admin := &fakeAccountAdmin{}
	d := sweepFixture()
	d.AccountAdmin = admin
	d.Auth = &fakeAuth{}
	h := newTestHandlerSkippingCSRF(d, accounts.RoleAdmin)

	// A granting act with a password present: only the missing session can
	// refuse it, so a 500 here is that branch and nothing else.
	req := httptest.NewRequest(http.MethodPost, createAccountAction(),
		strings.NewReader("name=newbie&kind=human&role=viewer&password=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	if len(admin.creates) != 0 {
		t.Errorf("CreateAccount was called %d times with no resolvable session", len(admin.creates))
	}
}

// ---------------------------------------------------------------------------
// Rendering and copy
// ---------------------------------------------------------------------------

// accountsWriteBody renders an Accounts page with the write half wired.
func accountsWriteBody(t *testing.T, path string) string {
	t.Helper()
	d := sweepFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

// TestAccountsWrite_TheStateControlAsymmetryIsInTheMarkup: the step-up matrix
// is visible in the HTML, not only in the handler. An enabled row's Disable
// control has no password field; a disabled row's Enable form has one.
func TestAccountsWrite_TheStateControlAsymmetryIsInTheMarkup(t *testing.T) {
	// The controls render only in the selected Account's panel (#830). The
	// reducing controls GET their confirmation page; the POST form, and the
	// enabled=false it submits, are on that page.
	disable := formWithAction(t, accountsWriteBody(t, accountPagePath("ana")), confirmDisableAction(targetViewerID))
	if strings.Contains(disable, `type="password"`) {
		t.Errorf("the Disable control carries a password field — disabling is the durable "+
			"off-switch and can only reduce:\n%s", disable)
	}
	if !strings.Contains(disable, `method="get"`) {
		t.Errorf("the Disable control does not GET its confirmation page:\n%s", disable)
	}
	confirm := contentOf(accountsConfirmBody(t, confirmDisableAction(targetViewerID)))
	if strings.Contains(confirm, `type="password"`) {
		t.Errorf("the Disable confirmation carries a password field:\n%s", confirm)
	}
	if !strings.Contains(confirm, `value="false"`) {
		t.Errorf("the Disable confirmation does not submit enabled=false:\n%s", confirm)
	}

	enable := formWithAction(t, accountsWriteBody(t, accountPagePath("retired-ci")), setAccountEnabledAction(targetDisabledID))
	if !strings.Contains(enable, `type="password"`) {
		t.Errorf("the Enable form carries no password field — re-enabling a disabled Account "+
			"is privilege-granting:\n%s", enable)
	}
	if !strings.Contains(enable, `value="true"`) {
		t.Errorf("the Enable form does not submit enabled=true:\n%s", enable)
	}

	// And the revoke control, which is also a reducing act.
	revoke := formWithAction(t, accountsWriteBody(t, accountPagePath("gleipnir-prod")),
		confirmRevokeAction(targetOperatorID, targetLiveToken))
	if strings.Contains(revoke, `type="password"`) {
		t.Errorf("the Revoke control carries a password field — revocation is the incident "+
			"instrument and only ever reduces:\n%s", revoke)
	}
	if !strings.Contains(revoke, `method="get"`) {
		t.Errorf("the Revoke control does not GET its confirmation page:\n%s", revoke)
	}
}

// TestAccountsWrite_TheListPostsNothing: the list carries no POST form, no
// role form and no Enable POST. Its only forms are Disable GETs to the
// confirmation page, marked from=list. Create lives on the New account page.
func TestAccountsWrite_TheListPostsNothing(t *testing.T) {
	body := accountsWriteBody(t, accountsScreenPath)
	content := contentOf(body)
	if len(formsWithMethod(content, "post")) != 0 {
		t.Errorf("the list carries a POST form:\n%s", content)
	}
	for _, a := range sweepAccounts().accounts {
		for _, action := range []string{
			setAccountRoleAction(a.ID), setAccountEnabledAction(a.ID), confirmLowerRoleAction(a.ID),
		} {
			if strings.Contains(body, `action="`+action+`"`) {
				t.Errorf("the list carries a form posting to %s", action)
			}
		}
	}
	disables := 0
	for _, form := range formsWithMethod(content, "get") {
		disables++
		if !strings.Contains(form, `<input type="hidden" name="from" value="list">`) ||
			!strings.Contains(form, `aria-label="Disable `) || !strings.Contains(form, `/disable"`) {
			t.Errorf("a form on the list is not a row's Disable carrying from=list:\n%s", form)
		}
	}
	if disables == 0 {
		t.Error("the list offers no Disable at all")
	}
	if strings.Contains(body, `action="`+createAccountAction()+`"`) {
		t.Error("the create form is on the list; it belongs to the New account page")
	}
	if !strings.Contains(body, `href="`+newAccountPath+`"`) {
		t.Error("the list does not link to the New account page")
	}
	if !strings.Contains(accountsWriteBody(t, newAccountPath), `action="`+createAccountAction()+`"`) {
		t.Error("the create form is not on the New account page")
	}
}

// TestAccountsWrite_EveryRoleSelectPreselectsTheCurrentRoleAndCannotSubmitIt:
// each role-change form shows the Account's current role as a disabled,
// empty-value placeholder in a required select, so a browser will not submit
// it and a non-validating client posts no role at all (#830).
func TestAccountsWrite_EveryRoleSelectPreselectsTheCurrentRoleAndCannotSubmitIt(t *testing.T) {
	cases := []struct {
		query, id, role string
		raise, lower    bool
	}{
		{accountPagePath("ana"), targetViewerID, "viewer", true, false},
		{accountPagePath("mike"), targetAdminID, "admin", false, true},
		{accountPagePath("gleipnir-prod"), targetOperatorID, "operator", true, true},
	}
	for _, tc := range cases {
		body := accountsWriteBody(t, tc.query)
		// Raise posts to the role route; Lower GETs its confirmation page.
		forms := regexp.MustCompile(`(?s)<form[^>]*action="(?:`+regexp.QuoteMeta(setAccountRoleAction(tc.id))+`|`+
			regexp.QuoteMeta(confirmLowerRoleAction(tc.id))+`)".*?</form>`).
			FindAllString(body, -1)
		if len(forms) == 0 {
			t.Fatalf("%s: no role form found for %s", tc.query, tc.id)
		}
		var raise, lower int
		for _, f := range forms {
			if strings.Contains(f, `type="password"`) {
				if !strings.Contains(f, `<select name="role" required>`) {
					t.Errorf("%s: the Raise role select is not required:\n%s", tc.query, f)
				}
			} else {
				if !strings.Contains(f, `<select name="role" aria-describedby="lower-role-hint">`) {
					t.Errorf("%s: the Lower role select does not point at its hint:\n%s", tc.query, f)
				}
				if strings.Contains(f, "required") {
					t.Errorf("%s: the Lower role form is required, so it can be invalid and dim:\n%s", tc.query, f)
				}
			}
			if got := len(regexp.MustCompile(`<option[^>]* selected`).FindAllString(f, -1)); got != 1 {
				t.Errorf("%s: %d selected options, want exactly 1:\n%s", tc.query, got, f)
			}
			if !strings.Contains(f, `<option value="" selected disabled>`+tc.role+` (current)</option>`) {
				t.Errorf("%s: the current role is not the disabled placeholder:\n%s", tc.query, f)
			}
			if strings.Contains(f, `<option value="`+tc.role+`"`) {
				t.Errorf("%s: the current role is offered as a target:\n%s", tc.query, f)
			}
			if strings.Contains(f, `type="password"`) {
				raise++
			} else {
				lower++
			}
		}
		if (raise == 1) != tc.raise || (lower == 1) != tc.lower || raise > 1 || lower > 1 {
			t.Errorf("%s: %d Raise and %d Lower forms, want raise=%v lower=%v",
				tc.query, raise, lower, tc.raise, tc.lower)
		}
	}
}

// TestAccountsWrite_TheSignedInAccountsPanelSaysWhyItCannotChange: the
// signed-in Account's own page offers no role or state control and states the
// capability layer's refusal instead; its API Tokens stay manageable.
func TestAccountsWrite_TheSignedInAccountsPanelSaysWhyItCannotChange(t *testing.T) {
	d := sweepFixture()
	fa := sweepAccounts()
	fa.accounts = append(fa.accounts, accounts.Account{
		ID: testAccountID(accounts.RoleAdmin), Name: testAccountName(accounts.RoleAdmin),
		Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	d.Accounts = fa
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}

	self := testAccountID(accounts.RoleAdmin)
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), accountPagePath(testAccountName(accounts.RoleAdmin)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, template.HTMLEscapeString(selfPanelNote)) {
		t.Errorf("the panel does not say why it cannot change:\n%s", contentOf(body))
	}
	for _, action := range []string{
		setAccountRoleAction(self), setAccountEnabledAction(self),
		confirmLowerRoleAction(self), confirmDisableAction(self),
	} {
		if strings.Contains(body, `action="`+action+`"`) {
			t.Errorf("the signed-in Account's panel offers a form posting to %s", action)
		}
	}
	if !strings.Contains(body, `action="`+mintAPITokenAction(self)+`"`) {
		t.Error("the signed-in Account's panel lost its mint form")
	}
}

// formWithAction extracts the <form> element whose action is exactly action.
func formWithAction(t *testing.T, body, action string) string {
	t.Helper()
	marker := `action="` + action + `"`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no form posts to %s:\n%s", action, contentOf(body))
	}
	start := strings.LastIndex(body[:i], "<form")
	if start < 0 {
		t.Fatalf("the action %s is not inside a <form>", action)
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		t.Fatalf("the form posting to %s is not closed", action)
	}
	return body[start : start+end]
}

func TestAccountsWrite_TheMintFormOffersNoFreeFormTTL(t *testing.T) {
	body := accountsWriteBody(t, accountPagePath("gleipnir-prod"))
	form := formWithAction(t, body, mintAPITokenAction(targetOperatorID))

	if !strings.Contains(form, `<select id="mint-ttl" name="ttl">`) {
		t.Errorf("the lifetime control is not a closed select:\n%s", form)
	}
	if strings.Contains(form, `name="ttl" type="number"`) || strings.Contains(form, `name="ttl_seconds"`) {
		t.Errorf("the lifetime control is free-form — a forgotten field must never silently "+
			"mint an immortal credential:\n%s", form)
	}
	for _, c := range ttlChoices {
		if !strings.Contains(form, `value="`+c.Value+`"`) {
			t.Errorf("the lifetime select does not offer %q", c.Value)
		}
	}
	if strings.Contains(form, "selected") {
		t.Errorf("an option is pre-selected — a lifetime must be chosen, not defaulted:\n%s", form)
	}

	// And the handler half: an absent or unrecognised ttl is a 400 that mints
	// nothing.
	for _, ttl := range []string{"", "forever", "0", "86400"} {
		x := newWriteFix(t, nil)
		form := url.Values{"name": {"ci-deploy"}, "password": {"whatever the fake accepts"}}
		if ttl != "" {
			form.Set("ttl", ttl)
		}
		rec := x.post(t, mintAPITokenAction(targetOperatorID), form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("ttl=%q: status = %d, want 400", ttl, rec.Code)
		}
		if len(x.admin.mints) != 0 {
			t.Errorf("ttl=%q: the mint seam was called", ttl)
		}
	}
}

// TestAccountsWrite_TheNewAccountPageSaysNothingAboutPasswords: the OAuth
// sentence the create panel once carried is deleted, and no surface that sets
// a Console password is offered here.
func TestAccountsWrite_TheNewAccountPageSaysNothingAboutPasswords(t *testing.T) {
	for _, path := range []string{accountsScreenPath, newAccountPath} {
		body := contentOf(accountsWriteBody(t, path))
		if strings.Contains(body, "Console password") || strings.Contains(body, "OAuth") {
			t.Errorf("%s still speaks of a Console password or OAuth:\n%s", path, body)
		}
	}
}

// TestAccountsWrite_TheSelfTargetAndLastAdminRefusalsAreExplicit: spec 15's
// "States" asks that these two be said rather than hidden. The sentences are
// OUR wording — spec 15 asks for explicitness, not for particular words — and
// the test compares against the package consts rather than a copy of the
// prose.
func TestAccountsWrite_TheSelfTargetAndLastAdminRefusalsAreExplicit(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		want  string
		path  string
		form  url.Values
		apply func(*fakeAccountAdmin, error)
	}{
		{
			name:  "self-targeted role change",
			err:   capability.ErrSelfTargeted,
			want:  selfTargetRefusal,
			path:  setAccountRoleAction(targetAdminID),
			form:  url.Values{"role": {"operator"}},
			apply: func(a *fakeAccountAdmin, err error) { a.roleErr = err },
		},
		{
			name:  "self-targeted disable",
			err:   capability.ErrSelfTargeted,
			want:  selfTargetRefusal,
			path:  setAccountEnabledAction(targetAdminID),
			form:  url.Values{"enabled": {"false"}},
			apply: func(a *fakeAccountAdmin, err error) { a.enableErr = err },
		},
		{
			name:  "demoting the last admin",
			err:   accounts.ErrLastAdmin,
			want:  lastAdminRefusal,
			path:  setAccountRoleAction(targetAdminID),
			form:  url.Values{"role": {"operator"}},
			apply: func(a *fakeAccountAdmin, err error) { a.roleErr = err },
		},
		{
			name:  "disabling the last admin",
			err:   accounts.ErrLastAdmin,
			want:  lastAdminRefusal,
			path:  setAccountEnabledAction(targetAdminID),
			form:  url.Values{"enabled": {"false"}},
			apply: func(a *fakeAccountAdmin, err error) { a.enableErr = err },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			tc.apply(x.admin, tc.err)

			rec := x.post(t, tc.path, tc.form)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Errorf("the refusal is not the explicit sentence:\n%s", contentOf(body))
			}
			if strings.Contains(body, "could not confirm") {
				t.Error("the refusal fell through to the generic could-not-confirm sentence")
			}
		})
	}
}

func TestAccountsWrite_ACapabilityRefusalIsRenderedNotReinterpreted(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		form  url.Values
		apply func(*fakeAccountAdmin, error)
	}{
		{"create", createAccountAction(), url.Values{"name": {"n"}, "kind": {"human"}, "role": {"viewer"}},
			func(a *fakeAccountAdmin, err error) { a.createErr = err }},
		{"role", setAccountRoleAction(targetViewerID), url.Values{"role": {"admin"}},
			func(a *fakeAccountAdmin, err error) { a.roleErr = err }},
		{"enabled", setAccountEnabledAction(targetDisabledID), url.Values{"enabled": {"true"}},
			func(a *fakeAccountAdmin, err error) { a.enableErr = err }},
		{"mint", mintAPITokenAction(targetOperatorID), url.Values{"name": {"t"}, "ttl": {"30d"}},
			func(a *fakeAccountAdmin, err error) { a.mintErr = err }},
		{"revoke", revokeAPITokenAction(targetLiveToken), url.Values{},
			func(a *fakeAccountAdmin, err error) { a.revokeErr = err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			tc.apply(x.admin, authz.ErrUnauthorized)

			form := url.Values{"password": {"whatever the fake accepts"}}
			for k, vs := range tc.form {
				form[k] = vs
			}
			rec := x.post(t, tc.path, form)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			if !strings.Contains(rec.Body.String(), authz.ErrUnauthorized.Error()) {
				t.Errorf("the refusal does not carry the capability layer's own text:\n%s",
					contentOf(rec.Body.String()))
			}
		})
	}
}

// TestAccountsWrite_AnUnchangedOrMissingRoleIsRefusedAndNeverWrites: a role
// the target already holds, or none at all, is a 400 that reaches neither the
// step-up nor the capability layer (#830).
func TestAccountsWrite_AnUnchangedOrMissingRoleIsRefusedAndNeverWrites(t *testing.T) {
	x := newWriteFix(t, nil)
	for _, tc := range []struct {
		name string
		id   string
		form url.Values
	}{
		{"admin to admin", targetAdminID, url.Values{"role": {"admin"}}},
		{"viewer to viewer", targetViewerID, url.Values{"role": {"viewer"}, "password": {"p"}}},
		{"no role", targetViewerID, url.Values{}},
		{"empty role field", targetAdminID, url.Values{"role": {""}}},
	} {
		rec := x.post(t, setAccountRoleAction(tc.id), tc.form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body %s", tc.name, rec.Code, contentOf(rec.Body.String()))
		}
		body := rec.Body.String()
		want := "That is already this Account&#39;s role"
		if strings.HasPrefix(tc.name, "no role") || strings.HasPrefix(tc.name, "empty") {
			want = template.HTMLEscapeString("No role was chosen: " + lowerRoleHint + ".")
		}
		if !strings.Contains(body, want) {
			t.Errorf("%s: the refusal does not say %q:\n%s", tc.name, want, contentOf(body))
		}
	}
	if len(x.admin.roles) != 0 {
		t.Errorf("SetAccountRole was called %d times for a refused request", len(x.admin.roles))
	}
	if len(x.auth.stepUpCalls) != 0 {
		t.Errorf("step-up was attempted %d times for a refused request", len(x.auth.stepUpCalls))
	}
}

// ---------------------------------------------------------------------------
// The real lane: no fakes on the path under test
// ---------------------------------------------------------------------------

// realWriteFix wires the Console's write half over a REAL store, a real
// accounts.TokenService, a real capability.AccountAdmin (with the real RoleGate and
// a real auditsink over a real trail) and a real consoleauth.Service.
//
// It exists because three of this issue's acceptance criteria cannot be proved
// against a fake: that revoking through the Console cuts the next request
// carrying the token; that each write records ITS OWN audit kind; and that a
// granting act writes a step_up event while a reducing one does not.
type realWriteFix struct {
	handler  http.Handler
	trail    *store.Store
	tokens   *accounts.TokenService
	actor    accounts.Account
	target   accounts.Account
	sessions *consoleauth.Store
	svc      *consoleauth.Service
	clk      *testClock
	session  *http.Cookie
	csrf     string
}

const realWritePassword = "a real console password"

func newRealWriteFix(t *testing.T, opts ...func(*Deps)) *realWriteFix {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Two admins, so the last-enabled-admin guard does not refuse a change to
	// either — that rule is the store's and is not what these tests are about.
	actor, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create acting account: %v", err)
	}
	if _, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "second-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatalf("create second admin: %v", err)
	}
	target, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "gleipnir-prod", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create target account: %v", err)
	}

	hash, err := accounts.HashPassword(accounts.NewPassword(realWritePassword))
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, actor.ID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}

	sink := auditsink.New(st.Audit())
	tokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	capSvc := newCapService(capSeams{
		reg:           registry.NewInMemory(),
		authz:         authz.NewRoleGate(),
		audit:         sink,
		accountsStore: st.Accounts(),
		apiTokens:     tokenSvc,
	})

	clk := &testClock{t: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	sessions := consoleauth.NewStore(consoleauth.WithClock(clk.now))
	svc := consoleauth.NewService(st.Accounts(), st.Passwords(), sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now)), sink)

	authn := controlplane.NewAuthenticator(
		tokenSvc,
		controlplane.WithConsoleSessions(svc, controlplane.ConsoleSessionOptions{
			Public:       Unauthenticated,
			Scope:        SessionScope,
			Unauthorized: UnauthorizedHandler(),
		}),
	)
	mux := http.NewServeMux()
	d := renderableDeps()
	d.Auth = svc
	d.Accounts = capSvc.AccountAdmin
	d.AccountAdmin = capSvc.AccountAdmin
	for _, opt := range opts {
		opt(&d)
	}
	Register(mux, d)

	id, _, err := svc.Login(ctx, consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword(realWritePassword), Source: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}

	return &realWriteFix{
		handler:  authn.Middleware(Secure(mux, nil)),
		trail:    st,
		tokens:   tokenSvc,
		actor:    actor,
		target:   target,
		sessions: sessions,
		svc:      svc,
		clk:      clk,
		session:  &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()},
		csrf:     sessions.CSRFToken(id).Reveal(),
	}
}

func (x *realWriteFix) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{"csrf_token": {x.csrf}}
	for k, vs := range form {
		body[k] = vs
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(x.session)
	rec := httptest.NewRecorder()
	x.handler.ServeHTTP(rec, req)
	x.followSessionCookie(rec)
	return rec
}

// get renders path with the fixture's current session, following any rotated
// cookie exactly as post does.
func (x *realWriteFix) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(x.session)
	rec := httptest.NewRecorder()
	x.handler.ServeHTTP(rec, req)
	x.followSessionCookie(rec)
	return rec
}

// followSessionCookie does what a browser does when a response sets the
// session cookie: it keeps the new value, and the CSRF token that derives from
// it. A step-up rotates the session id, so every later request must carry the
// new pair. A CLEARING Set-Cookie (empty value or MaxAge < 0) is not followed:
// it would replace a live session with nothing.
func (x *realWriteFix) followSessionCookie(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.Name != consoleauth.SessionCookieName || c.Value == "" || c.MaxAge < 0 {
			continue
		}
		x.session = &http.Cookie{Name: consoleauth.SessionCookieName, Value: c.Value}
		x.csrf = x.sessions.CSRFToken(consoleauth.ParseSessionID(c.Value)).Reveal()
	}
}

// records returns the whole trail, oldest first.
func (x *realWriteFix) records(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := x.trail.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	return recs
}

// kinds returns every audit kind on the trail, oldest first.
func (x *realWriteFix) kinds(t *testing.T) []string {
	t.Helper()
	recs := x.records(t)
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Kind)
	}
	return out
}

// mintedTokenPattern extracts the plaintext from a mint response body — the
// <code> element the reveal-once page renders it in.
func scrapeMintedToken(t *testing.T, body string) string {
	t.Helper()
	const open = "<code>" + accounts.TokenPrefix
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("the mint response carries no token:\n%s", contentOf(body))
	}
	rest := body[i+len("<code>"):]
	j := strings.Index(rest, "</code>")
	if j < 0 {
		t.Fatal("the token element is not closed")
	}
	return rest[:j]
}

// TestAccountsWrite_RevokingCutsTheNextRequestCarryingTheToken is the
// acceptance criterion, end to end over the real chain with no fake on the
// path under test.
//
// The scrape-then-verify ordering is what makes this prove the RENDERED
// credential is the real one, rather than a string the test invented.
func TestAccountsWrite_RevokingCutsTheNextRequestCarryingTheToken(t *testing.T) {
	x := newRealWriteFix(t)
	ctx := context.Background()

	mint := x.post(t, mintAPITokenAction(x.target.ID), url.Values{
		"name": {"ci-deploy"}, "ttl": {"90d"}, "password": {realWritePassword},
	})
	if mint.Code != http.StatusOK {
		t.Fatalf("mint status = %d, want 200; body %s", mint.Code, contentOf(mint.Body.String()))
	}
	credential := scrapeMintedToken(t, mint.Body.String())

	acct, tok, err := x.tokens.Verify(ctx, credential)
	if err != nil {
		t.Fatalf("the rendered credential does not verify: %v", err)
	}
	if acct.ID != x.target.ID {
		t.Fatalf("the credential authenticates as %s, want %s", acct.ID, x.target.ID)
	}

	revoke := x.post(t, revokeAPITokenAction(tok.ID), nil)
	if revoke.Code != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303; body %s", revoke.Code, contentOf(revoke.Body.String()))
	}

	if _, _, err := x.tokens.Verify(ctx, credential); !errors.Is(err, accounts.ErrTokenInvalid) {
		t.Fatalf("after revocation Verify returned %v, want accounts.ErrTokenInvalid — revocation "+
			"must cut the NEXT request carrying the token", err)
	}
}

// TestAccountsWrite_EveryWriteRecordsItsOwnAuditKindThroughTheRealLane is what
// stops the five read-audit exemptions' `why` strings from being unfalsifiable
// prose: each names a capability audit kind, and each kind is asserted to come
// out of the REAL sink, attributed to the signed-in Account.
func TestAccountsWrite_EveryWriteRecordsItsOwnAuditKindThroughTheRealLane(t *testing.T) {
	x := newRealWriteFix(t)

	steps := []struct {
		name string
		path string
		form url.Values
		kind string
	}{
		{"create", createAccountAction(),
			url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {realWritePassword}},
			audit.KindAccountCreate},
		{"raise a role", setAccountRoleAction(x.target.ID),
			url.Values{"role": {"admin"}, "password": {realWritePassword}},
			audit.KindAccountRole},
		{"disable", setAccountEnabledAction(x.target.ID),
			url.Values{"enabled": {"false"}},
			audit.KindAccountDisable},
		{"re-enable", setAccountEnabledAction(x.target.ID),
			url.Values{"enabled": {"true"}, "password": {realWritePassword}},
			audit.KindAccountEnable},
		{"mint", mintAPITokenAction(x.target.ID),
			url.Values{"name": {"ci-deploy"}, "ttl": {"30d"}, "password": {realWritePassword}},
			audit.KindAPITokenMint},
	}

	var mintedTokenID string
	for _, s := range steps {
		rec := x.post(t, s.path, s.form)
		if rec.Code >= 400 {
			t.Fatalf("%s: status = %d; body %s", s.name, rec.Code, contentOf(rec.Body.String()))
		}
		if s.kind == audit.KindAPITokenMint {
			credential := scrapeMintedToken(t, rec.Body.String())
			_, tok, err := x.tokens.Verify(context.Background(), credential)
			if err != nil {
				t.Fatalf("the minted credential does not verify: %v", err)
			}
			mintedTokenID = tok.ID
		}
	}
	if rec := x.post(t, revokeAPITokenAction(mintedTokenID), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: status = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}

	got := x.kinds(t)
	for _, want := range []string{
		audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountDisable,
		audit.KindAccountEnable, audit.KindAPITokenMint, audit.KindAPITokenRevoke,
	} {
		if !containsKind(got, want) {
			t.Errorf("the trail carries no %s record. The read-audit exemption for this route "+
				"names that kind, and an exemption whose claim is never checked is prose.\ngot %v",
				want, got)
		}
	}

	// Attributed to the signed-in Account, not to nobody. Every one of the
	// six, not just the first found: an unattributed administrative row is an
	// audit trail that cannot answer "who".
	attributed := 0
	for _, r := range x.records(t) {
		if !containsKind([]string{
			audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountDisable,
			audit.KindAccountEnable, audit.KindAPITokenMint, audit.KindAPITokenRevoke,
		}, r.Kind) {
			continue
		}
		attributed++
		if r.Attribution.Verified.AccountID != x.actor.ID {
			t.Errorf("the %s record is attributed to %q, want the signed-in Account %q",
				r.Kind, r.Attribution.Verified.AccountID, x.actor.ID)
		}
	}
	if attributed != 6 {
		t.Errorf("found %d administrative records to attribute, want 6", attributed)
	}
}

// TestAccountsWrite_SelfDemoteAndSelfDisableAreRefusedThroughTheRealCapabilityLayer
// proves the Console reaches the capability seam with a populated
// Principal.AccountID on the real session lane (#830): a hand-built POST to
// change or disable the signed-in Account is refused with the capability
// layer's own sentence, audited as a refusal, and writes nothing. The same-role
// case shows the Console's unchanged-role refusal does not pre-empt it.
func TestAccountsWrite_SelfDemoteAndSelfDisableAreRefusedThroughTheRealCapabilityLayer(t *testing.T) {
	x := newRealWriteFix(t)
	ctx := context.Background()
	want := template.HTMLEscapeString(selfTargetRefusal)

	for _, tc := range []struct {
		name string
		path string
		form url.Values
	}{
		{"demote", setAccountRoleAction(x.actor.ID), url.Values{"role": {"operator"}}},
		{"same role", setAccountRoleAction(x.actor.ID), url.Values{"role": {"admin"}, "password": {realWritePassword}}},
		{"disable", setAccountEnabledAction(x.actor.ID), url.Values{"enabled": {"false"}}},
	} {
		rec := x.post(t, tc.path, tc.form)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s: status = %d, want 409; body %s", tc.name, rec.Code, contentOf(rec.Body.String()))
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: the refusal is not the capability layer's sentence:\n%s", tc.name, contentOf(rec.Body.String()))
		}
	}

	got, err := x.trail.Accounts().Get(ctx, x.actor.ID)
	if err != nil {
		t.Fatalf("re-read the acting Account: %v", err)
	}
	if got.Role != accounts.RoleAdmin || !got.Enabled {
		t.Errorf("the acting Account is now %s, enabled=%v — a refused act wrote", got.Role, got.Enabled)
	}
	kinds := x.kinds(t)
	refusals := 0
	for _, k := range kinds {
		if k == audit.KindRefusal {
			refusals++
		}
	}
	if refusals != 3 {
		t.Errorf("trail carries %d refusal records, want exactly one per refused request (3): %v", refusals, kinds)
	}
	for _, k := range []string{audit.KindAccountRole, audit.KindAccountDisable} {
		if containsKind(kinds, k) {
			t.Errorf("the trail carries a %s record for a refused act: %v", k, kinds)
		}
	}
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

// TestAccountsWrite_AGrantingActAlsoWritesAStepUpEvent — and the NEGATIVE half
// is the point. It is what keeps the revoke and disable exemptions' wording
// honest, and why those two rows claim no step_up event.
//
// Every claim the five read-audit rows make about step_up is asserted here on
// the real lane, positive AND negative, because two of those rows make a
// CONDITIONAL claim — step_up on a raise but not a lower, on an enable but not
// a disable — and a conditional claim half-asserted is a claim about nothing.
func TestAccountsWrite_AGrantingActAlsoWritesAStepUpEvent(t *testing.T) {
	t.Run("a create writes both account_create and step_up", func(t *testing.T) {
		x := newRealWriteFix(t)
		rec := x.post(t, createAccountAction(), url.Values{
			"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {realWritePassword},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		got := x.kinds(t)
		for _, want := range []string{audit.KindAccountCreate, audit.KindStepUp} {
			if !containsKind(got, want) {
				t.Errorf("the trail carries no %s record; got %v", want, got)
			}
		}
	})

	t.Run("a raise writes account_role and step_up", func(t *testing.T) {
		x := newRealWriteFix(t)
		// The target is an operator; admin is a raise.
		rec := x.post(t, setAccountRoleAction(x.target.ID), url.Values{
			"role": {"admin"}, "password": {realWritePassword},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		got := x.kinds(t)
		for _, want := range []string{audit.KindAccountRole, audit.KindStepUp} {
			if !containsKind(got, want) {
				t.Errorf("the trail carries no %s record. The role route's read-audit row claims "+
					"a step_up when the change RAISES the role; this is that half.\ngot %v", want, got)
			}
		}
	})

	t.Run("a lower writes account_role and NO step_up", func(t *testing.T) {
		x := newRealWriteFix(t)
		// The target is an operator; viewer is a lower, and no password field
		// is submitted at all.
		rec := x.post(t, setAccountRoleAction(x.target.ID), url.Values{"role": {"viewer"}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		got := x.kinds(t)
		if !containsKind(got, audit.KindAccountRole) {
			t.Errorf("the trail carries no account_role record; got %v", got)
		}
		if containsKind(got, audit.KindStepUp) {
			t.Errorf("lowering a role wrote a step_up event. A demote costs no password (owner "+
				"decision 2026-09-19) and the role route's read-audit row says so.\ngot %v", got)
		}
	})

	t.Run("an enable writes account_enable and step_up, the disable before it neither", func(t *testing.T) {
		x := newRealWriteFix(t)
		if rec := x.post(t, setAccountEnabledAction(x.target.ID), url.Values{"enabled": {"false"}}); rec.Code != http.StatusSeeOther {
			t.Fatalf("disable status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		// The disable half of the enabled route's read-audit row, asserted
		// here so the enable assertion below cannot be satisfied by a step_up
		// the disable wrote.
		if containsKind(x.kinds(t), audit.KindStepUp) {
			t.Fatalf("disabling wrote a step_up event; got %v", x.kinds(t))
		}

		rec := x.post(t, setAccountEnabledAction(x.target.ID), url.Values{
			"enabled": {"true"}, "password": {realWritePassword},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("enable status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		got := x.kinds(t)
		for _, want := range []string{audit.KindAccountEnable, audit.KindStepUp} {
			if !containsKind(got, want) {
				t.Errorf("the trail carries no %s record. The enabled route's read-audit row "+
					"claims a step_up on the ENABLE only; this is that half.\ngot %v", want, got)
			}
		}
	})

	t.Run("a revoke writes api_token_revoke and NO step_up", func(t *testing.T) {
		x := newRealWriteFix(t)
		_, _, err := x.tokens.Mint(context.Background(), x.target.ID, "ci-deploy", time.Hour)
		if err != nil {
			t.Fatalf("mint a token to revoke: %v", err)
		}
		toks, err := x.tokens.List(context.Background(), x.target.ID)
		if err != nil || len(toks) == 0 {
			t.Fatalf("list tokens: %v (%d)", err, len(toks))
		}

		before := x.kinds(t)
		if containsKind(before, audit.KindStepUp) {
			t.Fatalf("the trail already carries a step_up before the revoke: %v", before)
		}
		rec := x.post(t, revokeAPITokenAction(toks[0].ID), nil)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}

		got := x.kinds(t)
		if !containsKind(got, audit.KindAPITokenRevoke) {
			t.Errorf("the trail carries no api_token_revoke record; got %v", got)
		}
		if containsKind(got, audit.KindStepUp) {
			t.Errorf("revoking wrote a step_up event. Revocation grants nothing and costs no "+
				"password (owner decision 2026-09-19); the read-audit exemption says so, and "+
				"this is the assertion that keeps that honest.\ngot %v", got)
		}
	})

	t.Run("a disable writes account_disable and NO step_up", func(t *testing.T) {
		x := newRealWriteFix(t)
		rec := x.post(t, setAccountEnabledAction(x.target.ID), url.Values{"enabled": {"false"}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		got := x.kinds(t)
		if !containsKind(got, audit.KindAccountDisable) {
			t.Errorf("the trail carries no account_disable record; got %v", got)
		}
		if containsKind(got, audit.KindStepUp) {
			t.Errorf("disabling wrote a step_up event — the durable off-switch costs no "+
				"password.\ngot %v", got)
		}
	})
}
