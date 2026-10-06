package console

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest/astguard"
)

// no_dispatch_test.go is the Console's structural half of invariant 10,
// mirroring api/no_dispatch_test.go and mcp/no_dispatch_test.go.
//
// ADR-0026 decision 1 requires it in those words: "The `no_dispatch`-style
// structural guard extends to the Console package: a Console file that holds a
// `*capability.Service`, calls `capability.New`, or reaches capability's
// internal dispatch fails to compile the test suite. The guard is extended,
// never dropped — a new execution surface is exactly when the temptation to
// shortcut appears."
//
// The guard exists at package creation rather than arriving with the composer
// (issue #438). Adding it later would mean the window in which the shortcut is
// cheapest is the window in which nothing is watching, and a guard that arrives
// after the code it guards has only ever proved that the code passing it today
// passes it today.
//
// Like the Control API's guard and unlike the MCP surface's, there is no
// read/exec partition: every file here legitimately handles
// capability.Principal, since that is how a page attributes what it renders.

// writeSeamName reports whether name is one of the package's THREE write
// seams: JobCanceller (cancel.go, #595), ApprovalDecider (decide.go, #453) and
// AccountAdministrator (accounts_write.go, #655). Each lives in its own file
// so seams.go's "every seam here is read-only" claim stays unqualified, and
// each is refused by name — and through an alias — on a type assertion below.
//
// A list rather than three literal comparisons, because this guard has already
// been found to under-enforce once: the check and the alias collector must
// agree about what a write seam IS, and a single list is what makes them.
func writeSeamName(name string) bool {
	switch name {
	case "ApprovalDecider", "JobCanceller", "AccountAdministrator":
		return true
	default:
		return false
	}
}

const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	eventsImportPath     = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"

	// authzImportPath is cancel.go's own import (#595); decide.go (#453),
	// accounts.go (#654) and accounts_write.go (#655) are the other three
	// files that name package authz, each for the same one symbol
	// (ErrUnauthorized). The allowlist below is PACKAGE-WIDE rather than
	// per-file, so a further importer needs no change here — see the
	// allowlist's own doc.
	authzImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"

	// approvalDecideFile is the one file allowed to name
	// capability.ApprovalDecision (see the allowlist below): decide.go, the
	// only admissible caller of DecideApproval. e.Name() is a base name, so
	// this comparison is well-formed, and a rename of decide.go fails this
	// guard loudly rather than silently disabling it.
	//
	// Rejected alternative: an adapter in the composition root that calls
	// DecideApproval so the Console package never names the argument type at
	// all. That would leave this guard untouched — and leave a guard whose
	// message asserts something no longer true (that no Console file may
	// name the type), while routing AROUND the guard instead of updating it.
	// A file-scoped allowlist with fixtures in both directions is the honest
	// version: the guard still says something true, and it fails loudly if
	// the one admissible file moves or a second one is added.
	approvalDecideFile = "decide.go"
)

// dispatchViolations AST-inspects file and returns one message per rule caught.
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, capImported := astguard.LocalImportAlias(file, capabilityImportPath)
	regAlias, regImported := astguard.LocalImportAlias(file, registryImportPath)
	pvAlias, pvImported := astguard.LocalImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := astguard.LocalImportAlias(file, nodevocabImportPath)
	evAlias, evImported := astguard.LocalImportAlias(file, eventsImportPath)
	authzAlias, authzImported := astguard.LocalImportAlias(file, authzImportPath)

	// A dot-import of any banned package erases the qualifier every check
	// below matches on: `import . ".../events"` turns the recovery into
	// `d.Events.(*Bus)`, which names nothing this guard can see. There is no
	// legitimate reason for one here, so it is a violation on its own.
	// policyview and nodevocab (security review, cycle 2) are on this list
	// for the identical reason: a dot-import of either erases the qualifier
	// G2's namesBannedType matches results against, below.
	for _, banned := range []struct{ alias, pkg string }{
		{regAlias, "registry"}, {evAlias, "events"}, {capAlias, "capability"}, {authzAlias, "authz"},
		{pvAlias, "policyview"}, {nvAlias, "nodevocab"},
	} {
		if banned.alias == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s — that erases the package qualifier this guard matches on, so "+
					"every check below silently stops working", fileName, banned.pkg))
		}
	}

	// The authz allowlist (#595): cancel.go is the Console's ONLY importer
	// of package authz, and it is documented there to use exactly one
	// symbol — the authz.ErrUnauthorized sentinel, to RENDER a refusal the
	// capability layer already made. Any other selector on the package —
	// authz.NewRoleGate, authz.RoleGate, a future exported gate helper — is
	// a violation. This is an ALLOWLIST rather than a denylist naming
	// NewRoleGate/RoleGate specifically, because a denylist silently admits
	// the next exported gate helper the authz package grows; an allowlist
	// fails closed on anything new instead.
	if authzImported {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != authzAlias || sel.Sel.Name == "ErrUnauthorized" {
				return true
			}
			// The literal package name, not the local alias: the message
			// must name what the guard actually checked against
			// (authz.<Name>) even when the file imported the package under
			// a different local identifier, so an aliased import cannot
			// make the violation message read as clean.
			violations = append(violations, fmt.Sprintf(
				"%s names authz.%s — the Console renders a refusal the capability layer made "+
					"(authz.ErrUnauthorized only) and never holds, constructs or calls a gate "+
					"(invariant 10, ADR-0026 decision 4)", fileName, sel.Sel.Name))
			return true
		})
	}

	// bannedSelector reports whether expr NAMES one of the two write
	// surfaces the read seams exist to withhold, pointer or not.
	//
	// registry.Repository carries Upsert, SetRelayLabels and SetRevoked.
	// events.Bus carries all four Publish methods, so a Console file that
	// recovered it could author an enrollment attempt that never happened or
	// a tool call nobody made — history, on the surface whose entire job is
	// to report history.
	//
	// The pointer unwrap is load-bearing: registry.Repository is an interface
	// and is named bare, but events.Bus is a STRUCT and is only ever
	// recovered as *events.Bus. A guard that matched SelectorExpr alone
	// looked right and caught nothing.
	bannedSelector := func(expr ast.Expr) (message string, banned bool) {
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		switch {
		case regImported && pkg.Name == regAlias && sel.Sel.Name == "Repository":
			return "names registry.Repository — the Console must never recover the full registry " +
				"write surface from a narrowed reader (no-dispatch structural guarantee)", true
		case evImported && pkg.Name == evAlias && sel.Sel.Name == "Bus":
			return "names events.Bus — the Console must never recover the event seam's four Publish " +
				"methods from a narrowed EventReader; the Console watches history and never authors " +
				"it (seams.go)", true
		}
		return "", false
	}

	// A type alias is the cheapest way past a name-matching guard: after
	// `type b = events.Bus` the assertion is `d.Events.(*b)` and mentions
	// events nowhere. Collect the local names first so the check below can
	// resolve them. A DEFINED type (no `=`) is collected too: it cannot
	// actually satisfy the assertion, but naming one of these here has no
	// legitimate purpose either, and a guard that has to reason about which
	// spelling compiles is a guard nobody trusts.
	//
	// The SAME lesson applies to the package's THREE write seams —
	// ApprovalDecider, JobCanceller and AccountAdministrator (#655) — and a
	// security review (cycle 2) caught that the prior revision did not apply
	// it: the *ast.Ident arm below only ever matched the names LITERALLY, so
	// `type probeSeam = ApprovalDecider` followed by
	// `any(d.Approvals).(probeSeam)` recovered the seam with the guard
	// silent. spec.Type can be a bare *ast.Ident for a package-LOCAL type
	// (there is no selector to inspect, unlike registry.Repository or
	// events.Bus), so that case is collected here too, by name, alongside
	// the selector-based aliases above.
	aliasOf := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if msg, banned := bannedSelector(spec.Type); banned {
			aliasOf[spec.Name.Name] = msg
			return true
		}
		if ident, ok := spec.Type.(*ast.Ident); ok && writeSeamName(ident.Name) {
			aliasOf[spec.Name.Name] = fmt.Sprintf(
				"aliases %s — recovering one of the package's three write seams through a renamed "+
					"alias is the same escalation as recovering it by its own name", ident.Name)
		}
		return true
	})

	// writeSurfaceMethod matches the method names that make an interface a
	// WRITE surface. An anonymous interface is the third way around a
	// name-matching guard — `d.Events.(interface{ PublishEnrollment(...) })`
	// recovers exactly one publisher and names no banned type at all — and it
	// is the shape that needs no import to work.
	//
	// This list is consulted ONLY from checkRecoveredWriteSurface below, which
	// is itself reached ONLY from *ast.TypeAssertExpr and *ast.CaseClause. So
	// it catches a write method RECOVERED by a type assertion or a
	// type-switch case, and a bare anonymous-interface DECLARATION — for
	// example, declaring ApprovalDecider itself in decide.go — produces
	// nothing on its own; see the fixtures below for both directions.
	//
	// The approval verbs are here because the claim that survives (#453) is
	// narrower than "zero mutating routes": the WRITE HALF of the approval
	// mechanism is reachable only through the two named seams this package
	// declares for it — ApprovalDecider (decide.go) for deciding, and no seam
	// at all for opening or closing a Grant window. That is a fact about the
	// TYPES the composition root hands this package, not a promise about the
	// handlers, and it only holds if a fourth door cannot open by anonymous
	// recovery: Deps.Approvals is wired to the same *capability.Service that
	// carries DecideApproval, RequestGrant and RevokeGrant
	// (control_surfaces.go), so an anonymous-interface assertion would
	// recover any of them without naming a banned type or adding an import.
	// This verb list is what keeps that door shut — the same hole for
	// ApprovalReader that #427 closed for events.Bus.
	//
	// The dispatch/control verbs (#595) close the SAME hole, not a new one
	// the Cancel seam introduced: Deps.Approvals and Deps.Queries were
	// already wired to that same *capability.Service before this issue, so
	// an anonymous-interface assertion could already have recovered Run,
	// Plan, EngageFreeze, ReleaseFreeze or ResolveTask from either seam with
	// no import and no banned type named. Deps.Cancel (cancel.go) is a THIRD
	// field wired to the same object, and closing the pre-existing hole
	// belongs in the same change that adds another way to reach it.
	// ResolveTask (mcptask.go) writes a task handle's status — a real write,
	// not exposed by ApprovalReader or QueryReader, so "Resolve" belongs on
	// this list for the identical reason "Decide" and "Revoke" already are.
	//
	// Mint (#654) closes the SAME hole, not a new one the Accounts seam
	// introduced. Deps.Approvals, Deps.Queries, Deps.Cancel and Deps.Decide
	// are all already wired to one *capability.Service
	// (control_surfaces.go), and MintAPIToken landed on that type in #653 —
	// so `d.Approvals.(interface{ MintAPIToken(…) })` compiles on main
	// TODAY, with this guard silent, and recovers the reveal-once credential
	// mint with no import and no banned type named. Deps.Accounts
	// (seams.go) is a FIFTH field wired to the same object, and closing the
	// pre-existing hole belongs in the same change that adds another way to
	// reach it. MintAPIToken is the last uncovered write verb on that type.
	//
	// Record is deliberately NOT here, and the distinction is worth being
	// precise about: *capability.Service has exactly one Record* method,
	// RecordEventSubscription, and it is not a hole this list would close —
	// it is QueryReader's OWN declared method (seams.go), the one every
	// screen on this seam is already meant to call. Banning "Record" would
	// not stop an escalation; it would ban re-declaring the read this
	// package is supposed to make. A prefix belongs on this list only when
	// the seam's underlying *capability.Service has a write under that name
	// which the seam's OWN interface does not already expose.
	writeSurfaceMethod := func(name string) bool {
		for _, prefix := range []string{
			"Publish", "Set",
			// The approval mechanism's write half (ADR-0027): deciding a
			// Request, opening a window, closing one, spending one, and the
			// store-level writes underneath all three.
			"Decide", "Revoke", "Request", "Claim", "Create", "Bind",
			// The capability layer's dispatch and control-action verbs
			// (#595): Run and Plan dispatch; Engage/Release and Cancel are
			// ControlActions; Resolve is ResolveTask, a task-handle write.
			// All six are reachable from Deps.Approvals, Deps.Queries, or
			// Deps.Cancel today (see the comment above).
			"Run", "Plan", "Engage", "Release", "Cancel", "Resolve",
			// The account lane's reveal-once credential write (#654):
			// MintAPIToken, reachable from any of the five seams wired to
			// the same *capability.Service.
			"Mint",
		} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return name == "Upsert" || name == "RecordDecision"
	}

	checkRecoveredWriteSurface := func(expr ast.Expr) {
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		switch t := expr.(type) {
		case *ast.SelectorExpr:
			if msg, banned := bannedSelector(t); banned {
				violations = append(violations, fmt.Sprintf("%s: type-asserts to a type that %s", fileName, msg))
			}
		case *ast.Ident:
			// The residual an allowlist-by-file otherwise opens: after
			// narrowing the capability.ApprovalDecision ban to decide.go, any
			// console file could still write d.Approvals.(ApprovalDecider) —
			// a NAMED local seam. This arm refuses that BY THEIR OWN NAME,
			// and — since a security review (cycle 2) found the first
			// version of this claim false — refuses a direct ALIAS of
			// either name too (`type probeSeam = ApprovalDecider`), because
			// the aliasOf pass above now records that alias just as it
			// already did for registry.Repository/events.Bus.
			//
			// What this does NOT catch, and the message below does not
			// claim to: a SECOND, independently-declared interface (or
			// struct) that merely happens to share ApprovalDecider's or
			// JobCanceller's method set structurally, without naming either
			// identifier anywhere. That residual is the same one the
			// anonymous-interface check below already lives with for every
			// other banned method name. Declaring or accepting one of the
			// three write seams as a parameter stays legal — only a type
			// assertion or type-switch case naming one, or an alias of one,
			// is refused.
			if writeSeamName(t.Name) {
				violations = append(violations, fmt.Sprintf(
					"%s: type-asserts to %s — recovering one of the package's three write seams "+
						"by its own name is the same escalation as recovering the underlying type",
					fileName, t.Name))
				return
			}
			if msg, ok := aliasOf[t.Name]; ok {
				violations = append(violations, fmt.Sprintf(
					"%s: type-asserts to the local type %q, which %s", fileName, t.Name, msg))
			}
		case *ast.InterfaceType:
			if t.Methods == nil {
				return
			}
			for _, m := range t.Methods.List {
				for _, name := range m.Names {
					if writeSurfaceMethod(name.Name) {
						violations = append(violations, fmt.Sprintf(
							"%s: type-asserts to an anonymous interface declaring %s — recovering a "+
								"write method from a narrowed read seam is the thing this guard "+
								"exists to stop, whichever type it is spelled through", fileName, name.Name))
					}
				}
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if capImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == capAlias {
					switch v.Sel.Name {
					case "Service":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.Service — Console handlers must never hold a capability.Service directly, only an injected interface (no-dispatch structural guarantee, ADR-0026 decision 1)",
							fileName))
					case "New":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.New — the exported dispatch constructor must never be called from a Console file (no-dispatch structural guarantee, ADR-0026 decision 1)",
							fileName))
					case "ApprovalDecision":
						// The argument type of DecideApproval. Naming it is
						// what BUILDING the call requires, so it is allowed
						// in exactly the one file that is meant to build it
						// (#453) — everywhere else, naming it is the first
						// half of an escalation with no legitimate use.
						//
						// RESIDUAL, worth being honest about (found under
						// review, cycle 2): this rule stops a second file
						// from NAMING the type or RECOVERING the method by
						// assertion — it does not, and cannot, stop a second
						// file from calling d.Decide.DecideApproval(...)
						// directly, because Deps.Decide is already a
						// package-visible, legitimately-typed seam and
						// calling a method through the type it is declared
						// as is not an escalation this guard exists to
						// catch. A two-file change — a helper in decide.go
						// that BUILDS the capability.ApprovalDecision and is
						// called from elsewhere — would reach DecideApproval
						// without naming the type at the call site and
						// without tripping anything here. That is not a
						// regression this change introduced: the equivalent
						// hole is wider still for JobCanceller, whose
						// CancelJob takes no argument type to ban at all.
						// The violation message below says exactly what is
						// enforced and no more.
						if fileName != approvalDecideFile {
							violations = append(violations, fmt.Sprintf(
								"%s references capability.ApprovalDecision — only decide.go may NAME this type; naming a write's argument type outside its one admissible file is the first half of undoing that (this guard does not and cannot stop a call through the already-typed Deps.Decide seam itself)",
								fileName))
						}
					case "GrantRequest":
						// The argument type of the OTHER approval write verb.
						// No file in this package may open a Grant window at
						// all, decide.go included, so this stays banned
						// outright — never narrowed to an allowlist.
						violations = append(violations, fmt.Sprintf(
							"%s references capability.GrantRequest — the Console never asks for a Grant; naming the argument type of a write is the first half of undoing that",
							fileName))
					}
				}
			}
			// policyview.Cache and nodevocab.Cache (#680) are the types that
			// carry Set. The Console is handed QueryReader (seams.go), whose
			// DescribeNode is Get-only for both, and this rule stops any file
			// in the package recovering either writer by naming the concrete
			// type — a type assertion, a type switch case, or a second
			// construction of the cache.
			//
			// What this buys is narrower than "no type can be recovered". An
			// anonymous interface recovers Set without ever naming Cache, and
			// this guard would not see it (the registry.Repository rule above
			// has the identical hole). It closes the obvious door, not every
			// door; the seam's type and review close the rest.
			if pvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == pvAlias {
					switch v.Sel.Name {
					case "Cache", "New":
						violations = append(violations, fmt.Sprintf(
							"%s references policyview.%s — the Console must never hold a *policyview.Cache: Cache carries Set, and the effective-Policy panel is read-only STRUCTURALLY rather than by permission (ADR-0002, invariant 2; ADR-0011, invariant 12)",
							fileName, v.Sel.Name))
					}
				}
			}
			if nvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == nvAlias {
					switch v.Sel.Name {
					case "Cache", "New":
						violations = append(violations, fmt.Sprintf(
							"%s references nodevocab.%s — the Console must never hold a *nodevocab.Cache: Cache carries Set (ADR-0002, invariant 2; ADR-0011, invariant 12)",
							fileName, v.Sel.Name))
					}
				}
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — the Console must never construct a dispatch (no-dispatch structural guarantee, ADR-0026 decision 1)",
					fileName))
			}
		case *ast.TypeAssertExpr:
			checkRecoveredWriteSurface(v.Type)
		case *ast.InterfaceType:
			violations = append(violations, astguard.SeamHandsBackUnauditedRead(fileName, v, file)...)
		case *ast.CaseClause:
			for _, expr := range v.List {
				checkRecoveredWriteSurface(expr)
			}
		}
		return true
	})
	return violations
}

func TestConsole_NoDispatchOutsideCapabilityLayer(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, v := range dispatchViolations(name, file) {
			t.Error(v)
		}
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package.
	if checked == 0 {
		t.Fatal("no_dispatch guard inspected zero files — the guard is not running")
	}
}

// TestDispatchViolations_Fixtures exercises the guard on sources that are not
// in this package, because a guard nobody has ever seen fail is a guard that
// might not run. Mirrors api/no_dispatch_test.go's fixture table.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"`
	const authzImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"`

	cases := []struct {
		name string
		src  string
		// file is the filename dispatchViolations is told this source came
		// from. Defaults to "fixture.go", which is never decide.go, so every
		// case not naming this exercises the ordinary (non-allowlisted) path.
		file       string
		wantSubstr string // "" = expect NO violations
	}{
		{
			name: "type assertion recovering the policyview cache",
			src: `package console
import ` + pvImport + `
func f(p any) { _ = p.(*policyview.Cache) }
`,
			wantSubstr: "policyview.Cache",
		},
		{
			name: "type-switch case recovering the policyview cache",
			src: `package console
import ` + pvImport + `
func f(p any) {
	switch p.(type) {
	case *policyview.Cache:
	}
}
`,
			wantSubstr: "policyview.Cache",
		},
		{
			name: "constructing a policyview cache, through an alias",
			src: `package console
import pv ` + pvImport + `
var _ = pv.New()
`,
			wantSubstr: "policyview.New",
		},
		{
			// The false-positive guard: this is exactly what seams.go and
			// node.go do, and must keep doing.
			// This is the deleted PolicyReader shape (#680): a Get-by-id seam
			// with no context.Context, which is exactly what G2 now forbids —
			// a read no lane could have recorded or attributed. It is no
			// longer legitimate: the Node-detail Policy panel reads through
			// QueryReader.DescribeNode instead.
			name: "the deleted PolicyReader shape hands back a Snapshot with no context",
			src: `package console
import ` + pvImport + `
type reader interface {
	Get(nodeID string) (policyview.Snapshot, bool)
}
func f(r reader) *policyview.Snapshot {
	s, _ := r.Get("n")
	return &s
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The false-positive guard for the new shape: QueryReader's
			// DescribeNode takes a context.Context, so it must not fire.
			name: "QueryReader's DescribeNode takes a context and does not violate",
			src: `package console
import (
	"context"
	` + capImport + `
)
type reader interface {
	DescribeNode(ctx context.Context, p capability.Principal, nodeID string) (capability.NodeDetail, error)
}
`,
			wantSubstr: "",
		},
		{
			name: "the deleted FleetReader shape hands back a Node with no context",
			src: `package console
import ` + regImport + `
type reader interface {
	Get(nodeID string) (registry.Node, bool)
	List() []registry.Node
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// LOW 3 (security review, cycle 2): a map result is one of the two
			// shapes namesBannedType did not walk before this guard was hardened.
			name: "a seam handing back a map of registry.Node with no context",
			src: `package console
import ` + regImport + `
type reader interface {
	ByID() map[string]registry.Node
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The other shape: a channel result.
			name: "a seam handing back a channel of policyview.Snapshot with no context",
			src: `package console
import ` + pvImport + `
type reader interface {
	Stream() <-chan policyview.Snapshot
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The dot-import evasion (security review, cycle 2): erasing the
			// policyview qualifier would otherwise let a map/chan/slice of
			// Snapshot slip past namesBannedType silently.
			name: "dot-importing policyview erases the qualifier G2 matches on",
			src: `package console
import . ` + pvImport + `
`,
			wantSubstr: "dot-imports policyview",
		},
		{
			name: "dot-importing nodevocab erases the qualifier G2 matches on",
			src: `package console
import . ` + nvImport + `
`,
			wantSubstr: "dot-imports nodevocab",
		},
		{
			name: "constructing a nodevocab cache",
			src: `package console
import ` + nvImport + `
var _ = nodevocab.New()
`,
			wantSubstr: "nodevocab.New",
		},
		{
			name: "type assertion recovering the nodevocab cache",
			src: `package console
import ` + nvImport + `
func f(v any) { _ = v.(*nodevocab.Cache) }
`,
			wantSubstr: "nodevocab.Cache",
		},
		{
			name: "type assertion recovering registry.Repository",
			src: `package console
import ` + regImport + `
func f(nodes any) { _ = nodes.(registry.Repository) }
`,
			wantSubstr: "registry.Repository",
		},
		{
			name: "aliased capability import dodging the literal package name",
			src: `package console
import c2 ` + capImport + `
var _ = c2.Service{}
`,
			wantSubstr: "capability.Service",
		},
		{
			// The evasion that actually compiles against today's wiring:
			// Deps.Approvals IS a *capability.Service, so this assertion
			// succeeds at runtime and recovers the decision path from a seam
			// whose whole point is not having one.
			name: "anonymous interface recovering DecideApproval from the approval seam",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		DecideApproval(context.Context, capability.Principal, capability.ApprovalDecision) (approval.Request, error)
	})
}
`,
			wantSubstr: "DecideApproval",
		},
		{
			name: "anonymous interface recovering RevokeGrant from the approval seam",
			src: `package console
import "context"
func f(a any) {
	_, _ = a.(interface {
		RevokeGrant(context.Context, string, string) error
	})
}
`,
			wantSubstr: "RevokeGrant",
		},
		{
			// Fixture (i): naming the decision argument type at all still
			// violates in an ordinary file (the default filename, never
			// decide.go).
			name: "naming the decision argument type at all",
			src: `package console
import ` + capImport + `
var _ = capability.ApprovalDecision{}
`,
			wantSubstr: "capability.ApprovalDecision",
		},
		{
			// Fixture (ii): the SAME source, told it came from decide.go,
			// produces nothing — the one file the allowlist admits.
			name: "naming the decision argument type in decide.go produces nothing",
			src: `package console
import ` + capImport + `
var _ = capability.ApprovalDecision{}
`,
			file:       "decide.go",
			wantSubstr: "",
		},
		{
			// Fixture (iii): a TYPE ASSERTION recovering DecideApproval
			// through an anonymous interface still violates even in
			// decide.go — copied verbatim from "anonymous interface
			// recovering DecideApproval from the approval seam" below, with
			// file set to decide.go. Naming the argument TYPE is allowed
			// there; recovering the METHOD through an anonymous interface
			// never is, whichever file it is spelled in.
			name: "anonymous interface recovering DecideApproval still violates in decide.go",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		DecideApproval(context.Context, capability.Principal, capability.ApprovalDecision) (approval.Request, error)
	})
}
`,
			file:       "decide.go",
			wantSubstr: "DecideApproval",
		},
		{
			// Fixture (iv): the false-positive guard for the seam itself —
			// declaring the NAMED ApprovalDecider interface in decide.go is
			// not a type assertion and must produce nothing, mirroring
			// "declaring the JobCanceller seam produces nothing" below.
			name: "declaring the ApprovalDecider seam in decide.go produces nothing",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	` + capImport + `
)
type ApprovalDecider interface {
	DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error)
}
func f(a ApprovalDecider) { _, _ = a.DecideApproval(context.Background(), capability.Principal{}, capability.ApprovalDecision{}) }
`,
			file:       "decide.go",
			wantSubstr: "",
		},
		{
			// Fixture (v): the residual the allowlist otherwise opens — a
			// type assertion to the NAMED local seam, in ANY file (not just
			// decide.go), recovers the write method without naming the
			// banned type or importing anything new, so it must violate
			// wherever it is spelled.
			name: "type-asserting to the ApprovalDecider seam by name violates anywhere",
			src: `package console
func f(a any) { _, _ = a.(ApprovalDecider) }
`,
			wantSubstr: "ApprovalDecider",
		},
		{
			// Security review, cycle 2: the fixture that proved the prior
			// revision's claim false. A type ALIAS of the seam is the exact
			// evasion the file's own comment names two lines above the
			// aliasOf pass — reproduced here as a standing regression test
			// rather than only as a one-off probe file.
			name: "a type alias of ApprovalDecider still violates",
			src: `package console
type probeSeam = ApprovalDecider
func f(a any) { _, _ = a.(probeSeam) }
`,
			wantSubstr: "probeSeam",
		},
		{
			// The false-positive guard for the widened verb list: these are
			// the reads ApprovalReader actually declares, and seams.go must
			// keep being allowed to declare them.
			name: "declaring the approval read seam produces nothing",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)
type approvals interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
	Approval(ctx context.Context, id string) (approval.Request, error)
	ActiveGrants(ctx context.Context) ([]approval.Grant, error)
	GrantForApproval(ctx context.Context, requestID string) (approval.Grant, error)
}
func f(a approvals) { _, _ = a.PendingApprovals(context.Background()) }
`,
			wantSubstr: "",
		},
		{
			// The SAME pre-existing hole (#595), reached through a third
			// door: Deps.Cancel is wired to the same *capability.Service
			// Deps.Approvals and Deps.Queries already were, so an anonymous
			// interface matching Run's signature recovers dispatch from the
			// Cancel seam too — nothing this issue added made Run reachable,
			// it only added another seam that fails to close it.
			name: "anonymous interface recovering Run from the cancel seam",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)
func f(c any) {
	_, _ = c.(interface {
		Run(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) ([]capability.NodeResult, error)
	})
}
`,
			wantSubstr: "Run",
		},
		{
			name: "anonymous interface recovering CancelTask from the cancel seam",
			src: `package console
import (
	"context"
	` + capImport + `
)
func f(c any) {
	_, _ = c.(interface {
		CancelTask(ctx context.Context, p capability.Principal, taskID string) (capability.TaskView, error)
	})
}
`,
			wantSubstr: "CancelTask",
		},
		{
			name: "anonymous interface recovering ResolveTask from the cancel seam",
			src: `package console
import (
	"context"
	` + capImport + `
)
func f(c any) {
	_, _ = c.(interface {
		ResolveTask(ctx context.Context, p capability.Principal, taskID string) (capability.TaskView, error)
	})
}
`,
			wantSubstr: "ResolveTask",
		},
		{
			// The false-positive guard for the new seam itself: JobCanceller
			// is a NAMED interface (cancel.go), not an anonymous one recovered
			// through a type assertion, so declaring it must produce nothing.
			name: "declaring the JobCanceller seam produces nothing",
			src: `package console
import "context"
type canceller interface {
	CancelJob(ctx context.Context, p any, jobID string) error
}
func f(c canceller) { _ = c.CancelJob(context.Background(), nil, "job-1") }
`,
			wantSubstr: "",
		},
		{
			// The pre-existing hole the Mint prefix closes (#654): this
			// compiles against today's wiring, because every seam on Deps
			// that is a *capability.Service carries MintAPIToken since
			// #653. Recovering a reveal-once credential mint from a read
			// seam is the escalation; which of the five fields it is
			// spelled through is incidental.
			name: "anonymous interface recovering MintAPIToken from a read seam",
			src: `package console
import (
	"context"
	"time"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)
func f(a any) {
	_, _ = a.(interface {
		MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	})
}
`,
			wantSubstr: "MintAPIToken",
		},
		{
			// The false-positive guard for the new seam: AccountReader is a
			// NAMED interface (seams.go) declaring two READS, not an
			// anonymous one recovered through a type assertion, so
			// declaring it must produce nothing — the same direction
			// "declaring the approval read seam produces nothing" covers
			// for ApprovalReader.
			name: "declaring the AccountReader seam produces nothing",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)
type AccountReader interface {
	Accounts(ctx context.Context, p capability.Principal) ([]accounts.Account, error)
	APITokens(ctx context.Context, p capability.Principal, accountID string) ([]accounts.APIToken, error)
}
func f(a AccountReader) { _, _ = a.Accounts(context.Background(), capability.Principal{}) }
`,
			wantSubstr: "",
		},
		{
			// The third write seam (#655), by its own name. Same direction
			// as the ApprovalDecider/JobCanceller arms: recovering a write
			// seam from an `any` is the escalation, whichever of the three
			// it is.
			name: "type-asserting to the AccountAdministrator seam by name violates anywhere",
			src: `package console
func f(a any) { _, _ = a.(AccountAdministrator) }
`,
			wantSubstr: "AccountAdministrator",
		},
		{
			// And through a renamed alias, which is the evasion the alias
			// collector exists for.
			name: "a type alias of AccountAdministrator still violates",
			src: `package console
type probeAcct = AccountAdministrator
func f(a any) { _, _ = a.(probeAcct) }
`,
			wantSubstr: "probeAcct",
		},
		{
			// The false-positive guard: AccountAdministrator is a NAMED
			// interface declared in accounts_write.go, not one recovered
			// through a type assertion, so declaring it and calling through
			// it must produce nothing — the same direction "declaring the
			// AccountReader seam produces nothing" covers for the read seam.
			name: "declaring the AccountAdministrator seam produces nothing",
			file: "accounts_write.go",
			src: `package console
import (
	"context"
	"time"
	` + capImport + `
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)
type AccountAdministrator interface {
	CreateAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error)
	SetAccountRole(ctx context.Context, p capability.Principal, id string, role accounts.Role) error
	SetAccountEnabled(ctx context.Context, p capability.Principal, id string, enabled bool) error
	MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	RevokeAPIToken(ctx context.Context, p capability.Principal, id string) error
}
func f(a AccountAdministrator) { _ = a.RevokeAPIToken(context.Background(), capability.Principal{}, "tok-1") }
`,
			wantSubstr: "",
		},
		{
			name: "constructing a role gate",
			src: `package console
import ` + authzImport + `
var _ = authz.NewRoleGate()
`,
			wantSubstr: "authz.NewRoleGate",
		},
		{
			name: "naming the role gate type",
			src: `package console
import ` + authzImport + `
var _ *authz.RoleGate
`,
			wantSubstr: "authz.RoleGate",
		},
		{
			// An aliased import must not let the message read clean: it is
			// built from the literal package name, never the local alias
			// (cycle-2 review, finding 4) — the same evasion "aliased
			// capability import dodging the literal package name" above
			// tests for capability.Service.
			name: "an aliased authz import still names the gate",
			src: `package console
import az ` + authzImport + `
var _ = az.NewRoleGate()
`,
			wantSubstr: "authz.NewRoleGate",
		},
		{
			// The false-positive guard for the one symbol cancel.go is
			// allowed to use: recognizing the refusal sentinel produces
			// nothing.
			name: "matching the refusal sentinel produces nothing",
			src: `package console
import (
	"errors"
	` + authzImport + `
)
func f(err error) bool { return errors.Is(err, authz.ErrUnauthorized) }
`,
			wantSubstr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.file
			if name == "" {
				name = "fixture.go"
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, name, tc.src, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile: %v", err)
			}

			violations := dispatchViolations(name, file)

			if tc.wantSubstr == "" {
				if len(violations) != 0 {
					t.Fatalf("dispatchViolations() = %v, want none (this is legitimate read usage)", violations)
				}
				return
			}
			for _, v := range violations {
				if strings.Contains(v, tc.wantSubstr) {
					return
				}
			}
			t.Fatalf("dispatchViolations() = %v, want a violation containing %q", violations, tc.wantSubstr)
		})
	}
}

// TestNoAdapterSetsARiskClass is the structural half of invariant 13 for this
// surface (ADR-0012, ADR-0042, #878): no adapter sets an Action's risk class.
// The capability layer derives it and refuses an Action that arrives with one;
// this guard (astguard.RiskClassViolations) makes the attempt fail go test.
// What this surface may do beyond comparing a class is the allowlist below, by
// file and function, each with its reason; an entry that no longer names a
// class constant fails the test so the list cannot quietly widen.
func TestNoAdapterSetsARiskClass(t *testing.T) {
	allowed := map[string]map[string]string{
		"vocab.go": {
			"riskOf": "display: infers the class an audit-trail row describes, for a chip, and builds no Action (the Console does not execute)",
		},
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	usesConstant := map[string]map[string]bool{} // file -> function -> names a class constant
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		checked++
		for _, msg := range astguard.RiskClassViolations(name, file, allowed[name]) {
			t.Error(msg)
		}
		usesConstant[name] = map[string]bool{}
		for _, fn := range astguard.RiskClassConstantFuncs(file) {
			usesConstant[name][fn] = true
		}
	}
	if checked == 0 {
		t.Fatal("no non-test .go files checked: the guard is vacuous")
	}
	for file, funcs := range allowed {
		for fn, reason := range funcs {
			if reason == "" {
				t.Errorf("allowlist entry %s %s has no reason", file, fn)
			}
			if !usesConstant[file][fn] {
				t.Errorf("allowlist entry %s %s no longer names a risk class constant outside a comparison; remove it", file, fn)
			}
		}
	}
}
