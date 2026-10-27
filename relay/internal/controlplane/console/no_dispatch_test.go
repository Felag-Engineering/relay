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

	"github.com/Felag-Engineering/relay/relay/internal/relaytest/astguard"
)

// no_dispatch_test.go is the Console's structural half of invariant 10,
// mirroring api/no_dispatch_test.go and mcp/no_dispatch_test.go.
//
// ADR-0052 decision 1 is the current authority: no Console route dispatches,
// and the structural guard covers the Console like every adapter, with no
// exception. ADR-0026 decision 1 gave the original wording: "The
// `no_dispatch`-style structural guard extends to the Console package: a
// Console file that holds a `*capability.Service`, calls `capability.New`, or
// reaches capability's internal dispatch fails to compile the test suite. The
// guard is extended, never dropped ..."
//
// The concrete capability services and their constructors (the retired
// Service and New included), the display-only caches and registry.Repository
// are refused by .golangci.yml's "adapter boundary" forbidigo patterns,
// matched on the resolved package path, so an alias or a dot-import cannot
// dodge them; the store, database/sql, the wire protocol and the dispatcher
// by its adapters-narrow-only depguard rule. This guard keeps what neither
// can express: which single authz symbol may be named, which file may name a
// write's argument type, a write seam recovered by assertion, alias or
// anonymous interface, and the shape of a seam this package declares.
//
// The guard exists at package creation rather than arriving later. Adding it
// later would mean the window in which the shortcut is cheapest is the window
// in which nothing is watching, and a guard that arrives after the code it
// guards has only ever proved that the code passing it today passes it today.
//
// Like the Control API's guard and unlike the MCP surface's, there is no
// read/exec partition: every file here legitimately handles
// capability.Principal, since that is how a page attributes what it renders.

// writeSeamName reports whether name is a write seam the Console must never
// recover by assertion: the package's two, JobCanceller (cancel.go) and
// AccountAdministrator (accounts_write.go), each in its own file so seams.go's
// "every seam here is read-only" claim stays unqualified, and ApprovalDecider,
// which is RETIRED — the Console decides no approval (AP-80) — and stays on
// the list so that re-declaring one and recovering it still trips. Each is
// refused by name, and through an alias, on a type assertion below.
//
// A list rather than literal comparisons, because this guard has already been
// found to under-enforce once: the check and the alias collector must agree
// about what a write seam IS, and a single list is what makes them.
func writeSeamName(name string) bool {
	switch name {
	case "ApprovalDecider", "JobCanceller", "AccountAdministrator":
		return true
	default:
		return false
	}
}

const (
	capabilityImportPath = "github.com/Felag-Engineering/relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	eventsImportPath     = "github.com/Felag-Engineering/relay/relay/internal/events"

	// authzImportPath is cancel.go's own import; accounts.go and
	// accounts_write.go are the other files that name package authz, each for
	// the same one symbol (ErrUnauthorized). The allowlist below is
	// PACKAGE-WIDE rather than per-file, so a further importer needs no change
	// here — see the allowlist's own doc.
	authzImportPath = "github.com/Felag-Engineering/relay/relay/internal/authz"
)

// dispatchViolations AST-inspects file and returns one message per rule caught.
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, capImported := astguard.LocalImportAlias(file, capabilityImportPath)
	regAlias, regImported := astguard.LocalImportAlias(file, registryImportPath)
	pvAlias, _ := astguard.LocalImportAlias(file, policyviewImportPath)
	nvAlias, _ := astguard.LocalImportAlias(file, nodevocabImportPath)
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
	// The SAME lesson applies to the package's write seams — JobCanceller and
	// AccountAdministrator, and the retired ApprovalDecider: the *ast.Ident arm
	// below must not match the names only LITERALLY, or
	// `type probeSeam = ApprovalDecider` followed by
	// `any(d.Approvals).(probeSeam)` recovers the seam with the guard
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
				"aliases %s — recovering one of the package's write seams through a renamed "+
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
	// type-switch case, and a bare anonymous-interface DECLARATION produces
	// nothing on its own; see the fixtures below for both directions.
	//
	// The approval verbs are here because the approval mechanism's WRITE HALF
	// has NO seam in this package: the Console decides no approval and opens
	// or closes no Grant window (AP-80). That is a fact about the TYPES the
	// composition root hands this package, not a promise about the handlers,
	// and it only holds if a door cannot open by anonymous recovery:
	// Deps.Approvals is wired to the *capability.Approvals that carries
	// DecideApproval, RequestGrant and RevokeGrant (control_surfaces.go), so
	// an anonymous-interface assertion would recover any of them without
	// naming a banned type or adding an import. This verb list is what keeps
	// that door shut — the same hole for ApprovalReader that the events.Bus
	// ban closes for the event seam.
	//
	// The dispatch/control verbs (#595) close the SAME hole, not a new one
	// the Cancel seam introduced: Deps.Approvals was already wired
	// (before #899) to the *capability.Service, so an anonymous-interface
	// assertion could already have recovered Run, Plan, EngageFreeze,
	// ReleaseFreeze or ResolveTask from it with no import and no banned type
	// named. Deps.Cancel (cancel.go) is another field wired to the same
	// object, and closing the pre-existing hole belongs in the same change
	// that adds another way to reach it.
	// ResolveTask (mcptask.go) writes a task handle's status — a real write,
	// not exposed by ApprovalReader or QueryReader, so "Resolve" belongs on
	// this list for the identical reason "Decide" and "Revoke" already are.
	//
	// Mint (#654) closes the SAME hole, not a new one the Accounts seam
	// introduced. MintAPIToken now lives on *capability.AccountAdmin, which
	// control_surfaces.go wires to Deps.Accounts and Deps.AccountAdmin — so
	// an anonymous-interface assertion on either field would recover the
	// reveal-once credential mint with no import and no banned type named.
	// Closing the pre-existing hole belongs in the same change that adds
	// another way to reach it. MintAPIToken is the last uncovered write verb
	// on that type.
	//
	// Record is deliberately NOT here, and the distinction is worth being
	// precise about: *capability.ReadLane has exactly one Record* method,
	// RecordEventSubscription, and it is not a hole this list would close —
	// it is QueryReader's OWN declared method (seams.go), the one every
	// screen on this seam is already meant to call. Banning "Record" would
	// not stop an escalation; it would ban re-declaring the read this
	// package is supposed to make. A prefix belongs on this list only when
	// the seam's underlying capability type has a write under that name
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
			// Run, Plan, Cancel and Resolve are reachable from
			// Deps.Cancel (the *capability.Execution); Deps.Approvals is the
			// narrower *capability.Approvals and carries none of them.
			// Engage/Release left the execution service in #899 and stay
			// listed so that re-wiring a Control onto any Deps field
			// cannot reopen them (see the comment above).
			"Run", "Plan", "Engage", "Release", "Cancel", "Resolve",
			// #895: Start is Run's non-blocking sibling — the same dispatch
			// pipeline — and Drain closes the Execution to every later Start,
			// so a Console file recovering it is a denial of service.
			"Start", "Drain",
			// The account lane's reveal-once credential write (#654):
			// MintAPIToken, reachable from the two seams wired to the
			// *capability.AccountAdmin.
			"Mint",
		} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return name == "Upsert" || name == "RecordDecision"
	}

	// approvalListingMethod matches the READ methods of *capability.Approvals
	// that ApprovalReader deliberately does not declare. Deps.Approvals is
	// wired to *capability.Approvals, which carries PendingApprovals,
	// LastApprovedOfSameShape, ActiveGrants and GrantForApproval beyond the
	// one Approval read the seam declares. The narrowing holds only if those
	// cannot be recovered by anonymous assertion — the same hole the write-verb
	// list closes for writes. Like writeSurfaceMethod, it is consulted only for
	// type assertions and type-switch cases, so a named seam DECLARING such a
	// method is not refused by this rule.
	approvalListingMethod := func(name string) bool {
		for _, prefix := range []string{"Pending", "LastApproved", "Active", "GrantFor"} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	}

	// A NAMED local interface declaring one of those methods is the same door
	// with a name on it (`type lister interface{ PendingApprovals(...) }`
	// then `any(d.Approvals).(lister)`). Record it in aliasOf so the
	// *ast.Ident arm refuses asserting to it; declaring it stays legal.
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		iface, ok := spec.Type.(*ast.InterfaceType)
		if !ok || iface.Methods == nil {
			return true
		}
		for _, m := range iface.Methods.List {
			for _, name := range m.Names {
				if writeSurfaceMethod(name.Name) || approvalListingMethod(name.Name) {
					aliasOf[spec.Name.Name] = fmt.Sprintf(
						"is an interface declaring %s — recovering a write or listing method from a "+
							"narrowed seam through a named interface is the same escalation as "+
							"through an anonymous one", name.Name)
				}
			}
		}
		return true
	})

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
			// A NAMED local seam is refused BY ITS OWN NAME, and a direct ALIAS
			// of one too (`type probeSeam = ApprovalDecider`), because the
			// aliasOf pass above records that alias just as it does for
			// registry.Repository and events.Bus. ApprovalDecider is retired
			// and no longer declared, so recovering it by name is refused as the
			// escalation it would be.
			//
			// What this does NOT catch, and the message below does not claim
			// to: a SECOND, independently-declared interface (or struct) that
			// merely happens to share a write seam's method set structurally,
			// without naming its identifier anywhere. That residual is the same
			// one the anonymous-interface check below already lives with for
			// every other banned method name. Declaring or accepting a write
			// seam as a parameter stays legal — only a type assertion or
			// type-switch case naming one, or an alias of one, is refused.
			if writeSeamName(t.Name) {
				violations = append(violations, fmt.Sprintf(
					"%s: type-asserts to %s — recovering one of the package's write seams "+
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
					} else if approvalListingMethod(name.Name) {
						violations = append(violations, fmt.Sprintf(
							"%s: type-asserts to an anonymous interface declaring %s — the Console lists no "+
								"pending approval and no Grant (AP-80); recovering a listing read from the "+
								"narrowed approval seam undoes that", fileName, name.Name))
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
					case "ApprovalDecision":
						// The argument type of DecideApproval. No file in this
						// package may name it: the Console decides no approval
						// (AP-80), so naming the type is the first half of
						// undoing that, and there is no allowlisted file.
						violations = append(violations, fmt.Sprintf(
							"%s references capability.ApprovalDecision — the Console decides no approval (AP-80); naming the decision argument type is the first half of undoing that",
							fileName))
					case "GrantRequest":
						// The argument type of the approval mechanism's other
						// write verb. No file in this package may open a Grant
						// window, so this stays banned outright — never narrowed
						// to an allowlist.
						violations = append(violations, fmt.Sprintf(
							"%s references capability.GrantRequest — the Console never asks for a Grant; naming the argument type of a write is the first half of undoing that",
							fileName))
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
	return append(violations, tagInternalWriteViolations(fileName, file)...)
}

// tagInternalWriteNames are the tag write's internal seams: the unfloored
// recorder, the audit repository's atomic write, and the in-memory test seeder.
// The Console holds the concrete audit repository as d.audit, which offers the
// atomic write without its floor, so naming any of them, by selector or as a
// declared seam method, is refused (invariant 7, invariant 10, ADR-0050). The
// floored entry, WriteTag, is not on this list: the Console writes a tag only
// through the capability layer's TagWriter (tags.go).
var tagInternalWriteNames = map[string]bool{
	"RecordTagWrite":     true,
	"AppendWithTagWrite": true,
	"ApplyTagChanges":    true,
	"TagWriteRecorder":   true,
	"TagWriteAppender":   true,
}

// tagInternalWriteViolations is the tag rule of dispatchViolations,
// unconditional in every file.
func tagInternalWriteViolations(fileName string, file *ast.File) []string {
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if tagInternalWriteNames[v.Sel.Name] {
				violations = append(violations, fmt.Sprintf(
					"%s references %s — a tag is written only through the capability layer's TagWriter, whose floor this seam lacks",
					fileName, v.Sel.Name))
			}
		case *ast.InterfaceType:
			for _, m := range v.Methods.List {
				for _, name := range m.Names {
					if tagInternalWriteNames[name.Name] {
						violations = append(violations, fmt.Sprintf(
							"%s declares a seam method %s — a tag is written only through the capability layer's TagWriter, whose floor this seam lacks",
							fileName, name.Name))
					}
				}
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
	const capImport = `"github.com/Felag-Engineering/relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/relay/relay/internal/nodevocab"`
	const authzImport = `"github.com/Felag-Engineering/relay/relay/internal/authz"`

	cases := []struct {
		name string
		src  string
		// file is the filename dispatchViolations is told this source came
		// from. Defaults to "fixture.go".
		file       string
		wantSubstr string // "" = expect NO violations
	}{
		{
			name: "asserting the audit repository to the atomic tag write is refused",
			src: `package console
import "github.com/Felag-Engineering/relay/relay/internal/audit"
func f(x audit.Repository) {
	_ = x.(audit.TagWriteAppender)
}
`,
			wantSubstr: "references TagWriteAppender",
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
			name: "type assertion recovering registry.Repository",
			src: `package console
import ` + regImport + `
func f(nodes any) { _ = nodes.(registry.Repository) }
`,
			wantSubstr: "registry.Repository",
		},
		{
			// The evasion that actually compiles against today's wiring:
			// Deps.Approvals IS a *capability.Approvals, so this assertion
			// succeeds at runtime and recovers the decision path from a seam
			// whose whole point is not having one.
			name: "anonymous interface recovering DecideApproval from the approval seam",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/relay/relay/internal/approval"
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
			// Naming the decision argument type violates in an ordinary file.
			name: "naming the decision argument type at all",
			src: `package console
import ` + capImport + `
var _ = capability.ApprovalDecision{}
`,
			wantSubstr: "capability.ApprovalDecision",
		},
		{
			// The same source violates under the name decide.go too: there is
			// no allowlisted file any more.
			name: "naming the decision argument type violates in decide.go too",
			src: `package console
import ` + capImport + `
var _ = capability.ApprovalDecision{}
`,
			file:       "decide.go",
			wantSubstr: "ApprovalDecision",
		},
		{
			// A TYPE ASSERTION recovering DecideApproval through an
			// anonymous interface violates whichever file it is spelled in.
			name: "anonymous interface recovering DecideApproval still violates in decide.go",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/relay/relay/internal/approval"
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
			// A type assertion to the retired NAMED seam recovers the write
			// method without naming the banned type or importing anything
			// new, so it must violate wherever it is spelled.
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
			// The false-positive guard: the narrowed ApprovalReader declares
			// the one read Job detail makes, and seams.go must keep being
			// allowed to declare it.
			name: "declaring the approval read seam produces nothing",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
type approvals interface {
	Approval(ctx context.Context, id string) (approval.Request, error)
}
func f(a approvals) { _, _ = a.Approval(context.Background(), "x") }
`,
			wantSubstr: "",
		},
		{
			name: "anonymous interface recovering PendingApprovals from the approval seam",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		PendingApprovals(context.Context) ([]approval.Request, error)
	})
}
`,
			wantSubstr: "PendingApprovals",
		},
		{
			name: "anonymous interface recovering LastApprovedOfSameShape from the approval seam",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		LastApprovedOfSameShape(context.Context, approval.Request) (approval.Request, error)
	})
}
`,
			wantSubstr: "LastApprovedOfSameShape",
		},
		{
			name: "anonymous interface recovering ActiveGrants from the approval seam",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		ActiveGrants(context.Context) ([]approval.Grant, error)
	})
}
`,
			wantSubstr: "ActiveGrants",
		},
		{
			name: "anonymous interface recovering GrantForApproval from the approval seam",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		GrantForApproval(context.Context, string) (approval.Grant, error)
	})
}
`,
			wantSubstr: "GrantForApproval",
		},
		{
			name: "a type-switch case recovering PendingApprovals from the approval seam",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	switch a.(type) {
	case interface {
		PendingApprovals(context.Context) ([]approval.Request, error)
	}:
	}
}
`,
			wantSubstr: "PendingApprovals",
		},
		{
			name: "anonymous interface recovering Approval, the one declared read, produces nothing",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
func f(a any) {
	_, _ = a.(interface {
		Approval(ctx context.Context, id string) (approval.Request, error)
	})
}
`,
			wantSubstr: "",
		},
		{
			// The rule is about recovery, not declaration.
			name: "a named seam declaring a listing read produces nothing",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
type lister interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
}
func f(l lister) { _, _ = l.PendingApprovals(context.Background()) }
`,
			wantSubstr: "",
		},
		{
			name: "asserting to a named local interface declaring PendingApprovals",
			src: `package console
import (
	"context"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
)
type lister interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
}
func f(a any) { _, _ = a.(lister) }
`,
			wantSubstr: "declaring PendingApprovals",
		},
		{
			name: "a type-switch case naming a local interface declaring DecideApproval",
			src: `package console
import "context"
type decider interface {
	DecideApproval(ctx context.Context, id string) error
}
func f(a any) {
	switch a.(type) {
	case decider:
	}
}
`,
			wantSubstr: "declaring DecideApproval",
		},
		{
			// The SAME pre-existing hole (#595), reached through a third
			// door: Deps.Cancel is wired to the same *capability.Execution
			// Deps.Approvals and Deps.Queries already were, so an anonymous
			// interface matching Run's signature recovers dispatch from the
			// Cancel seam too — nothing this issue added made Run reachable,
			// it only added another seam that fails to close it.
			name: "anonymous interface recovering Run from the cancel seam",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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
			// #895: Start is Run's non-blocking sibling; the same hole.
			name: "anonymous interface recovering Start from the query seam",
			src: `package console
import (
	"context"
	` + capImport + `
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)
func f(q any) {
	_, _ = q.(interface {
		Start(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action, o capability.StartOptions) (capability.StartedJob, error)
	})
}
`,
			wantSubstr: "Start",
		},
		{
			name: "anonymous interface recovering Drain from the query seam",
			src: `package console
import "context"
func f(q any) {
	_, _ = q.(interface {
		Drain(ctx context.Context) error
	})
}
`,
			wantSubstr: "Drain",
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
			// that is a *capability.AccountAdmin carries MintAPIToken.
			// Recovering a reveal-once credential mint from a read seam is
			// the escalation; which field it is spelled through is
			// incidental.
			name: "anonymous interface recovering MintAPIToken from a read seam",
			src: `package console
import (
	"context"
	"time"
	` + capImport + `
	"github.com/Felag-Engineering/relay/relay/internal/accounts"
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
	"github.com/Felag-Engineering/relay/relay/internal/accounts"
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
			// The second write seam, by its own name. Same direction as the
			// ApprovalDecider/JobCanceller arms: recovering a write seam from
			// an `any` is the escalation, whichever it is.
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
	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)
type AccountAdministrator interface {
	CreateAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error)
	SetAccountRole(ctx context.Context, p capability.Principal, id string, role accounts.Role) error
	SetAccountRoleFrom(ctx context.Context, p capability.Principal, id string, from, to accounts.Role) error
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
			// tests for capability.Execution.
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
