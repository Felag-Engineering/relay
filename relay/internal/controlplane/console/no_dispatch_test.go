package console

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	eventsImportPath     = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"

	// authzImportPath is cancel.go's own import (#595) — the Console's FIRST
	// and ONLY file that names package authz. See the allowlist below.
	authzImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
)

// localImportAlias resolves the local identifier file uses for importPath: the
// explicit alias when the import has one, otherwise the last path segment.
// Resolving by import PATH rather than an assumed package name is what stops an
// aliased import (`import c2 ".../capability"`) from dodging the check.
func localImportAlias(file *ast.File, importPath string) (alias string, ok bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return path[strings.LastIndex(path, "/")+1:], true
	}
	return "", false
}

// dispatchViolations AST-inspects file and returns one message per rule caught.
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, capImported := localImportAlias(file, capabilityImportPath)
	regAlias, regImported := localImportAlias(file, registryImportPath)
	pvAlias, pvImported := localImportAlias(file, policyviewImportPath)
	evAlias, evImported := localImportAlias(file, eventsImportPath)
	authzAlias, authzImported := localImportAlias(file, authzImportPath)

	// A dot-import of any banned package erases the qualifier every check
	// below matches on: `import . ".../events"` turns the recovery into
	// `d.Events.(*Bus)`, which names nothing this guard can see. There is no
	// legitimate reason for one here, so it is a violation on its own.
	for _, banned := range []struct{ alias, pkg string }{
		{regAlias, "registry"}, {evAlias, "events"}, {capAlias, "capability"}, {authzAlias, "authz"},
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
	aliasOf := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if msg, banned := bannedSelector(spec.Type); banned {
			aliasOf[spec.Name.Name] = msg
		}
		return true
	})

	// writeSurfaceMethod matches the method names that make an interface a
	// WRITE surface. An anonymous interface is the third way around a
	// name-matching guard — `d.Events.(interface{ PublishEnrollment(...) })`
	// recovers exactly one publisher and names no banned type at all — and it
	// is the shape that needs no import to work.
	//
	// The approval verbs are here because seams.go and approvals.go now claim
	// that "zero mutating routes in the Console" is a FACT ABOUT THE INTERFACE
	// rather than a property of the handlers. It is not, on its own:
	// Deps.Approvals is wired to the same *capability.Service that carries
	// DecideApproval, RequestGrant and RevokeGrant (control_surfaces.go), so an
	// anonymous-interface assertion recovers any of them without naming a
	// banned type or adding an import. A claim that strong has to be enforced,
	// not asserted — this is the same hole for ApprovalReader that #427 closed
	// for events.Bus.
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
					case "ApprovalDecision", "GrantRequest":
						// The two argument types of the approval write half.
						// A Console file has no reason to NAME either: it
						// cannot decide and cannot open a window, and the only
						// use for the type is building the call. Banning the
						// type is what makes the anonymous-interface recovery
						// awkward to spell as well as caught above.
						violations = append(violations, fmt.Sprintf(
							"%s references capability.%s — the Console never decides an approval and never asks for a Grant; v0.6.0's \"zero mutating routes\" is a fact about ApprovalReader (seams.go), and naming the argument type of a write is the first half of undoing it",
							fileName, v.Sel.Name))
					}
				}
			}
			// policyview.Cache is the type that carries Set. The Console is
			// handed PolicyReader (seams.go), which is Get only, and this rule
			// stops any file in the package recovering the writer by naming
			// the concrete type — a type assertion, a type switch case, or a
			// second construction of the cache.
			//
			// What this buys is narrower than "no type can be recovered". An
			// anonymous interface — `d.Policy.(interface{ Set(string,
			// policyview.Snapshot) })` — recovers Set without ever naming
			// Cache, and this guard would not see it (the registry.Repository
			// rule above has the identical hole). It closes the obvious door,
			// not every door; the seam's type and review close the rest.
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
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — the Console must never construct a dispatch (no-dispatch structural guarantee, ADR-0026 decision 1)",
					fileName))
			}
		case *ast.TypeAssertExpr:
			checkRecoveredWriteSurface(v.Type)
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
	const authzImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"`

	cases := []struct {
		name       string
		src        string
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
			name: "reading a reported Snapshot produces nothing",
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
			wantSubstr: "",
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
			name: "naming the decision argument type at all",
			src: `package console
import ` + capImport + `
var _ = capability.ApprovalDecision{}
`,
			wantSubstr: "capability.ApprovalDecision",
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
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile: %v", err)
			}

			violations := dispatchViolations("fixture.go", file)

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
