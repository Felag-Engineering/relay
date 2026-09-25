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

// capabilityImportPath and registryImportPath are the fully-qualified import
// paths this guard treats as "the capability layer" and "the registry",
// resolved by import PATH rather than by an assumed local package name — so
// an aliased import (e.g. `import c2 "…/internal/capability"`) cannot dodge
// the check.
const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	contextImportPath    = "context"
)

// capabilityReadAllowlist is the exhaustive set of capability-package
// identifiers a STRICT (read) file may reference: pure, stateless
// Selector/Predicate parsing helpers with no path to a *capability.Service
// or dispatch. Everything else on the capability import — including
// capability.Service and the exported capability.New dispatch constructor,
// both of which are forbidden in every file regardless of strictness — is a
// violation for a strict file. It does not govern exec files; see
// strictCapabilityIdents below.
var capabilityReadAllowlist = map[string]bool{
	"ParseSelector":        true,
	"Selector":             true,
	"Predicate":            true,
	"Namespace":            true,
	"NamespaceUnspecified": true,
	"NamespaceNode":        true,
	"NamespaceRelay":       true,
	"NamespaceTag":         true,
	"NamespaceState":       true,
	// StateEval (#414, ADR-0034) is the evaluation context Selector.Matches
	// needs beyond a Node's own record — a clock reading and the
	// cert-expiring window. It carries no dispatch capability of its own: a
	// read tool builds one from its own clock/window seam and hands it
	// straight to Matches, exactly as it already hands ParseSelector's
	// output there.
	"StateEval": true,
	// ErrNodeNotFound, ErrInvalidFilter and ErrReadUnaudited (#680) are inert
	// sentinel VALUES the read tools need for errors.Is, so they can tell "no
	// such Node" from "this Relay is broken" from "the trail is down" and
	// render honestly — none of them carries any path to a *capability.Service.
	"ErrNodeNotFound":  true,
	"ErrInvalidFilter": true,
	"ErrReadUnaudited": true,
}

// readFiles and execFiles partition this package's non-test .go files
// (RB1, plan review): readFiles are the original #117 read tools plus their
// shared attribution helper, which must never spell a capability. token
// beyond the pure-read allowlist above. execFiles (#118's execution tools)
// are relaxed to also reference capability.Principal/Selector/NodeResult/
// FrozenError/CapExceededError — needed for Executor's signature and error
// rendering — but remain subject to every unconditional rule below
// (capability.Service, capability.New, newDispatch, registry.Repository).
//
// TestNoDispatchConstruction asserts readFiles ∪ execFiles covers EVERY
// non-test .go file actually present in this directory: a new source file
// that isn't added to one of these maps fails the build rather than silently
// going unguarded.
var readFiles = map[string]bool{
	"mcp.go":              true,
	"tools_nodes.go":      true,
	"tools_operations.go": true,
	"attribution.go":      true,
	// readaudit.go (#288) is the read-access audit seam: a data struct, a
	// write-only interface, and a helper. It names no capability identifier
	// at all — RecordRead takes a context and an event, never a Principal —
	// so it classifies strict alongside the read tools it serves.
	"readaudit.go": true,
	// wire.go (#161) is pure data — the 13 exported MCP tool output structs,
	// no methods, no capability.*/newDispatch references — so it classifies
	// as a strict readFile like mcp.go/tools_nodes.go/tools_operations.go.
	"wire.go": true,
	// taskshim.go (#375) is the SEP-2663 response transformer. It classifies
	// STRICT — the strongest available guarantee, and deliberately so: it sits
	// on the /mcp RCE path and sees every request, so the guard makes it
	// structurally unable to name a capability identifier at all. It parses
	// JSON and writes JSON; it cannot resolve a Selector, build an Action, or
	// reach the Job engine even by accident.
	"taskshim.go": true,
	// toolevents.go (#416, D9) is the tool-call event publisher for the
	// Admin Console's live feed. It classifies STRICT — the strongest
	// available guarantee, and deliberately so: it sits on the /mcp RCE
	// path and sees EVERY request (its middleware wraps "tools/call" for
	// every tool, read and execution alike), so the guard makes it
	// structurally unable to name a capability identifier at all. Its
	// entire purpose is to emit metadata about calls it must never be able
	// to execute or read the result of.
	"toolevents.go": true,
}

var execFiles = map[string]bool{
	"tools_execution.go": true,
	"tools_jobs.go":      true,
	// tasks.go (#374) serves tasks/get and tasks/cancel. It spells
	// capability.Principal and capability.TaskView for the TaskResolver seam's
	// signature, so it classifies relaxed alongside the other execution files —
	// and remains subject to every unconditional rule, including the one that
	// matters most here: it may never reach capability.Service or newDispatch,
	// so resolving a task handle can never become a second path to a Node.
	"tasks.go": true,
	// tools_approval.go (#391, ADR-0029) serves approve_request, the in-band
	// approval rung. It spells capability.Principal and
	// capability.ApprovalDecision for the ApprovalDecider seam, so it
	// classifies relaxed — but the rule that matters most here is
	// unconditional and still binds: it may never reach capability.Service or
	// newDispatch. Approving releases a Plan; it does not run one. Answering a
	// gate must never become a second path to a Node, and this is what makes
	// that structural rather than a matter of review.
	"tools_approval.go": true,
	// elicit.go (S2b of #646, ADR-0029 decision 6) renders an askable park as
	// an MRTR question. It spells capability.ParkedError/Principal to read
	// what the capability layer already decided, so it classifies relaxed —
	// but it names no decision identifier at all (no_decision_test.go needs
	// no new exemption for it) and remains bound by every unconditional rule,
	// including the one that matters most: it may never reach
	// capability.Service or newDispatch.
	"elicit.go": true,
}

// classifyFile reports whether name is a strict read file (strict=true) or a
// relaxed exec file (strict=false), and whether name was classified at all.
// A name absent from both readFiles and execFiles is unclassified
// (classified=false) — this is the fail-closed case TestNoDispatchConstruction
// treats as a build failure.
func classifyFile(name string) (strict, classified bool) {
	if readFiles[name] {
		return true, true
	}
	if execFiles[name] {
		return false, true
	}
	return false, false
}

// localImportAlias resolves the local identifier file uses to refer to
// importPath: the explicit alias if the import declaration has one,
// otherwise the conventional last path segment (Go's default when no alias
// is given). ok is false if file doesn't import importPath at all.
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

// seamHandsBackUnauditedRead is G2 (#680): an interface method declared in a
// non-test file whose RESULTS name registry.Node, policyview.Snapshot or
// nodevocab.Snapshot (bare, pointer, or slice) and whose PARAMETERS contain
// no context.Context is a violation — it declares a seam that hands back a
// Node or a display-only snapshot with no context, which is a read no lane
// could have recorded or attributed (invariant 10, ADR-0025). Phrased as a
// property, not a type denylist: it fires on the deleted NodeReader/
// PolicyReader/VocabReader shapes and does not fire on the lane-shaped
// ReadLane, whose every method takes a context.Context.
//
// This closes the obvious door, not every door (security review, cycle 2):
// MapType/ChanType below catch a map or channel of one of the three banned
// types, but a local type alias for one of them, a generic type parameter
// shaped like one, or an anonymous struct embedding one would not be. The
// real bar is the composition-root guard
// (TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache,
// cmd/relay/control_surfaces_test.go) plus no surface being handed a
// registry or cache at all.
func seamHandsBackUnauditedRead(fileName string, iface *ast.InterfaceType, file *ast.File) []string {
	if iface.Methods == nil {
		return nil
	}
	regAlias, regImported := localImportAlias(file, registryImportPath)
	pvAlias, pvImported := localImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := localImportAlias(file, nodevocabImportPath)
	ctxAlias, ctxImported := localImportAlias(file, contextImportPath)

	var namesBannedType func(expr ast.Expr) bool
	namesBannedType = func(expr ast.Expr) bool {
		switch t := expr.(type) {
		case *ast.StarExpr:
			return namesBannedType(t.X)
		case *ast.ArrayType:
			return namesBannedType(t.Elt)
		case *ast.MapType:
			return namesBannedType(t.Key) || namesBannedType(t.Value)
		case *ast.ChanType:
			return namesBannedType(t.Value)
		case *ast.SelectorExpr:
			pkg, ok := t.X.(*ast.Ident)
			if !ok {
				return false
			}
			switch {
			case regImported && pkg.Name == regAlias && t.Sel.Name == "Node":
				return true
			case pvImported && pkg.Name == pvAlias && t.Sel.Name == "Snapshot":
				return true
			case nvImported && pkg.Name == nvAlias && t.Sel.Name == "Snapshot":
				return true
			}
		}
		return false
	}

	hasContextParam := func(ft *ast.FuncType) bool {
		if !ctxImported || ft.Params == nil {
			return false
		}
		for _, p := range ft.Params.List {
			sel, ok := p.Type.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == ctxAlias && sel.Sel.Name == "Context" {
				return true
			}
		}
		return false
	}

	var violations []string
	for _, m := range iface.Methods.List {
		ft, ok := m.Type.(*ast.FuncType)
		if !ok || ft.Results == nil {
			continue
		}
		bannedResult := false
		for _, r := range ft.Results.List {
			if namesBannedType(r.Type) {
				bannedResult = true
				break
			}
		}
		if !bannedResult || hasContextParam(ft) {
			continue
		}
		methodName := "<unnamed>"
		if len(m.Names) > 0 {
			methodName = m.Names[0].Name
		}
		violations = append(violations, fmt.Sprintf(
			"%s: interface method %s declares a seam that hands back a Node or a display-only snapshot with no context — a read no lane could have recorded or attributed (invariant 10, ADR-0025); read through the capability read lane",
			fileName, methodName))
	}
	return violations
}

// dispatchViolations AST-inspects file (whose source came from fileName,
// used only in messages) and returns one message per rule it catches. Every
// rule below fires regardless of strictCapabilityIdents:
//
//   - capability.Service (or an alias's .Service): the execution layer's
//     entry point. No mcp file may ever hold one directly — the only path to
//     dispatch is through the injected Executor interface.
//   - capability.New (or an alias's .New): the exported dispatch
//     constructor. Holding its result is equivalent to holding a Service.
//   - the unexported newDispatch identifier: capability's internal
//     constructor, sealed to package capability by dispatch_construction_test.go
//     (a reference here wouldn't even compile, but this gives an explicit
//     failure message instead of an opaque compiler error).
//   - a type assertion (or type-switch case) to registry.Repository: the
//     runtime path back from a narrowed NodeReader to the full registry
//     interface (Upsert/SetRelayLabels/Delete/…), even though mcp.New's
//     adapters (mcp.go) make this fail at runtime today, this guard catches
//     the attempt at test time with a clear message.
//   - a dot-import of capability, registry, policyview or nodevocab
//     (security review, cycle 2): it erases the package qualifier every
//     rule above and below matches on, so it is refused outright, in both
//     read and exec files.
//
// One rule is gated by strictCapabilityIdents: any other selector on the
// capability import that isn't in capabilityReadAllowlist. When true (a
// strict/read file), this closes the gap where a future capability export we
// haven't audited yet would silently be allowed through. When false (an
// exec file), it does not fire at all — exec files are allowed to reference
// capability.Principal/Selector/NodeResult/FrozenError/CapExceededError (and
// anything else the capability package exports) precisely because they are
// the sanctioned execution-path files; the unconditional rules above are
// what still bars them from constructing a dispatch directly.
func dispatchViolations(fileName string, file *ast.File, strictCapabilityIdents bool) []string {
	var violations []string

	capAlias, capImported := localImportAlias(file, capabilityImportPath)
	regAlias, regImported := localImportAlias(file, registryImportPath)
	pvAlias, pvImported := localImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := localImportAlias(file, nodevocabImportPath)

	// A dot-import of any of these four erases the package qualifier every
	// check in this function matches on: `import . ".../registry"` turns
	// `registry.Repository` into a bare `Repository` this guard cannot see,
	// and the same holds for capability/policyview/nodevocab. There is no
	// legitimate reason for one here in either a read or an exec file, so it
	// is a violation on its own, unconditionally. Mirrors
	// console/no_dispatch_test.go's identical rule (security review, cycle 2).
	for _, banned := range []struct{ alias, pkg string }{
		{capAlias, "capability"}, {regAlias, "registry"}, {pvAlias, "policyview"}, {nvAlias, "nodevocab"},
	} {
		if banned.alias == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s — that erases the package qualifier this guard matches on, so "+
					"every check below silently stops working", fileName, banned.pkg))
		}
	}

	checkRepositoryAssertion := func(expr ast.Expr) {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !regImported || pkg.Name != regAlias || sel.Sel.Name != "Repository" {
			return
		}
		violations = append(violations, fmt.Sprintf(
			"%s: type-asserts to registry.Repository — this package must never recover the full registry write surface from a narrowed NodeReader (no-dispatch structural guarantee)",
			fileName))
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if capImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == capAlias {
					switch {
					case v.Sel.Name == "Service":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.Service — mcp tools must never hold a capability.Service directly, only the injected Executor interface (no-dispatch structural guarantee)",
							fileName))
					case v.Sel.Name == "New":
						violations = append(violations, fmt.Sprintf(
							"%s references capability.New — the exported dispatch constructor must never be called from an mcp tool file (no-dispatch structural guarantee)",
							fileName))
					case strictCapabilityIdents && !capabilityReadAllowlist[v.Sel.Name]:
						violations = append(violations, fmt.Sprintf(
							"%s references capability.%s, which is not on the pure-read allow-list (%v) — audit it before allowing it here (no-dispatch structural guarantee)",
							fileName, v.Sel.Name, capabilityReadAllowlist))
					}
				}
			}
			// G1 (#680): policyview.Cache/New and nodevocab.Cache/New are the
			// types that carry Set. package mcp is handed ReadLane
			// (mcp.go), which exposes ListNodes/DescribeNode/ListOperations
			// only, and this rule stops any file in the package from
			// recovering either writer by naming the concrete type — no
			// adapter may hold or construct a display-only cache (ADR-0002/
			// invariant 2, ADR-0011/invariant 12).
			if pvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == pvAlias && (v.Sel.Name == "Cache" || v.Sel.Name == "New") {
					violations = append(violations, fmt.Sprintf(
						"%s references policyview.%s — mcp must never hold or construct a *policyview.Cache: Cache carries Set, and this package's Policy view is read-only STRUCTURALLY rather than by permission (ADR-0002, invariant 2; ADR-0011, invariant 12)",
						fileName, v.Sel.Name))
				}
			}
			if nvImported {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == nvAlias && (v.Sel.Name == "Cache" || v.Sel.Name == "New") {
					violations = append(violations, fmt.Sprintf(
						"%s references nodevocab.%s — mcp must never hold or construct a *nodevocab.Cache: Cache carries Set, and this package's Template vocabulary view is read-only STRUCTURALLY rather than by permission (ADR-0002, invariant 2; ADR-0011, invariant 12)",
						fileName, v.Sel.Name))
				}
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — mcp tools must never construct a dispatch (no-dispatch structural guarantee)",
					fileName))
			}
		case *ast.TypeAssertExpr:
			checkRepositoryAssertion(v.Type)
		case *ast.InterfaceType:
			violations = append(violations, seamHandsBackUnauditedRead(fileName, v, file)...)
		case *ast.CaseClause:
			for _, expr := range v.List {
				checkRepositoryAssertion(expr)
			}
		}
		return true
	})

	return violations
}

// TestNoDispatchConstruction is docs/specs/execution.md's acceptance criterion for this
// issue ("no read tool can reach dispatch"), extended by #118 to also cover
// the execution tools: every non-test .go file in this directory is
// classified via classifyFile (readFiles/execFiles above) — an unclassified
// file fails the build outright — and AST-parsed for dispatchViolations at
// the strictness classifyFile assigns it.
//
// This mirrors capability/dispatch_construction_test.go's own AST guard and
// jobs.TestNoDatabaseSQLImport's parse-and-inspect style. The structural
// guarantee it defends is the read-only interfaces in mcp.go (ReadLane /
// OperationLister — ListNodes/DescribeNode/ListOperations/Operations only,
// never Run) and their runtime narrowing via readLaneAdapter/
// operationListerAdapter in New (mcp.go), PLUS #118's execution tools
// dispatching only through the injected Executor/JobResultReader
// (execAdapter/jobResultReaderAdapter), never a capability.Service or
// capability.New held directly, and never registry.Repository recovered
// from a narrowed reader. This test is defense in depth that catches the
// mistake at `go test` time with an explicit message, rather than an opaque
// compiler error or runtime panic.
func TestNoDispatchConstruction(t *testing.T) {
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
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		strict, classified := classifyFile(name)
		if !classified {
			t.Fatalf("%s is neither in readFiles nor execFiles — a new mcp source file must be classified so dispatch cannot hide in an unguarded file", name)
		}

		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}

		for _, msg := range dispatchViolations(name, file, strict) {
			t.Error(msg)
		}
	}
}

// TestFileClassification_CoversEveryRealFile proves readFiles/execFiles
// above are exhaustive against this directory's actual contents right now —
// a narrower, targeted complement to TestNoDispatchConstruction's own
// classification check, so a missing classification fails with a message
// pointed at classifyFile specifically.
func TestFileClassification_CoversEveryRealFile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, classified := classifyFile(name); !classified {
			t.Errorf("%s is not classified as a readFile or execFile — no_dispatch_test.go's partition must cover every non-test .go file", name)
		}
	}
}

// TestFileClassification_UnclassifiedNameFails locks in the fail-closed
// behavior: a filename absent from both maps is NOT classified, exactly the
// case TestNoDispatchConstruction turns into a build failure for a real new
// file.
func TestFileClassification_UnclassifiedNameFails(t *testing.T) {
	if _, classified := classifyFile("some_new_unclassified_file.go"); classified {
		t.Fatal("classifyFile unexpectedly classified an unknown filename — the partition must fail closed for new files")
	}
}

// TestDispatchViolations_Fixtures runs dispatchViolations against small,
// synthetic source snippets rather than this package's real files, proving
// each rule actually fires (and that legitimate read-only usage doesn't) at
// the strictness the case specifies.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"`

	cases := []struct {
		name       string
		src        string
		strict     bool
		wantSubstr string // substring expected in one of the returned violations
	}{
		{
			name: "literal capability.Service selector (strict/read mode)",
			src: `package mcp
import capability ` + capImport + `
var _ = capability.Service{}
`,
			strict:     true,
			wantSubstr: "capability.Service",
		},
		{
			name: "literal capability.Service selector fires in exec mode too",
			src: `package mcp
import capability ` + capImport + `
var _ = capability.Service{}
`,
			strict:     false,
			wantSubstr: "capability.Service",
		},
		{
			name: "aliased capability import dodging the literal package name",
			src: `package mcp
import c2 ` + capImport + `
var _ = c2.Service{}
`,
			strict:     true,
			wantSubstr: "capability.Service",
		},
		{
			name: "exported capability.New dispatch constructor, default import name (strict/read mode)",
			src: `package mcp
import ` + capImport + `
func f() { capability.New(nil) }
`,
			strict:     true,
			wantSubstr: "capability.New",
		},
		{
			name: "exported capability.New fires in exec mode too",
			src: `package mcp
import ` + capImport + `
func f() { capability.New(nil) }
`,
			strict:     false,
			wantSubstr: "capability.New",
		},
		{
			name: "exported capability.New via an alias",
			src: `package mcp
import cap ` + capImport + `
func f() { cap.New(nil) }
`,
			strict:     true,
			wantSubstr: "capability.New",
		},
		{
			name: "capability selector not on the pure-read allow-list (strict/read mode)",
			src: `package mcp
import ` + capImport + `
var _ = capability.NewBlastCap(0, 0)
`,
			strict:     true,
			wantSubstr: "not on the pure-read allow-list",
		},
		{
			name: "unexported newDispatch identifier (would also fail to compile outside package capability)",
			src: `package mcp
func f() { newDispatch() }
`,
			strict:     true,
			wantSubstr: "newDispatch",
		},
		{
			name: "unexported newDispatch identifier fires in exec mode too",
			src: `package mcp
func f() { newDispatch() }
`,
			strict:     false,
			wantSubstr: "newDispatch",
		},
		{
			name: "type assertion recovering registry.Repository from a narrowed NodeReader",
			src: `package mcp
import ` + regImport + `
func f(nodes NodeReader) {
	_ = nodes.(registry.Repository)
}
`,
			strict:     true,
			wantSubstr: "registry.Repository",
		},
		{
			name: "type assertion recovering registry.Repository fires in exec mode too",
			src: `package mcp
import ` + regImport + `
func f(nodes NodeReader) {
	_ = nodes.(registry.Repository)
}
`,
			strict:     false,
			wantSubstr: "registry.Repository",
		},
		{
			name: "type-switch case recovering registry.Repository",
			src: `package mcp
import ` + regImport + `
func f(nodes NodeReader) {
	switch nodes.(type) {
	case registry.Repository:
	}
}
`,
			strict:     true,
			wantSubstr: "registry.Repository",
		},
		{
			name: "constructing a policyview cache",
			src: `package mcp
import ` + pvImport + `
var _ = policyview.New()
`,
			strict:     true,
			wantSubstr: "policyview.New",
		},
		{
			name: "type assertion recovering the policyview cache",
			src: `package mcp
import ` + pvImport + `
func f(p any) { _ = p.(*policyview.Cache) }
`,
			strict:     true,
			wantSubstr: "policyview.Cache",
		},
		{
			name: "constructing a nodevocab cache",
			src: `package mcp
import ` + nvImport + `
var _ = nodevocab.New()
`,
			strict:     true,
			wantSubstr: "nodevocab.New",
		},
		{
			name: "type assertion recovering the nodevocab cache",
			src: `package mcp
import ` + nvImport + `
func f(v any) { _ = v.(*nodevocab.Cache) }
`,
			strict:     true,
			wantSubstr: "nodevocab.Cache",
		},
		{
			name: "the deleted NodeReader shape hands back a Node with no context",
			src: `package mcp
import ` + regImport + `
type NodeReader interface {
	Get(nodeID string) (registry.Node, bool)
	List() []registry.Node
}
`,
			strict:     true,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			name: "the deleted PolicyReader shape hands back a Snapshot with no context",
			src: `package mcp
import ` + pvImport + `
type PolicyReader interface {
	Get(nodeID string) (policyview.Snapshot, bool)
}
`,
			strict:     true,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			name: "the deleted VocabReader shape hands back a Snapshot with no context",
			src: `package mcp
import ` + nvImport + `
type VocabReader interface {
	Get(nodeID string) (nodevocab.Snapshot, bool)
}
`,
			strict:     true,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			name: "the new ReadLane shape takes a context and does not violate",
			src: `package mcp
import (
	"context"
	` + regImport + `
)
type ReadLane interface {
	ListNodes(ctx context.Context, selector string) ([]registry.Node, error)
	DescribeNode(ctx context.Context, nodeID string) (registry.Node, error)
}
`,
			strict:     true,
			wantSubstr: "",
		},
		{
			// LOW 3 (security review, cycle 2): a map result is one of the
			// two shapes namesBannedType did not walk before this guard was
			// hardened.
			name: "a seam handing back a map of registry.Node with no context",
			src: `package mcp
import ` + regImport + `
type NodeReader interface {
	ByID() map[string]registry.Node
}
`,
			strict:     true,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The other shape: a channel result.
			name: "a seam handing back a channel of nodevocab.Snapshot with no context",
			src: `package mcp
import ` + nvImport + `
type VocabReader interface {
	Stream() <-chan nodevocab.Snapshot
}
`,
			strict:     true,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The dot-import evasion (security review, cycle 2): erasing the
			// registry qualifier would otherwise let a map/chan/slice of Node
			// slip past namesBannedType silently.
			name: "dot-importing registry erases the qualifier G2 matches on",
			src: `package mcp
import . ` + regImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports registry",
		},
		{
			name: "dot-importing policyview erases the qualifier G2 matches on",
			src: `package mcp
import . ` + pvImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports policyview",
		},
		{
			name: "dot-importing nodevocab erases the qualifier G2 matches on",
			src: `package mcp
import . ` + nvImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports nodevocab",
		},
		{
			name: "dot-importing capability erases the qualifier this guard matches on, in exec mode too",
			src: `package mcp
import . ` + capImport + `
`,
			strict:     false,
			wantSubstr: "dot-imports capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile: %v", err)
			}

			violations := dispatchViolations("fixture.go", file, tc.strict)
			if tc.wantSubstr == "" {
				if len(violations) != 0 {
					t.Fatalf("dispatchViolations() = %v, want none", violations)
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("dispatchViolations() = empty, want a violation containing %q", tc.wantSubstr)
			}
			for _, v := range violations {
				if strings.Contains(v, tc.wantSubstr) {
					return
				}
			}
			t.Fatalf("dispatchViolations() = %v, want one containing %q", violations, tc.wantSubstr)
		})
	}
}

// TestDispatchViolations_AllowsReadHelpers proves the strict allow-list
// isn't so strict it would flag this package's actual, legitimate use of
// capability.ParseSelector (tools_nodes.go) — a false positive here would be
// as bad as a false negative on the fixtures above.
func TestDispatchViolations_AllowsReadHelpers(t *testing.T) {
	const src = `package mcp
import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"

func f(s string) {
	sel, _ := capability.ParseSelector(s)
	var p capability.Predicate
	p.Namespace = capability.NamespaceNode
	_ = sel
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v", err)
	}

	if violations := dispatchViolations("fixture.go", file, true); len(violations) != 0 {
		t.Fatalf("dispatchViolations() = %v, want none (this is legitimate pure-read Selector usage)", violations)
	}
}

// TestDispatchViolations_ExecModeAllowsExecutionCapabilityIdents proves the
// relaxed (exec) mode actually relaxes: capability.Principal/Selector/
// NodeResult/FrozenError/CapExceededError — exactly what Executor's
// signature and renderRunError need — produce no violation when
// strictCapabilityIdents is false, but DO produce a violation when true (the
// same source would be rejected in a strict/read file).
func TestDispatchViolations_ExecModeAllowsExecutionCapabilityIdents(t *testing.T) {
	const src = `package mcp
import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"

func f(p capability.Principal, sel capability.Selector) (capability.NodeResult, *capability.FrozenError, *capability.CapExceededError) {
	return capability.NodeResult{}, nil, nil
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v", err)
	}

	if violations := dispatchViolations("fixture.go", file, false); len(violations) != 0 {
		t.Fatalf("dispatchViolations(strict=false) = %v, want none (exec files may reference these identifiers)", violations)
	}

	if violations := dispatchViolations("fixture.go", file, true); len(violations) == 0 {
		t.Fatal("dispatchViolations(strict=true) = empty, want violations (read files may not reference capability.Principal/Selector/NodeResult/FrozenError/CapExceededError)")
	}
}

// toolCallEventAllowedFields is mcp.ToolCallEvent's exact, closed field
// set — the same AST field-allowlist rule internal/events applies to its
// own copy of the type (events/no_read_output_test.go), applied here to
// this package's copy. An unlisted field fails the build; a
// result-shaped-name match (case-insensitive substring, on either the field
// name or its type expression) fails it too, so "just widen the allowlist"
// alone can't smuggle output through.
var toolCallEventAllowedFields = map[string]bool{
	"Tool":               true,
	"Arguments":          true,
	"ArgumentsTruncated": true,
}

var resultShapedFieldNames = []string{
	"result", "results", "output", "stdout", "stderr", "content",
	"body", "payload", "truncatedoutput", "exitcode", "noderesult",
}

// TestToolCallEventHasNoResultField AST-locates `type ToolCallEvent struct`
// in toolevents.go and asserts its field-name set is exactly
// toolCallEventAllowedFields, with the result-shaped-name denylist layered
// on top (ADR-0025; D9 in docs/design/console/99-open-decisions.md).
func TestToolCallEventHasNoResultField(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "toolevents.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	fields, found := toolCallEventFields(file)
	if !found {
		t.Fatal("toolevents.go does not declare type ToolCallEvent struct — this test has nothing to check")
	}

	seen := map[string]bool{}
	for _, f := range fields {
		for _, n := range f.Names {
			seen[n.Name] = true
			if !toolCallEventAllowedFields[n.Name] {
				t.Errorf("ToolCallEvent has field %q, which is not on the exact allowlist (%v) — ADR-0025", n.Name, toolCallEventAllowedFields)
			}
			lower := strings.ToLower(n.Name)
			for _, denied := range resultShapedFieldNames {
				if strings.Contains(lower, denied) {
					t.Errorf("ToolCallEvent field %q matches the result-shaped denylist entry %q (ADR-0025)", n.Name, denied)
				}
			}
		}
	}
	for name := range toolCallEventAllowedFields {
		if !seen[name] {
			t.Errorf("ToolCallEvent is missing expected field %q", name)
		}
	}
}

// toolCallEventFields AST-locates `type ToolCallEvent struct { ... }` in
// file and returns its fields, or found=false if no such declaration
// exists.
func toolCallEventFields(file *ast.File) (fields []*ast.Field, found bool) {
	for _, decl := range file.Decls {
		gd, isGen := decl.(*ast.GenDecl)
		if !isGen || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, isType := spec.(*ast.TypeSpec)
			if !isType || ts.Name.Name != "ToolCallEvent" {
				continue
			}
			st, isStruct := ts.Type.(*ast.StructType)
			if !isStruct {
				continue
			}
			return st.Fields.List, true
		}
	}
	return nil, false
}
