package mcp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest/astguard"
)

// capabilityImportPath and registryImportPath are the fully-qualified import
// paths this guard treats as "the capability layer" and "the registry",
// resolved by import PATH rather than by an assumed local package name — so
// an aliased import (e.g. `import c2 "…/internal/capability"`) cannot dodge
// the check.
const (
	capabilityImportPath = "github.com/Felag-Engineering/relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/relay/relay/internal/nodevocab"
)

// What an import path or a resolved identifier can express is enforced by
// golangci-lint, not here: .golangci.yml's adapters-narrow-only depguard rule
// keeps the store, database/sql, the wire protocol and the dispatcher out of
// every file of this package, and its "adapter boundary" forbidigo patterns
// refuse the concrete capability services and their constructors, the
// display-only caches and registry.Repository by resolved package path, so an
// aliased or dot-import cannot dodge them. This guard keeps only what neither
// can express: which identifiers a file may use from the capability package it
// is allowed to import, and the shape of a seam this package declares.

// capabilityReadAllowlist is the exhaustive set of capability-package
// identifiers a STRICT file may reference: the Selector parser and the inert
// values the read tools need, with no path to a capability service or to
// dispatch. It is exactly the code identifiers the strict files use today, so
// a new reference — including Selector, Predicate and ErrReadUnaudited, which
// appear only in comments — must be audited before it is added. depguard
// cannot express it: these four and capability.Execution share one import
// path.
var capabilityReadAllowlist = map[string]bool{
	"ParseSelector": true,
	// StateEval (ADR-0034) is the evaluation context Selector.Matches needs
	// beyond a Node's own record — a clock reading and the cert-expiring
	// window. It carries no dispatch capability of its own: a read tool builds
	// one from its own clock/window seam and hands it straight to Matches,
	// exactly as it already hands ParseSelector's output there.
	"StateEval": true,
	// ErrNodeNotFound and ErrInvalidFilter are inert sentinel VALUES the read
	// tools need for errors.Is, so they can tell "no such Node" from "this
	// Relay is broken" and render honestly — neither carries any path to a
	// capability service.
	"ErrNodeNotFound":  true,
	"ErrInvalidFilter": true,
}

// execFiles are the files relaxed from capabilityReadAllowlist: the execution
// tools, which spell capability.Principal/Selector/NodeResult/FrozenError/
// CapExceededError and the like for the Executor and
// ApprovalAnswerer seams and for error rendering. Every other non-test file in
// this package is STRICT by default, so a new file is guarded the moment it
// exists: a new read tool needs no entry here, and a new file that needs more
// of package capability fails this guard until it is listed — which is the
// review this list exists to force. Relaxed files remain bound by the lint
// rules above (no concrete capability service, ever) and by every other rule
// in dispatchViolations.
var execFiles = map[string]bool{
	"tools_execution.go": true,
	"tools_jobs.go":      true,
	// tools_approval.go accepts an elicited answer (ADR-0029 decision 6). It
	// spells capability.Principal for the ApprovalAnswerer seam. Recording an
	// answer releases a Plan; it does not run one.
	"tools_approval.go": true,
	// elicit.go renders an askable park as an MRTR question (ADR-0029
	// decision 6). It spells capability.ParkedError/Principal to read what
	// the capability layer already decided, and names no decision identifier
	// at all.
	"elicit.go": true,
}

// dispatchViolations AST-inspects file (whose source came from fileName,
// used only in messages) and returns one message per rule it catches. Every
// rule below fires regardless of strictCapabilityIdents:
//
//   - the unexported newDispatch identifier: capability's internal
//     constructor, sealed to package capability by dispatch_construction_test.go
//     (a reference here wouldn't even compile, but this gives an explicit
//     failure message instead of an opaque compiler error).
//   - a seam that hands back a Node or a display-only snapshot with no
//     context (astguard.SeamHandsBackUnauditedRead, ADR-0025).
//   - a dot-import of capability, registry, policyview or nodevocab: it
//     erases the package qualifier the allowlist and the seam check match
//     on, so it is refused outright, in both strict and relaxed files.
//
// One rule is gated by strictCapabilityIdents: any selector on the
// capability import that isn't in capabilityReadAllowlist. When true (every
// file not in execFiles), a capability export nobody has audited for a read
// path is refused. When false (an execFiles entry), it does not fire at all.
func dispatchViolations(fileName string, file *ast.File, strictCapabilityIdents bool) []string {
	var violations []string

	capAlias, capImported := astguard.LocalImportAlias(file, capabilityImportPath)
	regAlias, _ := astguard.LocalImportAlias(file, registryImportPath)
	pvAlias, _ := astguard.LocalImportAlias(file, policyviewImportPath)
	nvAlias, _ := astguard.LocalImportAlias(file, nodevocabImportPath)

	// A dot-import of any of these four erases the package qualifier the
	// checks below match on: `import . ".../registry"` turns
	// `[]registry.Node` into a bare `[]Node` the seam check cannot see, and
	// `import . ".../capability"` turns every capability selector into a bare
	// identifier the allowlist cannot see. There is no legitimate reason for
	// one here, so it is a violation on its own, unconditionally.
	for _, banned := range []struct{ alias, pkg string }{
		{capAlias, "capability"}, {regAlias, "registry"}, {pvAlias, "policyview"}, {nvAlias, "nodevocab"},
	} {
		if banned.alias == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s — that erases the package qualifier this guard matches on, so "+
					"every check below silently stops working", fileName, banned.pkg))
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if capImported && strictCapabilityIdents {
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == capAlias && !capabilityReadAllowlist[v.Sel.Name] {
					violations = append(violations, fmt.Sprintf(
						"%s references capability.%s, which is not on the pure-read allow-list (%v) — audit it before allowing it here, or list the file in execFiles (no-dispatch structural guarantee)",
						fileName, v.Sel.Name, capabilityReadAllowlist))
				}
			}
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — mcp tools must never construct a dispatch (no-dispatch structural guarantee)",
					fileName))
			}
		case *ast.InterfaceType:
			violations = append(violations, astguard.SeamHandsBackUnauditedRead(fileName, v, file)...)
		}
		return true
	})

	// Unconditional, outside the strict/exec partition: no MCP file holds enroll.Minter.
	violations = append(violations, astguard.EnrollMinterViolations(fileName, file)...)
	violations = append(violations, policyAliasViolations(fileName, file)...)
	return append(violations, tagWriteViolations(fileName, file)...)
}

// tagWriteViolations is the tag rule of dispatchViolations, unconditional in
// every file, relaxed or not: no MCP tool writes a tag (ADR-0050 decision 2),
// so this surface may not select an identifier that names the tag write
// (capability.TagWriter, capability.NewTagWriter, TagWriteRecorder,
// audit.TagWriteAppender, AppendWithTagWrite, RecordTagWrite, WriteTag,
// WriteInitialTags) or the in-memory seeder ApplyTagChanges, whatever the receiver or package, nor
// declare a seam method that does. Reading tags (TagLabels) is not a write.
func tagWriteViolations(fileName string, file *ast.File) []string {
	isTagWrite := func(name string) bool {
		return strings.Contains(name, "TagWrite") || strings.Contains(name, "WriteTag") ||
			strings.Contains(name, "InitialTag") || name == "ApplyTagChanges"
	}
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if isTagWrite(v.Sel.Name) {
				violations = append(violations, fmt.Sprintf(
					"%s references %s — a tag is written by a human Account through the Control API and no MCP tool writes one (ADR-0050)",
					fileName, v.Sel.Name))
			}
		case *ast.InterfaceType:
			for _, m := range v.Methods.List {
				for _, name := range m.Names {
					if isTagWrite(name.Name) {
						violations = append(violations, fmt.Sprintf(
							"%s declares a seam method %s — a tag is written by a human Account through the Control API and no MCP tool writes one (ADR-0050)",
							fileName, name.Name))
					}
				}
			}
		}
		return true
	})
	return violations
}

// policyAliasViolations is the Policy alias rule of dispatchViolations,
// unconditional in every file: this surface carries no Policy alias, so it may
// not select an identifier that mentions one, whatever the receiver or package
// (capability.PolicyAliasAdmin, audit.PolicyAliasAppender, or
// x.(audit.PolicyAliasAppender).AppendWithPolicyAlias on a concrete audit
// repository), nor declare a seam method that reads or writes one. The alias
// seams are the Console's alone.
func policyAliasViolations(fileName string, file *ast.File) []string {
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if strings.Contains(v.Sel.Name, "PolicyAlias") {
				violations = append(violations, fmt.Sprintf(
					"%s references %s — Policy aliases are display data for the Console alone, and this surface carries none",
					fileName, v.Sel.Name))
			}
		case *ast.InterfaceType:
			for _, m := range v.Methods.List {
				for _, name := range m.Names {
					if strings.Contains(name.Name, "PolicyAlias") {
						violations = append(violations, fmt.Sprintf(
							"%s declares a seam method %s — Policy aliases are display data for the Console alone, and this surface carries none",
							fileName, name.Name))
					}
				}
			}
		}
		return true
	})
	return violations
}

// nonTestGoFiles lists this package's non-test .go files, failing the test if
// there are none: a guard that inspects nothing reports success forever.
func nonTestGoFiles(t *testing.T) (dir string, names []string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir = filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		t.Fatal("no non-test .go files found — the guard would inspect nothing")
	}
	return dir, names
}

// TestNoDispatchConstruction is docs/specs/execution.md's acceptance
// criterion "no read tool can reach dispatch", extended to the execution
// tools: every non-test .go file in this directory is AST-parsed for
// dispatchViolations, strict unless execFiles relaxes it.
//
// The structural guarantee it defends is the read-only interfaces in mcp.go
// (ReadLane / OperationLister — never Run) and their runtime narrowing in New,
// plus the execution tools dispatching only through the injected Executor and
// JobResultReader. This test is defense in depth that catches the mistake at
// `go test` time with an explicit message, rather than an opaque compiler
// error or runtime panic.
func TestNoDispatchConstruction(t *testing.T) {
	dir, names := nonTestGoFiles(t)
	fset := token.NewFileSet()
	for _, name := range names {
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, msg := range dispatchViolations(name, file, !execFiles[name]) {
			t.Error(msg)
		}
	}
}

// TestExecFiles_NameRealFiles keeps execFiles from carrying a stale entry: a
// relaxation for a file that no longer exists would silently relax whichever
// new file is next given that name.
func TestExecFiles_NameRealFiles(t *testing.T) {
	_, names := nonTestGoFiles(t)
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}
	for name := range execFiles {
		if !present[name] {
			t.Errorf("execFiles lists %s, which is not a non-test .go file in this package — remove the entry", name)
		}
	}
}

// TestDispatchViolations_Fixtures runs dispatchViolations against small,
// synthetic source snippets rather than this package's real files, proving
// each rule actually fires (and that legitimate read-only usage doesn't) at
// the strictness the case specifies.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/relay/relay/internal/nodevocab"`

	cases := []struct {
		name       string
		src        string
		strict     bool
		wantSubstr string // substring expected in one of the returned violations
	}{
		{
			name: "holding enroll.Minter is refused",
			src: `package mcp
import "github.com/Felag-Engineering/relay/relay/internal/enroll"
type D struct{ M *enroll.Minter }
`,
			strict:     false,
			wantSubstr: "imports internal/enroll",
		},
		{
			name: "capability selector not on the pure-read allow-list (strict)",
			src: `package mcp
import ` + capImport + `
var _ = capability.NewBlastCap(nil)
`,
			strict:     true,
			wantSubstr: "not on the pure-read allow-list",
		},
		{
			name: "an aliased capability import cannot dodge the allow-list",
			src: `package mcp
import c2 ` + capImport + `
var _ c2.Principal
`,
			strict:     true,
			wantSubstr: "capability.Principal, which is not on the pure-read allow-list",
		},
		{
			name: "a concrete capability service is refused by the allow-list in a strict file too",
			src: `package mcp
import ` + capImport + `
var _ *capability.Execution
`,
			strict:     true,
			wantSubstr: "capability.Execution, which is not on the pure-read allow-list",
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
			name: "the Policy alias service is refused",
			src: `package mcp
import ` + capImport + `
var _ *capability.PolicyAliasAdmin
`,
			strict:     true,
			wantSubstr: "references PolicyAliasAdmin",
		},
		{
			name: "the Policy alias service is refused through an aliased capability import",
			src: `package mcp
import c2 ` + capImport + `
var _ = c2.NewPolicyAliasAdmin
`,
			strict:     true,
			wantSubstr: "references NewPolicyAliasAdmin",
		},
		{
			name: "the Policy alias service is refused in an execFiles-relaxed file",
			src: `package mcp
import ` + capImport + `
var _ *capability.PolicyAliasAdmin
`,
			strict:     false,
			wantSubstr: "references PolicyAliasAdmin",
		},
		{
			name: "asserting an audit repository to the alias appender is refused",
			src: `package mcp
import "github.com/Felag-Engineering/relay/relay/internal/audit"
func f(x audit.Repository) {
	_ = x.(audit.PolicyAliasAppender).AppendWithPolicyAlias
}
`,
			strict:     false,
			wantSubstr: "references PolicyAliasAppender",
		},
		{
			name: "calling the atomic alias write on any receiver is refused",
			src: `package mcp
func f(x interface{}) {
	_ = x.(interface{ AppendWithPolicyAlias() }).AppendWithPolicyAlias
}
`,
			strict:     false,
			wantSubstr: "references AppendWithPolicyAlias",
		},
		{
			name: "a seam declaring an alias write is refused",
			src: `package mcp
import "context"
type AliasWriter interface {
	ClearPolicyAlias(ctx context.Context, fingerprint string) error
}
`,
			strict:     false,
			wantSubstr: "declares a seam method ClearPolicyAlias",
		},
		{
			name: "the tag writer is refused",
			src: `package mcp
import ` + capImport + `
var _ *capability.TagWriter
`,
			strict:     true,
			wantSubstr: "references TagWriter",
		},
		{
			name: "the tag writer is refused through an aliased capability import",
			src: `package mcp
import c2 ` + capImport + `
var _ = c2.NewTagWriter
`,
			strict:     true,
			wantSubstr: "references NewTagWriter",
		},
		{
			name: "the tag writer is refused in an execFiles-relaxed file",
			src: `package mcp
import ` + capImport + `
var _ capability.TagWriteRecorder
`,
			strict:     false,
			wantSubstr: "references TagWriteRecorder",
		},
		{
			name: "asserting an audit repository to the atomic tag write is refused",
			src: `package mcp
import "github.com/Felag-Engineering/relay/relay/internal/audit"
func f(x audit.Repository) {
	_ = x.(audit.TagWriteAppender)
}
`,
			strict:     false,
			wantSubstr: "references TagWriteAppender",
		},
		{
			name: "a selector writing initial tags is refused",
			src: `package mcp
func f(x interface{ WriteInitialTags() }) { x.WriteInitialTags() }
`,
			strict:     false,
			wantSubstr: "references WriteInitialTags",
		},
		{
			name: "the in-memory tag seeder is refused",
			src: `package mcp
func f(x interface{ ApplyTagChanges() }) { x.ApplyTagChanges() }
`,
			strict:     false,
			wantSubstr: "references ApplyTagChanges",
		},
		{
			name: "a seam declaring a tag write is refused",
			src: `package mcp
import "context"
type TagSetter interface {
	WriteTag(ctx context.Context, label string) error
}
`,
			strict:     false,
			wantSubstr: "declares a seam method WriteTag",
		},
		{
			name: "reading a Node's tags is not a tag write",
			src: `package mcp
import ` + regImport + `
func f(n registry.Node) map[string]string { return n.TagLabels }
`,
			strict:     true,
			wantSubstr: "",
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
			name: "dot-importing registry erases the qualifier the seam check matches on",
			src: `package mcp
import . ` + regImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports registry",
		},
		{
			name: "dot-importing policyview erases the qualifier the seam check matches on",
			src: `package mcp
import . ` + pvImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports policyview",
		},
		{
			name: "dot-importing nodevocab erases the qualifier the seam check matches on",
			src: `package mcp
import . ` + nvImport + `
`,
			strict:     true,
			wantSubstr: "dot-imports nodevocab",
		},
		{
			name: "dot-importing capability erases the qualifier the allow-list matches on, in exec mode too",
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
// the four capability identifiers the strict files reference (tools_nodes.go,
// tools_operations.go, mcp.go) — a false positive here would be as bad as a
// false negative on the fixtures above.
func TestDispatchViolations_AllowsReadHelpers(t *testing.T) {
	const src = `package mcp
import (
	"errors"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

func f(s string, err error) {
	sel, _ := capability.ParseSelector(s)
	ev := capability.StateEval{}
	_ = errors.Is(err, capability.ErrNodeNotFound)
	_ = capability.ErrInvalidFilter
	_, _ = sel, ev
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

// TestDispatchViolations_StrictRefusesWhatLeftTheAllowList pins the three
// names that left the allow-list: each appears in strict files only in
// comments, so a code reference must be audited first.
func TestDispatchViolations_StrictRefusesWhatLeftTheAllowList(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/relay/relay/internal/capability"`
	for _, name := range []string{"Predicate", "Selector", "ErrReadUnaudited"} {
		t.Run(name, func(t *testing.T) {
			src := "package mcp\nimport " + capImport + "\nvar _ = capability." + name + "\n"
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile: %v", err)
			}
			violations := dispatchViolations("fixture.go", file, true)
			if len(violations) == 0 || !strings.Contains(violations[0], "not on the pure-read allow-list") {
				t.Fatalf("dispatchViolations() = %v, want a pure-read allow-list violation", violations)
			}
		})
	}
}

// TestDispatchViolations_ExecModeAllowsExecutionCapabilityIdents proves the
// relaxed (exec) mode actually relaxes: capability.Principal/Selector/
// NodeResult/FrozenError/CapExceededError — exactly what Executor's
// signature and renderRunError need — produce no violation when
// strictCapabilityIdents is false, but DO produce a violation when true (the
// same source would be rejected in a strict file).
func TestDispatchViolations_ExecModeAllowsExecutionCapabilityIdents(t *testing.T) {
	const src = `package mcp
import "github.com/Felag-Engineering/relay/relay/internal/capability"

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
		t.Fatal("dispatchViolations(strict=true) = empty, want violations (strict files may not reference capability.Principal/Selector/NodeResult/FrozenError/CapExceededError)")
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

// TestNoAdapterSetsARiskClass is the structural half of invariant 13 for this
// surface (ADR-0012, ADR-0042, #878): no adapter sets an Action's risk class.
// The capability layer derives it and refuses an Action that arrives with one;
// this guard (astguard.RiskClassViolations) makes the attempt fail go test.
// What this surface may do beyond comparing a class is the allowlist below, by
// file and function, each with its reason; an entry that no longer names a
// class constant fails the test so the list cannot quietly widen.
func TestNoAdapterSetsARiskClass(t *testing.T) {
	allowed := map[string]map[string]string{}

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
