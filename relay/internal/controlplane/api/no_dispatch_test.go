package api

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

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest/astguard"
)

// no_dispatch_test.go is the Control API's structural half of invariant 10,
// mirroring mcp/no_dispatch_test.go: the ONLY path from a route to a dispatch
// is the injected Executor interface (execution.go). A file here that held a
// *capability.Execution (or any concrete capability service), called a
// capability constructor, or reached capability's internal newDispatch would
// be a second control path — the thing ADR-0009/0010 exist to prevent.
//
// The concrete capability services and their constructors, the display-only
// caches and registry.Repository are refused by .golangci.yml's "adapter
// boundary" forbidigo patterns, matched on the resolved package path; the
// store, database/sql, the wire protocol and the dispatcher by its
// adapters-narrow-only and api-imports depguard rules. This guard keeps what
// neither can express: newDispatch, the shape of a seam this package declares,
// and the dot-import that would hide that shape.
//
// Unlike mcp's guard there is no read/exec partition. mcp needs one because
// its read tools must never name a capability identifier at all; every file in
// package api legitimately handles capability.Principal (it is how every route
// attributes its action), so the strict pure-read allowlist would be pure
// false positives here. The rules below are exactly mcp's UNCONDITIONAL ones,
// applied flat to every non-test file — which also means a new source file is
// covered automatically, with no classification map to forget to update.

const (
	capabilityImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
)

// dispatchViolations AST-inspects file (fileName is used only in messages) and
// returns one message per rule it catches:
//
//   - the unexported newDispatch identifier: capability's internal constructor,
//     sealed to package capability. A reference here would not compile, but the
//     guard gives an explicit message instead of an opaque compiler error.
//   - G2, same formulation as mcp's and the Console's: an interface method
//     declared in a non-test file whose RESULTS name registry.Node,
//     policyview.Snapshot or nodevocab.Snapshot and whose PARAMETERS contain
//     no context.Context — a read no lane could have recorded or attributed
//     (invariant 10, ADR-0025).
//   - a dot-import of capability, registry, policyview or nodevocab: it
//     erases the package qualifier G2 matches on, so it is refused outright.
//
// This guard is flat by design — no read/exec partition, because every file
// in package api legitimately handles capability.Principal (see the file
// header) — so every rule is unconditional and a new source file is covered
// automatically.
func dispatchViolations(fileName string, file *ast.File) []string {
	var violations []string

	capAlias, _ := astguard.LocalImportAlias(file, capabilityImportPath)
	regAlias, _ := astguard.LocalImportAlias(file, registryImportPath)
	pvAlias, _ := astguard.LocalImportAlias(file, policyviewImportPath)
	nvAlias, _ := astguard.LocalImportAlias(file, nodevocabImportPath)

	// A dot-import of any of these four erases the package qualifier G2
	// matches on: `import . ".../registry"` turns `[]registry.Node` into a
	// bare `[]Node` this guard cannot see. There is no legitimate reason for
	// one here, so it is a violation on its own. Mirrors the Console's and
	// the MCP surface's identical rule.
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
		case *ast.Ident:
			if v.Name == "newDispatch" {
				violations = append(violations, fmt.Sprintf(
					"%s references newDispatch — Control API routes must never construct a dispatch (no-dispatch structural guarantee)",
					fileName))
			}
		case *ast.InterfaceType:
			violations = append(violations, astguard.SeamHandsBackUnauditedRead(fileName, v, file)...)
		}
		return true
	})

	return violations
}

// TestNoDispatchConstruction is #356's acceptance criterion ("a route that
// attempts to dispatch outside the capability layer does not compile"): every
// non-test .go file in this package is AST-parsed and checked. It is defense in
// depth over the interface boundary — Deps.Exec is an Executor, so the compiler
// already refuses a Service today — catching a future widening at `go test`
// time with a message that names the rule.
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
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, msg := range dispatchViolations(name, file) {
			t.Error(msg)
		}
		checked++
	}

	// Non-vacuity: if a refactor ever moved every route out of this directory,
	// the loop above would pass by checking nothing at all.
	if checked == 0 {
		t.Fatal("checked 0 files — the guard must actually inspect this package's sources")
	}
}

// TestDispatchViolations_Fixtures runs dispatchViolations against synthetic
// snippets rather than this package's real files, proving each rule actually
// fires — and that the legitimate capability usage these routes depend on does
// not.
func TestDispatchViolations_Fixtures(t *testing.T) {
	const capImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"`
	const regImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"`
	const pvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"`
	const nvImport = `"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"`

	cases := []struct {
		name       string
		src        string
		wantSubstr string // "" = expect NO violations
	}{
		{
			name: "unexported newDispatch identifier",
			src: `package api
func f() { newDispatch() }
`,
			wantSubstr: "newDispatch",
		},
		{
			// The false-positive guard: this is exactly what execution.go does.
			name: "legitimate execution-route capability usage produces nothing",
			src: `package api
import ` + capImport + `
func f(p capability.Principal, s string) (capability.PlanResult, []capability.NodeResult, error) {
	sel, _ := capability.ParseSelector(s)
	_ = sel
	var fe *capability.FrozenError
	var ce *capability.CapExceededError
	_, _ = fe, ce
	return capability.PlanResult{}, nil, nil
}
`,
			wantSubstr: "",
		},
		{
			name: "the deleted Get-by-id NodeReader shape hands back a Node with no context",
			src: `package api
import ` + regImport + `
type NodeReader interface {
	Get(nodeID string) (registry.Node, bool)
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			name: "an interface method returning registry.Node WITH a context does not violate",
			src: `package api
import (
	"context"
	` + regImport + `
)
type NodeReader interface {
	Get(ctx context.Context, nodeID string) (registry.Node, bool)
}
`,
			wantSubstr: "",
		},
		{
			// LOW 3 (security review, cycle 2): a map result is one of the two
			// shapes namesBannedType did not walk before this guard was
			// hardened.
			name: "a seam handing back a map of registry.Node with no context",
			src: `package api
import ` + regImport + `
type NodeReader interface {
	ByID() map[string]registry.Node
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The other shape: a channel result.
			name: "a seam handing back a channel of nodevocab.Snapshot with no context",
			src: `package api
import ` + nvImport + `
type VocabReader interface {
	Stream() <-chan nodevocab.Snapshot
}
`,
			wantSubstr: "hands back a Node or a display-only snapshot with no context",
		},
		{
			// The dot-import evasion (security review, cycle 2): erasing the
			// registry qualifier would otherwise let a map/chan/slice of Node
			// slip past namesBannedType silently.
			name: "dot-importing registry erases the qualifier G2 matches on",
			src: `package api
import . ` + regImport + `
`,
			wantSubstr: "dot-imports registry",
		},
		{
			name: "dot-importing policyview erases the qualifier G2 matches on",
			src: `package api
import . ` + pvImport + `
`,
			wantSubstr: "dot-imports policyview",
		},
		{
			name: "dot-importing nodevocab erases the qualifier G2 matches on",
			src: `package api
import . ` + nvImport + `
`,
			wantSubstr: "dot-imports nodevocab",
		},
		{
			name: "dot-importing capability is refused outright",
			src: `package api
import . ` + capImport + `
`,
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

			violations := dispatchViolations("fixture.go", file)

			if tc.wantSubstr == "" {
				if len(violations) != 0 {
					t.Fatalf("dispatchViolations() = %v, want none (this is legitimate execution-route usage)", violations)
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
