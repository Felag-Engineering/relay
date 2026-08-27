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

	// A dot-import of either banned package erases the qualifier every check
	// below matches on: `import . ".../events"` turns the recovery into
	// `d.Events.(*Bus)`, which names nothing this guard can see. There is no
	// legitimate reason for one here, so it is a violation on its own.
	for _, banned := range []struct{ alias, pkg string }{
		{regAlias, "registry"}, {evAlias, "events"}, {capAlias, "capability"},
	} {
		if banned.alias == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s — that erases the package qualifier this guard matches on, so "+
					"every check below silently stops working", fileName, banned.pkg))
		}
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
	writeSurfaceMethod := func(name string) bool {
		return strings.HasPrefix(name, "Publish") || strings.HasPrefix(name, "Set") ||
			name == "Upsert"
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
