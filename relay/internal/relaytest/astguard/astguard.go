// Package astguard holds the AST helpers shared by the repository's
// structural guards: the no_dispatch guards of the Control API, the MCP
// surface and the Console (invariant 10's `no_dispatch` structural guard,
// ADR-0009/0010/0025/0026), accounts' secret-logging guard (#674), and the
// risk-class guard that keeps any adapter from setting an Action's class
// (RiskClassViolations, invariant 13, ADR-0012, #878).
//
// Only the pieces that were byte-identical across those guards live here.
// Each guard's rule set (its dispatchViolations, allowlists and file
// classification) differs by surface and stays in its own _test.go file, so
// what each surface forbids is still read in one place beside the code it
// guards.
//
// Like its parent relaytest, astguard links into no production binary: only
// _test.go files import it.
package astguard

import (
	"fmt"
	"go/ast"
	"strconv"
	"strings"
)

// The import paths SeamHandsBackUnauditedRead resolves. Matched by import
// PATH rather than an assumed local package name, so an aliased import
// cannot dodge the check.
const (
	registryImportPath   = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	contextImportPath    = "context"
)

// LocalImportAlias resolves the local identifier file uses for importPath:
// the explicit alias when the import declaration has one, otherwise the last
// path segment (Go's default when no alias is given). Resolving by import
// PATH rather than an assumed package name is what stops an aliased import
// (`import c2 ".../capability"`) from dodging a guard. ok is false when file
// does not import importPath at all.
func LocalImportAlias(file *ast.File, importPath string) (alias string, ok bool) {
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

// SeamHandsBackUnauditedRead is the no_dispatch guards' G2 (#680), applied
// identically by the Control API, the MCP surface and the Console: an
// interface method declared in a non-test file whose RESULTS name
// registry.Node, policyview.Snapshot or nodevocab.Snapshot (bare, pointer, or
// slice) and whose PARAMETERS contain no context.Context is a violation — it
// declares a seam that hands back a Node or a display-only snapshot with no
// context, which is a read no lane could have recorded or attributed
// (invariant 10, ADR-0025). Phrased as a property, not a type denylist: it
// fires on the deleted Get-by-id reader shapes (api's NodeReader, mcp's
// NodeReader/PolicyReader/VocabReader, the Console's FleetReader/
// PolicyReader) and does not fire on the lane-shaped seams that replaced
// them, whose every method takes a context.Context.
//
// This closes the obvious door, not every door (security review, cycle 2):
// MapType/ChanType below catch a map or channel of one of the three banned
// types, but a local type alias for one of them, a generic type parameter
// shaped like one, or an anonymous struct embedding one would not be. The
// real bar is the composition-root guard
// (TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache,
// cmd/relay/control_surfaces_test.go) plus no surface being handed a
// registry or cache at all.
//
// fileName is used only in the returned messages; one message is returned
// per offending method.
func SeamHandsBackUnauditedRead(fileName string, iface *ast.InterfaceType, file *ast.File) []string {
	if iface.Methods == nil {
		return nil
	}
	regAlias, regImported := LocalImportAlias(file, registryImportPath)
	pvAlias, pvImported := LocalImportAlias(file, policyviewImportPath)
	nvAlias, nvImported := LocalImportAlias(file, nodevocabImportPath)
	ctxAlias, ctxImported := LocalImportAlias(file, contextImportPath)

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
