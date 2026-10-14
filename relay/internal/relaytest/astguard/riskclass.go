package astguard

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
)

const jobsImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"

// riskClassConstants are the jobs.RiskClass values an adapter could use to
// pick a class. The type itself (jobs.RiskClass) and the display function
// jobs.RiskClassName are deliberately not here.
var riskClassConstants = map[string]bool{
	"RiskClassRead":        true,
	"RiskClassMutate":      true,
	"RiskClassUnspecified": true,
}

// RiskClassViolations is the structural half of invariant 13 for an adapter
// package (the Control API, the MCP surface, the Console; ADR-0012,
// ADR-0042): no adapter sets an Action's risk class. Only the capability layer
// derives it, and refuses an Action that arrives carrying one; this guard
// makes "an adapter sets a class" fail `go test` rather than rely on that
// refusal being the first anyone hears of it.
//
// The rules are mechanical, with J the file's local name for the jobs package
// (resolved by import path, so an alias cannot dodge them):
//
//   - R0: a dot-import of jobs. It erases the qualifier every other rule
//     matches on.
//   - R1: a J.Action composite literal with a RiskClass key, WHATEVER THE
//     VALUE (`RiskClass: d.Risk` names no constant), or any unkeyed element
//     (which sets the class by position). Elided element types
//     (`[]J.Action{{...}}`, a map value) are resolved from the enclosing
//     array or map literal.
//   - R2: an assignment whose left side is a selector ending in RiskClass.
//     Syntactic: there is no type information here.
//   - R3: a J.RiskClassRead, J.RiskClassMutate or J.RiskClassUnspecified
//     selector, unless it is a direct operand of == or != (a comparison reads
//     a class and cannot set one) or its enclosing top-level function is a
//     key of allowed. A method's key is "Recv.Method". A constant at package
//     scope has no function to allow and is a violation unless compared.
//
// Allowed without listing: the type J.RiskClass, the display function
// J.RiskClassName, and a RiskClass key in a composite literal of any other
// type (view models, approval.GrantScope). allowed maps a function to the
// reason it may name a class constant, so the allowlist documents itself; a
// switch `case J.RiskClassRead:` is a false positive on purpose and belongs in
// allowed, not in a widened rule.
//
// This closes the obvious doors, not every door: a local alias of a constant,
// an Action built in a package this guard is not run over (the walks are
// non-recursive, so controlplane/mcp/requeststate and the controlplane root
// package are out of reach), or a value laundered through a helper would get
// past it. The real bar is the capability layer's runtime refusal
// (ClassPresetError, TemplateClassPresetError); this is defense in depth over
// it, the same framing SeamHandsBackUnauditedRead uses.
func RiskClassViolations(fileName string, file *ast.File, allowed map[string]string) []string {
	var violations []string
	add := func(format string, args ...any) {
		violations = append(violations, fmt.Sprintf("%s: ", fileName)+fmt.Sprintf(format, args...)+
			" — no adapter sets a risk class; the capability layer derives it (invariant 13, ADR-0012)")
	}

	alias, imported := LocalImportAlias(file, jobsImportPath)
	if imported && alias == "." {
		add("dot-import of jobs hides which identifiers name a risk class")
	}

	sc := scanRiskClass(file)
	for _, s := range sc.actionLiterals {
		add("%s sets the RiskClass of a jobs.Action literal", where(s))
	}
	for _, s := range sc.assignments {
		add("%s assigns to a RiskClass field", where(s))
	}
	for _, s := range sc.constants {
		if _, ok := allowed[s.fn]; ok && s.fn != "" {
			continue
		}
		add("%s names the risk class constant jobs.%s", where(s), s.name)
	}
	return violations
}

// RiskClassConstantFuncs returns the top-level functions of file ("Recv.Method"
// for a method) that name a jobs risk class constant outside a comparison. A
// guard's allowlist is checked against it, so an entry whose function no longer
// does so fails the guard instead of quietly widening what is allowed.
func RiskClassConstantFuncs(file *ast.File) []string {
	seen := map[string]bool{}
	for _, s := range scanRiskClass(file).constants {
		if s.fn != "" {
			seen[s.fn] = true
		}
	}
	out := make([]string, 0, len(seen))
	for fn := range seen {
		out = append(out, fn)
	}
	sort.Strings(out)
	return out
}

// rcSite is one finding: the top-level function it sits in ("" at package
// scope) and, for a constant, which one.
type rcSite struct {
	fn   string
	name string
}

func where(s rcSite) string {
	if s.fn == "" {
		return "package scope"
	}
	return "function " + s.fn
}

type rcScan struct {
	actionLiterals []rcSite
	assignments    []rcSite
	constants      []rcSite
}

func scanRiskClass(file *ast.File) rcScan {
	var sc rcScan
	alias, imported := LocalImportAlias(file, jobsImportPath)
	if alias == "." {
		imported = false
	}

	// Pre-pass over the whole file: the selectors that are a direct operand of
	// == or !=, and the element type each elided composite literal inherits
	// from its enclosing array or map literal. ast.Inspect is preorder, so a
	// parent's elision is recorded before its children are visited.
	compared := map[*ast.SelectorExpr]bool{}
	elided := map[*ast.CompositeLit]ast.Expr{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				for _, operand := range []ast.Expr{n.X, n.Y} {
					if sel, ok := unparen(operand).(*ast.SelectorExpr); ok {
						compared[sel] = true
					}
				}
			}
		case *ast.CompositeLit:
			typ := n.Type
			if typ == nil {
				typ = elided[n]
			}
			var elemTypes []ast.Expr
			switch t := typ.(type) {
			case *ast.ArrayType:
				elemTypes = []ast.Expr{t.Elt}
			case *ast.MapType:
				elemTypes = []ast.Expr{t.Key, t.Value}
			}
			for _, el := range n.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					// A map's key and value are the two elision sites.
					if lit, ok := kv.Key.(*ast.CompositeLit); ok && lit.Type == nil && len(elemTypes) == 2 {
						elided[lit] = elemTypes[0]
					}
					if lit, ok := kv.Value.(*ast.CompositeLit); ok && lit.Type == nil && len(elemTypes) > 0 {
						elided[lit] = elemTypes[len(elemTypes)-1]
					}
					continue
				}
				if lit, ok := el.(*ast.CompositeLit); ok && lit.Type == nil && len(elemTypes) > 0 {
					elided[lit] = elemTypes[0]
				}
			}
		}
		return true
	})

	isJobs := func(e ast.Expr, name string) bool {
		if !imported {
			return false
		}
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == alias
	}
	isJobsAction := func(e ast.Expr) bool {
		if star, ok := e.(*ast.StarExpr); ok {
			e = star.X
		}
		return isJobs(e, "Action")
	}

	visit := func(fn string, root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				typ := n.Type
				if typ == nil {
					typ = elided[n]
				}
				if typ == nil || !isJobsAction(typ) {
					return true
				}
				for _, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						sc.actionLiterals = append(sc.actionLiterals, rcSite{fn: fn})
						break
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "RiskClass" {
						sc.actionLiterals = append(sc.actionLiterals, rcSite{fn: fn})
						break
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "RiskClass" {
						sc.assignments = append(sc.assignments, rcSite{fn: fn})
					}
				}
			case *ast.SelectorExpr:
				if compared[n] || !riskClassConstants[n.Sel.Name] || !isJobs(n, n.Sel.Name) {
					return true
				}
				sc.constants = append(sc.constants, rcSite{fn: fn, name: n.Sel.Name})
			}
			return true
		})
	}

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			visit("", decl)
			continue
		}
		visit(funcKey(fd), fd)
	}
	return sc
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// funcKey is a function's allowlist key: its name, or "Recv.Method" with any
// pointer and type parameters stripped from the receiver.
func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fd.Name.Name
		}
		return fd.Name.Name
	}
}
