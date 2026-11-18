package astguard

import "go/ast"

const (
	capabilityImportPath = "github.com/Felag-Engineering/relay/relay/internal/capability"
	authzImportPath      = "github.com/Felag-Engineering/relay/relay/internal/authz"
)

// hostSignalLevers are *capability.Control methods that act on a Node's host
// signal without the layer's authorization. They are the capability layer's
// own; no adapter may name them.
var hostSignalLevers = map[string]bool{
	"EngageFreezeLocal":  true,
	"ReleaseFreezeLocal": true,
}

// authzGateNames are the authz package's role gate, the production Authorizer.
// authz.ErrUnauthorized, the refusal sentinel, is not one.
var authzGateNames = map[string]bool{
	"RoleGate":    true,
	"NewRoleGate": true,
}

// authorizerMethodNames are the Authorizer's decision methods that carry a
// ControlAction or an approval decision. "Authorize", the dispatch half, is
// deliberately absent: it is a generic name, and dispatch is already sealed by
// the no_dispatch rules.
var authorizerMethodNames = map[string]bool{
	"AuthorizeControl":          true,
	"AuthorizeApprovalDecision": true,
}

// authorizerTypeNames are the capability interfaces an adapter must not hold.
var authorizerTypeNames = map[string]bool{
	"Authorizer":        true,
	"ControlAuthorizer": true,
}

// ControlAuthorizationViolations returns one message for each identifier in
// file that names an Authorizer decision method or a host-signal lever
// (EngageFreezeLocal, ReleaseFreezeLocal), and for each reference to the
// capability package's Authorizer or ControlAuthorizer type or to authz.RoleGate
// or authz.NewRoleGate. An adapter never holds or calls the Authorizer: the
// capability layer's entry point for the act strips caller-asserted attribution
// and records the refusal (invariant 10, EX-7). It matches identifiers, so a call, a method value, a declared
// interface method and a method an adapter type declares all fire, while a
// comment naming one does not. Callers walk non-test files only.
func ControlAuthorizationViolations(fileName string, file *ast.File) []string {
	const tail = ": an adapter never holds or calls the Authorizer; it asks the capability " +
		"layer's entry point for the act, which strips caller-asserted attribution and " +
		"records the refusal (invariant 10, EX-7)"
	const leverTail = ": an unauthorized host-signal lever only the Relay's host may pull; " +
		"an adapter asks the capability layer's entry point for the act (invariant 10, EX-7)"
	capAlias, hasCap := LocalImportAlias(file, capabilityImportPath)
	authzAlias, hasAuthz := LocalImportAlias(file, authzImportPath)
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if authorizerMethodNames[n.Name] {
				violations = append(violations, fileName+" names "+n.Name+tail)
			}
			if hostSignalLevers[n.Name] {
				violations = append(violations, fileName+" names "+n.Name+leverTail)
			}
		case *ast.SelectorExpr:
			x, ok := n.X.(*ast.Ident)
			if ok && hasCap && x.Name == capAlias && authorizerTypeNames[n.Sel.Name] {
				violations = append(violations, fileName+" names "+x.Name+"."+n.Sel.Name+tail)
			}
			if ok && hasAuthz && x.Name == authzAlias && authzGateNames[n.Sel.Name] {
				violations = append(violations, fileName+" names "+x.Name+"."+n.Sel.Name+tail)
			}
		}
		return true
	})
	return violations
}
