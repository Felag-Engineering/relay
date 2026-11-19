package astguard

import "go/ast"

const revocationImportPath = "github.com/Felag-Engineering/relay/relay/internal/revocation"

// revocationActNames are the revocation.Service methods that revoke without the
// capability layer's floor and records. They carry no revocation-package type
// in their signatures (RevokeNode takes a string), so an adapter could declare
// an interface with one and be handed the service without importing the
// package: the identifiers are banned as well as the import.
var revocationActNames = map[string]bool{
	"RevokeNode":         true,
	"RevokeNodeRecorded": true,
	"RevokeToken":        true,
}

// RevocationViolations returns one message when file imports internal/revocation
// under any name (default, alias, dot or blank), and one for each identifier
// that names a revoke act. An adapter never holds revocation.Service or its
// act; it revokes only through the capability layer's Revocations entry points,
// which authorize, act and record together (invariant 10). It matches
// identifiers, so a call, a method value, a declared interface method and a
// method an adapter type declares all fire, while a comment naming one does not.
// Callers walk non-test files only.
func RevocationViolations(fileName string, file *ast.File) []string {
	const tail = ": an adapter never holds revocation.Service or its revoke act; it revokes only " +
		"through the capability layer's Revocations entry points, which authorize, act and " +
		"record together (invariant 10)"
	var violations []string
	if _, ok := LocalImportAlias(file, revocationImportPath); ok {
		violations = append(violations, fileName+" imports internal/revocation"+tail)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && revocationActNames[id.Name] {
			violations = append(violations, fileName+" names "+id.Name+tail)
		}
		return true
	})
	return violations
}
