package astguard

import "go/ast"

const enrollImportPath = "github.com/Felag-Engineering/relay/relay/internal/enroll"

// EnrollMinterViolations returns one message when file imports internal/enroll
// under any name: default, alias, dot or blank. An adapter never holds
// enroll.Minter; it mints an Enrollment Token only through the capability
// layer's EnrollmentTokens seam (invariant 10). Matched by import path, so an
// alias cannot dodge it. It is the go-test twin of .golangci.yml's
// adapters-narrow-only entry for the same package.
func EnrollMinterViolations(fileName string, file *ast.File) []string {
	if _, ok := LocalImportAlias(file, enrollImportPath); !ok {
		return nil
	}
	return []string{fileName + " imports internal/enroll \u2014 an adapter never holds enroll.Minter; " +
		"it mints an Enrollment Token only through the capability layer's EnrollmentTokens seam (invariant 10)"}
}
