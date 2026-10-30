package astguard

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestEnrollMinterViolations_Fixtures plants each way an adapter could import
// internal/enroll and proves the guard fires on every one, and stays silent on
// a file that mints through the capability layer.
func TestEnrollMinterViolations_Fixtures(t *testing.T) {
	const enrollImport = `"` + enrollImportPath + `"`
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"default import holding the minter", `package p
import ` + enrollImport + `
type D struct{ M *enroll.Minter }`, true},
		{"aliased import", `package p
import e2 ` + enrollImport + `
var _ = e2.NewMinter`, true},
		{"dot import", `package p
import . ` + enrollImport + `
var _ *Minter`, true},
		{"blank import", `package p
import _ ` + enrollImport, true},
		{"capability only", `package p
import "` + capabilityImportPathForTest + `"
var _ capability.EnrollmentMint`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := EnrollMinterViolations("fixture.go", file)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("violations = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], "imports internal/enroll") {
				t.Fatalf("violations = %v, want one naming internal/enroll", got)
			}
		})
	}
}

const capabilityImportPathForTest = "github.com/Felag-Engineering/relay/relay/internal/capability"
