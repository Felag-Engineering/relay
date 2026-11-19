package astguard

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestRevocationViolations_Fixtures plants each way an adapter could hold the
// revocation service or its act and proves the guard fires on every one, and
// stays silent on the capability layer's own entry points.
func TestRevocationViolations_Fixtures(t *testing.T) {
	const revocationImport = `"` + revocationImportPath + `"`
	cases := []struct {
		name       string
		src        string
		wantSubstr string // empty means the guard must stay silent
	}{
		{"default import holding the service", `package p
import ` + revocationImport + `
type D struct{ R *revocation.Service }`, "imports internal/revocation"},
		{"aliased import", `package p
import r2 ` + revocationImport + `
var _ = r2.NewService`, "imports internal/revocation"},
		{"dot import", `package p
import . ` + revocationImport + `
var _ *Service`, "imports internal/revocation"},
		{"blank import", `package p
import _ ` + revocationImport, "imports internal/revocation"},
		{"calling RevokeNodeRecorded", `package p
func f(d D) { d.X.RevokeNodeRecorded(nil, "n", nil) }`, "names RevokeNodeRecorded"},
		{"method value RevokeToken", `package p
func f(d D) { _ = d.X.RevokeToken }`, "names RevokeToken"},
		{"interface declaring RevokeNode", `package p
type R interface{ RevokeNode(nodeID string) }`, "names RevokeNode"},
		{"method RevokeNode declared on an adapter type", `package p
type T struct{}
func (T) RevokeNode(nodeID string) {}`, "names RevokeNode"},
		{"the layer's token revoke entry", `package p
func f(d D) { _ = d.Revocations.RevokeEnrollmentToken(nil, p, "t") }`, ""},
		{"the layer's node revoke entry", `package p
func f(d D) { _ = d.Revocations.RevokeNodeWithReason(nil, p, "n", "why") }`, ""},
		{"API token revoke", `package p
func f(d D) { _ = d.AccountAdmin.RevokeAPIToken(nil, p, "t") }`, ""},
		{"a handler named handleRevokeNode", `package p
func handleRevokeNode() {}`, ""},
		{"a comment naming RevokeToken", `package p
// RevokeToken is the ungated act.
var _ = 1`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := RevocationViolations("fixture.go", file)
			if tc.wantSubstr == "" {
				if len(got) != 0 {
					t.Fatalf("violations = %v, want none", got)
				}
				return
			}
			if !strings.Contains(strings.Join(got, "\n"), tc.wantSubstr) {
				t.Fatalf("violations = %v, want one naming %q", got, tc.wantSubstr)
			}
		})
	}
}
