package astguard

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const authzImportPathForTest = "github.com/Felag-Engineering/relay/relay/internal/authz"

// TestControlAuthorizationViolations_Fixtures plants each way an adapter could
// hold or call the Authorizer and proves the guard fires on every one, and
// stays silent on the capability layer's entry points and on prose.
func TestControlAuthorizationViolations_Fixtures(t *testing.T) {
	const capImport = `import "` + capabilityImportPathForTest + `"` + "\n"
	cases := []struct {
		name       string
		src        string
		wantSubstr string // empty: the guard must stay silent
	}{
		{"calling AuthorizeControl", `package p
func f() { d.Authz.AuthorizeControl(ctx, p, a) }`, "AuthorizeControl"},
		{"method value", `package p
func f() { f := g.AuthorizeApprovalDecision; _ = f }`, "AuthorizeApprovalDecision"},
		{"declared interface method", `package p
type G interface{ AuthorizeControl(ctx context.Context) error }`, "AuthorizeControl"},
		{"method declared on an adapter type", `package p
func (x T) AuthorizeControl() {}`, "AuthorizeControl"},
		{"holding ControlAuthorizer", `package p
` + capImport + `var _ capability.ControlAuthorizer`, "capability.ControlAuthorizer"},
		{"aliased Authorizer", `package p
import c2 "` + capabilityImportPathForTest + `"
var _ c2.Authorizer`, "c2.Authorizer"},
		{"calling EngageFreezeLocal", `package p
func f() { d.Control.EngageFreezeLocal(ctx, p, r) }`, "EngageFreezeLocal"},
		{"method value ReleaseFreezeLocal", `package p
func f() { f := c.ReleaseFreezeLocal; _ = f }`, "ReleaseFreezeLocal"},
		{"holding authz.RoleGate", `package p
import "` + authzImportPathForTest + `"
var _ authz.RoleGate`, "authz.RoleGate"},
		{"aliased authz.NewRoleGate", `package p
import az "` + authzImportPathForTest + `"
var _ = az.NewRoleGate`, "az.NewRoleGate"},
		{"authz.ErrUnauthorized is not a gate", `package p
import "` + authzImportPathForTest + `"
var _ = authz.ErrUnauthorized`, ""},
		{"entry point and prose", `package p
` + capImport + `// AuthorizeControl is decided in the layer.
func f() { g.AuthorizeNodeRevoke(ctx, p); _ = capability.ControlRevokeNode }`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := ControlAuthorizationViolations("fixture.go", file)
			if tc.wantSubstr == "" {
				if len(got) != 0 {
					t.Fatalf("violations = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.wantSubstr) {
				t.Fatalf("violations = %v, want one naming %q", got, tc.wantSubstr)
			}
		})
	}
}
