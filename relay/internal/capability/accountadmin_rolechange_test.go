package capability

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// The invalid cells are the five spellings on which `to != from &&
// to.AtLeast(from)` fails open: accounts.Role.AtLeast returns false when
// EITHER side is invalid, so that form reads "not a raise" on a corrupt stored
// role and skips the password.
func TestRoleChangeCouldGrant_EveryRolePairAndFailsClosed(t *testing.T) {
	// The nine ordered valid pairs, by hand so the expectation is stated and not re-derived
	// from the implementation.
	pairs := []struct {
		from, to accounts.Role
		want     bool
	}{
		{accounts.RoleViewer, accounts.RoleViewer, false},
		{accounts.RoleViewer, accounts.RoleOperator, true},
		{accounts.RoleViewer, accounts.RoleAdmin, true},
		{accounts.RoleOperator, accounts.RoleViewer, false},
		{accounts.RoleOperator, accounts.RoleOperator, false},
		{accounts.RoleOperator, accounts.RoleAdmin, true},
		{accounts.RoleAdmin, accounts.RoleViewer, false},
		{accounts.RoleAdmin, accounts.RoleOperator, false},
		{accounts.RoleAdmin, accounts.RoleAdmin, false},
	}
	for _, c := range pairs {
		t.Run(string(c.from)+"->"+string(c.to), func(t *testing.T) {
			if got := RoleChangeCouldGrant(c.from, c.to); got != c.want {
				t.Errorf("RoleChangeCouldGrant(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
			}
		})
	}

	valid := []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}
	invalid := []accounts.Role{"", "superadmin", "Admin", "VIEWER", "root"}
	all := append(append([]accounts.Role{}, valid...), invalid...)
	invalidCells := 0
	for _, from := range all {
		for _, to := range all {
			if from.Valid() && to.Valid() {
				continue
			}
			invalidCells++
			if !RoleChangeCouldGrant(from, to) {
				t.Errorf("RoleChangeCouldGrant(%q, %q) = false; an unknown role on either side "+
					"must count as a grant, or a corrupt stored role silently skips step-up", from, to)
			}
		}
	}
	if invalidCells != 55 {
		t.Fatalf("the invalid-role sweep covered %d cells, want 55; the table is not what it claims", invalidCells)
	}
}
