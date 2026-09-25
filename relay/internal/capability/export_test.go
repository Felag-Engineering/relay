package capability

// export_test.go exposes test-only seams to the external capability_test
// package. authz imports capability, so a test proving the role floor against
// the REAL authz.RoleGate (askable_rolefloor_test.go) cannot live inside this
// package without an import cycle.

// NewMemApprovalStoreForTest returns the same in-memory ApprovalStore this
// package's own approval tests use (memApprovals), so an external test does
// not need a second fake that could drift from it.
func NewMemApprovalStoreForTest() ApprovalStore { return newMemApprovals() }
