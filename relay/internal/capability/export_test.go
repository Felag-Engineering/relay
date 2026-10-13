package capability

// export_test.go exposes test-only seams to the external capability_test
// package. authz imports capability, so a test proving the role floor against
// the REAL authz.RoleGate (askable_rolefloor_test.go) cannot live inside this
// package without an import cycle.

// NewMemApprovalStoreForTest returns the same in-memory ApprovalStore this
// package's own approval tests use (memApprovals), so an external test does
// not need a second fake that could drift from it.
func NewMemApprovalStoreForTest() ApprovalStore { return newMemApprovals() }

// NewExecutionWithoutEngineForTest returns an Execution over the no-op
// dispatcher and the no-op CapChecker, for askable_rolefloor_test.go, which
// must stay external (the authz import cycle) and never dispatches: Run
// authorizes, then parks or refuses. NewExecution cannot serve it, because
// it wires the real engine and so refuses the no-op seams.
func NewExecutionWithoutEngineForTest(control *Control, read *ReadLane, approvals *Approvals) *Execution {
	return newExecution(control, read, approvals, noopCapChecker{}, nil, noopDispatcher{}, nil)
}
