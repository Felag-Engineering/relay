package capability_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// askable_rolefloor_test.go proves issue #723's acceptance criterion "the role
// floor cannot refuse an answer the askable predicate permitted" against the
// REAL role ladder (internal/authz), not a fake standing in for it. This has
// to be an external test package: authz imports capability, so a test built
// against authz.NewRoleGate() from inside package capability would be an
// import cycle.

// nopAuditSink is a tiny local capability.AuditSink. This test is about the
// role floor, not about what lands in the trail, and capability's own
// noopAuditSink is unexported.
type nopAuditSink struct{}

func (nopAuditSink) Record(context.Context, capability.AuditEntry) error        { return nil }
func (nopAuditSink) RecordFreeze(context.Context, capability.FreezeEvent) error { return nil }
func (nopAuditSink) RecordCancel(context.Context, capability.Principal, string) error {
	return nil
}
func (nopAuditSink) RecordRead(context.Context, capability.Principal, string, string, string, string) error {
	return nil
}
func (nopAuditSink) RecordAccountAdmin(context.Context, capability.Principal, capability.AccountAdminEvent) error {
	return nil
}

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the default of the underlying constructor stays.
// gate, approvals and approvalAuthz are all required, because NewApprovals is.
type capSeams struct {
	reg           registry.Repository
	authz         capability.Authorizer
	audit         capability.AuditSink
	gate          capability.ApprovalGate
	approvals     capability.ApprovalStore
	approvalAuthz capability.ApprovalAuthorizer
	now           func() time.Time
}

// neverFrozen is a FreezeStore that is never frozen, standing in for
// capability's unexported noopFreezeStore: NewControl requires a store.
type neverFrozen struct{}

func (neverFrozen) Frozen(context.Context) (bool, error)          { return false, nil }
func (neverFrozen) Engage(context.Context, string) error          { return nil }
func (neverFrozen) Release(context.Context, string, string) error { return nil }

// emptyQueries implements capability.AuditQuery and capability.JobQuery with
// zero values: NewReadLane requires both query seams, and this test reads
// neither.
type emptyQueries struct{}

func (emptyQueries) QueryAudit(context.Context, capability.AuditFilter, capability.PageRequest) (capability.AuditPage, error) {
	return capability.AuditPage{}, nil
}

func (emptyQueries) AuditCounts(context.Context, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (emptyQueries) AuditReach(context.Context, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

func (emptyQueries) QueryJobs(context.Context, capability.JobFilter, capability.PageRequest) (capability.JobPage, error) {
	return capability.JobPage{}, nil
}

func (emptyQueries) QueryTasks(context.Context, capability.TaskFilter, capability.PageRequest) (capability.TaskPage, error) {
	return capability.TaskPage{}, nil
}

// newCapService builds the capability layer for a test: a thin wrapper over
// the capability constructors, so the layer's shape changes in one place.
func newCapService(t *testing.T, s capSeams) *capLayer {
	t.Helper()
	if s.audit == nil || s.authz == nil {
		t.Fatalf("newCapService: audit and authz are required")
	}
	if s.gate == nil || s.approvals == nil || s.approvalAuthz == nil {
		t.Fatalf("newCapService: gate, approvals and approvalAuthz are required")
	}
	rec := capability.NewRecorder(s.audit, nil, nil)
	ctl := capability.NewControl(rec, s.authz, neverFrozen{})
	read := capability.NewReadLane(rec, s.reg, emptyQueries{}, emptyQueries{}, nil, nil, 0, s.now)
	appr := capability.NewApprovals(rec, s.gate, s.approvals, s.approvalAuthz, nil, nil, nil, s.now)
	return &capLayer{capability.NewExecutionWithoutEngineForTest(ctl, read, appr), appr}
}

// capLayer is the Execution and the Approvals it is built over, embedded so a
// test calls Run and DecideApproval on one value.
type capLayer struct {
	*capability.Execution
	*capability.Approvals
}

// maxSweptActionKind bounds TestRoleFloorCannotRefuseAnAskablePark's sweep.
// jobs.ActionKind knows exactly three values today (Unspecified, Operation,
// RawExec); 32 leaves generous headroom above that so a kind added later,
// however it is numbered, is swept before it is ever wired into RoleGate.
const maxSweptActionKind = jobs.ActionKind(32)

// TestRoleFloorCannotRefuseAnAskablePark sweeps every role the ladder knows
// against every Action kind from jobs.ActionKind(0) through
// maxSweptActionKind — not just the two RoleGate happens to recognize today:
// whichever pairs pass Authorize and park askable, the SAME role floor
// (AuthorizeApprovalDecision) must let that same caller decide it, end to
// end through DecideApproval.
//
// The full range is swept, rather than one hand-picked "unrecognized" kind,
// so this test cannot go stale by omission: if RoleGate ever starts
// admitting a THIRD Action kind anywhere in range, the assertions below on
// admin's authorized-kind set catch it immediately rather than the sweep
// silently continuing to check only the two kinds it always knew about.
func TestRoleFloorCannotRefuseAnAskablePark(t *testing.T) {
	gate, err := approval.NewGate([]approval.Rule{{
		Name:  "askable",
		Match: approval.Match{},
		Require: approval.Requirement{
			Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour,
		},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	roleGate := authz.NewRoleGate()
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

	roles := []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}

	kinds := make([]struct {
		name string
		act  jobs.Action
	}, 0, maxSweptActionKind+1)
	for k := jobs.ActionKind(0); k <= maxSweptActionKind; k++ {
		act := jobs.Action{Kind: k}
		name := fmt.Sprintf("kind-%d", k)
		switch k {
		case jobs.ActionOperation:
			act.OperationName = "service.restart"
			name = "operation"
		case jobs.ActionRawExec:
			act.RawExecArgv = []string{"uptime"}
			name = "raw-exec"
		}
		kinds = append(kinds, struct {
			name string
			act  jobs.Action
		}{name, act})
	}

	askableCount := 0
	// adminAuthorizedKinds is what makes the doc comment above true: it is
	// checked against exactly {Operation, RawExec} after the sweep, over the
	// WHOLE swept range, rather than trusting the comment's claim on faith.
	adminAuthorizedKinds := map[jobs.ActionKind]bool{}

	for _, role := range roles {
		for _, kc := range kinds {
			t.Run(string(role)+"/"+kc.name, func(t *testing.T) {
				reg := registry.NewInMemory()
				if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
					t.Fatalf("seed registry: %v", err)
				}
				// A fresh Service per pair, so no pair bounces off another
				// pair's pending request for the identical Action/Selector.
				s := newCapService(t, capSeams{
					reg:           reg,
					authz:         roleGate,
					audit:         nopAuditSink{},
					gate:          gate,
					approvals:     capability.NewMemApprovalStoreForTest(),
					approvalAuthz: roleGate,
					now:           func() time.Time { return now },
				})

				p := capability.Principal{
					AccountID: "acct-" + string(role), Account: "acct-" + string(role),
					Role: string(role), Kind: capability.PrincipalKindHuman,
				}

				_, runErr := s.Run(context.Background(), p, capability.Selector{}, kc.act)

				var parked *capability.ParkedError
				authorized := errors.As(runErr, &parked)
				if role == accounts.RoleAdmin {
					adminAuthorizedKinds[kc.act.Kind] = authorized
				}
				if !authorized {
					// Authorize refused this pair before the gate was ever
					// consulted: this caller cannot request this kind at
					// all. Every rule in the fixture's gate matches every
					// Dispatch (an empty Match), so the only refusal path
					// reachable here is Authorize itself — pin that rather
					// than treating "not a park" as good enough.
					if runErr == nil {
						t.Fatal("Run: err = nil, want a refusal (Authorize should have denied this pair)")
					}
					if !errors.Is(runErr, authz.ErrUnauthorized) {
						t.Errorf("Run: err = %v, want an authz.ErrUnauthorized refusal", runErr)
					}
					return
				}
				if !parked.Askable {
					return
				}
				askableCount++

				got, err := s.Approval(context.Background(), parked.RequestID)
				if err != nil {
					t.Fatalf("Approval: %v", err)
				}
				if err := roleGate.AuthorizeApprovalDecision(context.Background(), p, got.ActionKind); err != nil {
					t.Errorf("role floor refused an answer the askable predicate already permitted: %v", err)
				}

				if _, err := s.DecideApproval(context.Background(), p, capability.ApprovalDecision{
					RequestID: parked.RequestID, PlanHash: parked.PlanHash,
					Approve: true, Channel: approval.ChannelInBand,
				}); err != nil {
					t.Errorf("DecideApproval as the askable caller: %v", err)
				}
			})
		}
	}

	// Non-vacuity: the property above is only meaningful if it was actually
	// exercised. Exactly these three pairs may request an Action AND find it
	// askable — every other pair is refused at Authorize before the gate is
	// ever reached (asserted below via adminAuthorizedKinds, the strictest
	// role in the sweep).
	if askableCount != 3 {
		t.Errorf("askable parks = %d, want exactly 3 (operator/operation, admin/operation, admin/raw-exec)", askableCount)
	}

	wantAdminAuthorized := map[jobs.ActionKind]bool{
		jobs.ActionOperation: true,
		jobs.ActionRawExec:   true,
	}
	for _, kc := range kinds {
		got := adminAuthorizedKinds[kc.act.Kind]
		want := wantAdminAuthorized[kc.act.Kind]
		if got != want {
			t.Errorf("admin authorized for %s (kind %d) = %v, want %v — the doc comment's claim that "+
				"RoleGate recognizes only Operation and RawExec in this range no longer holds",
				kc.name, kc.act.Kind, got, want)
		}
	}
}
