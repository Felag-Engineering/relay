package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// freeze_authz_test.go covers #397's capability-layer half: the Freeze's role
// floor is consulted HERE, not in a surface, so MCP, the Control API, and the
// Console inherit one answer (invariant 10).
//
// What the floor is — a human operator+ to engage, admin to release — is
// authz.RoleGate's to decide and is tested there. These tests prove the
// capability layer asks, refuses on a denial, touches nothing when refused,
// and audits the refusal.

// newFreezeService builds a Service with the given Authorizer and spies,
// wired exactly as the Freeze methods need (no dispatcher, no cap).
func newFreezeService(t *testing.T, gate Authorizer) (*testSvc, *fakeFreezeStore, *spyAuditSink) {
	t.Helper()
	store := &fakeFreezeStore{}
	audit := &spyAuditSink{}
	svc := buildRaw(t, seams{
		reg:     seedOneNode(t),
		authz:   gate,
		cap:     noopCapChecker{},
		disp:    noopDispatcher{},
		audit:   audit,
		freeze:  store,
		metrics: noopMetricsSink{},
	})
	return svc, store, audit
}

// errRefused stands in for whatever authz.RoleGate returns; this package
// cannot import authz (authz imports capability), so the refusal's identity
// is asserted in authz's own tests and only its EFFECT is asserted here.
var errRefused = errors.New("test: refused by the gate")

// TestEngageFreeze_ConsultsTheControlAuthorizer is the acceptance that the
// gate is reached at all — the defect #397 records was not a wrong floor, it
// was no call.
func TestEngageFreeze_ConsultsTheControlAuthorizer(t *testing.T) {
	gate := &spyAuthorizer{}
	svc, store, _ := newFreezeService(t, gate)

	if err := svc.EngageFreeze(context.Background(), Principal{Account: "alice", Role: "operator", Kind: PrincipalKindHuman}); err != nil {
		t.Fatalf("EngageFreeze: %v", err)
	}

	if len(gate.controlCalls) != 1 || gate.controlCalls[0] != ControlFreezeEngage {
		t.Fatalf("AuthorizeControl calls = %v, want exactly [%s]", gate.controlCalls, ControlFreezeEngage)
	}
	if len(store.engageCalls) != 1 {
		t.Errorf("FreezeStore.Engage calls = %d, want 1 once authorized", len(store.engageCalls))
	}
}

// TestEngageFreeze_RefusedIsNotEngagedAndIsAudited: a denied engage must not
// touch the store, and must leave a refusal in the same trail a denied
// dispatch lands in.
func TestEngageFreeze_RefusedIsNotEngagedAndIsAudited(t *testing.T) {
	gate := &spyAuthorizer{controlErr: errRefused}
	svc, store, audit := newFreezeService(t, gate)
	p := Principal{Account: "gleipnir", Role: "operator", Kind: "machine"}

	err := svc.EngageFreeze(context.Background(), p)
	if !errors.Is(err, errRefused) {
		t.Fatalf("EngageFreeze() error = %v, want the gate's refusal", err)
	}
	if len(store.engageCalls) != 0 {
		t.Errorf("FreezeStore.Engage was called %d times on a refused engage; the fleet must not stop", len(store.engageCalls))
	}
	if len(audit.freezeCalls) != 0 {
		t.Errorf("RecordFreeze called %d times on a refused engage; nothing was engaged, so a freeze event would be fiction", len(audit.freezeCalls))
	}

	if len(audit.entries) != 1 {
		t.Fatalf("AuditSink.Record calls = %d, want exactly 1 refusal", len(audit.entries))
	}
	got := audit.entries[0]
	if got.Kind != AuditKindRefusal {
		t.Errorf("audit Kind = %v, want AuditKindRefusal", got.Kind)
	}
	if got.Principal != p {
		t.Errorf("audit Principal = %+v, want %+v — a refusal without the Principal answers nothing", got.Principal, p)
	}
	if got.Reason != errRefused.Error() {
		t.Errorf("audit Reason = %q, want the gate's own reason %q", got.Reason, errRefused.Error())
	}
	// A control refusal carries no Selector, Action, Job, or Results: nothing
	// was resolved and nothing ran.
	if got.JobID != "" || len(got.Results) != 0 {
		t.Errorf("audit entry names a Job or Results (%q, %d) for an act that never dispatched", got.JobID, len(got.Results))
	}
	if len(got.Selector.Predicates) != 0 || got.Action.Kind != jobs.ActionKind(0) {
		t.Errorf("audit entry carries a Selector/Action (%+v, %v) for an act that has neither", got.Selector, got.Action.Kind)
	}
}

// TestReleaseFreeze_RefusedIsNotReleasedAndIsAudited is engage's counterpart
// on the deliberate rung.
func TestReleaseFreeze_RefusedIsNotReleasedAndIsAudited(t *testing.T) {
	gate := &spyAuthorizer{controlErr: errRefused}
	svc, store, audit := newFreezeService(t, gate)
	p := Principal{Account: "olly", Role: "operator", Kind: PrincipalKindHuman}

	err := svc.ReleaseFreeze(context.Background(), p, "incident closed")
	if !errors.Is(err, errRefused) {
		t.Fatalf("ReleaseFreeze() error = %v, want the gate's refusal", err)
	}
	if len(gate.controlCalls) != 1 || gate.controlCalls[0] != ControlFreezeRelease {
		t.Fatalf("AuthorizeControl calls = %v, want exactly [%s]", gate.controlCalls, ControlFreezeRelease)
	}
	if len(store.releaseCalls) != 0 {
		t.Errorf("FreezeStore.Release was called %d times on a refused release; the Freeze must hold", len(store.releaseCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Fatalf("audit entries = %+v, want exactly one refusal", audit.entries)
	}
	if audit.entries[0].Principal != p {
		t.Errorf("audit Principal = %+v, want %+v", audit.entries[0].Principal, p)
	}
}

// TestReleaseFreeze_RequiresAReason is ADR-0013's asymmetry enforced where
// every surface inherits it: an authorized admin still cannot release without
// saying why, and the attempt is on the record.
func TestReleaseFreeze_RequiresAReason(t *testing.T) {
	for _, reason := range []string{"", "   ", "\t\n"} {
		t.Run("reason="+reason, func(t *testing.T) {
			gate := &spyAuthorizer{}
			svc, store, audit := newFreezeService(t, gate)
			p := Principal{Account: "admin", Role: "admin", Kind: PrincipalKindHuman}

			err := svc.ReleaseFreeze(context.Background(), p, reason)
			if !errors.Is(err, ErrFreezeReasonRequired) {
				t.Fatalf("ReleaseFreeze(%q) error = %v, want ErrFreezeReasonRequired", reason, err)
			}
			if len(store.releaseCalls) != 0 {
				t.Errorf("FreezeStore.Release was called on a reasonless release")
			}
			if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
				t.Fatalf("audit entries = %+v, want exactly one refusal", audit.entries)
			}
			if audit.entries[0].Principal != p {
				t.Errorf("audit Principal = %+v, want %+v", audit.entries[0].Principal, p)
			}
		})
	}
}

// TestFreezeLocalLever_BypassesTheRoleGate is ADR-0013's second root of
// authority: root on the Relay host can still pull the cord when the
// distrusted thing is the API credential itself.
//
// The gate here refuses everything. That is the point — the local lever must
// not be a Principal the ladder happens to wave through, and the attribution
// it records must stay "local-host" so the trail keeps saying where the act
// came from.
func TestFreezeLocalLever_BypassesTheRoleGate(t *testing.T) {
	gate := &spyAuthorizer{controlErr: errRefused}
	svc, store, audit := newFreezeService(t, gate)

	if err := svc.EngageFreezeLocal(context.Background()); err != nil {
		t.Fatalf("EngageFreezeLocal: %v", err)
	}
	if len(gate.controlCalls) != 0 {
		t.Errorf("AuthorizeControl was consulted for the host lever (%v); it has no Account to authorize", gate.controlCalls)
	}
	if len(store.engageCalls) != 1 || store.engageCalls[0] != "local-host" {
		t.Fatalf("FreezeStore.Engage calls = %v, want one call attributed to local-host", store.engageCalls)
	}

	const reason = "released locally on relay host"
	if err := svc.ReleaseFreezeLocal(context.Background(), reason); err != nil {
		t.Fatalf("ReleaseFreezeLocal: %v", err)
	}
	if len(store.releaseCalls) != 1 {
		t.Fatalf("FreezeStore.Release calls = %d, want 1", len(store.releaseCalls))
	}
	if got := store.releaseCalls[0]; got.principal != "local-host" || got.reason != reason {
		t.Errorf("FreezeStore.Release call = %+v, want {local-host %q}", got, reason)
	}

	if len(audit.freezeCalls) != 2 {
		t.Fatalf("RecordFreeze calls = %d, want 2 (engage + release)", len(audit.freezeCalls))
	}
	for _, e := range audit.freezeCalls {
		if e.Principal.Attribution() != "local-host" {
			t.Errorf("FreezeEvent principal = %q, want local-host", e.Principal.Attribution())
		}
	}
}

// TestReleaseFreezeLocal_StillRequiresAReason: the host lever is a different
// root of authority, not an exemption from saying why the fleet is running
// again.
func TestReleaseFreezeLocal_StillRequiresAReason(t *testing.T) {
	svc, store, _ := newFreezeService(t, &spyAuthorizer{})

	if err := svc.ReleaseFreezeLocal(context.Background(), "  "); !errors.Is(err, ErrFreezeReasonRequired) {
		t.Fatalf("ReleaseFreezeLocal(blank) error = %v, want ErrFreezeReasonRequired", err)
	}
	if len(store.releaseCalls) != 0 {
		t.Error("FreezeStore.Release was called on a reasonless local release")
	}
}
