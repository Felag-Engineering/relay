package capability

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// fakeFreezeStore is a configurable FreezeStore: frozen/err control what
// Frozen reports, and engageCalls/releaseCalls record every Engage/Release
// invocation so tests can assert on principal/reason.
type fakeFreezeStore struct {
	frozen    bool
	frozenErr error

	engageCalls  []string
	releaseCalls []struct{ principal, reason string }
}

func (f *fakeFreezeStore) Frozen(context.Context) (bool, error) {
	return f.frozen, f.frozenErr
}

func (f *fakeFreezeStore) Engage(_ context.Context, principal string) error {
	f.engageCalls = append(f.engageCalls, principal)
	return nil
}

func (f *fakeFreezeStore) Release(_ context.Context, principal, reason string) error {
	f.releaseCalls = append(f.releaseCalls, struct{ principal, reason string }{principal, reason})
	return nil
}

// TestRunRefusedWhenFrozen is acceptance criterion 1/5: a frozen Relay
// refuses dispatch before any Task is sent, for either risk class, and the
// dispatcher is never reached.
func TestRunRefusedWhenFrozen(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{frozen: true}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: freezeStore, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}

	tests := []struct {
		name  string
		class jobs.RiskClass
	}{
		{"read", jobs.RiskClassRead},
		{"mutate", jobs.RiskClassMutate},
	}
	for _, tt := range tests {
		class := tt.class
		t.Run(tt.name, func(t *testing.T) {
			authz.called, capChecker.called, disp.called, audit.called = false, false, false, false
			act := jobs.Action{RiskClass: class}
			_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)

			var frozenErr *FrozenError
			if !errors.As(err, &frozenErr) {
				t.Fatalf("Run() error = %v, want errors.As to find a *FrozenError", err)
			}
			if authz.called {
				t.Error("Authorizer must not be called when the Relay is frozen")
			}
			if capChecker.called {
				t.Error("CapChecker must not be called when the Relay is frozen")
			}
			if disp.called {
				t.Error("dispatcher must not be called when the Relay is frozen")
			}
			if !audit.called {
				t.Error("AuditSink must be called when the Relay is frozen — refusals are audited")
			}
			if audit.entry.Kind != AuditKindRefusal {
				t.Errorf("AuditEntry.Kind = %v, want AuditKindRefusal", audit.entry.Kind)
			}
		})
	}
}

// TestRunNotFrozenProceedsNormally: with the Freeze not engaged, Run
// proceeds through the rest of the pipeline as usual.
func TestRunNotFrozenProceedsNormally(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{jobID: "job-1"}
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{frozen: false}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: freezeStore, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})
	if err != nil {
		t.Fatalf("Run() with the Freeze not engaged returned unexpected error: %v", err)
	}
	if !disp.called {
		t.Error("dispatcher was not called; the Freeze gate should not block a non-frozen Run")
	}
}

// TestRunFreezeReadErrorFailsClosed: if Frozen itself errors (a store blip),
// Run refuses dispatch rather than risk a fail-open.
func TestRunFreezeReadErrorFailsClosed(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{frozenErr: errors.New("store unavailable")}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: freezeStore, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})
	if err == nil {
		t.Fatal("Run() with a Frozen read error should return an error (fail closed)")
	}
	if disp.called {
		t.Error("dispatcher must not be called when the Freeze state cannot be read")
	}
	if !audit.called {
		t.Error("AuditSink must be called when the Freeze read fails — refusals are audited")
	}
}

// TestEngageFreezePersistsAndAudits is acceptance criterion 6 (engage half):
// EngageFreeze persists via FreezeStore.Engage and records a RecordFreeze
// audit event attributed to the local-host principal.
func TestEngageFreezePersistsAndAudits(t *testing.T) {
	reg := seedOneNode(t)
	freezeStore := &fakeFreezeStore{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: allowAllAuthorizer{}, cap: noopCapChecker{}, disp: noopDispatcher{}, audit: audit, freeze: freezeStore, metrics: noopMetricsSink{}}

	principal := Principal{Account: "local-host"}
	if err := svc.EngageFreeze(context.Background(), principal); err != nil {
		t.Fatalf("EngageFreeze: %v", err)
	}

	if len(freezeStore.engageCalls) != 1 || freezeStore.engageCalls[0] != "local-host" {
		t.Errorf("FreezeStore.Engage calls = %v, want one call with principal local-host", freezeStore.engageCalls)
	}
	if len(audit.freezeCalls) != 1 {
		t.Fatalf("AuditSink.RecordFreeze calls = %d, want 1", len(audit.freezeCalls))
	}
	got := audit.freezeCalls[0]
	if !got.Engage {
		t.Error("FreezeEvent.Engage = false, want true")
	}
	if got.Principal != principal {
		t.Errorf("FreezeEvent.Principal = %+v, want %+v", got.Principal, principal)
	}
}

// TestReleaseFreezePersistsAndAudits is acceptance criterion 6 (release
// half): ReleaseFreeze persists via FreezeStore.Release (with the reason)
// and records a RecordFreeze audit event carrying that reason.
func TestReleaseFreezePersistsAndAudits(t *testing.T) {
	reg := seedOneNode(t)
	freezeStore := &fakeFreezeStore{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: allowAllAuthorizer{}, cap: noopCapChecker{}, disp: noopDispatcher{}, audit: audit, freeze: freezeStore, metrics: noopMetricsSink{}}

	principal := Principal{Account: "local-host"}
	reason := "released locally on relay host"
	if err := svc.ReleaseFreeze(context.Background(), principal, reason); err != nil {
		t.Fatalf("ReleaseFreeze: %v", err)
	}

	if len(freezeStore.releaseCalls) != 1 {
		t.Fatalf("FreezeStore.Release calls = %d, want 1", len(freezeStore.releaseCalls))
	}
	if got := freezeStore.releaseCalls[0]; got.principal != "local-host" || got.reason != reason {
		t.Errorf("FreezeStore.Release call = %+v, want {local-host %q}", got, reason)
	}
	if len(audit.freezeCalls) != 1 {
		t.Fatalf("AuditSink.RecordFreeze calls = %d, want 1", len(audit.freezeCalls))
	}
	got := audit.freezeCalls[0]
	if got.Engage {
		t.Error("FreezeEvent.Engage = true, want false")
	}
	if got.Reason != reason {
		t.Errorf("FreezeEvent.Reason = %q, want %q", got.Reason, reason)
	}
	if got.Principal != principal {
		t.Errorf("FreezeEvent.Principal = %+v, want %+v", got.Principal, principal)
	}
}

// TestFreezeSurvivesRestart is acceptance criterion 2, proven at the
// capability layer: engaging via a Service backed by a real store, closing
// and reopening the store, and building a second Service on the reopened
// store's Freeze() still refuses dispatch.
func TestFreezeSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-1", NodeLabels: map[string]string{"role": "web"}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	svcA := New(reg, WithFreeze(st.Freeze()))
	if err := svcA.EngageFreeze(context.Background(), Principal{Account: "local-host"}); err != nil {
		t.Fatalf("EngageFreeze: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store.Open: %v", err)
	}
	t.Cleanup(func() { st2.Close() }) //nolint:errcheck

	svcB := New(reg, WithFreeze(st2.Freeze()))
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	_, err = svcB.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})

	var frozenErr *FrozenError
	if !errors.As(err, &frozenErr) {
		t.Fatalf("Run() on the reopened store's Service error = %v, want errors.As to find a *FrozenError (the Freeze must survive a restart)", err)
	}
}
