package capability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// mutableSettings is a source a test changes between requests, standing in for
// the composition root's live snapshot. A pointer type, as the interface requires.
type mutableSettings struct {
	mu sync.Mutex
	s  OperatorSettings
}

func (m *mutableSettings) OperatorSettings() OperatorSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.s
}

func (m *mutableSettings) set(f func(*OperatorSettings)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.s)
}

// TestCapability_ReadsReachSettingsPerRequest: the layer reads the blast caps,
// the state:cert-expiring window and the dispatch concurrency from its source on
// every request, so a change to the source applies to the next request without
// rebuilding anything (RC-21).
func TestCapability_ReadsReachSettingsPerRequest(t *testing.T) {
	alice := Principal{Account: "alice"}

	t.Run("blast caps", func(t *testing.T) {
		src := &mutableSettings{s: OperatorSettings{MutateBlastCap: 3, DispatchConcurrency: 1}}
		reg := seedNodes(t, 4)
		conduit := newFakeConduit(nil)
		for _, id := range []string{"node-0", "node-1", "node-2", "node-3"} {
			conduit.connected[id] = true
			conduit.results[id] = jobs.Result{Outcome: jobs.OutcomeSuccess}
			conduit.verdicts[id] = jobs.Verdict{Allowed: true}
		}
		jobsRepo, tasksRepo := testEngineStore(t)
		svc := build(t, seams{reg: reg, settings: src, cap: NewBlastCap(src),
			authz: &spyAuthorizer{}, audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
			jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit})
		sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
		act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart"}

		var capErr *CapExceededError
		if _, err := svc.Run(context.Background(), alice, sel, act); !errors.As(err, &capErr) || capErr.Cap != 3 {
			t.Fatalf("Run at mutate-cap 3 over 4 Nodes = %v, want a CapExceededError with Cap 3", err)
		}
		src.set(func(s *OperatorSettings) { s.MutateBlastCap = 2 })
		raw := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}}
		pr, err := svc.Plan(context.Background(), alice, sel, raw)
		if err != nil || pr.CapExceeded == nil || pr.CapExceeded.Cap != 2 {
			t.Fatalf("Plan after lowering the cap to 2 = %+v, %v; want CapExceeded.Cap 2", pr, err)
		}
		src.set(func(s *OperatorSettings) { s.MutateBlastCap = 4 })
		results, err := svc.Run(context.Background(), alice, sel, act)
		if err != nil || len(results) != 4 {
			t.Fatalf("Run after raising the cap to 4 = %d results, %v; want 4, nil", len(results), err)
		}
	})

	t.Run("cert-expiring window", func(t *testing.T) {
		now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		reg := registry.NewInMemory()
		if _, err := reg.Upsert(registry.Report{NodeID: "node-1"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if err := reg.RecordEnrollment("node-1", registry.Certificate{NotAfter: now.Add(10 * time.Hour)}, now); err != nil {
			t.Fatalf("RecordEnrollment: %v", err)
		}
		src := &mutableSettings{}
		svc := build(t, seams{reg: reg, settings: src, auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{},
			audit: &spyAuditSink{}, now: func() time.Time { return now }})

		listing, err := svc.ListNodes(context.Background(), alice, "state:cert-expiring")
		if err != nil || len(listing.Nodes) != 0 || listing.Eval.CertExpiringWithin != 0 {
			t.Fatalf("ListNodes with window 0 = %d Nodes, window %v, %v; want none, 0", len(listing.Nodes), listing.Eval.CertExpiringWithin, err)
		}
		src.set(func(s *OperatorSettings) { s.CertExpiringWithin = 84 * time.Hour })
		listing, err = svc.ListNodes(context.Background(), alice, "state:cert-expiring")
		if err != nil || len(listing.Nodes) != 1 || listing.Eval.CertExpiringWithin != 84*time.Hour {
			t.Fatalf("ListNodes with window 84h = %d Nodes, window %v, %v; want 1, 84h", len(listing.Nodes), listing.Eval.CertExpiringWithin, err)
		}
		src.set(func(s *OperatorSettings) { s.CertExpiringWithin = -time.Hour })
		if listing, _ = svc.ListNodes(context.Background(), alice, ""); listing.Eval.CertExpiringWithin != 0 {
			t.Errorf("a negative window reads as %v, want it clamped to 0", listing.Eval.CertExpiringWithin)
		}
	})

	t.Run("dispatch concurrency", func(t *testing.T) {
		src := &mutableSettings{s: OperatorSettings{DispatchConcurrency: 1}}
		jobsRepo, tasksRepo := testEngineStore(t)
		svc := build(t, seams{reg: registry.NewInMemory(), settings: src,
			authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
			jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: newFakeConduit(nil)})
		eng := svc.disp.(*jobEngine)
		if got := eng.dispatchLimit(); got != 1 {
			t.Fatalf("dispatchLimit = %d, want 1", got)
		}
		src.set(func(s *OperatorSettings) { s.DispatchConcurrency = 3 })
		if got := eng.dispatchLimit(); got != 3 {
			t.Fatalf("dispatchLimit after the source changed = %d, want 3", got)
		}
		src.set(func(s *OperatorSettings) { s.DispatchConcurrency = 0 })
		if got := eng.dispatchLimit(); got != 1 {
			t.Fatalf("dispatchLimit for a non-positive value = %d, want the fail-safe 1", got)
		}
	})
}

// TestNewExecution_RefusesSplitOperatorSettings: the read lane, the BlastCap and
// the Execution must hold one source, so a reload cannot leave the layer reading
// two. Each case has a valid DispatchConcurrency on every source, so only the
// identity guard can fire.
func TestNewExecution_RefusesSplitOperatorSettings(t *testing.T) {
	newSrc := func() *StaticOperatorSettings { return concurrencyOf(DefaultDispatchConcurrency) }
	construct := func(t *testing.T, readSrc, capSrc, execSrc OperatorSettingsSource) {
		t.Helper()
		jr, tr := testEngineStore(t)
		rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}, nil, nil)
		ctl := NewControl(rec, &spyAuthorizer{}, &fakeFreezeStore{})
		read := newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, readSrc, nil)
		appr := newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil)
		NewExecution(ctl, read, appr, NewBlastCap(capSrc), nil, jr, tr, newFakeConduit(nil), execSrc, nil, nil)
	}
	wantPanic := func(t *testing.T, want string, f func()) {
		t.Helper()
		defer func() {
			msg, _ := recover().(string)
			if !strings.Contains(msg, want) {
				t.Errorf("panic = %q, want it to contain %q", msg, want)
			}
		}()
		f()
	}

	t.Run("read lane on another source", func(t *testing.T) {
		a, b := newSrc(), newSrc()
		wantPanic(t, "the read lane and the Execution must share one OperatorSettingsSource", func() { construct(t, a, b, b) })
	})
	t.Run("BlastCap on another source", func(t *testing.T) {
		a, b := newSrc(), newSrc()
		wantPanic(t, "the BlastCap and the Execution must share one OperatorSettingsSource", func() { construct(t, a, b, a) })
	})
	t.Run("equal values are still two sources", func(t *testing.T) {
		wantPanic(t, "must share one OperatorSettingsSource", func() { construct(t, newSrc(), newSrc(), newSrc()) })
	})
	t.Run("one shared source is accepted", func(t *testing.T) {
		a := newSrc()
		construct(t, a, a, a)
	})
}

func TestNewBlastCap_RefusesNilSource(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewBlastCap(nil) did not panic")
		}
	}()
	NewBlastCap(nil)
}
