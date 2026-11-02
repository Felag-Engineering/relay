package capability

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// listCountingRegistry counts List calls, which is how Selector resolution
// reads the registry.
type listCountingRegistry struct {
	registry.Repository
	lists atomic.Int32
}

func (r *listCountingRegistry) List() []registry.Node {
	r.lists.Add(1)
	return r.Repository.List()
}

// createJobCountingRepo counts CreateJob calls, the only way a Job ID is minted
// into the store.
type createJobCountingRepo struct {
	jobs.JobRepository
	creates atomic.Int32
}

func (r *createJobCountingRepo) CreateJob(ctx context.Context, j jobs.Job) error {
	r.creates.Add(1)
	return r.JobRepository.CreateJob(ctx, j)
}

// emptySelectorInputs are the three ways a caller reaches an empty Selector:
// the selector argument omitted (an adapter hands over ""), empty, and only
// whitespace.
func emptySelectorInputs(t *testing.T) map[string]Selector {
	t.Helper()
	empty, err := ParseSelector("")
	if err != nil {
		t.Fatalf("ParseSelector(\"\"): %v", err)
	}
	blank, err := ParseSelector(" \t ")
	if err != nil {
		t.Fatalf("ParseSelector(blank): %v", err)
	}
	return map[string]Selector{"omitted": {}, "empty": empty, "whitespace": blank}
}

func assertEmptySelectorRefusal(t *testing.T, err error) {
	t.Helper()
	var emptyErr *EmptySelectorError
	if !errors.As(err, &emptyErr) {
		t.Fatalf("err = %v, want *EmptySelectorError", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "empty_selector") || !strings.Contains(msg, WholeFleetSelector) {
		t.Errorf("refusal %q must carry the token empty_selector and name %s", msg, WholeFleetSelector)
	}
}

func auditKinds(entries []AuditEntry) []AuditKind {
	var kinds []AuditKind
	for _, e := range entries {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// TestExecution_EmptySelectorIsRefusedBeforeAnythingResolves proves that a
// dispatch whose Selector names nothing is refused before the registry is read,
// an idempotency key is claimed, anything parks or a Job ID is minted, even
// where the same call with a Selector would park (#1274).
func TestExecution_EmptySelectorIsRefusedBeforeAnythingResolves(t *testing.T) {
	acts := map[string]jobs.Action{
		"native read":   readFacts(),
		"native mutate": mutateAct(),
		"raw exec":      mutateRawExec(),
	}
	callers := map[string]string{"run": "", "start without key": "", "start with key": "k-1"}

	for inputName, sel := range emptySelectorInputs(t) {
		for actName, act := range acts {
			for callName, key := range callers {
				t.Run(inputName+"/"+actName+"/"+callName, func(t *testing.T) {
					approvals := newMemApprovals()
					metrics := &recordingMetrics{}
					var reg *listCountingRegistry
					var jobRepo *createJobCountingRepo
					f := newStartFx(t, func(s *seams) {
						reg = &listCountingRegistry{Repository: s.reg}
						s.reg = reg
						jobRepo = &createJobCountingRepo{JobRepository: s.jobsRepo}
						s.jobsRepo = jobRepo
						s.gate = gateEverything(t)
						s.approvals = approvals
						s.approvalAuthz = &spyApprovalAuthorizer{}
						s.metrics = metrics
					})

					var err error
					if callName == "run" {
						_, err = f.svc.Run(context.Background(), alice, sel, act)
					} else {
						_, err = f.svc.Start(context.Background(), alice, sel, act, keyed(key))
					}

					assertEmptySelectorRefusal(t, err)
					if n := reg.lists.Load(); n != 0 {
						t.Errorf("registry List called %d times, want 0: nothing may resolve", n)
					}
					if n := jobRepo.creates.Load(); n != 0 {
						t.Errorf("CreateJob called %d times, want 0: no Job may exist", n)
					}
					if n := f.idem.calls.Load(); n != 0 {
						t.Errorf("idempotency repository touched %d times, want 0", n)
					}
					for _, id := range startNode {
						if n := f.conduit.dispatched(id); n != 0 {
							t.Errorf("%s was sent %d Tasks, want 0", id, n)
						}
					}
					if len(approvals.byID) != 0 {
						t.Errorf("approval store holds %d Requests, want 0: nothing may park", len(approvals.byID))
					}
					if kinds := auditKinds(f.audit.entries); len(kinds) != 1 || kinds[0] != AuditKindRefusal {
						t.Errorf("audit kinds = %v, want exactly one AuditKindRefusal", kinds)
					}
					if len(metrics.refusals) != 1 || metrics.refusals[0] != RefusalMalformed {
						t.Errorf("refusal metrics = %v, want [RefusalMalformed]", metrics.refusals)
					}
				})
			}
		}
	}

	t.Run("control: a named Selector parks, so the gate was armed", func(t *testing.T) {
		f := newStartFx(t, func(s *seams) {
			s.gate = gateEverything(t)
			s.approvals = newMemApprovals()
			s.approvalAuthz = &spyApprovalAuthorizer{}
		})
		_, err := f.svc.Run(context.Background(), alice, fleetSel, mutateAct())
		var parked *ParkedError
		if !errors.As(err, &parked) {
			t.Fatalf("err = %v, want *ParkedError", err)
		}
	})
}

// TestPlan_EmptySelectorIsRefusedNotReported proves a Policy preflight refuses
// an empty Selector as a dispatch does, rather than reporting no_nodes_matched
// (#1274).
func TestPlan_EmptySelectorIsRefusedNotReported(t *testing.T) {
	acts := map[string]jobs.Action{"native read": readFacts(), "raw exec": mutateRawExec()}
	for inputName, sel := range emptySelectorInputs(t) {
		for actName, act := range acts {
			t.Run(inputName+"/"+actName, func(t *testing.T) {
				var log []string
				conduit := newFakeConduit(&log)
				svc, audit, _ := newPlanTestService(t, seedNodes(t, 2), conduit)

				res, err := svc.Plan(context.Background(), alice, sel, act)

				assertEmptySelectorRefusal(t, err)
				if res.NoNodesMatched || len(res.Verdicts) != 0 {
					t.Errorf("PlanResult = %+v, want the zero value: a refusal, not a report", res)
				}
				if len(log) != 0 {
					t.Errorf("conduit saw %v, want no query", log)
				}
				if kinds := auditKinds(audit.entries); len(kinds) != 1 || kinds[0] != AuditKindRefusal {
					t.Errorf("audit kinds = %v, want exactly one AuditKindRefusal and no AuditKindPlan", kinds)
				}
			})
		}
	}
}

// TestExecution_FreezeStillOutranksAnEmptySelector pins the order: the Freeze is
// the outermost gate (ADR-0013), so an empty Selector during a Freeze is
// reported as the Freeze.
func TestExecution_FreezeStillOutranksAnEmptySelector(t *testing.T) {
	f := newStartFx(t)
	f.freeze.frozen = true

	_, err := f.svc.Run(context.Background(), alice, Selector{}, mutateAct())

	var frozen *FrozenError
	if !errors.As(err, &frozen) {
		t.Fatalf("err = %v, want *FrozenError", err)
	}
	var emptyErr *EmptySelectorError
	if errors.As(err, &emptyErr) {
		t.Fatalf("err = %v, must not be an EmptySelectorError while frozen", err)
	}
}

// TestWholeFleetSelector_ParsesToTheDefaultOSLabel keeps the Selector the
// refusal recommends a valid one that reaches a Node carrying node:os=linux.
func TestWholeFleetSelector_ParsesToTheDefaultOSLabel(t *testing.T) {
	sel, err := ParseSelector(WholeFleetSelector)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", WholeFleetSelector, err)
	}
	want := Predicate{Namespace: NamespaceNode, Key: "os", Value: "linux"}
	if len(sel.Predicates) != 1 || sel.Predicates[0] != want {
		t.Fatalf("predicates = %+v, want exactly %+v", sel.Predicates, want)
	}
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(linuxReport("node-1")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got := sel.Resolve(reg, StateEval{}); len(got) != 1 {
		t.Fatalf("%s matched %d Nodes, want 1", WholeFleetSelector, len(got))
	}
}

// TestListNodes_EmptyOrWhitespaceFilterListsEveryNode proves reads are
// unchanged: an empty filter still means every Node, because a read dispatches
// nothing (#1274).
func TestListNodes_EmptyOrWhitespaceFilterListsEveryNode(t *testing.T) {
	svc, _ := registryLaneFixture(t, registry.Report{NodeID: "node-1"}, registry.Report{NodeID: "node-2"})
	for _, filter := range []string{"", "   "} {
		listing, err := svc.ListNodes(context.Background(), testPrincipal, filter)
		if err != nil {
			t.Fatalf("ListNodes(%q): %v", filter, err)
		}
		if len(listing.Nodes) != 2 {
			t.Errorf("ListNodes(%q) returned %d Nodes, want 2", filter, len(listing.Nodes))
		}
	}
}
