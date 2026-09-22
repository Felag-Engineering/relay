package auditquery

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// counterID returns an idGen-shaped func (assignable to capability's
// unexported idGen: identical underlying function type) that yields
// prefix+"1", prefix+"2", ... in call order, mirroring capability's own
// sequentialIDs test helper — duplicated here rather than exported, since
// capability's test helper is unexported and this package must not widen
// capability's surface just to reach it.
func counterID(prefix string) func() (string, error) {
	n := 0
	return func() (string, error) {
		n++
		return fmt.Sprintf("%s%d", prefix, n), nil
	}
}

// probeConduit is a capability.Conduit whose Connected method runs probe
// exactly once — on the FIRST call — then always reports the Node
// connected. dispatchOne calls Connected as its first step for each Task,
// after every Task in the Job has been persisted Pending and before any is
// MarkDispatched, so the first call is the earliest point at which the
// probe can observe (and, here, cancel) a Job with every Task still
// Pending.
//
// The probe runs from inside svc.Run, on the same goroutine driving the
// test, so it must never call t.Fatal (or anything else that calls
// FailNow): that would abandon svc.Run mid-call rather than simply failing
// the test. Failures are collected into probeErrs and asserted after Run
// returns.
type probeConduit struct {
	probe         func()
	probed        bool
	dispatchCalls int
}

func (c *probeConduit) Connected(string) bool {
	if !c.probed {
		c.probed = true
		c.probe()
	}
	return true
}

func (c *probeConduit) Dispatch(context.Context, string, jobs.Task) (jobs.Result, error) {
	c.dispatchCalls++
	return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
}

func (c *probeConduit) Cancel(context.Context, string, string) error { return nil }

func (c *probeConduit) Query(context.Context, string, jobs.Action) (jobs.Verdict, error) {
	return jobs.Verdict{}, nil
}

// TestRun_RequesterIsReadableAndEnforcedWhileEveryTaskIsPending (#616, AC4)
// is the capability read lane's end-to-end proof: the requester recorded on
// a Job is durable and enforced WHILE every one of its Tasks is still
// Pending — before any dispatch has been attempted — reading and cancelling
// through the same seams a real surface uses (Service.QueryJobs,
// Service.CancelJob), against one real SQLite store, wired the way
// cmd/relay/main.go wires the production execution path.
//
// This test fails on main: main's requester is joined from the audit
// dispatch row, which does not exist until AFTER disp.run returns, so step
// (b) below would read an empty requester and step (f) would be refused
// with ErrJobNotRequestedByCaller for a Job the caller actually owns.
func TestRun_RequesterIsReadableAndEnforcedWhileEveryTaskIsPending(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	// Two Nodes, matched by a plain node: Selector — no state: predicate, so
	// registry connectivity/state never gates the match — and DaemonVersion
	// left unset: registry.NewInMemory's minimum-version gate defaults to ""
	// (off), so neither Node is ever Outdated regardless.
	reg := registry.NewInMemory()
	for _, id := range []string{"node-1", "node-2"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}

	requester := capability.Principal{AccountID: "acct-machine-1", Account: "agent-1", Role: "operator", Kind: "machine"}
	other := capability.Principal{AccountID: "acct-machine-2", Account: "agent-2", Role: "operator", Kind: "machine"}

	const jobID = "job-id-1" // counterID("id-"): the Job gets the first minted id.
	var probeErrs []string
	record := func(format string, args ...any) { probeErrs = append(probeErrs, fmt.Sprintf(format, args...)) }

	q := New(st.AuditQueries(), st.JobQueries())
	conduit := &probeConduit{}

	svc := capability.New(reg,
		capability.WithAuthorizer(authz.NewRoleGate()),
		capability.WithCapChecker(capability.NewBlastCap(10, 10)),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithFreeze(st.Freeze()),
		capability.WithQueries(q, q),
		capability.WithExecution(st.Jobs(), st.Tasks(), conduit, capability.WithExecNewID(counterID("id-"))),
	)

	conduit.probe = func() {
		// (a) Every Task is still Pending.
		tasks, err := st.Tasks().ByJob(ctx, jobID)
		if err != nil {
			record("ByJob(%s): %v", jobID, err)
		}
		if len(tasks) != 2 {
			record("ByJob(%s) returned %d Tasks, want 2", jobID, len(tasks))
		}
		for _, task := range tasks {
			if task.State != jobs.DispatchStatePending {
				record("task %s state = %v, want Pending", task.ID, task.State)
			}
		}

		// (b) QueryJobs reads back the requester while the Job is in flight.
		one, err := svc.QueryJobs(ctx, requester, capability.JobFilter{JobID: jobID}, capability.PageRequest{Limit: 1})
		if err != nil {
			record("QueryJobs(JobID): %v", err)
		} else if len(one.Jobs) != 1 {
			record("QueryJobs(JobID) returned %d rows, want 1", len(one.Jobs))
		} else if got := one.Jobs[0]; got.RequesterAccountID != "acct-machine-1" || got.Requester != "agent-1" || got.RequesterKind != "machine" {
			record("requester = %+v, want ID=acct-machine-1 Name=agent-1 Kind=machine", got)
		}

		// (c) The RequesterAccountID filter selects by the recorded requester.
		mine, err := svc.QueryJobs(ctx, requester, capability.JobFilter{RequesterAccountID: "acct-machine-1"}, capability.PageRequest{Limit: 10})
		if err != nil {
			record("QueryJobs(RequesterAccountID=acct-machine-1): %v", err)
		} else if len(mine.Jobs) != 1 || mine.Jobs[0].JobID != jobID {
			record("QueryJobs(RequesterAccountID=acct-machine-1) = %+v, want exactly [%s]", mine.Jobs, jobID)
		}
		notMine, err := svc.QueryJobs(ctx, requester, capability.JobFilter{RequesterAccountID: "acct-machine-2"}, capability.PageRequest{Limit: 10})
		if err != nil {
			record("QueryJobs(RequesterAccountID=acct-machine-2): %v", err)
		} else if len(notMine.Jobs) != 0 {
			record("QueryJobs(RequesterAccountID=acct-machine-2) = %+v, want none", notMine.Jobs)
		}

		// (d) No kind=dispatch audit row exists for this Job yet — (b) and
		// (c) did not come from the audit join. QueryJobs itself writes read
		// records, and the cancels below write refusal/cancel records, so
		// filter by kind rather than asserting the trail is empty.
		trail, err := st.AuditQueries().Query(ctx, audit.Query{JobID: jobID}, 100, "")
		if err != nil {
			record("AuditQueries.Query(JobID): %v", err)
		}
		for _, row := range trail.Rows {
			if row.Kind == audit.KindDispatch {
				record("audit trail already holds a kind=dispatch row for %s before dispatch: %+v", jobID, row)
			}
		}

		// (e) A different machine Account may not cancel this Job.
		if err := svc.CancelJob(ctx, other, jobID); !errors.Is(err, capability.ErrJobNotRequestedByCaller) {
			record("CancelJob(other) = %v, want ErrJobNotRequestedByCaller", err)
		}
		stillPending, err := st.Tasks().ByJob(ctx, jobID)
		if err != nil {
			record("ByJob(%s) after refused cancel: %v", jobID, err)
		}
		for _, task := range stillPending {
			if task.State != jobs.DispatchStatePending {
				record("after refused cancel, task %s state = %v, want still Pending", task.ID, task.State)
			}
		}

		// (f) The recorded requester may cancel its own in-flight Job. This
		// MUST run after (e): it resolves the Tasks the refused cancel above
		// must find untouched.
		if err := svc.CancelJob(ctx, requester, jobID); err != nil {
			record("CancelJob(requester): %v, want nil", err)
		}
		cancelled, err := st.Tasks().ByJob(ctx, jobID)
		if err != nil {
			record("ByJob(%s) after cancel: %v", jobID, err)
		}
		for _, task := range cancelled {
			if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
				record("after cancel, task %s = state %v outcome %v, want Resolved/OutcomeCancelled", task.ID, task.State, task.Outcome)
			}
		}
	}

	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	results, err := svc.Run(ctx, requester, sel, act)
	// Cancelled-before-dispatch is not a dispatch failure: dispatchOne's
	// ErrInvalidTaskState branch honours the cancel rather than reporting it
	// as an error.
	if err != nil {
		t.Errorf("Run: %v, want nil", err)
	}

	if !conduit.probed {
		t.Fatal("probe never ran — Connected was never called")
	}
	for _, msg := range probeErrs {
		t.Error(msg)
	}

	if len(results) != 2 {
		t.Fatalf("Run returned %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Outcome != jobs.OutcomeCancelled {
			t.Errorf("result for %s: Outcome = %v, want OutcomeCancelled", r.NodeID, r.Outcome)
		}
	}
	if conduit.dispatchCalls != 0 {
		t.Errorf("Dispatch was called %d times, want 0 — both Tasks were cancelled before dispatchOne could send them", conduit.dispatchCalls)
	}
}
