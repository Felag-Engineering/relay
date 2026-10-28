package capability

import (
	"context"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// dispatch is the authorized, resolved, cap-checked unit ready to execute:
// the Selector has been resolved to concrete Nodes, the Principal has
// cleared the Authorizer, and the blast-radius cap has cleared the
// CapChecker. It is unexported, and so is newDispatch, its only
// constructor — this is the compile-enforced half of "one capability
// layer" (ADR-0009/0010, invariant 10): no package outside
// capability can construct a dispatch, so a surface reaching around
// Execution.Run to dispatch directly fails to compile rather than relying on
// review discipline. See dispatch_construction_test.go.
type dispatch struct {
	principal Principal
	selector  Selector
	nodes     []registry.Node
	action    jobs.Action

	// excluded are matched Nodes left out of a Template dispatch (ADR-0042):
	// each gets a Task resolved unsupported without ever being sent, so the
	// Job records every matched Node truthfully. Empty for a Native Operation
	// or Raw Exec. Set by Execution.Run from resolveAction, never by
	// newDispatch itself.
	excluded []excludedNode

	// nodeClass is each dispatched Node's own reported class for a Template
	// (ADR-0042): its Task is recorded under it, so output retention follows
	// the Node that produced the output rather than the dispatch's
	// most-restrictive class. Nil for a Native Operation or Raw Exec.
	nodeClass map[string]jobs.RiskClass

	// jobID is a Job ID reserved — and already bound to the releasing
	// approval — before dispatch (AP-77). When empty, the dispatcher mints
	// its own, exactly as before. Set by Execution.Run after the release claim
	// wins, never by newDispatch itself.
	jobID string

	// approvalID is the approval Request that released this dispatch, copied
	// onto its dispatch-intent record. Set by Execution.Run, never by
	// newDispatch itself.
	approvalID string
}

// newDispatch builds a dispatch from an already-authorized, already-resolved
// unit of work. It is unexported for the same reason dispatch itself is:
// only Execution.Run may call it.
func newDispatch(p Principal, sel Selector, nodes []registry.Node, act jobs.Action) dispatch {
	return dispatch{principal: p, selector: sel, nodes: nodes, action: act}
}

// NodeResult is one Node's outcome from executing a dispatch. JobID is
// denormalized onto every NodeResult (rather than added as a new return value
// on Execution.Run) so a caller that only sees Run's results — the
// devharness's run_job op, and any future real surface — can learn which Job
// it belongs to (to later query_job/CancelJob it) without widening Run's
// signature. It is set by the real Job engine (execution.go); noopDispatcher
// leaves it empty (there is no real Job).
type NodeResult struct {
	NodeID  string
	Outcome jobs.Outcome
	JobID   string
	// Stdout, Stderr, and Truncated are the full per-Node captured output and
	// the daemon-side truncated flag, retained whole for the audit trail
	// (full-output-always, ADR-0025 decision 3). Empty for outcomes with no real execution
	// (e.g. unreachable) except version-refused, whose Stderr carries the
	// Relay-synthesized jobs.VersionRefusedMessage (matching the Task row);
	// always empty for noopDispatcher, which performs no execution. A
	// failure row may also carry Relay-authored Stderr where the wire
	// boundary refused the daemon's report as a protocol violation
	// (jobs.ProtocolViolation.Explanation) — again no daemon bytes.
	Stdout    []byte
	Stderr    []byte
	Truncated bool

	// RiskClass is the class this Node's Task ran under. For a Native
	// Operation or Raw Exec it is the Action's; for a Template Operation it
	// is that Node's OWN reported class, which may be looser than the
	// dispatch's most-restrictive one (ADR-0042). Output retention keys on
	// this, never on the dispatch's class, so one Node cannot cause another
	// Node's read output to be retained (ADR-0025). Unspecified on results
	// that ran nothing (a reattach, noopDispatcher).
	RiskClass jobs.RiskClass
}

// dispatchResult is what dispatcher.run returns: the Job's identity plus its
// per-Node results. jobID is entry-level (one Job per Run) rather than read
// off results, so a dispatcher that fails before producing any result still
// reports its Job to the audit stage. A zero-match dispatch never reaches the
// dispatcher (Execution.Run refuses it as no_nodes_matched).
type dispatchResult struct {
	jobID   string
	results []NodeResult
	// halt is the Job's halt, zero if it did not halt.
	halt jobs.Halt
}

// dispatcher executes an already-built dispatch. Both the interface and its
// run method are unexported, and run's parameter type (dispatch) is itself
// unexported — a foreign package can neither implement dispatcher nor call
// run, and even if it could, it has no way to fabricate a dispatch value to
// pass. The real Job engine must therefore be added as new files
// inside package capability (not internal/jobs), injecting its external
// collaborators (revocation.Connections, jobs.TaskRepository) through their
// own exported constructor, NewExecution, which builds the in-package Job
// engine — see pipeline.go.
//
// Sealing the constructor and this seam only guarantees that dispatch is
// unreachable except through Execution.Run; it does not by itself guarantee
// that dispatch is safe. The allow-all/no-op Authorizer/CapChecker/AuditSink
// seams are safe only when the dispatcher is noopDispatcher, which performs
// no execution (reachable only from tests). Anything that swaps in a real
// dispatcher MUST require real Authorizer, CapChecker, and AuditSink
// implementations rather than letting a real dispatcher ride these
// defaults — see checkRealDispatch in pipeline.go.
type dispatcher interface {
	run(ctx context.Context, d dispatch) (dispatchResult, error)

	// cancel stops a Job's Tasks (ADR-0013): undispatched Tasks are
	// marked cancelled without ever being sent, in-flight Tasks are asked to
	// cancel over their Tunnels, and already-resolved Tasks are left
	// untouched. It takes no dispatch value — cancel targets a previously
	// dispatched Job by ID, not a fresh unit of work — so it does not weaken
	// the dispatch/newDispatch seal.
	cancel(ctx context.Context, jobID string) error

	// query answers a Plan (ADR-0011): for each of d's matched Nodes it
	// asks the daemon a read-only PolicyQuery and collects a per-Node
	// verdict — allow/deny(rule) from the daemon's live engine, or
	// unknown(offline) for a matched-but-disconnected Node (invariant 12).
	// query flows through the SAME sealed seam as run/cancel (invariant 10),
	// but persists NOTHING: no Job, no Stage, no Task, no MarkDispatched —
	// a Plan creates no dedup entry by construction.
	query(ctx context.Context, d dispatch) (planResult, error)

	// reserveJobID returns an ID in the dispatcher's own Job-ID format, so an
	// approval's release claim (AP-77) can be bound to it before the Job
	// exists. It persists nothing: a reserved ID that no Job ever ends up
	// carrying (a claim that wins and then fails to dispatch) is harmless by
	// construction.
	reserveJobID() (string, error)
}

// starter is the optional half of a dispatcher that can return once a Job is
// persisted (Execution.Start). Only the real Job engine implements it;
// it is deliberately not part of dispatcher, so a dispatcher that cannot
// persist ahead of its fan-out (noopDispatcher, a test spy) is simply run
// synchronously.
type starter interface {
	// start persists d's Job and returns its ID, with finish to run the
	// fan-out. finish must be called exactly once.
	start(ctx context.Context, d dispatch) (jobID string, finish func() (dispatchResult, error), err error)

	// jobPersisted reports whether jobID's Tasks are committed.
	jobPersisted(ctx context.Context, jobID string) (bool, error)
}

var _ starter = (*jobEngine)(nil)

// noopDispatcher performs no execution and says so honestly: every matched
// Node gets OutcomeUnspecified, never a fabricated success. Only in-package
// tests install it; the real dispatcher is jobEngine (execution.go).
type noopDispatcher struct{}

func (noopDispatcher) run(_ context.Context, d dispatch) (dispatchResult, error) {
	results := make([]NodeResult, 0, len(d.nodes))
	for _, n := range d.nodes {
		results = append(results, NodeResult{NodeID: n.NodeID, Outcome: jobs.OutcomeUnspecified})
	}
	return dispatchResult{results: results}, nil
}

func (noopDispatcher) cancel(context.Context, string) error {
	return nil
}

// reserveJobID implements dispatcher. It runs nothing, so a bound ID that no
// Job ever carries is harmless, and the claim path in Execution.Run stays
// unconditional whether or not a real dispatcher is wired.
func (noopDispatcher) reserveJobID() (string, error) {
	id, err := defaultID()
	if err != nil {
		return "", err
	}
	return "job-" + id, nil
}

// query implements dispatcher honestly: it performs no PolicyQuery and says
// so — every matched Node gets VerdictUnknown, never a fabricated allow.
// jobEngine.query (plan.go) is the real per-Node PolicyQuery/PolicyVerdict
// fan-out.
func (noopDispatcher) query(_ context.Context, d dispatch) (planResult, error) {
	verdicts := make([]NodeVerdict, 0, len(d.nodes))
	for _, n := range d.nodes {
		verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictUnknown, Reason: "not evaluated (noopDispatcher)", Outdated: n.Outdated})
	}
	return planResult{verdicts: verdicts}, nil
}
