package capability

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// dispatch is the authorized, resolved, cap-checked unit ready to execute:
// the Selector has been resolved to concrete Nodes, the Principal has
// cleared the Authorizer, and the blast-radius cap has cleared the
// CapChecker. It is unexported, and so is newDispatch, its only
// constructor — this is the compile-enforced half of "one capability
// layer" (ADR-0009/0010, invariant 10): no package outside
// capability can construct a dispatch, so a surface reaching around
// Service.Run to dispatch directly fails to compile rather than relying on
// review discipline. See dispatch_construction_test.go.
type dispatch struct {
	principal Principal
	selector  Selector
	nodes     []registry.Node
	action    jobs.Action

	// jobID is a Job ID reserved — and already bound to the releasing
	// approval — before dispatch (AP-77). When empty, the dispatcher mints
	// its own, exactly as before. Set by Service.Run after the release claim
	// wins, never by newDispatch itself.
	jobID string
}

// newDispatch builds a dispatch from an already-authorized, already-resolved
// unit of work. It is unexported for the same reason dispatch itself is:
// only Service.Run may call it.
func newDispatch(p Principal, sel Selector, nodes []registry.Node, act jobs.Action) dispatch {
	return dispatch{principal: p, selector: sel, nodes: nodes, action: act}
}

// NodeResult is one Node's outcome from executing a dispatch. JobID is
// denormalized onto every NodeResult (rather than added as a new return value
// on Service.Run) so a caller that only sees Run's results — the #103
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
	// (#122 full-output-always). Empty for outcomes with no real execution
	// (e.g. unreachable) except version-refused, whose Stderr carries the
	// Relay-synthesized jobs.VersionRefusedMessage (matching the Task row);
	// always empty for noopDispatcher, which performs no execution. A
	// failure row may also carry Relay-authored Stderr where the wire
	// boundary refused the daemon's report as a protocol violation
	// (jobs.ProtocolViolation.Explanation, #632) — again no daemon bytes.
	Stdout    []byte
	Stderr    []byte
	Truncated bool
}

// dispatchResult is what dispatcher.run returns: the Job's identity plus its
// per-Node results. jobID is entry-level (one Job per Run) rather than read
// off results, so a dispatcher that fails before producing any result still
// reports its Job to the audit stage. A zero-match dispatch never reaches the
// dispatcher (Service.Run refuses it as no_nodes_matched).
type dispatchResult struct {
	jobID   string
	results []NodeResult
}

// dispatcher executes an already-built dispatch. Both the interface and its
// run method are unexported, and run's parameter type (dispatch) is itself
// unexported — a foreign package can neither implement dispatcher nor call
// run, and even if it could, it has no way to fabricate a dispatch value to
// pass. The real Job engine (#99) must therefore be added as new files
// inside package capability (not internal/jobs), injecting its external
// collaborators (revocation.Connections, jobs.TaskRepository) through their
// own exported Option, e.g. WithExecution(...) — see service.go.
//
// Sealing the constructor and this seam only guarantees that dispatch is
// unreachable except through Service.Run; it does not by itself guarantee
// that dispatch is safe. New's allow-all/no-op Authorizer/CapChecker/
// AuditSink defaults are safe today only because the default dispatcher is
// noopDispatcher, which performs no execution. Any option that swaps in a
// real dispatcher (e.g. #99's WithExecution) MUST require real Authorizer,
// CapChecker, and AuditSink implementations rather than letting a real
// dispatcher ride these defaults — see the contract note on New in
// service.go.
type dispatcher interface {
	run(ctx context.Context, d dispatch) (dispatchResult, error)

	// cancel stops a Job's Tasks (#101, ADR-0013): undispatched Tasks are
	// marked cancelled without ever being sent, in-flight Tasks are asked to
	// cancel over their Tunnels, and already-resolved Tasks are left
	// untouched. It takes no dispatch value — cancel targets a previously
	// dispatched Job by ID, not a fresh unit of work — so it does not weaken
	// the dispatch/newDispatch seal.
	cancel(ctx context.Context, jobID string) error

	// query answers a Plan (#119, ADR-0011): for each of d's matched Nodes it
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

// noopDispatcher is the v0.0.5 default. It performs no execution and says
// so honestly: every matched Node gets OutcomeUnspecified, never a
// fabricated success. #99 replaces this with the real Job engine.
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
// Job ever carries is harmless, and the claim path in Service.Run stays
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
// #119's jobEngine.query (plan.go) replaces this with the real per-Node
// PolicyQuery/PolicyVerdict fan-out.
func (noopDispatcher) query(_ context.Context, d dispatch) (planResult, error) {
	verdicts := make([]NodeVerdict, 0, len(d.nodes))
	for _, n := range d.nodes {
		verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictUnknown, Reason: "not evaluated (noopDispatcher)", Outdated: n.Outdated})
	}
	return planResult{verdicts: verdicts}, nil
}
