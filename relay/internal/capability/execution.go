// At-most-once execution across a Relay restart (ADR-0004) — design note.
//
// This is the "written down, not just asserted" discipline the ROADMAP
// requires for the Job engine (v0.0.5 [4/8]/#99), feeding the crash test in
// [8/8]/#103:
//
//   - IDs are generated before persistence (jobEngine.newID, an idGen seam
//     over crypto/rand). A Task ID is therefore never generated twice: it
//     exists exactly once, the moment it is minted, and is immediately
//     written to the store.
//   - The order is persist-then-dispatch: every Task for a Job is CreateTask'd
//     (State = Pending) BEFORE any of them is dispatched. A crash between
//     "generate Job/Tasks" and "start dispatching" leaves only Pending rows —
//     never a Task that was sent but never recorded.
//   - Dispatch itself is persist-then-send: a Task is MarkDispatched in the
//     store BEFORE jobEngine calls Conduit.Dispatch. A crash after
//     MarkDispatched but before (or during) the send/result leaves the Task
//     Dispatched with no Result — exactly TaskRepository.InFlight()'s
//     definition.
//   - On restart, the Relay reconciles via TaskRepository.InFlight(): those
//     Tasks may be safely re-sent-for-result because the relay-daemon dedups
//     Task execution by Task ID (ADR-0004) — resend is safe ONLY because of
//     that dedup, never because the Relay trusts its own retry to be novel.
//   - Pending survivors (a crash before dispatch reached them) were never
//     sent and are NOT auto-run — there is no store-and-forward (ADR-0004);
//     resuming a stalled Job is the caller's re-target decision, not an
//     automatic behavior.
//   - Unreachable Tasks (MarkUnreachable) are already terminal — Resolved,
//     never Dispatched — and are never part of InFlight() reconciliation.
package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Conduit sends one Task down a connected Node's Tunnel and blocks for its
// Result. It is domain-typed (jobs.Task/jobs.Result), not gleipnirv1, so
// package capability keeps its narrow import set (registry + jobs only —
// see TestCapabilityImportsOnlyRegistryAndJobs); the proto-speaking adapter
// that sends over the real mTLS Tunnel lives outside this package and is
// deferred (see execution_test.go and the plan for #99).
type Conduit interface {
	// Connected reports whether nodeID currently has a live Tunnel. This is
	// the dispatch-time connectivity gate behind ADR-0004's offline
	// fail-fast: a disconnected Node's Task is never sent, queued, or
	// retried.
	Connected(nodeID string) bool

	// Dispatch sends task down nodeID's Tunnel and blocks for its Result.
	// Callers must only call Dispatch after Connected(nodeID) reports true.
	Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error)

	// Cancel sends TaskCancel for taskID down nodeID's Tunnel, best-effort
	// (ADR-0013). It does not wait for or rewrite the Task's outcome — the
	// daemon reports the true outcome (OUTCOME_CANCELLED, or the real result
	// if the Task won the race) through the normal result path.
	Cancel(ctx context.Context, nodeID string, taskID string) error
}

// idGen mints a new unique ID. It is a seam so in-package tests can inject
// deterministic IDs; the production default is defaultID.
type idGen func() (string, error)

// defaultID generates a random 16-byte ID, hex-encoded, mirroring
// enroll.randomNodeID's shape. It carries no entity prefix — jobEngine adds
// "job-"/"stage-"/"task-" itself per ID kind, so a single seam covers all
// three.
func defaultID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("capability: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// jobEngine is the real Job engine: it implements the unexported dispatcher
// interface (dispatch.go) and is reachable only through Service.Run, never
// directly by a foreign package. It fans a resolved dispatch out to one
// persisted Task per matched Node, fails offline Nodes fast, sends the rest
// through Conduit, and reports truthful per-Node outcomes.
type jobEngine struct {
	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
	conduit   Conduit
	newID     idGen
	now       func() time.Time
}

var _ dispatcher = (*jobEngine)(nil)

// run implements dispatcher. See the at-most-once design note above for why
// IDs are minted before persistence and every Task is persisted (Pending)
// before any Task is dispatched.
func (e *jobEngine) run(ctx context.Context, d dispatch) (dispatchResult, error) {
	jobID, err := e.prefixedID("job-")
	if err != nil {
		return dispatchResult{}, fmt.Errorf("capability: generate job id: %w", err)
	}
	if err := e.jobsRepo.CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: e.now()}); err != nil {
		return dispatchResult{}, fmt.Errorf("capability: create job %q: %w", jobID, err)
	}

	stageID, err := e.prefixedID("stage-")
	if err != nil {
		return dispatchResult{}, fmt.Errorf("capability: generate stage id: %w", err)
	}
	if err := e.jobsRepo.AddStage(ctx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		return dispatchResult{}, fmt.Errorf("capability: add stage %q to job %q: %w", stageID, jobID, err)
	}

	// Persist ALL Pending Tasks before dispatching any of them: this is
	// "one Task per matched Node, unique IDs, persisted before dispatch"
	// (acceptance criterion 2), and leaves a clean Pending/Dispatched split
	// on any mid-Job crash.
	pending := make([]jobs.Task, 0, len(d.nodes))
	for _, n := range d.nodes {
		taskID, err := e.prefixedID("task-")
		if err != nil {
			return dispatchResult{}, fmt.Errorf("capability: generate task id for node %q: %w", n.NodeID, err)
		}
		task := jobs.Task{
			ID:      taskID,
			JobID:   jobID,
			StageID: stageID,
			NodeID:  n.NodeID,
			Action:  d.action,
			// TimeoutSeconds is left at its zero value: jobs.Action carries
			// no timeout field, and threading a real per-Task timeout
			// through Service.Run/Action/dispatch is later-issue work
			// outside #99's acceptance.
			CreatedAt: e.now(),
		}
		if err := e.tasksRepo.CreateTask(ctx, task); err != nil {
			return dispatchResult{}, fmt.Errorf("capability: create task %q for node %q: %w", taskID, n.NodeID, err)
		}
		pending = append(pending, task)
	}

	results := make([]NodeResult, 0, len(pending))
	var errs []error
	for _, task := range pending {
		outcome, err := e.dispatchOne(ctx, task)
		if err != nil {
			errs = append(errs, err)
		}
		results = append(results, NodeResult{NodeID: task.NodeID, Outcome: outcome})
	}

	return dispatchResult{jobID: jobID, results: results}, errors.Join(errs...)
}

// dispatchOne carries one persisted (Pending) Task through the rest of its
// dispatch-state lifecycle: offline -> MarkUnreachable (terminal, never
// sent); connected -> MarkDispatched, then Conduit.Dispatch. A send error
// leaves the Task Dispatched (never Resolved) so it surfaces via
// TaskRepository.InFlight() for restart reconciliation, and is reported
// honestly as OutcomeFailure rather than fabricated as success.
//
// run persists every Task Pending before dispatching any of them, so a
// concurrent CancelJob (ADR-0013) can legitimately MarkCancelled a Task
// that is still Pending in this loop by the time dispatchOne reaches it;
// MarkDispatched then returns ErrInvalidTaskState. That is not a failure —
// the Task already reached a terminal, truthful outcome (Resolved,
// OutcomeCancelled) — so dispatchOne honors it rather than dispatching an
// already-cancelled Task or fabricating OutcomeFailure over a real cancel.
func (e *jobEngine) dispatchOne(ctx context.Context, task jobs.Task) (jobs.Outcome, error) {
	if !e.conduit.Connected(task.NodeID) {
		if err := e.tasksRepo.MarkUnreachable(ctx, task.ID, e.now()); err != nil {
			return jobs.OutcomeUnreachable, fmt.Errorf("capability: mark task %q unreachable: %w", task.ID, err)
		}
		return jobs.OutcomeUnreachable, nil
	}

	if err := e.tasksRepo.MarkDispatched(ctx, task.ID, e.now()); err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) {
			// A concurrent CancelJob may have MarkCancelled this Task while it
			// was still Pending, between run's persist loop and this call. If
			// so, the Task already carries a terminal, truthful outcome —
			// honor it rather than fabricating OutcomeFailure or dispatching a
			// Task the caller already asked to stop.
			if cur, getErr := e.tasksRepo.Get(ctx, task.ID); getErr == nil && cur.State == jobs.DispatchStateResolved {
				return cur.Outcome, nil
			}
		}
		return jobs.OutcomeFailure, fmt.Errorf("capability: mark task %q dispatched: %w", task.ID, err)
	}

	result, dispatchErr := e.conduit.Dispatch(ctx, task.NodeID, task)
	if dispatchErr != nil {
		// Connected but the send/exec did not complete: the Task stays
		// Dispatched (no Resolve), so it is reconciled on restart via
		// InFlight() rather than silently declared unreachable.
		return jobs.OutcomeFailure, fmt.Errorf("capability: dispatch task %q to node %q: %w", task.ID, task.NodeID, dispatchErr)
	}

	if err := e.tasksRepo.Resolve(ctx, task.ID, result); err != nil {
		return jobs.OutcomeFailure, fmt.Errorf("capability: resolve task %q: %w", task.ID, err)
	}
	return result.Outcome, nil
}

// cancel implements dispatcher (#101, ADR-0013): it stops jobID's Tasks by
// their current dispatch state — Pending Tasks are MarkCancelled without
// ever being sent, Dispatched Tasks are asked to cancel over their Tunnels
// (Conduit.Cancel), and Resolved Tasks are left untouched, keeping their
// truthful outcome (a Task that already completed, or that won the race
// against cancellation, reports its real outcome — ADR-0013/0004 never
// rewrite a resolved outcome retroactively). Per-Task errors are joined, not
// short-circuited, so one failing Task does not stop the rest from being
// cancelled.
//
// Best-effort race gap (deliberate, per ADR-0013's cancel contract — do not
// try to close it): a Task that transitions Pending -> Dispatched in the
// window between the ByJob read below and the MarkCancelled attempt is
// neither cancelled here (the MarkCancelled call fails with
// ErrInvalidTaskState, joined into the returned error) nor sent
// Conduit.Cancel (the loop only cancels what it read as Dispatched) — it
// runs to completion uncancelled. This is unreachable today (no real
// concurrent dispatcher is wired in this milestone), but whoever wires one
// in a later issue must know: cancel only ever *asks*, it never fabricates a
// cancelled outcome for a Task that won the race.
func (e *jobEngine) cancel(ctx context.Context, jobID string) error {
	if _, err := e.jobsRepo.GetJob(ctx, jobID); err != nil {
		return err
	}

	tasks, err := e.tasksRepo.ByJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("capability: list tasks for job %q: %w", jobID, err)
	}

	var errs []error
	for _, task := range tasks {
		switch task.State {
		case jobs.DispatchStatePending:
			if err := e.tasksRepo.MarkCancelled(ctx, task.ID, e.now()); err != nil {
				errs = append(errs, fmt.Errorf("capability: mark task %q cancelled: %w", task.ID, err))
			}
		case jobs.DispatchStateDispatched:
			if err := e.conduit.Cancel(ctx, task.NodeID, task.ID); err != nil {
				errs = append(errs, fmt.Errorf("capability: cancel task %q on node %q: %w", task.ID, task.NodeID, err))
			}
		case jobs.DispatchStateResolved:
			// Already terminal with a truthful outcome — never touched.
		}
	}
	return errors.Join(errs...)
}

// prefixedID mints a new ID via e.newID and adds prefix ("job-", "stage-",
// or "task-").
func (e *jobEngine) prefixedID(prefix string) (string, error) {
	id, err := e.newID()
	if err != nil {
		return "", err
	}
	return prefix + id, nil
}

// ExecOption configures a jobEngine built by WithExecution, primarily so
// tests can inject deterministic newID/now seams.
type ExecOption func(*jobEngine)

// WithExecNewID overrides the jobEngine's idGen seam (production default:
// defaultID).
func WithExecNewID(f idGen) ExecOption {
	return func(e *jobEngine) { e.newID = f }
}

// WithExecClock overrides the jobEngine's clock seam (production default:
// time.Now, UTC).
func WithExecClock(f func() time.Time) ExecOption {
	return func(e *jobEngine) { e.now = f }
}

// WithExecution wires the real Job engine into a Service: it fans a resolved
// Selector to one persisted Task per matched Node, fails offline Nodes fast
// (ADR-0004), and dispatches the rest through c. jr, tr, and c must not be
// nil — a nil collaborator here is a composition-root wiring bug, not a
// recoverable runtime condition, so WithExecution panics rather than
// constructing a half-wired engine.
//
// Per the contract on New (service.go), a Service configured with
// WithExecution MUST also be configured with a real Authorizer, CapChecker,
// and AuditSink (WithAuthorizer/WithCapChecker/WithAuditSink); New enforces
// this at construction and panics otherwise, regardless of Option order.
func WithExecution(jr jobs.JobRepository, tr jobs.TaskRepository, c Conduit, opts ...ExecOption) Option {
	if jr == nil || tr == nil || c == nil {
		panic("capability: WithExecution: jobsRepo, tasksRepo, and conduit must not be nil")
	}
	e := &jobEngine{
		jobsRepo:  jr,
		tasksRepo: tr,
		conduit:   c,
		newID:     defaultID,
		now:       func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(e)
	}
	return func(s *Service) {
		s.disp = e
		s.realDispatcher = true
	}
}
