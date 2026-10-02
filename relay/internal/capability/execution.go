// At-most-once execution across a Relay restart (ADR-0004) — design note.
//
// This is the "written down, not just asserted" discipline this project
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
//   - The requester (#616) is written in the CreateJob that precedes every
//     CreateTask, so it is durable before any Task is Pending, let alone
//     Dispatched.
//   - Unreachable Tasks (MarkUnreachable) are already terminal — Resolved,
//     never Dispatched — and are never part of InFlight() reconciliation.
//     Version-refused Tasks (MarkVersionRefused, ADR-0014) are the same
//     shape: an outdated Node's Task never leaves Pending, so it too is
//     never part of InFlight() reconciliation.
package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Conduit sends one Task down a connected Node's Tunnel and blocks for its
// Result. It is domain-typed (jobs.Task/jobs.Result), not relayv1, so
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

	// Query sends a PolicyQuery for act down nodeID's Tunnel and blocks for
	// the daemon's PolicyVerdict (ADR-0011) — plan mode's probe, never
	// Dispatch's TaskRequest: it carries no Task ID, sends no Task, and
	// cannot be deduped into execution or leave any Job/Task/dedup trace.
	// Callers must only call Query after Connected(nodeID); a
	// matched-but-disconnected Node is never queried — it is a Relay-side
	// unknown(offline) conclusion instead (invariant 12).
	Query(ctx context.Context, nodeID string, act jobs.Action) (jobs.Verdict, error)
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

// requesterOf projects the Principal that asked for a dispatch onto the
// Requester recorded on its Job (#616). A Principal with no AccountID (a
// fixture, the dev harness) records NO requester — it never records a
// name-only one, which could be mistaken for a verified owner.
func requesterOf(p Principal) jobs.Requester {
	req := jobs.Requester{AccountID: p.AccountID, AccountName: p.Account, Kind: p.Kind}
	if !req.Recorded() {
		return jobs.Requester{}
	}
	return req
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

	// events is the event seam's Job-grained publisher (#416). Defaulted to
	// noopJobEventSink by WithExecution so a directly-constructed engine is
	// never nil; Service.New propagates a real one on top when WithJobEvents
	// was used (service.go). Purely observational — see JobEventSink's doc
	// comment.
	events JobEventSink
}

var _ dispatcher = (*jobEngine)(nil)

// run implements dispatcher. See the at-most-once design note above for why
// IDs are minted before persistence and every Task is persisted (Pending)
// before any Task is dispatched.
func (e *jobEngine) run(ctx context.Context, d dispatch) (dispatchResult, error) {
	// d.jobID carries a Job ID already reserved and bound to a releasing
	// approval (AP-77, checkApproval/Service.Run). Using it here, rather than
	// minting a fresh one, is what makes the release claim and the Job it
	// authorizes the SAME id — the join a re-attach depends on.
	jobID := d.jobID
	reserved := jobID != ""
	if !reserved {
		var err error
		jobID, err = e.prefixedID("job-")
		if err != nil {
			return dispatchResult{}, fmt.Errorf("capability: generate job id: %w", err)
		}
	}

	// runCtx: for a RESERVED id, the approval's release claim (BindJob)
	// already committed before run was ever called — there is no un-claim
	// path (store/approvals.go). An earlier review pass detached only the
	// CreateJob call below from the request ctx's own cancellation; Codex
	// (#713, "final diff" review) found that left every step AFTER
	// CreateJob — AddStage, Task persistence, and dispatch — still resuming
	// on the (possibly by-then-cancelled) request ctx, so a timeout/drop
	// landing just after CreateJob commits could leave a Job with no
	// Stage/Tasks: the approval stays bound and every re-drive re-attaches
	// to that empty Job until it expires, and the approved work never runs.
	// So for a reserved id the WHOLE persist-then-dispatch pipeline —
	// CreateJob, AddStage, every CreateTask, and every dispatchOne — runs on
	// a context detached from the caller's own cancellation
	// (context.WithoutCancel): once the claim commits, a client
	// timeout/drop/cancel can neither strand the approval nor abandon the
	// approved work. The Job runs to completion, and a re-drive re-attaches
	// to the running or finished Job. The claim itself (Service.Run's
	// BindJob, before run is ever called) stays on the request ctx
	// unchanged: a call cancelled before the claim commits dispatches
	// nothing.
	//
	// This needs no NEW upper bound of its own: Conduit.Dispatch's wait for
	// each Task's Result is already bounded by the daemon's own hard
	// per-Task wall-clock cap (daemon/src/dispatch.rs's MAX_TIMEOUT, 300s,
	// ADR-0004) — the daemon always answers within it, and a Node that
	// disconnects mid-wait unblocks Dispatch immediately (the waiter
	// channel close in dispatch/router.go) — so looping over a
	// blast-cap-bounded node set (invariant 5) finishes in bounded time even
	// on a ctx with no deadline of its own. The store calls above and below
	// (CreateJob/AddStage/CreateTask/MarkDispatched/Resolve) are local
	// SQLite calls already bounded by the driver's own busy_timeout
	// (store.go's busyTimeoutMillis).
	runCtx := ctx
	if reserved {
		runCtx = context.WithoutCancel(ctx)
	}
	if err := e.jobsRepo.CreateJob(runCtx, jobs.Job{ID: jobID, CreatedAt: e.now(), Requester: requesterOf(d.principal)}); err != nil {
		return dispatchResult{}, fmt.Errorf("capability: create job %q: %w", jobID, err)
	}
	// Published error-free by construction (#416): the sink is
	// observational and can never change dispatch control flow — the same
	// MetricsSink precedent as service.go's IncDispatch/IncRefusal calls.
	e.publishJobEvent(JobEvent{
		Transition: JobCreated,
		JobID:      jobID,
		Principal:  d.principal,
		Selector:   d.selector,
		Action:     d.action,
		Nodes:      len(d.nodes) + len(d.excluded),
	})

	stageID, err := e.prefixedID("stage-")
	if err != nil {
		return dispatchResult{}, fmt.Errorf("capability: generate stage id: %w", err)
	}
	if err := e.jobsRepo.AddStage(runCtx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		return dispatchResult{}, fmt.Errorf("capability: add stage %q to job %q: %w", stageID, jobID, err)
	}

	// Persist ALL Pending Tasks before dispatching any of them: this is
	// "one Task per matched Node, unique IDs, persisted before dispatch"
	// (acceptance criterion 2), and leaves a clean Pending/Dispatched split
	// on any mid-Job crash.
	//
	// A Node excluded from a Template dispatch (ADR-0042) gets a Task too,
	// persisted the same way and then resolved unsupported without ever being
	// sent — so the Job records every matched Node, and get_job re-reads the
	// exclusion exactly as it reads any other outcome.
	pending := make([]pendingTask, 0, len(d.nodes)+len(d.excluded))
	persist := func(n registry.Node, unsupported string) error {
		taskID, err := e.prefixedID("task-")
		if err != nil {
			return fmt.Errorf("capability: generate task id for node %q: %w", n.NodeID, err)
		}
		task := jobs.Task{
			ID:             taskID,
			JobID:          jobID,
			StageID:        stageID,
			NodeID:         n.NodeID,
			Action:         d.action,
			TimeoutSeconds: d.action.TimeoutSeconds,
			CreatedAt:      e.now(),
		}
		if err := e.tasksRepo.CreateTask(runCtx, task); err != nil {
			return fmt.Errorf("capability: create task %q for node %q: %w", taskID, n.NodeID, err)
		}
		pending = append(pending, pendingTask{task: task, outdated: n.Outdated, unsupported: unsupported})
		return nil
	}
	for _, n := range d.nodes {
		if err := persist(n, ""); err != nil {
			return dispatchResult{}, err
		}
	}
	for _, x := range d.excluded {
		if err := persist(x.node, x.reason); err != nil {
			return dispatchResult{}, err
		}
	}

	results := make([]NodeResult, 0, len(pending))
	var errs []error
	for _, pt := range pending {
		res, err := e.dispatchOne(runCtx, pt)
		if err != nil {
			errs = append(errs, err)
		}
		results = append(results, NodeResult{
			NodeID:    pt.task.NodeID,
			Outcome:   res.Outcome,
			JobID:     jobID,
			Stdout:    res.Stdout,
			Stderr:    res.Stderr,
			Truncated: res.Truncated,
		})
	}

	// Tally ONLY r.Outcome — never r.Stdout/r.Stderr. This is the second
	// place (alongside internal/events itself) the no-read-output property
	// is made structural: JobEvent.Outcomes is counts, never []NodeResult,
	// so this adapter never even touches captured output (JobEvent's doc
	// comment, seams.go).
	outcomes := make(map[jobs.Outcome]int, len(results))
	for _, r := range results {
		outcomes[r.Outcome]++
	}
	e.publishJobEvent(JobEvent{
		Transition: JobCompleted,
		JobID:      jobID,
		Principal:  d.principal,
		Selector:   d.selector,
		Action:     d.action,
		Nodes:      len(d.nodes) + len(d.excluded),
		Outcomes:   outcomes,
	})

	return dispatchResult{jobID: jobID, results: results}, errors.Join(errs...)
}

// publishJobEvent publishes ev via e.events if one is wired. WithExecution
// defaults events to noopJobEventSink so a *jobEngine built through it is
// never nil, but this package's own white-box tests construct &jobEngine{}
// literals directly (bypassing WithExecution) — the nil check keeps run
// safe for those too, exactly like s.observer's nil check in
// enroll.Server.Enroll and mcp's `cfg.toolCalls != nil` guard.
func (e *jobEngine) publishJobEvent(ev JobEvent) {
	if e.events != nil {
		e.events.RecordJob(ev)
	}
}

// pendingTask pairs a persisted (Pending) Task with its source Node's
// Outdated flag (registry.Node.Outdated, ADR-0014), read at the moment run
// resolves the Selector — dispatchOne needs it to decide the version gate
// without re-querying the registry.
//
// unsupported, when non-empty, marks a Task whose Node was excluded from a
// Template dispatch (ADR-0042): it is resolved unsupported with this
// Relay-authored reason and never sent.
type pendingTask struct {
	task        jobs.Task
	outdated    bool
	unsupported string
}

// dispatchOne carries one persisted (Pending) Task through the rest of its
// dispatch-state lifecycle: outdated -> MarkVersionRefused (terminal, never
// sent, ADR-0014); offline -> MarkUnreachable (terminal, never sent);
// connected -> MarkDispatched, then Conduit.Dispatch. A send error leaves the
// Task Dispatched (never Resolved) so it surfaces via TaskRepository.InFlight()
// for restart reconciliation, and is reported honestly as OutcomeFailure
// rather than fabricated as success.
//
// The version gate runs FIRST, before the Connected check: it is a Relay-side,
// connectivity-independent refusal (ADR-0014's minimum-daemon-version gate),
// so an outdated Node is refused whether or not it currently has a Tunnel, and
// the Conduit is never opened for it. It runs AFTER the upstream blast-cap
// check (Service.Run) — outdated Nodes still matched the Selector and still
// count against the cap (invariant #5); only the send is refused.
//
// run persists every Task Pending before dispatching any of them, so a
// concurrent CancelJob (ADR-0013) can legitimately MarkCancelled a Task
// that is still Pending in this loop by the time dispatchOne reaches it;
// MarkDispatched then returns ErrInvalidTaskState. That is not a failure —
// the Task already reached a terminal, truthful outcome (Resolved,
// OutcomeCancelled) — so dispatchOne honors it rather than dispatching an
// already-cancelled Task or fabricating OutcomeFailure over a real cancel.
func (e *jobEngine) dispatchOne(ctx context.Context, pt pendingTask) (jobs.Result, error) {
	task := pt.task

	// Excluded from a Template dispatch before the cap was ever counted
	// (ADR-0042): never sent, whatever its version or connectivity.
	if pt.unsupported != "" {
		if err := e.tasksRepo.MarkUnsupported(ctx, task.ID, pt.unsupported, e.now()); err != nil {
			return jobs.Result{Outcome: jobs.OutcomeUnsupported}, fmt.Errorf("capability: mark task %q unsupported: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeUnsupported, Stderr: []byte(pt.unsupported)}, nil
	}

	if pt.outdated {
		if err := e.tasksRepo.MarkVersionRefused(ctx, task.ID, e.now()); err != nil {
			return jobs.Result{Outcome: jobs.OutcomeVersionRefused}, fmt.Errorf("capability: mark task %q version-refused: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeVersionRefused, Stderr: []byte(jobs.VersionRefusedMessage)}, nil
	}

	if !e.conduit.Connected(task.NodeID) {
		if err := e.tasksRepo.MarkUnreachable(ctx, task.ID, e.now()); err != nil {
			return jobs.Result{Outcome: jobs.OutcomeUnreachable}, fmt.Errorf("capability: mark task %q unreachable: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeUnreachable}, nil
	}

	if err := e.tasksRepo.MarkDispatched(ctx, task.ID, e.now()); err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) {
			// A concurrent CancelJob may have MarkCancelled this Task while it
			// was still Pending, between run's persist loop and this call. If
			// so, the Task already carries a terminal, truthful outcome —
			// honor it rather than fabricating OutcomeFailure or dispatching a
			// Task the caller already asked to stop.
			if cur, getErr := e.tasksRepo.Get(ctx, task.ID); getErr == nil && cur.State == jobs.DispatchStateResolved {
				return jobs.Result{Outcome: cur.Outcome, Stdout: cur.Stdout, Stderr: cur.Stderr}, nil
			}
		}
		return jobs.Result{Outcome: jobs.OutcomeFailure}, fmt.Errorf("capability: mark task %q dispatched: %w", task.ID, err)
	}

	result, dispatchErr := e.conduit.Dispatch(ctx, task.NodeID, task)
	if dispatchErr != nil {
		// Connected but the send/exec did not complete: the Task stays
		// Dispatched (no Resolve), so it is reconciled on restart via
		// InFlight() rather than silently declared unreachable.
		return jobs.Result{Outcome: jobs.OutcomeFailure}, fmt.Errorf("capability: dispatch task %q to node %q: %w", task.ID, task.NodeID, dispatchErr)
	}

	if err := e.tasksRepo.Resolve(ctx, task.ID, result); err != nil {
		return jobs.Result{Outcome: jobs.OutcomeFailure}, fmt.Errorf("capability: resolve task %q: %w", task.ID, err)
	}
	return result, nil
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

// reserveJobID implements dispatcher (AP-77): it returns a fresh "job-"
// prefixed ID in the same format run mints, so an approval's release claim
// can be bound to it before the Job exists. It persists nothing.
func (e *jobEngine) reserveJobID() (string, error) {
	return e.prefixedID("job-")
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
		// A directly-constructed engine (e.g. in a test that never calls
		// Service.New) must never hold a nil sink. Service.New overwrites
		// this with the real one when WithJobEvents was used (service.go).
		events: noopJobEventSink{},
	}
	for _, o := range opts {
		o(e)
	}
	return func(s *Service) {
		s.disp = e
		s.realDispatcher = true
	}
}
