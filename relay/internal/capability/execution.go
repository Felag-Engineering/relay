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
//   - The order is persist-then-dispatch: every Task for a Job and the Job's
//     dispatch_intent audit record commit in ONE transaction (#887,
//     IntentRecorder) BEFORE any Task is dispatched. A failed commit leaves no
//     Task, so there is nothing to dispatch or reconcile, and no retry path
//     exists. A crash between "generate Job/Tasks" and "start dispatching"
//     leaves only Pending rows — never a Task that was sent but never
//     recorded.
//   - Dispatch itself is persist-then-send: a Task is MarkDispatched in the
//     store BEFORE jobEngine calls Conduit.Dispatch. A crash after
//     MarkDispatched but before (or during) the send/result leaves the Task
//     Dispatched with no Result — exactly TaskRepository.InFlight()'s
//     definition.
//   - Dispatch is concurrent (bounded per Job, WithExecDispatchConcurrency),
//     but persist-then-dispatch and persist-then-send still hold per Task:
//     every Task is Pending before any dispatch goroutine starts, and each
//     goroutine does MarkDispatched before Conduit.Dispatch.
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
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

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

// DefaultDispatchConcurrency is the default bound on how many Tasks of ONE Job
// are in flight at once (#886). It bounds reach (invariant 11) and is
// startup-only. It is not the blast cap: the cap bounds how many Nodes a Job
// may touch (invariant 5); this bounds how many it touches at the same time.
const DefaultDispatchConcurrency = 16

// errDispatchPanicked marks a Task whose dispatch worker panicked (#942). It
// carries no panic value: the run error reaches callers.
var errDispatchPanicked = errors.New("capability: dispatch worker panicked")

// jobGate is the per-Job cancel gate. Holding mu across "is it cancelled? then
// MarkDispatched" makes "no Task is dispatched after the cancel is recorded"
// structural rather than a matter of timing.
type jobGate struct {
	mu        sync.Mutex
	cancelled bool
}

// isCancelled reports whether the Job's cancel has been recorded. A nil gate
// is ungated and never cancelled.
func (g *jobGate) isCancelled() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cancelled
}

func (g *jobGate) markCancelled() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cancelled = true
}

// admit runs mark (a MarkDispatched closure) under the gate lock, and only if
// the Job is not cancelled; otherwise it returns (false, nil) without calling
// mark. A nil gate calls mark unconditionally.
func (g *jobGate) admit(mark func() error) (admitted bool, err error) {
	if g == nil {
		return true, mark()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cancelled {
		return false, nil
	}
	return true, mark()
}

// openGate registers the cancel gate for a Job running in this process and
// returns it with a release func. It panics on a duplicate Job ID: a second
// run for one ID would silently overwrite the first gate and reopen the cancel
// gap, which is a composition bug, not a runtime condition.
func (e *jobEngine) openGate(jobID string) (*jobGate, func()) {
	e.gatesMu.Lock()
	defer e.gatesMu.Unlock()
	if e.gates == nil {
		e.gates = make(map[string]*jobGate)
	}
	if _, dup := e.gates[jobID]; dup {
		panic(fmt.Sprintf("capability: jobEngine.run: Job %q is already running in this process", jobID))
	}
	g := &jobGate{}
	e.gates[jobID] = g
	return g, func() {
		e.gatesMu.Lock()
		defer e.gatesMu.Unlock()
		delete(e.gates, jobID)
	}
}

// gateFor returns the gate of a Job running in this process, or nil.
func (e *jobEngine) gateFor(jobID string) *jobGate {
	e.gatesMu.Lock()
	defer e.gatesMu.Unlock()
	return e.gates[jobID]
}

// dispatchLimit is the per-Job in-flight bound. The fallback to 1 exists only
// for &jobEngine{} literals in white-box tests; WithExecution refuses < 1.
func (e *jobEngine) dispatchLimit() int {
	if e.concurrency < 1 {
		return 1
	}
	return e.concurrency
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

	// concurrency is the per-Job in-flight bound; WithExecution guarantees >= 1.
	concurrency int

	// gates holds the cancel gate of every Job running in THIS process.
	gatesMu sync.Mutex
	gates   map[string]*jobGate

	// events is the event seam's Job-grained publisher (#416). Defaulted to
	// noopJobEventSink by WithExecution so a directly-constructed engine is
	// never nil; Service.New propagates a real one on top when WithJobEvents
	// was used (service.go). Purely observational — see JobEventSink's doc
	// comment.
	events JobEventSink

	// intents persists a Job's Tasks together with its dispatch-intent audit
	// record (#887). Service.New propagates it from the AuditSink; run refuses
	// to persist Tasks without one.
	intents IntentRecorder
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
	// CreateJob, AddStage, the Tasks-and-intent commit, and every dispatchOne — runs on
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
	// channel close in dispatch/router.go). With at most `concurrency` Tasks
	// in flight, a Job over a blast-cap-bounded node set (invariant 5) takes
	// at most ceil(n/concurrency) times that cap, even on a ctx with no
	// deadline of its own. The store calls above and below
	// (CreateJob/AddStage/the Tasks-and-intent commit/MarkDispatched/Resolve) are local
	// SQLite calls already bounded by the driver's own busy_timeout
	// (store.go's busyTimeoutMillis).
	runCtx := ctx
	if reserved {
		runCtx = context.WithoutCancel(ctx)
	}

	// The gate exists before any Task does, so a cancel can never find a
	// persisted Task whose Job has no gate.
	gate, release := e.openGate(jobID)
	defer release()

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

	// Build ALL Pending Tasks here; they are committed together with the
	// dispatch intent below, before any is dispatched: this is "one Task per
	// matched Node, unique IDs, persisted before dispatch" (acceptance
	// criterion 2), and leaves a clean Pending/Dispatched split on any
	// mid-Job crash.
	//
	// A Node excluded from a Template dispatch (ADR-0042) gets a Task too,
	// built the same way and then resolved unsupported without ever being
	// sent — so the Job records every matched Node, and get_job re-reads the
	// exclusion exactly as it reads any other outcome. Excluded Tasks come
	// FIRST, and are resolved before the concurrent dispatch phase starts: they
	// never sit Pending behind a slow fan-out where a concurrent cancel or a
	// crash could leave them stranded.
	//
	// A dispatched Template Task is recorded under its own Node's reported
	// class (d.nodeClass), which decides whether its output is retained.
	pending := make([]pendingTask, 0, len(d.nodes)+len(d.excluded))
	stageTask := func(n registry.Node, unsupported string) error {
		taskID, err := e.prefixedID("task-")
		if err != nil {
			return fmt.Errorf("capability: generate task id for node %q: %w", n.NodeID, err)
		}
		action := d.action
		if c, ok := d.nodeClass[n.NodeID]; ok {
			action.RiskClass = c
		}
		task := jobs.Task{
			ID:             taskID,
			JobID:          jobID,
			StageID:        stageID,
			NodeID:         n.NodeID,
			Action:         action,
			TimeoutSeconds: d.action.TimeoutSeconds,
			CreatedAt:      e.now(),
		}
		pending = append(pending, pendingTask{task: task, outdated: n.Outdated, unsupported: unsupported})
		return nil
	}
	for _, x := range d.excluded {
		if err := stageTask(x.node, x.reason); err != nil {
			return dispatchResult{}, err
		}
	}
	for _, n := range d.nodes {
		if err := stageTask(n, ""); err != nil {
			return dispatchResult{}, err
		}
	}

	// Every Task and the Job's dispatch-intent record commit in ONE
	// transaction (#887), before any resolve: a failed commit leaves no Task,
	// so there is nothing to dispatch or reconcile, and no retry path exists.
	if e.intents == nil {
		return dispatchResult{}, errors.New("capability: job engine has no IntentRecorder; refusing to persist Tasks without a dispatch intent record")
	}
	tasks := make([]jobs.Task, len(pending))
	for i := range pending {
		tasks[i] = pending[i].task
	}
	intent := AuditEntry{
		Kind:       AuditKindDispatchIntent,
		Principal:  d.principal,
		Selector:   d.selector,
		Action:     d.action,
		JobID:      jobID,
		ApprovalID: d.approvalID,
		GrantID:    d.grantID,
		Asserted:   AssertionsFromContext(runCtx),
		CapCleared: len(d.nodes),
	}
	if err := e.intents.RecordIntent(runCtx, intent, tasks); err != nil {
		return dispatchResult{}, fmt.Errorf("capability: record dispatch intent and tasks for job %q: %w", jobID, err)
	}

	// Each worker writes only its own index, so results come out in pending
	// order (excluded first, then d.nodes) and need no lock.
	results := make([]NodeResult, len(pending))
	errs := make([]error, len(pending))
	resolve := func(i int, pt pendingTask) {
		res, err := e.dispatchOneRecovered(runCtx, gate, pt)
		errs[i] = err
		results[i] = NodeResult{
			NodeID:    pt.task.NodeID,
			Outcome:   res.Outcome,
			JobID:     jobID,
			Stdout:    res.Stdout,
			Stderr:    res.Stderr,
			Truncated: res.Truncated,
			RiskClass: pt.task.Action.RiskClass,
		}
	}
	// Excluded Tasks are resolved synchronously, before any real Task is
	// dispatched.
	for i, pt := range pending {
		if pt.unsupported != "" {
			resolve(i, pt)
		}
	}
	// Not errgroup.WithContext: one Task's error must never cancel its siblings.
	var g errgroup.Group
	g.SetLimit(e.dispatchLimit())
	for i, pt := range pending {
		if pt.unsupported != "" {
			continue
		}
		g.Go(func() error {
			resolve(i, pt)
			return nil
		})
	}
	_ = g.Wait() // workers always return nil; errors are collected per index

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

// dispatchOneRecovered runs dispatchOne and turns a panic into this Task's
// failure (#942). A worker goroutine has no request-level recovery, so an
// unrecovered panic would end the Relay process, not just the Job.
//
// It writes nothing to the store, exactly like the Conduit-error branch, so
// at-most-once (invariant 4) is unchanged: a Task that panicked after
// MarkDispatched stays Dispatched and is found by InFlight() reconciliation,
// never retried. A Task that panicked before MarkDispatched stays Pending and
// is never sent; nothing revisits a Pending Task, so its Job stays Running
// with an unresolved Task until cancelled — a known effect, not a recorded
// outcome.
//
// The panic's type and stack go only to the server-side log; the message too
// only for a runtime.Error, whose text carries no Task data. Neither is put in
// the returned error, which reaches callers through errors.Join.
func (e *jobEngine) dispatchOneRecovered(ctx context.Context, gate *jobGate, pt pendingTask) (res jobs.Result, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		attrs := []any{
			"job_id", pt.task.JobID, "task_id", pt.task.ID, "node_id", pt.task.NodeID,
			"panic_type", fmt.Sprintf("%T", r), "stack", string(debug.Stack()),
		}
		// runtime.Error's marker method, without importing runtime.
		if re, ok := r.(interface {
			error
			RuntimeError()
		}); ok {
			attrs = append(attrs, "panic", re.Error())
		}
		slog.ErrorContext(ctx, "capability: dispatch worker panicked; Task reported as failed, store state left as-is", attrs...)
		res = jobs.Result{Outcome: jobs.OutcomeFailure}
		err = fmt.Errorf("capability: task %q on node %q: %w", pt.task.ID, pt.task.NodeID, errDispatchPanicked)
	}()
	return e.dispatchOne(ctx, gate, pt)
}

// dispatchOne carries one persisted (Pending) Task through the rest of its
// dispatch-state lifecycle: excluded from a Template dispatch ->
// MarkUnsupported (terminal, never sent, ADR-0042); outdated ->
// MarkVersionRefused (terminal, never sent, ADR-0014); offline -> MarkUnreachable (terminal, never sent);
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
// gate is the Job's cancel gate (nil means ungated). Once the Job's cancel is
// recorded, no Task is MarkDispatched: MarkDispatched runs under the gate lock
// and only if the Job is not cancelled. Because of the early cancelled check, a
// cancelled Job's outdated or offline Node reports Cancelled rather than
// VersionRefused or Unreachable — deliberate, and what a pre-dispatch
// MarkCancelled already produced under sequential dispatch.
//
// run persists every Task Pending before dispatching any of them, so a
// concurrent CancelJob (ADR-0013) can legitimately MarkCancelled a Task
// that is still Pending while its Job's other Tasks are being dispatched;
// the state transition then returns ErrInvalidTaskState. That is not a
// failure — the Task already reached a terminal, truthful outcome (Resolved,
// OutcomeCancelled) — so dispatchOne honors it rather than dispatching an
// already-cancelled Task or fabricating OutcomeFailure over a real cancel.
func (e *jobEngine) dispatchOne(ctx context.Context, gate *jobGate, pt pendingTask) (jobs.Result, error) {
	task := pt.task

	// Excluded from a Template dispatch before the cap was ever counted
	// (ADR-0042): never sent, whatever its version or connectivity.
	if pt.unsupported != "" {
		if err := e.tasksRepo.MarkUnsupported(ctx, task.ID, pt.unsupported, e.now()); err != nil {
			if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
				return res, nil
			}
			return jobs.Result{Outcome: jobs.OutcomeUnsupported}, fmt.Errorf("capability: mark task %q unsupported: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeUnsupported, Stderr: []byte(pt.unsupported)}, nil
	}

	// Stops queued Tasks from running the version and connectivity checks
	// after a cancel.
	if gate.isCancelled() {
		return e.resolveCancelled(ctx, task)
	}

	if pt.outdated {
		if err := e.tasksRepo.MarkVersionRefused(ctx, task.ID, e.now()); err != nil {
			if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
				return res, nil
			}
			return jobs.Result{Outcome: jobs.OutcomeVersionRefused}, fmt.Errorf("capability: mark task %q version-refused: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeVersionRefused, Stderr: []byte(jobs.VersionRefusedMessage)}, nil
	}

	if !e.conduit.Connected(task.NodeID) {
		if err := e.tasksRepo.MarkUnreachable(ctx, task.ID, e.now()); err != nil {
			if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
				return res, nil
			}
			return jobs.Result{Outcome: jobs.OutcomeUnreachable}, fmt.Errorf("capability: mark task %q unreachable: %w", task.ID, err)
		}
		return jobs.Result{Outcome: jobs.OutcomeUnreachable}, nil
	}

	admitted, err := gate.admit(func() error {
		return e.tasksRepo.MarkDispatched(ctx, task.ID, e.now())
	})
	if !admitted {
		// The Job was cancelled first; this Task was never sent.
		return e.resolveCancelled(ctx, task)
	}
	if err != nil {
		// A concurrent CancelJob may have MarkCancelled this Task while it
		// was still Pending. If so, the Task already carries a terminal,
		// truthful outcome — honor it rather than fabricating OutcomeFailure
		// or dispatching a Task the caller already asked to stop.
		if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
			return res, nil
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

// resolvedByCancel reports the truthful outcome of a Task that another party
// already resolved, when err is the ErrInvalidTaskState a lost transition
// race produces.
func (e *jobEngine) resolvedByCancel(ctx context.Context, taskID string, err error) (jobs.Result, bool) {
	if !errors.Is(err, jobs.ErrInvalidTaskState) {
		return jobs.Result{}, false
	}
	cur, getErr := e.tasksRepo.Get(ctx, taskID)
	if getErr != nil || cur.State != jobs.DispatchStateResolved {
		return jobs.Result{}, false
	}
	return jobs.Result{Outcome: cur.Outcome, Stdout: cur.Stdout, Stderr: cur.Stderr}, true
}

// resolveCancelled resolves a never-sent Task of a cancelled Job as Cancelled.
// If cancel() already resolved it, that truthful outcome is returned instead.
func (e *jobEngine) resolveCancelled(ctx context.Context, task jobs.Task) (jobs.Result, error) {
	err := e.tasksRepo.MarkCancelled(ctx, task.ID, e.now())
	if err == nil {
		return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
	}
	if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
		return res, nil
	}
	return jobs.Result{Outcome: jobs.OutcomeCancelled}, fmt.Errorf("capability: mark task %q cancelled: %w", task.ID, err)
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
// Recording the cancel on the Job's in-process gate happens BEFORE the ByJob
// read. After that point no MarkDispatched for this Job can commit in this
// process, so the snapshot's Dispatched set is complete and Conduit.Cancel
// reaches every Task that was or ever will be dispatched; a worker that loses
// the race resolves its own Task Cancelled. That closes the
// Pending -> Dispatched window in-process.
//
// What stays best-effort under ADR-0013: (i) a Dispatched Task that wins the
// race keeps its real outcome; (ii) the pre-send window — a TaskCancel can
// reach the daemon before the TaskRequest of a Task already MarkDispatched,
// and the daemon treats a cancel for an unknown id as a no-op, so that Task
// runs. Cancel only ever *asks*; it never fabricates an outcome for a Task
// that won the race.
func (e *jobEngine) cancel(ctx context.Context, jobID string) error {
	if _, err := e.jobsRepo.GetJob(ctx, jobID); err != nil {
		return err
	}
	if g := e.gateFor(jobID); g != nil {
		g.markCancelled()
	}

	tasks, err := e.tasksRepo.ByJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("capability: list tasks for job %q: %w", jobID, err)
	}

	var errs []error
	for _, task := range tasks {
		switch task.State {
		case jobs.DispatchStatePending:
			err := e.tasksRepo.MarkCancelled(ctx, task.ID, e.now())
			if err == nil {
				break
			}
			if !errors.Is(err, jobs.ErrInvalidTaskState) {
				errs = append(errs, fmt.Errorf("capability: mark task %q cancelled: %w", task.ID, err))
				break
			}
			// Lost the race to a worker. Resolved is truthful and not an error;
			// Dispatched is reachable only for a Job not gated in this process
			// (left over from a restart, never re-run), so ask it to cancel.
			cur, getErr := e.tasksRepo.Get(ctx, task.ID)
			switch {
			case getErr == nil && cur.State == jobs.DispatchStateResolved:
			case getErr == nil && cur.State == jobs.DispatchStateDispatched:
				if err := e.conduit.Cancel(ctx, cur.NodeID, cur.ID); err != nil {
					errs = append(errs, fmt.Errorf("capability: cancel task %q on node %q: %w", cur.ID, cur.NodeID, err))
				}
			default:
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

// WithExecDispatchConcurrency sets the per-Job dispatch bound (default
// DefaultDispatchConcurrency). It bounds reach and is startup-only (invariant 11).
func WithExecDispatchConcurrency(n int) ExecOption {
	return func(e *jobEngine) { e.concurrency = n }
}

// WithExecClock overrides the jobEngine's clock seam (production default:
// time.Now, UTC).
func WithExecClock(f func() time.Time) ExecOption {
	return func(e *jobEngine) { e.now = f }
}

// WithExecution wires the real Job engine into a Service: it fans a resolved
// Selector to one persisted Task per matched Node, fails offline Nodes fast
// (ADR-0004), and dispatches the rest through c concurrently, at most
// WithExecDispatchConcurrency at a time. jr, tr, and c must not be
// nil — a nil collaborator here is a composition-root wiring bug, not a
// recoverable runtime condition, so WithExecution panics rather than
// constructing a half-wired engine.
//
// Per the contract on New (service.go), a Service configured with
// WithExecution MUST also be configured with a real Authorizer, CapChecker,
// and AuditSink (WithAuthorizer/WithCapChecker/WithAuditSink); New enforces
// this at construction and panics otherwise, regardless of Option order. That
// AuditSink must also implement IntentRecorder (#887): the Job's Tasks are
// persisted through it, in one transaction with its dispatch-intent record.
func WithExecution(jr jobs.JobRepository, tr jobs.TaskRepository, c Conduit, opts ...ExecOption) Option {
	if jr == nil || tr == nil || c == nil {
		panic("capability: WithExecution: jobsRepo, tasksRepo, and conduit must not be nil")
	}
	e := &jobEngine{
		jobsRepo:    jr,
		tasksRepo:   tr,
		conduit:     c,
		newID:       defaultID,
		concurrency: DefaultDispatchConcurrency,
		now:         func() time.Time { return time.Now().UTC() },
		// A directly-constructed engine (e.g. in a test that never calls
		// Service.New) must never hold a nil sink. Service.New overwrites
		// this with the real one when WithJobEvents was used (service.go).
		events: noopJobEventSink{},
	}
	for _, o := range opts {
		o(e)
	}
	if e.concurrency < 1 {
		panic("capability: WithExecution: dispatch concurrency must be at least 1")
	}
	return func(s *Service) {
		s.disp = e
		s.realDispatcher = true
	}
}
