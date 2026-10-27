package dispatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// reconcileDispatchTimeout bounds each reconcile Dispatch call. It must
// exceed the daemon's default per-Task timeout (dispatch.rs: 30s when
// TimeoutSeconds <= 0) so a resend for a Task that is genuinely still running
// on the daemon has time to return its real (or benign already-processed,
// per dedup.rs) Result before the bound trips — while still guaranteeing
// that a resend whose Result never comes always returns rather than leaking
// forever.
const reconcileDispatchTimeout = 35 * time.Second

// Reconciler recovers in-flight Tasks after a Relay restart or a Node
// reconnect (ADR-0004's at-most-once-across-restart discipline): it re-sends
// them for their result on connect, and ResolveOffline resolves them when
// their Node goes offline. SettleHaltedJobs is its start-up counterpart for
// halted Jobs and sends nothing. It is separate from Router so Router stays
// transport-only.
//
// Resend-for-result is safe ONLY because the relay-daemon dedups Task
// execution by task_id (ADR-0004): on a duplicate task_id the daemon does
// NOT re-run the Task, it returns a synthesized benign already-processed
// Result. The Relay itself never re-executes a Task; ReconcileNode only ever
// asks "what happened to the Task I already dispatched", never "run this
// again."
//
// A resend and a live worker's send of the same Task are serialised per task
// ID by Router.Dispatch's send slot: the worker's cancel guard commits
// its withhold inside that critical section and the Reconciler's guard re-reads
// the store inside it, so a Reconciler send either comes after the withhold
// (and reads Resolved, sending nothing) or before it (and the worker then
// sends too, never recording a Task that was sent as never sent).
//
// Residual: the slot lives only while a Dispatch call for the Task is
// in progress. If a Reconciler resend has fully returned (with a Result, or
// with a timeout or disconnect error) before the live worker reaches its guard,
// the slot is gone and the worker's guard can still record the Task cancelled,
// never sent, for a Task the Reconciler did send. The daemon still dedups by
// task_id (at-most-once holds), but the record is untruthful for that Task.
type Reconciler struct {
	tasks   jobs.TaskRepository
	conduit *Router
	now     func() time.Time

	mu         sync.Mutex
	inProgress map[string]bool
}

// NewReconciler returns a Reconciler over tasks and conduit, using
// time.Now (UTC) as its clock.
func NewReconciler(tasks jobs.TaskRepository, conduit *Router) *Reconciler {
	return &Reconciler{
		tasks:      tasks,
		conduit:    conduit,
		now:        func() time.Time { return time.Now().UTC() },
		inProgress: make(map[string]bool),
	}
}

// ReconcileNode resends every in-flight (Dispatched, no Result) Task
// belonging to nodeID and Resolves each once its Result returns. It is
// wired as Router's onConnect hook (run in its own goroutine by Register),
// firing on every registration including reconnects.
//
// Concurrent-reconnect guard: onConnect fires on every Register call, so a
// flapping nodeID can trigger two overlapping ReconcileNode goroutines, each
// resending the same task_id. The Router keeps every caller waiting on a task
// ID, so neither is orphaned, but the duplicate resends are wasted work. Two
// bounds: (a) every Dispatch call here runs under a bounded ctx
// (reconcileDispatchTimeout), so a call whose Result never comes returns
// rather than hangs; (b) this guard (inProgress, keyed by nodeID) makes a
// second concurrent ReconcileNode call for the same nodeID a no-op, so only
// one reconcile drives that nodeID's Dispatch calls at a time. A live
// worker's Dispatch of the same Task can still wait beside a resend, and both
// are woken by the one Result.
func (r *Reconciler) ReconcileNode(ctx context.Context, nodeID string) error {
	r.mu.Lock()
	if r.inProgress[nodeID] {
		r.mu.Unlock()
		return nil
	}
	r.inProgress[nodeID] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inProgress, nodeID)
		r.mu.Unlock()
	}()

	inFlight, err := r.tasks.InFlight(ctx)
	if err != nil {
		return fmt.Errorf("dispatch: reconcile node %q: list in-flight tasks: %w", nodeID, err)
	}

	var errs []error
	for _, task := range inFlight {
		if task.NodeID != nodeID {
			continue
		}
		if err := r.reconcileTask(ctx, nodeID, task); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ResolveOffline resolves every in-flight (Dispatched, no Result) Task
// belonging to nodeID with jobs.NodeOfflineResult: the Node's stream ended, no
// result arrived, and whether the Task ran is unknown. It is ReconcileNode's
// dual and sends nothing. A Task it resolves leaves InFlight(), so no later
// ReconcileNode re-sends it: a Task the Node never received must not run for
// the first time minutes or hours later (invariant 4, ADR-0004).
//
// skip holds the IDs of Tasks whose TaskResult was already delivered to a
// waiting Dispatch call that has not yet settled it (jobs.Settlement). Those
// Tasks are left for that call to resolve with the real result, so the
// offline resolution never overwrites a result that arrived.
//
// ErrInvalidTaskState and ErrTaskNotFound are tolerated, as in reconcileTask:
// they mean a worker or a reconcile resolved the Task first. Any other error
// is joined and returned; the Task then stays Dispatched and falls back to
// re-send-for-result on the Node's next connect.
func (r *Reconciler) ResolveOffline(ctx context.Context, nodeID string, skip map[string]struct{}) error {
	inFlight, err := r.tasks.InFlight(ctx)
	if err != nil {
		return fmt.Errorf("dispatch: resolve offline node %q: list in-flight tasks: %w", nodeID, err)
	}

	var errs []error
	for _, task := range inFlight {
		if task.NodeID != nodeID {
			continue
		}
		if _, delivered := skip[task.ID]; delivered {
			continue
		}
		res := jobs.NodeOfflineResult()
		if _, err := task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventResolve, Result: res}, r.now()); err != nil {
			if errors.Is(err, jobs.ErrInvalidTaskState) {
				continue
			}
			errs = append(errs, fmt.Errorf("dispatch: resolve offline task %q: %w", task.ID, err))
			continue
		}
		if err := r.tasks.Resolve(ctx, task.ID, res); err != nil {
			if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
				continue
			}
			errs = append(errs, fmt.Errorf("dispatch: resolve offline task %q: %w", task.ID, err))
		}
	}
	return errors.Join(errs...)
}

// SettleHaltedJobs resolves, sending nothing, every Task a halted mutate Job
// left Pending or Dispatched when the Relay stopped, and returns how many it
// resolved. It runs once at start, before any Node can connect, because
// ReconcileNode re-sends every Dispatched Task and must never send one of a
// halted Job (invariant 4, ADR-0004; execution.md, Halting a failing mutation).
//
// A Pending Task resolves as a live halt leaves it: Halt.Reason, no dispatch
// time. A Dispatched one may already have been sent, so it resolves with
// Halt.RestartResult, keeping its dispatch time, rather than claim it never
// was. The halting Task itself, if still Dispatched, is treated the same.
//
// It must not run while a Job engine is live: a live halted Job's in-flight
// Tasks finish and report their real outcomes, and only after a restart is no
// engine left to receive them.
//
// ErrInvalidTaskState and ErrTaskNotFound are tolerated and not counted, as in
// ResolveOffline: they mean the Task was resolved first. A Job that cannot be
// read, or that the listing named but carries no halt, leaves its Tasks as they
// are and is reported; every other error is joined and returned.
func (r *Reconciler) SettleHaltedJobs(ctx context.Context, halted jobs.HaltedJobRepository) (int, error) {
	survivors, err := halted.UnsettledTasksOfHaltedJobs(ctx)
	if err != nil {
		return 0, fmt.Errorf("dispatch: settle halted jobs: list unsettled tasks: %w", err)
	}

	var errs []error
	settled := 0
	halts := make(map[string]jobs.Halt)
	unreadable := make(map[string]bool)
	for _, task := range survivors {
		if unreadable[task.JobID] {
			continue
		}
		h, known := halts[task.JobID]
		if !known {
			job, err := halted.GetJob(ctx, task.JobID)
			if err != nil {
				unreadable[task.JobID] = true
				errs = append(errs, fmt.Errorf("dispatch: settle halted job %q: %w", task.JobID, err))
				continue
			}
			h = job.Halt
			halts[task.JobID] = h
		}
		if !h.Halted() {
			// The listing selects only halted Jobs, so this is a store that
			// disagrees with itself; sending nothing is the safe side.
			unreadable[task.JobID] = true
			errs = append(errs, fmt.Errorf("dispatch: settle halted job %q: listed as halted but carries no halt", task.JobID))
			continue
		}
		ok, err := r.settleHaltedTask(ctx, task, h)
		if err != nil {
			errs = append(errs, fmt.Errorf("dispatch: settle halted task %q: %w", task.ID, err))
			continue
		}
		if ok {
			settled++
		}
	}
	return settled, errors.Join(errs...)
}

// settleHaltedTask resolves one Task of the halted Job h without sending it. It
// reports false, with no error, for a Task that is not Pending or Dispatched or
// that was resolved first.
func (r *Reconciler) settleHaltedTask(ctx context.Context, task jobs.Task, h jobs.Halt) (bool, error) {
	var err error
	switch task.State {
	case jobs.DispatchStatePending:
		reason := h.Reason()
		var next jobs.Task
		next, err = task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventHalt, Reason: reason}, r.now())
		if err == nil {
			err = r.tasks.MarkHalted(ctx, task.ID, reason, next.ResolvedAt)
		}
	case jobs.DispatchStateDispatched:
		res := h.RestartResult()
		_, err = task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventResolve, Result: res}, r.now())
		if err == nil {
			err = r.tasks.Resolve(ctx, task.ID, res)
		}
	default:
		return false, nil
	}
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// reconcileTask resends one in-flight Task for a Result and Resolves it.
// ErrInvalidTaskState/ErrTaskNotFound are tolerated, not errors: they mean a
// concurrent reconcile (or the original dispatch, if it actually completed
// after all) already resolved this Task — the exact idempotency InFlight()'s
// contract promises (once Resolved, a Task no longer appears in InFlight()).
//
// Before each resend the Task's state is re-read immediately before the wire
// write. A Task no longer Dispatched is never sent from a stale
// snapshot: this matters because reconcileTask runs serially under a 35s
// per-Task bound, so a snapshot can be minutes old by its last Task. A failed
// re-read withholds the send and returns an error; the Task stays Dispatched
// and is retried on the next reconnect.
func (r *Reconciler) reconcileTask(ctx context.Context, nodeID string, task jobs.Task) error {
	dctx, cancel := context.WithTimeout(ctx, reconcileDispatchTimeout)
	defer cancel()

	// The guard runs synchronously on this goroutine inside Router.Dispatch,
	// so writing readErr needs no lock.
	var readErr error
	guard := func() bool {
		cur, err := r.tasks.Get(dctx, task.ID)
		if err != nil {
			readErr = err
			return true
		}
		return cur.State != jobs.DispatchStateDispatched
	}
	// The deferred Settle runs after the Resolve below, so a result the Router
	// delivered to this reconcile stays protected from the offline resolution
	// until this reconcile has persisted it.
	sendCtx, settlement := jobs.WithSettlement(jobs.WithSendGuard(dctx, guard))
	defer settlement.Settle()
	res, err := r.conduit.Dispatch(sendCtx, nodeID, task)
	if errors.Is(err, jobs.ErrSendWithheld) {
		if readErr != nil {
			return fmt.Errorf("dispatch: reconcile task %q on node %q: re-read before resend: %w", task.ID, nodeID, readErr)
		}
		// Resolved since the InFlight snapshot (e.g. withheld by its worker
		// on a cancel): nothing to send, nothing to write.
		return nil
	}
	if err != nil {
		// A Node that drops mid-reconcile has its in-flight Tasks resolved
		// offline (ResolveOffline). A Task already out of Dispatched is done,
		// not a reconcile failure.
		if cur, getErr := r.tasks.Get(ctx, task.ID); getErr == nil && cur.State != jobs.DispatchStateDispatched {
			return nil
		}
		return fmt.Errorf("dispatch: reconcile task %q on node %q: %w", task.ID, nodeID, err)
	}

	// The in-memory check feeds the same tolerated branch as a stale-state
	// Resolve: InFlight returns only Dispatched Tasks, so on a correct
	// snapshot it never fires, and it is here so that every Task write goes
	// through the same transition table. The store stamps its own resolved_at.
	if err := func() error {
		if _, err := task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventResolve, Result: res}, r.now()); err != nil {
			return err
		}
		return r.tasks.Resolve(ctx, task.ID, res)
	}(); err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
			// Already reconciled by someone else — done, not an error.
			return nil
		}
		return fmt.Errorf("dispatch: reconcile task %q: resolve: %w", task.ID, err)
	}
	return nil
}
