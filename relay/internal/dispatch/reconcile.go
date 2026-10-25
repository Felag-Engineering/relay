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
// that an orphaned waiter (see the concurrent-reconnect race below) always
// returns rather than leaking forever.
const reconcileDispatchTimeout = 35 * time.Second

// Reconciler recovers in-flight Tasks after a Relay restart or a Node
// reconnect (ADR-0004's at-most-once-across-restart discipline): it re-sends
// them for their result on connect, and ResolveOffline resolves them when
// their Node goes offline. It is separate from Router so Router stays
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
// flapping nodeID can trigger two overlapping ReconcileNode goroutines. Both
// resending the same task_id would register two waiters for one task_id in
// Router's flat waiters map — the second overwrites the first, orphaning the
// first Dispatch call (it can never receive a Result; it can only time out).
// This cannot cause double-EXECUTION (the daemon's dedup still holds), but it
// would leak a goroutine and skip a Resolve. Two mitigations: (a) every
// Dispatch call here runs under a bounded ctx (reconcileDispatchTimeout), so
// an orphaned call is guaranteed to return rather than hang; (b) this guard
// (inProgress, keyed by nodeID) makes a second concurrent ReconcileNode call
// for the same nodeID a no-op, so only one reconcile drives that nodeID's
// Dispatch calls at a time.
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
// waiting Dispatch call. Those Tasks are left for that call to resolve with
// the real result, so the offline resolution never overwrites a result that
// arrived.
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
	// The deferred Settled runs after the Resolve below, so a result the Router
	// delivered stays protected from the offline resolution until this
	// reconcile has persisted it.
	defer r.conduit.Settled(nodeID, task.ID)
	res, err := r.conduit.Dispatch(jobs.WithSendGuard(dctx, guard), nodeID, task)
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
