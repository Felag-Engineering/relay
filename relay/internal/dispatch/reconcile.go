package dispatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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
// reconnect (ADR-0004's at-most-once-across-restart discipline). It is
// separate from Router so Router stays transport-only.
//
// Resend-for-result is safe ONLY because the relay-daemon dedups Task
// execution by task_id (ADR-0004): on a duplicate task_id the daemon does
// NOT re-run the Task, it returns a synthesized benign already-processed
// Result. The Relay itself never re-executes a Task; ReconcileNode only ever
// asks "what happened to the Task I already dispatched", never "run this
// again."
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

// reconcileTask resends one in-flight Task for a Result and Resolves it.
// ErrInvalidTaskState/ErrTaskNotFound are tolerated, not errors: they mean a
// concurrent reconcile (or the original dispatch, if it actually completed
// after all) already resolved this Task — the exact idempotency InFlight()'s
// contract promises (once Resolved, a Task no longer appears in InFlight()).
func (r *Reconciler) reconcileTask(ctx context.Context, nodeID string, task jobs.Task) error {
	dctx, cancel := context.WithTimeout(ctx, reconcileDispatchTimeout)
	defer cancel()

	res, err := r.conduit.Dispatch(dctx, nodeID, task)
	if err != nil {
		return fmt.Errorf("dispatch: reconcile task %q on node %q: %w", task.ID, nodeID, err)
	}

	if err := r.tasks.Resolve(ctx, task.ID, res); err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
			// Already reconciled by someone else — done, not an error.
			return nil
		}
		return fmt.Errorf("dispatch: reconcile task %q: resolve: %w", task.ID, err)
	}
	return nil
}
