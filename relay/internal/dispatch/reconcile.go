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

// ResendForResultLimit is how long after marking a Task Dispatched the Relay
// will still send it for its result (EX-71). A re-send is safe only while the
// relay-daemon still holds the Task's dedup marker, and the limit sits well
// inside that retention, so a Relay that was down or restored from an older
// backup never makes a Node run a Task a second time (invariant 4).
const ResendForResultLimit = 10 * time.Minute

// withinResendLimit reports whether a Task marked Dispatched at dispatchedAt
// may still be sent for its result at now. No recorded dispatch time is past
// the limit, and so is a dispatch time later than now (a clock stepped back):
// its age cannot be shown to be inside the limit.
func withinResendLimit(dispatchedAt, now time.Time) bool {
	if dispatchedAt.IsZero() {
		return false
	}
	age := now.Sub(dispatchedAt)
	return age >= 0 && age <= ResendForResultLimit
}

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
//
// A re-send happens only within ResendForResultLimit of the Task's dispatch
// (EX-71, invariant 4), checked in the send guard on the re-read Task. A Task
// past it is resolved as EX-62 resolves an offline Task, never sent, and halts
// its Job by the dispatch's class.
type Reconciler struct {
	tasks   jobs.TaskRepository
	conduit *Router
	now     func() time.Time
	halts   HaltRecorder
	rec     ResendLimitRecorder

	mu         sync.Mutex
	inProgress map[string]bool
}

// HaltRecorder records the halt of a Job whose Task the Reconciler resolved
// past the resend limit. Structural: the store's JobRepository satisfies it.
type HaltRecorder interface {
	RecordHalt(ctx context.Context, jobID string, h jobs.Halt) error
}

// ResendLimitRecorder audits what the Reconciler did to a Task past the resend
// limit: its outcome, and the halt it caused. Structural, like
// SettlementRecorder: *auditsink.Sink satisfies it and this package imports
// neither internal/audit nor internal/capability.
type ResendLimitRecorder interface {
	RecordResendLimitSettlement(ctx context.Context, task jobs.Task, res jobs.Result) error
	RecordResendLimitHalt(ctx context.Context, task jobs.Task, h jobs.Halt) error
}

// ReconcilerOption configures a Reconciler.
type ReconcilerOption func(*Reconciler)

// WithReconcilerClock replaces the Reconciler's clock; nil keeps the real one.
func WithReconcilerClock(now func() time.Time) ReconcilerOption {
	return func(r *Reconciler) {
		if now != nil {
			r.now = now
		}
	}
}

// WithResendLimitSettlement wires the halt write and the audit for a Task past
// the resend limit. Either may be nil: that part is then skipped.
func WithResendLimitSettlement(halts HaltRecorder, rec ResendLimitRecorder) ReconcilerOption {
	return func(r *Reconciler) {
		r.halts = halts
		r.rec = rec
	}
}

// NewReconciler returns a Reconciler over tasks and conduit, using
// time.Now (UTC) as its clock unless an option says otherwise.
func NewReconciler(tasks jobs.TaskRepository, conduit *Router, opts ...ReconcilerOption) *Reconciler {
	r := &Reconciler{
		tasks:      tasks,
		conduit:    conduit,
		now:        func() time.Time { return time.Now().UTC() },
		inProgress: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
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
// are woken by the one Result. The resend limit applies to every Task it
// reaches (EX-71).
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
// is joined and returned; the Task then stays Dispatched and, inside
// ResendForResultLimit, falls back to re-send-for-result on the Node's next
// connect. Past the limit the next connect resolves it instead.
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
		if err := r.resolveAsOffline(ctx, task); err != nil {
			if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
				continue
			}
			errs = append(errs, fmt.Errorf("dispatch: resolve offline task %q: %w", task.ID, err))
		}
	}
	return errors.Join(errs...)
}

// resolveAsOffline resolves task with jobs.NodeOfflineResult, the one EX-62
// resolution: a Task the Relay will not send, whose run is unknown. The error
// is unclassified, so each caller decides which ones it tolerates.
func (r *Reconciler) resolveAsOffline(ctx context.Context, task jobs.Task) error {
	res := jobs.NodeOfflineResult()
	if _, err := task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventResolve, Result: res}, r.now()); err != nil {
		return err
	}
	return r.tasks.Resolve(ctx, task.ID, res)
}

// SettleHaltedJobs resolves, sending nothing, every Task a halted mutate Job
// left Pending or Dispatched when the Relay stopped, and returns how many it
// resolved. It runs once at start, before any Node can connect, because
// ReconcileNode re-sends every Dispatched Task and must never send one of a
// halted Job (invariant 4, ADR-0004; execution.md, Halting a failing mutation).
//
// A Pending Task was never sent and resolves as a live halt leaves it:
// cancelled with Halt.Reason, no dispatch time. A Dispatched one may already
// have reached its Node, so it resolves failure with exit code -1 and
// Halt.RestartReason, keeping its dispatch time, as NodeOfflineResult does for
// a Task whose outcome is unknown; an AI-agent reading it never mistakes
// "maybe ran" for "did not run". The halting Task itself, if still Dispatched,
// is treated the same. Each outcome is passed to rec, when non-nil, once it is
// stored; a failure to record is joined into the returned error.
//
// It must not run while a Job engine is live: a live halted Job's in-flight
// Tasks finish and report their real outcomes, and only after a restart is no
// engine left to receive them.
//
// ErrInvalidTaskState and ErrTaskNotFound are tolerated and not counted, as in
// ResolveOffline: they mean the Task was resolved first. A Job that cannot be
// read, or that the listing named but carries no halt, leaves its Tasks as they
// are and is reported; every other error is joined and returned.
func (r *Reconciler) SettleHaltedJobs(ctx context.Context, halted jobs.HaltedJobRepository, rec SettlementRecorder) (int, error) {
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
		res, ok, err := r.settleHaltedTask(ctx, task, h)
		if err != nil {
			errs = append(errs, fmt.Errorf("dispatch: settle halted task %q: %w", task.ID, err))
			continue
		}
		if !ok {
			continue
		}
		settled++
		if rec != nil {
			if err := rec.RecordHaltedSettlement(ctx, task, res); err != nil {
				errs = append(errs, fmt.Errorf("dispatch: record settled halted task %q: %w", task.ID, err))
			}
		}
	}
	return settled, errors.Join(errs...)
}

// SettlementRecorder records the outcome SettleHaltedJobs stored for a Task of
// a halted Job. Structural, like ViolationRecorder: *auditsink.Sink satisfies
// it and this package imports neither internal/audit nor internal/capability.
type SettlementRecorder interface {
	RecordHaltedSettlement(ctx context.Context, task jobs.Task, res jobs.Result) error
}

// settleHaltedTask resolves one Task of the halted Job h without sending it and
// returns the Result it stored. It reports false, with no error, for a Task
// that is not Pending or Dispatched or that was resolved first.
func (r *Reconciler) settleHaltedTask(ctx context.Context, task jobs.Task, h jobs.Halt) (jobs.Result, bool, error) {
	var err error
	var res jobs.Result
	switch task.State {
	case jobs.DispatchStatePending:
		reason := h.Reason()
		res = jobs.Result{Outcome: jobs.OutcomeCancelled, Stderr: []byte(reason)}
		var next jobs.Task
		next, err = task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventHalt, Reason: reason}, r.now())
		if err == nil {
			err = r.tasks.MarkHalted(ctx, task.ID, reason, next.ResolvedAt)
		}
	case jobs.DispatchStateDispatched:
		res = h.RestartResult()
		_, err = task.Transition(jobs.TaskEvent{Kind: jobs.TaskEventResolve, Result: res}, r.now())
		if err == nil {
			err = r.tasks.Resolve(ctx, task.ID, res)
		}
	default:
		return jobs.Result{}, false, nil
	}
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidTaskState) || errors.Is(err, jobs.ErrTaskNotFound) {
			return jobs.Result{}, false, nil
		}
		return jobs.Result{}, false, err
	}
	return res, true, nil
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
//
// The same guard enforces the resend limit (EX-71, invariant 4): a re-read Task
// marked Dispatched more than ResendForResultLimit ago, or with no dispatch
// time, is resolved as EX-62 resolves an offline Task inside the send slot and
// never sent; settlePastLimit then audits it and halts its Job. The same
// guard is also the Reconciler's resend bound (jobs.WithResendBound), which the
// Router evaluates even when a live worker has already sent the Task and still
// holds its send slot, so no re-send of a Task goes out past the limit whatever
// state that worker is in. A halt or cancel guard, by contrast, never withholds
// such a re-send.
func (r *Reconciler) reconcileTask(ctx context.Context, nodeID string, task jobs.Task) error {
	dctx, cancel := context.WithTimeout(ctx, reconcileDispatchTimeout)
	defer cancel()

	// The guard runs synchronously on this goroutine inside Router.Dispatch,
	// so writing readErr needs no lock.
	var (
		readErr   error
		pastLimit bool
		settled   jobs.Task
		settleErr error
	)
	guard := func() bool {
		cur, err := r.tasks.Get(dctx, task.ID)
		if err != nil {
			readErr = err
			return true
		}
		if cur.State != jobs.DispatchStateDispatched {
			return true
		}
		if withinResendLimit(cur.DispatchedAt, r.now()) {
			return false
		}
		pastLimit, settled = true, cur
		settleErr = r.resolveAsOffline(dctx, cur)
		return true
	}
	// The deferred Settle runs after the Resolve below, so a result the Router
	// delivered to this reconcile stays protected from the offline resolution
	// until this reconcile has persisted it.
	sendCtx, settlement := jobs.WithSettlement(jobs.WithResendBound(jobs.WithSendGuard(dctx, guard), guard))
	defer settlement.Settle()
	res, err := r.conduit.Dispatch(sendCtx, nodeID, task)
	if errors.Is(err, jobs.ErrSendWithheld) {
		if readErr != nil {
			return fmt.Errorf("dispatch: reconcile task %q on node %q: re-read before resend: %w", task.ID, nodeID, readErr)
		}
		if pastLimit {
			return r.settlePastLimit(ctx, settled, settleErr)
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

// settlePastLimit finishes a Task the send guard withheld as past the resend
// limit (EX-71): it audits the outcome and halts the Job when its dispatch
// class halts on a failure (EX-26, EX-27). resolveErr is what the guard's
// resolution returned. It moves no sibling: Pending ones are never sent
// (EX-32) and the next start's EX-28 sweep settles them once the Job carries a
// halt.
func (r *Reconciler) settlePastLimit(ctx context.Context, task jobs.Task, resolveErr error) error {
	if errors.Is(resolveErr, jobs.ErrInvalidTaskState) || errors.Is(resolveErr, jobs.ErrTaskNotFound) {
		// Resolved first by someone else, who owns its audit and halt.
		return nil
	}
	if resolveErr != nil {
		// Still Dispatched; the next connect finds it past the limit again.
		return fmt.Errorf("dispatch: resolve task %q past the resend limit: %w", task.ID, resolveErr)
	}

	res := jobs.NodeOfflineResult()
	var errs []error
	if r.rec != nil {
		if err := r.rec.RecordResendLimitSettlement(ctx, task, res); err != nil {
			errs = append(errs, fmt.Errorf("dispatch: audit task %q past the resend limit: %w", task.ID, err))
		}
	}

	// A Job that cannot be read halts: an unknown class fails closed.
	class := jobs.RiskClassUnspecified
	if siblings, err := r.tasks.ByJob(ctx, task.JobID); err == nil {
		class = jobs.DispatchClass(siblings)
	}
	if r.halts == nil || !jobs.HaltsJob(class, res.Outcome) {
		return errors.Join(errs...)
	}
	h := jobs.Halt{TaskID: task.ID, NodeID: task.NodeID, Outcome: res.Outcome, Resolved: true, At: r.now()}
	if err := r.halts.RecordHalt(ctx, task.JobID, h); err != nil {
		if !errors.Is(err, jobs.ErrJobAlreadyHalted) {
			errs = append(errs, fmt.Errorf("dispatch: halt job %q: %w", task.JobID, err))
		}
		return errors.Join(errs...)
	}
	if r.rec != nil {
		if err := r.rec.RecordResendLimitHalt(ctx, task, h); err != nil {
			errs = append(errs, fmt.Errorf("dispatch: audit halt of job %q: %w", task.JobID, err))
		}
	}
	return errors.Join(errs...)
}
