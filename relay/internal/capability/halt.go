// A mutate Job's halt on its first failure or timeout (execution.md, Halting a
// failing mutation), decided here and never by an adapter (invariant 10).
package capability

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// haltsJob reports whether a Task that ended in outcome o halts a Job of the
// given dispatch class: any class but read, and only failure or timeout.
// Unspecified halts, failing closed the same way caps.go maps it to the mutate
// lane. The class is the dispatch's, so a Template Job takes its most
// restrictive reported class (invariant 13) even when the failing Node itself
// reports read. denied_by_policy, unsupported, unreachable, version_refused,
// cancelled and success never halt.
func haltsJob(class jobs.RiskClass, o jobs.Outcome) bool {
	if class == jobs.RiskClassRead {
		return false
	}
	return o == jobs.OutcomeFailure || o == jobs.OutcomeTimeout
}

// halt stops jobID sending on task's outcome o: it closes the gate, so no
// Pending Task of the Job is MarkDispatched from then on, and records the halt
// on the Job. dispatchErr is what dispatchOne returned beside o; it tells a
// recorded resolution from the engine's report of a send or execution that did
// not complete.
//
// dispatchOne has usually closed the gate already, provisionally, on the
// Conduit's answer and before anything was persisted; halt then settles that
// halt and records it. A path that could not close it earlier closes it here,
// BEFORE any store read or write, so no Task is admitted while the outcome is
// read or the halt recorded. If the record cannot be written, the in-memory
// halt still governs the Job (fail closed): the Job row then carries no halt
// while the Tasks it left unsent carry the reason, and the halt is still
// audited from the gate. A panic here is handled the same way, and never ends
// the process. A halt only ever moves a Task that was never sent (invariant 4).
func (e *jobEngine) halt(ctx context.Context, jobID string, gate *jobGate, task jobs.Task, o jobs.Outcome, dispatchErr error) (err error) {
	h := jobs.Halt{TaskID: task.ID, NodeID: task.NodeID, Outcome: o, At: e.now()}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		msg := "capability: job halt panicked; Job not halted by this Task"
		if gate.markHalted(h) {
			msg = "capability: job halt panicked; Job halted, halt not recorded"
		}
		attrs := panicLogAttrs(r, "job_id", jobID, "task_id", task.ID, "node_id", task.NodeID)
		e.logger().ErrorContext(ctx, msg, attrs...)
		err = fmt.Errorf("capability: halt job %q on task %q: %w", jobID, task.ID, errDispatchPanicked)
	}()

	if !gate.markHalted(h) {
		return nil
	}
	// A halt dispatchOne closed first keeps its own outcome and time.
	h, _ = gate.haltedBy()
	h.Resolved = e.haltingTaskResolved(ctx, task.ID, h.Outcome, o, dispatchErr)
	gate.settleHalt(task.ID, h.Resolved)
	e.logger().InfoContext(ctx, "capability: mutate Job halted",
		"job_id", jobID, "task_id", task.ID, "node_id", task.NodeID,
		"outcome", jobs.OutcomeName(h.Outcome), "resolved", h.Resolved)

	if recErr := e.jobsRepo.RecordHalt(ctx, jobID, h); recErr != nil {
		if errors.Is(recErr, jobs.ErrJobAlreadyHalted) {
			return nil
		}
		e.logger().ErrorContext(ctx, "capability: halt applied but not recorded on the Job",
			"job_id", jobID, "task_id", task.ID, "node_id", task.NodeID, "error", recErr)
		return fmt.Errorf("capability: record halt of job %q: %w", jobID, recErr)
	}
	return nil
}

// haltingTaskResolved reports whether the store holds taskID Resolved with
// halted, the outcome the halt names. A nil dispatchErr means dispatchOne
// returned a recorded resolution (Resolve, the offline resolution, or a stored
// truth) with the outcome reported, so no read is made when that is the halt's
// outcome. Otherwise it reads the store once (storedResolution); a read error
// or any other state says false.
func (e *jobEngine) haltingTaskResolved(ctx context.Context, taskID string, halted, reported jobs.Outcome, dispatchErr error) bool {
	if dispatchErr == nil && reported == halted {
		return true
	}
	stored, ok := e.storedResolution(ctx, taskID)
	return ok && stored.Outcome == halted
}

// resolveHalted resolves a never-sent Task of a halted Job as Cancelled, with
// the halt's reason as its stderr. If another party already resolved it, that
// truthful outcome is returned instead.
func (e *jobEngine) resolveHalted(ctx context.Context, task jobs.Task, h jobs.Halt) (jobs.Result, error) {
	reason := h.Reason()
	_, err := e.advance(task, jobs.TaskEvent{Kind: jobs.TaskEventHalt, Reason: reason}, func(n jobs.Task) error {
		return e.tasksRepo.MarkHalted(ctx, n.ID, reason, n.ResolvedAt)
	})
	if err == nil {
		return jobs.Result{Outcome: jobs.OutcomeCancelled, Stderr: []byte(reason)}, nil
	}
	if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
		return res, nil
	}
	return jobs.Result{Outcome: jobs.OutcomeCancelled, Stderr: []byte(reason)},
		fmt.Errorf("capability: mark task %q halted: %w", task.ID, err)
}

// withholdHalted resolves a Task this worker MarkDispatched but will never
// send, because a sibling's halt closed the gate before the send began, as
// Cancelled with the halt's reason and DispatchedAt cleared. dispatchOne's send
// guard performs this commit itself, inside the Router's per-Task critical
// section; this method is the fallback for a Conduit that withheld without
// consulting the guard. If another party already resolved the Task, that
// truthful outcome is returned instead.
func (e *jobEngine) withholdHalted(ctx context.Context, task jobs.Task, h jobs.Halt) (jobs.Result, error) {
	reason := h.Reason()
	_, err := e.advance(task, jobs.TaskEvent{Kind: jobs.TaskEventHaltBeforeSend, Reason: reason}, func(n jobs.Task) error {
		return e.tasksRepo.MarkHaltedBeforeSend(ctx, n.ID, reason, n.ResolvedAt)
	})
	return e.haltWithheldOutcome(ctx, task, h, err)
}

// haltWithheldOutcome turns the result of a MarkHaltedBeforeSend into the
// Task's outcome.
func (e *jobEngine) haltWithheldOutcome(ctx context.Context, task jobs.Task, h jobs.Halt, err error) (jobs.Result, error) {
	reason := h.Reason()
	if err == nil {
		return jobs.Result{Outcome: jobs.OutcomeCancelled, Stderr: []byte(reason)}, nil
	}
	if res, ok := e.resolvedByCancel(ctx, task.ID, err); ok {
		return res, nil
	}
	return jobs.Result{Outcome: jobs.OutcomeCancelled, Stderr: []byte(reason)},
		fmt.Errorf("capability: mark task %q halted before send: %w", task.ID, err)
}
