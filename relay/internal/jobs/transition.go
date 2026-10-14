package jobs

import (
	"errors"
	"time"
)

// ErrUnknownTaskEvent is returned for a TaskEventKind that names no
// transition. It is a programming error, so it deliberately does not wrap
// ErrInvalidTaskState: callers read that sentinel as "another writer moved
// the Task first", and a bug must never be read that way.
var ErrUnknownTaskEvent = errors.New("jobs: unknown task event")

// TaskEventKind names one legal Task transition. The zero value is
// deliberately invalid.
type TaskEventKind int

const (
	// TaskEventDispatch: Pending -> Dispatched (persist-then-send).
	TaskEventDispatch TaskEventKind = iota + 1
	// TaskEventResolve: Dispatched -> Resolved with the daemon's Result.
	TaskEventResolve
	// TaskEventUnreachable: Pending -> Resolved, OutcomeUnreachable.
	TaskEventUnreachable
	// TaskEventVersionRefused: Pending -> Resolved, OutcomeVersionRefused.
	TaskEventVersionRefused
	// TaskEventUnsupported: Pending -> Resolved, OutcomeUnsupported.
	TaskEventUnsupported
	// TaskEventCancel: Pending -> Resolved, OutcomeCancelled.
	TaskEventCancel
	// TaskEventCancelBeforeSend: Dispatched -> Resolved, OutcomeCancelled,
	// for a Task marked Dispatched whose send never began.
	TaskEventCancelBeforeSend
)

// From returns the state a Task must be in for the event to apply. This is
// the one table of required source states: Task.Transition reads it, and the
// store's optimistic-concurrency guard reads it too, so the domain and the
// store cannot disagree. ok is false for a kind that names no transition.
func (k TaskEventKind) From() (state DispatchState, ok bool) {
	switch k {
	case TaskEventDispatch, TaskEventUnreachable, TaskEventVersionRefused,
		TaskEventUnsupported, TaskEventCancel:
		return DispatchStatePending, true
	case TaskEventResolve, TaskEventCancelBeforeSend:
		return DispatchStateDispatched, true
	default:
		return 0, false
	}
}

// TaskEvent is a requested Task transition and the data it carries.
type TaskEvent struct {
	Kind TaskEventKind
	// Result is the daemon's report; TaskEventResolve only.
	Result Result
	// Reason is the Relay-authored Stderr text; TaskEventUnsupported only.
	Reason string
}

// Transition applies ev to the Task and returns the resulting Task, or the
// Task unchanged and an error: ErrUnknownTaskEvent for a kind that names no
// transition, ErrInvalidTaskState (bare, as the store returns it) when the
// Task is not in the state the event requires. now stamps DispatchedAt or
// ResolvedAt.
//
// It is a pure decision with no I/O. The store re-checks the persisted row,
// so Transition never replaces the store's guard (invariant 4, ADR-0004).
func (t Task) Transition(ev TaskEvent, now time.Time) (Task, error) {
	from, ok := ev.Kind.From()
	if !ok {
		return t, ErrUnknownTaskEvent
	}
	if t.State != from {
		return t, ErrInvalidTaskState
	}
	next := t
	switch ev.Kind {
	case TaskEventDispatch:
		next.State = DispatchStateDispatched
		next.DispatchedAt = now
		return next, nil
	case TaskEventResolve:
		next.Outcome = ev.Result.Outcome
		next.ExitCode = ev.Result.ExitCode
		next.Stdout = ev.Result.Stdout
		next.Stderr = ev.Result.Stderr
	case TaskEventUnreachable:
		next.Outcome = OutcomeUnreachable
	case TaskEventVersionRefused:
		next.Outcome = OutcomeVersionRefused
		next.Stderr = []byte(VersionRefusedMessage)
	case TaskEventUnsupported:
		next.Outcome = OutcomeUnsupported
		next.Stderr = []byte(ev.Reason)
	case TaskEventCancel:
		next.Outcome = OutcomeCancelled
	case TaskEventCancelBeforeSend:
		next.Outcome = OutcomeCancelled
		next.DispatchedAt = time.Time{}
	}
	next.State = DispatchStateResolved
	next.ResolvedAt = now
	return next, nil
}
