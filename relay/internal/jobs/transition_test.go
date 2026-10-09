package jobs

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// legalTransitions is the whole table, written out independently of
// Task.Transition: every (state, kind) pair not in it must be refused.
var legalTransitions = map[DispatchState][]TaskEventKind{
	DispatchStatePending: {
		TaskEventDispatch, TaskEventUnreachable, TaskEventVersionRefused,
		TaskEventUnsupported, TaskEventCancel,
	},
	DispatchStateDispatched: {TaskEventResolve, TaskEventCancelBeforeSend},
}

func isLegal(s DispatchState, k TaskEventKind) bool {
	for _, l := range legalTransitions[s] {
		if l == k {
			return true
		}
	}
	return false
}

// TestTaskTransition_Table enumerates every state x event pair, legal and
// illegal, including the zero and out-of-range values of each.
func TestTaskTransition_Table(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	dispatchedAt := now.Add(-time.Minute)
	result := Result{Outcome: OutcomeFailure, ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")}

	states := []DispatchState{DispatchStatePending, DispatchStateDispatched, DispatchStateResolved, DispatchState(99)}
	known := []TaskEventKind{
		TaskEventDispatch, TaskEventResolve, TaskEventUnreachable, TaskEventVersionRefused,
		TaskEventUnsupported, TaskEventCancel, TaskEventCancelBeforeSend,
	}
	unknown := []TaskEventKind{0, 99}

	if errors.Is(ErrUnknownTaskEvent, ErrInvalidTaskState) {
		t.Fatal("ErrUnknownTaskEvent must not wrap ErrInvalidTaskState: a bug must never read as a lost race")
	}

	for _, s := range states {
		for _, k := range append(append([]TaskEventKind{}, known...), unknown...) {
			in := Task{ID: "t1", State: s, DispatchedAt: dispatchedAt}
			got, err := in.Transition(TaskEvent{Kind: k, Result: result, Reason: "why"}, now)

			switch {
			case k == 0 || k == 99:
				if !errors.Is(err, ErrUnknownTaskEvent) {
					t.Errorf("state %d kind %d: err = %v, want ErrUnknownTaskEvent", s, k, err)
				}
			case !isLegal(s, k):
				if err != ErrInvalidTaskState {
					t.Errorf("state %d kind %d: err = %v, want the bare ErrInvalidTaskState", s, k, err)
				}
			default:
				if err != nil {
					t.Errorf("state %d kind %d: unexpected error %v", s, k, err)
				}
				continue
			}
			if got.State != in.State || !got.DispatchedAt.Equal(in.DispatchedAt) || got.Outcome != in.Outcome || !got.ResolvedAt.IsZero() {
				t.Errorf("state %d kind %d: refused transition changed the Task: %+v", s, k, got)
			}
		}
	}

	type want struct {
		state        DispatchState
		outcome      Outcome
		exit         int32
		stdout       string
		stderr       string
		dispatchedAt time.Time
		resolvedAt   time.Time
	}
	legal := []struct {
		from DispatchState
		ev   TaskEvent
		want want
	}{
		{DispatchStatePending, TaskEvent{Kind: TaskEventDispatch},
			want{state: DispatchStateDispatched, dispatchedAt: now}},
		{DispatchStateDispatched, TaskEvent{Kind: TaskEventResolve, Result: result},
			want{DispatchStateResolved, OutcomeFailure, 3, "out", "err", dispatchedAt, now}},
		{DispatchStatePending, TaskEvent{Kind: TaskEventUnreachable},
			want{state: DispatchStateResolved, outcome: OutcomeUnreachable, dispatchedAt: dispatchedAt, resolvedAt: now}},
		{DispatchStatePending, TaskEvent{Kind: TaskEventVersionRefused},
			want{state: DispatchStateResolved, outcome: OutcomeVersionRefused, stderr: VersionRefusedMessage, dispatchedAt: dispatchedAt, resolvedAt: now}},
		{DispatchStatePending, TaskEvent{Kind: TaskEventUnsupported, Reason: "no such template"},
			want{state: DispatchStateResolved, outcome: OutcomeUnsupported, stderr: "no such template", dispatchedAt: dispatchedAt, resolvedAt: now}},
		{DispatchStatePending, TaskEvent{Kind: TaskEventCancel},
			want{state: DispatchStateResolved, outcome: OutcomeCancelled, dispatchedAt: dispatchedAt, resolvedAt: now}},
		{DispatchStateDispatched, TaskEvent{Kind: TaskEventCancelBeforeSend},
			want{state: DispatchStateResolved, outcome: OutcomeCancelled, resolvedAt: now}},
	}
	if len(legal) != 7 {
		t.Fatalf("the table has 7 legal transitions, the test lists %d", len(legal))
	}
	for _, c := range legal {
		in := Task{ID: "t1", State: c.from, DispatchedAt: dispatchedAt}
		got, err := in.Transition(c.ev, now)
		if err != nil {
			t.Errorf("kind %d: %v", c.ev.Kind, err)
			continue
		}
		w := c.want
		if got.State != w.state || got.Outcome != w.outcome || got.ExitCode != w.exit ||
			!bytes.Equal(got.Stdout, []byte(w.stdout)) || !bytes.Equal(got.Stderr, []byte(w.stderr)) ||
			!got.DispatchedAt.Equal(w.dispatchedAt) || !got.ResolvedAt.Equal(w.resolvedAt) {
			t.Errorf("kind %d: got %+v, want %+v", c.ev.Kind, got, w)
		}
		if got.ID != "t1" {
			t.Errorf("kind %d: Transition dropped the Task's identity", c.ev.Kind)
		}
		if in.State != c.from {
			t.Errorf("kind %d: Transition mutated its receiver", c.ev.Kind)
		}
	}
}

// TestTaskEventKind_From pins the one table of required source states, which
// the store's concurrency guard also reads.
func TestTaskEventKind_From(t *testing.T) {
	for s, kinds := range legalTransitions {
		for _, k := range kinds {
			if got, ok := k.From(); !ok || got != s {
				t.Errorf("kind %d: From() = (%d, %v), want (%d, true)", k, got, ok, s)
			}
		}
	}
	for _, k := range []TaskEventKind{0, 99} {
		if _, ok := k.From(); ok {
			t.Errorf("kind %d must have no source state", k)
		}
	}
}
