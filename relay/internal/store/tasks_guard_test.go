package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestTaskRepository_GuardAgreesWithTransition proves the one-table property
// at the store seam: for every repository method and every persisted state,
// the store's optimistic-concurrency guard accepts exactly the pairs
// jobs.Task.Transition accepts, and refuses the rest with ErrInvalidTaskState.
func TestTaskRepository_GuardAgreesWithTransition(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-g", "stage-g")
	repo := st.Tasks()
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

	apply := map[jobs.TaskEventKind]func(id string) error{
		jobs.TaskEventDispatch:         func(id string) error { return repo.MarkDispatched(ctx, id, at) },
		jobs.TaskEventResolve:          func(id string) error { return repo.Resolve(ctx, id, jobs.Result{Outcome: jobs.OutcomeSuccess}) },
		jobs.TaskEventUnreachable:      func(id string) error { return repo.MarkUnreachable(ctx, id, at) },
		jobs.TaskEventVersionRefused:   func(id string) error { return repo.MarkVersionRefused(ctx, id, at) },
		jobs.TaskEventUnsupported:      func(id string) error { return repo.MarkUnsupported(ctx, id, "r", at) },
		jobs.TaskEventCancel:           func(id string) error { return repo.MarkCancelled(ctx, id, at) },
		jobs.TaskEventCancelBeforeSend: func(id string) error { return repo.MarkCancelledBeforeSend(ctx, id, at) },
	}
	if len(apply) != 7 {
		t.Fatalf("expected one repository method per event kind, have %d", len(apply))
	}

	// seed reaches each persisted state through the real methods.
	seed := map[jobs.DispatchState]func(id string) error{
		jobs.DispatchStatePending:    func(string) error { return nil },
		jobs.DispatchStateDispatched: func(id string) error { return repo.MarkDispatched(ctx, id, at) },
		jobs.DispatchStateResolved:   func(id string) error { return repo.MarkUnreachable(ctx, id, at) },
	}

	n := 0
	for state, seedFn := range seed {
		for kind, applyFn := range apply {
			n++
			id := fmt.Sprintf("task-g-%d", n)
			if err := repo.CreateTask(ctx, jobs.Task{ID: id, JobID: "job-g", StageID: "stage-g", NodeID: "node-1", Action: testAction(), CreatedAt: at}); err != nil {
				t.Fatalf("CreateTask: %v", err)
			}
			if err := seedFn(id); err != nil {
				t.Fatalf("seeding state %d: %v", state, err)
			}
			if got, err := repo.Get(ctx, id); err != nil || got.State != state {
				t.Fatalf("seeded state = %v (err %v), want %v", got.State, err, state)
			}

			_, domainErr := jobs.Task{State: state}.Transition(jobs.TaskEvent{Kind: kind}, at)
			storeErr := applyFn(id)

			switch {
			case domainErr == nil && storeErr != nil:
				t.Errorf("kind %d from state %d: domain accepts, store refuses: %v", kind, state, storeErr)
			case domainErr != nil && !errors.Is(storeErr, jobs.ErrInvalidTaskState):
				t.Errorf("kind %d from state %d: domain refuses, store err = %v, want ErrInvalidTaskState", kind, state, storeErr)
			}
		}
	}
}

// TestTaskTransition_RefusesUnknownEventBeforeBegin pins that an event kind
// with no source state, or one whose source state has no persisted spelling,
// is a programming error: it never opens a transaction and never reads as a
// lost race.
func TestTaskTransition_RefusesUnknownEventBeforeBegin(t *testing.T) {
	st, _ := openTestStore(t)
	tasks := st.Tasks().(*sqliteTasks)
	called := false
	for _, k := range []jobs.TaskEventKind{0, 99} {
		err := tasks.transition(context.Background(), "nope", k, func(*sql.Tx) error { called = true; return nil })
		if !errors.Is(err, jobs.ErrUnknownTaskEvent) || errors.Is(err, jobs.ErrInvalidTaskState) {
			t.Errorf("kind %d: err = %v, want ErrUnknownTaskEvent", k, err)
		}
	}
	if called {
		t.Error("fn ran for an unknown event")
	}
}

func TestDispatchStateToString(t *testing.T) {
	for s, want := range map[jobs.DispatchState]string{
		jobs.DispatchStatePending:    "pending",
		jobs.DispatchStateDispatched: "dispatched",
	} {
		if got, ok := dispatchStateToString(s); !ok || got != want {
			t.Errorf("dispatchStateToString(%d) = (%q, %v), want (%q, true)", s, got, ok, want)
		}
	}
	for _, s := range []jobs.DispatchState{jobs.DispatchStateResolved, 99} {
		if got, ok := dispatchStateToString(s); ok {
			t.Errorf("dispatchStateToString(%d) = %q, must refuse: it is never a source state", s, got)
		}
	}
}
