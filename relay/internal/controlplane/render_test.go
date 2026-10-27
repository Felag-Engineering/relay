package controlplane

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

func TestMapSlice(t *testing.T) {
	double := func(n int) int { return n * 2 }

	if got := MapSlice([]int{1, 2, 3}, double); !slices.Equal(got, []int{2, 4, 6}) {
		t.Errorf("MapSlice = %v, want [2 4 6]", got)
	}
	for name, in := range map[string][]int{"nil": nil, "empty": {}} {
		got := MapSlice(in, double)
		if got == nil || len(got) != 0 {
			t.Errorf("MapSlice(%s) = %#v, want a non-nil empty slice", name, got)
		}
	}
}

// fakeJobResults is a JobResultReader over one Job and its Tasks.
type fakeJobResults struct {
	job   jobs.Job
	tasks []jobs.Task
}

func (f fakeJobResults) GetJob(_ context.Context, id string) (jobs.Job, error) {
	if id != f.job.ID {
		return jobs.Job{}, jobs.ErrJobNotFound
	}
	return f.job, nil
}

func (f fakeJobResults) TasksByJob(context.Context, string) ([]jobs.Task, error) {
	return f.tasks, nil
}

// TestRenderJob_CarriesTheHaltOfAHaltedJob: the shared renderer turns a
// persisted Halt into the one halt object both surfaces tag (#1150).
func TestRenderJob_CarriesTheHaltOfAHaltedJob(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		h := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeTimeout, Resolved: resolved}
		reader := fakeJobResults{
			job: jobs.Job{ID: "job-1", Halt: h},
			tasks: []jobs.Task{
				{ID: "task-2", NodeID: "node-2", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeCancelled, Stderr: []byte(h.Reason())},
				{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeTimeout},
			},
		}
		got, err := RenderJob(context.Background(), reader, "job-1")
		if err != nil {
			t.Fatalf("RenderJob: %v", err)
		}
		want := &RenderedHalt{NodeID: "node-1", Outcome: "timeout", Resolved: resolved, Reason: h.Reason()}
		if !reflect.DeepEqual(got.Halt, want) {
			t.Errorf("resolved=%v: Halt = %+v, want %+v", resolved, got.Halt, want)
		}
		if got.Status != JobStatusComplete || len(got.Results) != 2 || got.Results[0].NodeID != "node-1" {
			t.Errorf("resolved=%v: status %q results %+v, want a complete Job sorted by Node", resolved, got.Status, got.Results)
		}
	}
}

func TestRenderJob_NoHaltWhenTheJobDidNotHalt(t *testing.T) {
	reader := fakeJobResults{
		job:   jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}},
	}
	got, err := RenderJob(context.Background(), reader, "job-1")
	if err != nil {
		t.Fatalf("RenderJob: %v", err)
	}
	if got.Halt != nil || got.Status != JobStatusRunning {
		t.Errorf("RenderJob = halt %+v status %q, want no halt and a running Job", got.Halt, got.Status)
	}
}
