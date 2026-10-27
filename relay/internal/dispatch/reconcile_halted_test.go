package dispatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// fakeHaltedJobs is a jobs.HaltedJobRepository over a fixed list of unsettled
// Tasks and the Jobs they belong to.
type fakeHaltedJobs struct {
	jobs     map[string]jobs.Job
	list     []jobs.Task
	listErr  error
	jobErr   map[string]error
	getCalls map[string]int
}

func newFakeHaltedJobs(list []jobs.Task, js ...jobs.Job) *fakeHaltedJobs {
	f := &fakeHaltedJobs{jobs: make(map[string]jobs.Job), list: list, jobErr: map[string]error{}, getCalls: map[string]int{}}
	for _, j := range js {
		f.jobs[j.ID] = j
	}
	return f
}

func (f *fakeHaltedJobs) GetJob(_ context.Context, id string) (jobs.Job, error) {
	f.getCalls[id]++
	if err := f.jobErr[id]; err != nil {
		return jobs.Job{}, err
	}
	job, ok := f.jobs[id]
	if !ok {
		return jobs.Job{}, jobs.ErrJobNotFound
	}
	return job, nil
}

func (f *fakeHaltedJobs) UnsettledTasksOfHaltedJobs(context.Context) ([]jobs.Task, error) {
	return f.list, f.listErr
}

type recordedSettlement struct {
	task jobs.Task
	res  jobs.Result
}

type fakeSettlementRecorder struct{ got []recordedSettlement }

func (f *fakeSettlementRecorder) RecordHaltedSettlement(_ context.Context, task jobs.Task, res jobs.Result) error {
	f.got = append(f.got, recordedSettlement{task, res})
	return nil
}

func testHalt(resolved bool) jobs.Halt {
	return jobs.Halt{
		TaskID: "t-failed", NodeID: "node-1", Outcome: jobs.OutcomeFailure,
		Resolved: resolved, At: time.Unix(1700000000, 0).UTC(),
	}
}

// A restart resolves every unsent Task of a halted Job without sending any,
// and the Reconciler a Node then connects to has nothing of that Job to send.
func TestReconciler_SettleHaltedJobs_SendsNothingAndResolvesEveryUnsentTask(t *testing.T) {
	ctx := context.Background()
	halt := testHalt(true)
	dispatchedAt := time.Unix(1700000100, 0).UTC()
	pending := jobs.Task{ID: "t-pending", JobID: "job-h", NodeID: "node-3", State: jobs.DispatchStatePending}
	dispatched := jobs.Task{ID: "t-dispatched", JobID: "job-h", NodeID: "node-2", State: jobs.DispatchStateDispatched, DispatchedAt: dispatchedAt}
	other := jobs.Task{ID: "t-other-job-pending", JobID: "job-ok", NodeID: "node-3", State: jobs.DispatchStatePending}
	repo := newFakeTaskRepository(pending, dispatched, other)
	halted := newFakeHaltedJobs([]jobs.Task{dispatched, pending}, jobs.Job{ID: "job-h", Halt: halt})

	var mu sync.Mutex
	var sent []*relayv1.RelayMessage
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(repo, router)
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			mu.Lock()
			sent = append(sent, msg)
			mu.Unlock()
			return nil
		})
	}

	recorder := &fakeSettlementRecorder{}
	n, err := reconciler.SettleHaltedJobs(ctx, halted, recorder)
	if err != nil || n != 2 {
		t.Fatalf("SettleHaltedJobs = %d, %v; want 2, nil", n, err)
	}
	if halted.getCalls["job-h"] != 1 {
		t.Errorf("GetJob(job-h) called %d times, want once for the Job", halted.getCalls["job-h"])
	}

	gotPending, _ := repo.Get(ctx, pending.ID)
	if gotPending.State != jobs.DispatchStateResolved || gotPending.Outcome != jobs.OutcomeCancelled ||
		string(gotPending.Stderr) != halt.Reason() {
		t.Errorf("Pending task = %v/%v %q, want Resolved/cancelled with the halt's reason", gotPending.State, gotPending.Outcome, gotPending.Stderr)
	}
	gotDispatched, _ := repo.Get(ctx, dispatched.ID)
	if gotDispatched.State != jobs.DispatchStateResolved || gotDispatched.Outcome != jobs.OutcomeFailure ||
		gotDispatched.ExitCode != -1 || string(gotDispatched.Stderr) != halt.RestartReason() {
		t.Errorf("Dispatched task = %v/%v exit %d %q, want Resolved/failure, exit -1, the restart's reason",
			gotDispatched.State, gotDispatched.Outcome, gotDispatched.ExitCode, gotDispatched.Stderr)
	}
	// The audit records each outcome as stored: the never-sent sibling
	// cancelled, the maybe-sent one failure.
	if len(recorder.got) != 2 {
		t.Fatalf("recorded %d settlements, want 2", len(recorder.got))
	}
	for _, r := range recorder.got {
		want, _ := repo.Get(ctx, r.task.ID)
		if r.res.Outcome != want.Outcome || r.res.ExitCode != want.ExitCode || string(r.res.Stderr) != string(want.Stderr) {
			t.Errorf("recorded %s as %+v, stored %v/%d %q", r.task.ID, r.res, want.Outcome, want.ExitCode, want.Stderr)
		}
	}
	if untouched, _ := repo.Get(ctx, other.ID); untouched.State != jobs.DispatchStatePending {
		t.Errorf("a Task outside the list was touched: %+v", untouched)
	}

	for _, id := range []string{"node-1", "node-2", "node-3"} {
		if err := reconciler.ReconcileNode(ctx, id); err != nil {
			t.Fatalf("ReconcileNode(%s): %v", id, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 0 {
		t.Errorf("a reconcile after the sweep sent %v, want nothing", sent)
	}
}

// The halting Task is itself left Dispatched when its outcome was reported
// but never recorded. It is not re-sent either, and its record keeps the
// unrecorded-outcome lead.
func TestReconciler_SettleHaltedJobs_DoesNotResendTheHaltingTaskItself(t *testing.T) {
	ctx := context.Background()
	halt := testHalt(false)
	halt.TaskID = "t-halting"
	halting := jobs.Task{ID: "t-halting", JobID: "job-h", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	repo := newFakeTaskRepository(halting)
	halted := newFakeHaltedJobs([]jobs.Task{halting}, jobs.Job{ID: "job-h", Halt: halt})
	reconciler := NewReconciler(repo, NewRouter(nil, nil))

	if n, err := reconciler.SettleHaltedJobs(ctx, halted, nil); err != nil || n != 1 {
		t.Fatalf("SettleHaltedJobs = %d, %v; want 1, nil", n, err)
	}
	got, _ := repo.Get(ctx, halting.ID)
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeFailure {
		t.Fatalf("halting task = %v/%v, want Resolved/failure", got.State, got.Outcome)
	}
	if string(got.Stderr) != halt.RestartReason() {
		t.Errorf("halting task stderr = %q, want Halt.RestartReason", got.Stderr)
	}
	if !strings.Contains(string(got.Stderr), "no recorded result") || !strings.Contains(string(got.Stderr), "it may have run") {
		t.Errorf("halting task stderr = %q, want the unrecorded lead and the may-have-run tail", got.Stderr)
	}
}

// A Task resolved between the listing and the write is somebody else's to
// have resolved, not an error.
func TestReconciler_SettleHaltedJobs_ToleratesATaskResolvedFirst(t *testing.T) {
	ctx := context.Background()
	stale := jobs.Task{ID: "t-1", JobID: "job-h", NodeID: "node-2", State: jobs.DispatchStateDispatched}
	repo := newFakeTaskRepository(stale)
	if err := repo.Resolve(ctx, stale.ID, jobs.Result{Outcome: jobs.OutcomeSuccess}); err != nil {
		t.Fatalf("Resolve (setup): %v", err)
	}
	stalePending := jobs.Task{ID: "t-2", JobID: "job-h", NodeID: "node-3", State: jobs.DispatchStatePending}
	repo.tasks[stalePending.ID] = jobs.Task{ID: "t-2", JobID: "job-h", NodeID: "node-3", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeCancelled}
	halted := newFakeHaltedJobs([]jobs.Task{stale, stalePending}, jobs.Job{ID: "job-h", Halt: testHalt(true)})
	reconciler := NewReconciler(repo, NewRouter(nil, nil))

	n, err := reconciler.SettleHaltedJobs(ctx, halted, nil)
	if err != nil || n != 0 {
		t.Fatalf("SettleHaltedJobs = %d, %v; want 0, nil", n, err)
	}
	if got, _ := repo.Get(ctx, stale.ID); got.Outcome != jobs.OutcomeSuccess {
		t.Errorf("the real result was overwritten: %+v", got)
	}
}

// A Job that cannot be read is reported once and leaves its Tasks as they
// are; every other Job is still settled.
func TestReconciler_SettleHaltedJobs_ReportsAnUnreadableJobAndSettlesTheRest(t *testing.T) {
	ctx := context.Background()
	bad1 := jobs.Task{ID: "t-bad-1", JobID: "job-bad", NodeID: "node-1", State: jobs.DispatchStatePending}
	bad2 := jobs.Task{ID: "t-bad-2", JobID: "job-bad", NodeID: "node-2", State: jobs.DispatchStatePending}
	good := jobs.Task{ID: "t-good", JobID: "job-good", NodeID: "node-3", State: jobs.DispatchStatePending}
	repo := newFakeTaskRepository(bad1, bad2, good)
	boom := errors.New("store unavailable")
	halted := newFakeHaltedJobs([]jobs.Task{bad1, bad2, good}, jobs.Job{ID: "job-good", Halt: testHalt(true)})
	halted.jobErr["job-bad"] = boom
	reconciler := NewReconciler(repo, NewRouter(nil, nil))

	n, err := reconciler.SettleHaltedJobs(ctx, halted, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the read failure", err)
	}
	if n != 1 {
		t.Errorf("settled = %d, want 1", n)
	}
	if halted.getCalls["job-bad"] != 1 {
		t.Errorf("GetJob(job-bad) called %d times, want once", halted.getCalls["job-bad"])
	}
	if got, _ := repo.Get(ctx, good.ID); got.State != jobs.DispatchStateResolved {
		t.Errorf("the readable Job's Task = %v, want Resolved", got.State)
	}
	if got, _ := repo.Get(ctx, bad1.ID); got.State != jobs.DispatchStatePending {
		t.Errorf("the unreadable Job's Task = %v, want it untouched", got.State)
	}
}

// A Job the listing names but whose own record carries no halt is a store that
// disagrees with itself: it is reported, and its Tasks are left alone.
func TestReconciler_SettleHaltedJobs_ReportsAListedJobWithNoHalt(t *testing.T) {
	ctx := context.Background()
	task := jobs.Task{ID: "t-1", JobID: "job-odd", NodeID: "node-1", State: jobs.DispatchStatePending}
	repo := newFakeTaskRepository(task)
	halted := newFakeHaltedJobs([]jobs.Task{task}, jobs.Job{ID: "job-odd"})
	reconciler := NewReconciler(repo, NewRouter(nil, nil))

	n, err := reconciler.SettleHaltedJobs(ctx, halted, nil)
	if err == nil || !strings.Contains(err.Error(), "job-odd") || n != 0 {
		t.Errorf("SettleHaltedJobs = %d, %v; want 0 and an error naming the Job", n, err)
	}
	if got, _ := repo.Get(ctx, task.ID); got.State != jobs.DispatchStatePending {
		t.Errorf("the Task = %v, want it untouched", got.State)
	}
}

func TestReconciler_SettleHaltedJobs_ReportsAFailedListing(t *testing.T) {
	boom := errors.New("query failed")
	halted := newFakeHaltedJobs(nil)
	halted.listErr = boom
	reconciler := NewReconciler(newFakeTaskRepository(), NewRouter(nil, nil))

	n, err := reconciler.SettleHaltedJobs(context.Background(), halted, nil)
	if !errors.Is(err, boom) || n != 0 {
		t.Errorf("SettleHaltedJobs = %d, %v; want 0 and the listing error", n, err)
	}
}
