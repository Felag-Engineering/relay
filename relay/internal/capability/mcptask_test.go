package capability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// mcptask_test.go covers the capability layer's half of the MCP Tasks
// extension (#374): minting a handle on a park, resolving one, and the cancel
// boundary that keeps the AI's own session away from the approval object.

// memTasks is an in-memory MCPTaskStore mirroring the store's owner-scoping and
// its one-handle-per-parked-dispatch rule, so tests here exercise the same
// contract the SQLite implementation is held to.
type memTasks struct {
	mu      sync.Mutex
	byID    map[string]mcptask.Handle
	byReq   map[string]string
	creates int
}

func newMemTasks() *memTasks {
	return &memTasks{byID: map[string]mcptask.Handle{}, byReq: map[string]string{}}
}

func (m *memTasks) Create(_ context.Context, h mcptask.Handle) error {
	if err := h.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.byReq[h.ApprovalRequestID]; dup {
		return errors.New("memTasks: a handle already exists for that approval request")
	}
	m.byID[h.ID] = h
	m.byReq[h.ApprovalRequestID] = h.ID
	m.creates++
	return nil
}

func (m *memTasks) Get(_ context.Context, id, accountID string) (mcptask.Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.byID[id]
	if !ok || !h.OwnedBy(accountID) {
		return mcptask.Handle{}, mcptask.ErrNotFound
	}
	return h, nil
}

func (m *memTasks) ByApprovalRequest(_ context.Context, requestID string) (mcptask.Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byReq[requestID]
	if !ok {
		return mcptask.Handle{}, mcptask.ErrNotFound
	}
	return m.byID[id], nil
}

func (m *memTasks) BindJob(_ context.Context, id, jobID string, status mcptask.Status, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.byID[id]
	if !ok {
		return mcptask.ErrNotFound
	}
	h.JobID, h.LastStatus, h.LastUpdatedAt = jobID, status, now
	m.byID[id] = h
	return nil
}

func (m *memTasks) RecordStatus(_ context.Context, id string, status mcptask.Status, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.byID[id]
	if !ok {
		return mcptask.ErrNotFound
	}
	h.LastStatus, h.LastUpdatedAt = status, now
	m.byID[id] = h
	return nil
}

func (m *memTasks) Cancel(_ context.Context, id, accountID string, now time.Time) (mcptask.Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.byID[id]
	if !ok || !h.OwnedBy(accountID) {
		return mcptask.Handle{}, mcptask.ErrNotFound
	}
	if !h.Cancelled() {
		h.CancelledAt, h.LastStatus, h.LastUpdatedAt = now, mcptask.StatusCancelled, now
		m.byID[id] = h
	}
	return h, nil
}

// taskFixture builds a Service whose gate parks everything, with task handles
// wired, and returns it alongside the stores — including a spyJobQuery
// (#614) so a CancelTask test that reaches CancelJob for a machine Principal
// can set jobsResult to say who a Job's recorded requester is. Its zero
// value (no Jobs) makes every such cancel refuse — ErrJobNotRequestedByCaller
// — until a test opts in, which is the fail-closed default this fixture
// should have.
func taskFixture(t *testing.T) (*testSvc, *memApprovals, *memTasks, *spyDispatcher, *spyJobQuery) {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	approvals, tasks := newMemApprovals(), newMemTasks()
	disp := &spyDispatcher{jobID: "job-1"}
	jobQ := &spyJobQuery{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   gateEverything(t, 1), approvals: approvals, approvalAuthz: &spyApprovalAuthorizer{},
		mcpTasks: tasks,
		auditQ:   &spyAuditQuery{}, jobQ: jobQ,
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	return s, approvals, tasks, disp, jobQ
}

// TestParkMintsATaskHandle: a parked dispatch comes back carrying a handle, so
// a Tasks-capable client has something to poll.
func TestParkMintsATaskHandle(t *testing.T) {
	s, _, tasks, _, _ := taskFixture(t)

	parked := park(t, s, machineRequester)
	if parked.TaskID == "" {
		t.Fatal("a park with task handles wired produced no task id")
	}

	h, err := tasks.Get(context.Background(), parked.TaskID, machineRequester.AccountID)
	if err != nil {
		t.Fatalf("the minted handle is not resolvable by its own requester: %v", err)
	}
	if h.ApprovalRequestID != parked.RequestID {
		t.Errorf("handle points at request %q, want %q", h.ApprovalRequestID, parked.RequestID)
	}
}

// TestReDriveReattachesToTheSameHandle: polling by re-driving must not mint a
// second handle for one wait, or a client would believe it had two things
// outstanding.
func TestReDriveReattachesToTheSameHandle(t *testing.T) {
	s, _, tasks, _, _ := taskFixture(t)

	first := park(t, s, machineRequester)
	second := park(t, s, machineRequester)

	if first.TaskID != second.TaskID {
		t.Errorf("re-drive produced task %q, want the original %q", second.TaskID, first.TaskID)
	}
	if tasks.creates != 1 {
		t.Errorf("minted %d handles for one parked dispatch, want 1", tasks.creates)
	}
}

// TestParkStillWorksWithoutTaskHandles is ADR-0028's requirement that the
// universal path stay whole with the shim deleted: no store, no handle, and a
// park that is otherwise identical.
func TestParkStillWorksWithoutTaskHandles(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})

	parked := park(t, s, machineRequester)
	if parked.TaskID != "" {
		t.Errorf("TaskID = %q with no store wired, want empty", parked.TaskID)
	}
	if parked.RequestID == "" || parked.PlanHash == "" {
		t.Error("the park lost its decidable content when Tasks were absent")
	}
}

// TestResolveTaskFollowsTheApprovalThroughToCompletion walks the acceptance
// criterion: parked reports a non-terminal status, and after approval and
// dispatch the same handle reports completed against the Job that ran.
func TestResolveTaskFollowsTheApprovalThroughToCompletion(t *testing.T) {
	s, approvals, _, _, _ := taskFixture(t)
	ctx := context.Background()

	parked := park(t, s, machineRequester)

	view, err := s.ResolveTask(ctx, machineRequester, parked.TaskID)
	if err != nil {
		t.Fatalf("ResolveTask: %v", err)
	}
	if view.Status != mcptask.StatusWorking {
		t.Fatalf("Status = %v, want working while parked", view.Status)
	}
	if view.Status.Terminal() {
		t.Error("a parked task reported a terminal status")
	}
	if view.Summary == "" || view.PlanHash != parked.PlanHash {
		t.Errorf("view = %+v, want the Relay-authored summary and the parked plan hash", view)
	}

	approvals.approve(t, parked.RequestID, "acct-ana", "ana", apNow)
	if _, err := s.Run(ctx, machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("re-drive after approval: %v", err)
	}

	view, err = s.ResolveTask(ctx, machineRequester, parked.TaskID)
	if err != nil {
		t.Fatalf("ResolveTask after dispatch: %v", err)
	}
	if view.Status != mcptask.StatusCompleted {
		t.Fatalf("Status = %v, want completed once the Job ran", view.Status)
	}
	if view.JobID != "job-1" {
		t.Errorf("JobID = %q, want the Job the release produced", view.JobID)
	}
}

// TestResolveTaskRefusesAnotherAccount is the acceptance criterion "polling
// another Account's handle is refused" — and it must be refused
// indistinguishably from a handle that never existed.
func TestResolveTaskRefusesAnotherAccount(t *testing.T) {
	s, _, _, _, _ := taskFixture(t)
	ctx := context.Background()

	parked := park(t, s, machineRequester)
	other := Principal{AccountID: "acct-other", Account: "mallory", Role: "admin", Kind: PrincipalKindHuman}

	if _, err := s.ResolveTask(ctx, other, parked.TaskID); !errors.Is(err, mcptask.ErrNotFound) {
		t.Fatalf("ResolveTask by another account: err = %v, want ErrNotFound", err)
	}
	// The same answer an unminted id gets — a caller must not be able to
	// confirm that a guessed handle is real.
	if _, err := s.ResolveTask(ctx, other, "task-never-minted"); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("ResolveTask of an unknown id: err = %v, want ErrNotFound", err)
	}
	// Not even an admin. Resolving is not a read — [4/6] extends it to re-drive
	// the stored call under the owner's authority.
	if _, err := s.CancelTask(ctx, other, parked.TaskID); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("CancelTask by another account: err = %v, want ErrNotFound", err)
	}
}

// TestCancelParkedTaskLeavesTheApprovalPending is the security boundary of this
// issue. A cancel arrives over the AI's own session; if it could withdraw the
// pending approval, an AI-agent could yank a request back the moment it sensed a
// denial coming, erasing the evidence a human was about to rule on.
func TestCancelParkedTaskLeavesTheApprovalPending(t *testing.T) {
	s, approvals, _, disp, _ := taskFixture(t)
	ctx := context.Background()

	parked := park(t, s, machineRequester)

	view, err := s.CancelTask(ctx, machineRequester, parked.TaskID)
	if err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if view.Status != mcptask.StatusCancelled {
		t.Fatalf("Status = %v, want cancelled", view.Status)
	}

	// The approval Request is untouched: still pending, still in the queue.
	stored := approvals.byID[parked.RequestID]
	if stored.State != approval.StatePending {
		t.Fatalf("approval state = %v after a task cancel, want it still pending", stored.State)
	}
	if len(stored.Decisions) != 0 {
		t.Errorf("a task cancel recorded %d decisions; it must record none", len(stored.Decisions))
	}
	pending, err := approvals.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("approval queue has %d entries, want the request still waiting for a human", len(pending))
	}

	// And still decidable — the whole point of leaving it alone.
	approvals.approve(t, parked.RequestID, "acct-ana", "ana", apNow)
	if _, err := s.Run(ctx, machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("re-drive after approving a cancelled task's request: %v", err)
	}
	if !disp.called {
		t.Error("the approval could not release its dispatch after the handle was cancelled")
	}
}

// requesterIsSelf sets jobQ's answer to CancelJob's machine-scoping query
// (#614) so jobID's recorded requester is machineRequester's own Account —
// the one case a machine Principal's cancel is allowed.
func requesterIsSelf(jobQ *spyJobQuery, jobID string) {
	jobQ.jobsResult = JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: machineRequester.AccountID}}}
}

// TestCancelDispatchedTaskGoesThroughCancelJob: once a Job exists, cancelling
// the handle must cancel the real work through the ordinary path rather than
// through a second implementation. Uses the real machine Principal
// (machineRequester) throughout, with jobQ answering that job-1's recorded
// requester is that same Account — the case #614's scoping allows.
func TestCancelDispatchedTaskGoesThroughCancelJob(t *testing.T) {
	s, approvals, _, disp, jobQ := taskFixture(t)
	ctx := context.Background()

	parked := park(t, s, machineRequester)
	approvals.approve(t, parked.RequestID, "acct-ana", "ana", apNow)
	if _, err := s.Run(ctx, machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("re-drive: %v", err)
	}
	requesterIsSelf(jobQ, "job-1")

	if _, err := s.CancelTask(ctx, machineRequester, parked.TaskID); err != nil {
		t.Fatalf("CancelTask: %v", err)
	}
	if disp.cancelledJobID != "job-1" {
		t.Errorf("cancelled job = %q, want job-1 through the ordinary CancelJob path", disp.cancelledJobID)
	}
}

// TestCancelDoesNotMarkTheHandleWhenTheJobCancelFails: the client must learn
// its cancel did not take, rather than being told the task is cancelled while
// Tasks keep running on the fleet.
func TestCancelDoesNotMarkTheHandleWhenTheJobCancelFails(t *testing.T) {
	s, approvals, tasks, disp, jobQ := taskFixture(t)
	ctx := context.Background()

	parked := park(t, s, machineRequester)
	approvals.approve(t, parked.RequestID, "acct-ana", "ana", apNow)
	if _, err := s.Run(ctx, machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("re-drive: %v", err)
	}
	requesterIsSelf(jobQ, "job-1")

	boom := errors.New("dispatcher: cancel failed")
	disp.cancelErr = boom

	if _, err := s.CancelTask(ctx, machineRequester, parked.TaskID); !errors.Is(err, boom) {
		t.Fatalf("CancelTask: err = %v, want the dispatcher's failure", err)
	}
	h, err := tasks.Get(ctx, parked.TaskID, machineRequester.AccountID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if h.Cancelled() {
		t.Error("the handle was marked cancelled even though the Job cancel failed")
	}
}

// TestCancelDispatchedTaskRefusesMachineNotItsOwnJob: CancelTask inherits
// CancelJob's machine-Account scoping (#614) for a Job-backed cancel — a
// machine Principal whose Job has no recorded requester, or whose Job was
// requested by a different Account, is refused ErrJobNotRequestedByCaller,
// the dispatcher's cancel is never reached, and the handle is NOT marked
// cancelled — a refused cancel must not look like it took.
func TestCancelDispatchedTaskRefusesMachineNotItsOwnJob(t *testing.T) {
	cases := []struct {
		name      string
		requester string // RequesterAccountID jobQ answers with for job-1
	}{
		{"no recorded requester", ""},
		{"another Account's Job", "acct-other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, approvals, tasks, disp, jobQ := taskFixture(t)
			ctx := context.Background()

			parked := park(t, s, machineRequester)
			approvals.approve(t, parked.RequestID, "acct-ana", "ana", apNow)
			if _, err := s.Run(ctx, machineRequester, Selector{}, mutateAct()); err != nil {
				t.Fatalf("re-drive: %v", err)
			}
			jobQ.jobsResult = JobPage{Jobs: []JobSummary{{JobID: "job-1", RequesterAccountID: tc.requester}}}

			if _, err := s.CancelTask(ctx, machineRequester, parked.TaskID); !errors.Is(err, ErrJobNotRequestedByCaller) {
				t.Fatalf("CancelTask: err = %v, want ErrJobNotRequestedByCaller", err)
			}
			if disp.cancelledJobID != "" {
				t.Errorf("dispatcher cancel was reached (cancelledJobID = %q), want it never called", disp.cancelledJobID)
			}
			h, err := tasks.Get(ctx, parked.TaskID, machineRequester.AccountID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if h.Cancelled() {
				t.Error("the handle was marked cancelled even though CancelJob refused")
			}
		})
	}
}

// TestTasksUnavailableWithoutAStore: a surface asking about handles on a Relay
// that never wired them gets a legible refusal, not a nil-map panic.
func TestTasksUnavailableWithoutAStore(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})

	if _, err := s.ResolveTask(context.Background(), machineRequester, "task-1"); !errors.Is(err, ErrTasksUnavailable) {
		t.Errorf("ResolveTask: err = %v, want ErrTasksUnavailable", err)
	}
	if _, err := s.CancelTask(context.Background(), machineRequester, "task-1"); !errors.Is(err, ErrTasksUnavailable) {
		t.Errorf("CancelTask: err = %v, want ErrTasksUnavailable", err)
	}
}
