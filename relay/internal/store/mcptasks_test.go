package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
)

var handleNow = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

func handleRequest() approval.Request {
	return approval.NewRequest("req-1", "hash-1", "acct-g", "gleipnir-prod",
		jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate},
		[]string{"node-a"}, approval.SelectorShape{}, []string{"prod-mutates"},
		approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		handleNow)
}

func handleRepo(t *testing.T) (mcptask.Repository, mcptask.Handle) {
	t.Helper()
	st, _ := openTestStore(t)
	repo := st.MCPTasks()
	h := mcptask.NewHandle("task-1", handleRequest(), "acct-g", "gleipnir-prod", handleNow)
	if err := repo.Create(context.Background(), h); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return repo, h
}

// TestMCPTask_RoundTrips: every field survives a write and a read. A handle
// that lost its owner or its deadline in the store would be one no check could
// fail and no sweeper could retire.
func TestMCPTask_RoundTrips(t *testing.T) {
	repo, want := handleRepo(t)

	got, err := repo.Get(context.Background(), want.ID, want.AccountID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.ApprovalRequestID != want.ApprovalRequestID {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
	if got.AccountID != want.AccountID || got.Account != want.Account {
		t.Errorf("owner = %q/%q, want %q/%q", got.AccountID, got.Account, want.AccountID, want.Account)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("times = %v/%v, want %v/%v", got.CreatedAt, got.ExpiresAt, want.CreatedAt, want.ExpiresAt)
	}
	if got.LastStatus != mcptask.StatusWorking {
		t.Errorf("last_status = %v, want working", got.LastStatus)
	}
	if got.JobID != "" || got.Cancelled() {
		t.Errorf("a freshly minted handle has job %q / cancelled %v, want neither", got.JobID, got.Cancelled())
	}
}

// TestMCPTask_AnotherAccountCannotResolveIt is the acceptance criterion "an
// Account cannot resolve a handle it does not own", and the answer is
// deliberately indistinguishable from a handle that never existed — a distinct
// "not yours" would confirm that a guessed ID is real, which alone leaks that
// some Account has a fleet action waiting on a human.
func TestMCPTask_AnotherAccountCannotResolveIt(t *testing.T) {
	repo, h := handleRepo(t)
	ctx := context.Background()

	_, err := repo.Get(ctx, h.ID, "acct-someone-else")
	if !errors.Is(err, mcptask.ErrNotFound) {
		t.Fatalf("Get by a non-owner: err = %v, want ErrNotFound", err)
	}

	_, missing := repo.Get(ctx, "task-never-minted", "acct-someone-else")
	if !errors.Is(missing, mcptask.ErrNotFound) {
		t.Fatalf("Get of an unknown handle: err = %v, want ErrNotFound", missing)
	}

	// An empty account resolves nothing. Without this, a caller that forgot to
	// populate the principal would read every handle in the table.
	if _, err := repo.Get(ctx, h.ID, ""); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("Get with no account: err = %v, want ErrNotFound", err)
	}
}

// TestMCPTask_CancelDoesNotTouchTheApprovalRequest is ADR-0028's security
// boundary: a cancel arrives over the AI's own session, so it may end the
// client's polling contract and nothing more. An agent must not be able to yank
// a request back the moment it senses a denial coming.
func TestMCPTask_CancelDoesNotTouchTheApprovalRequest(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	approvals, handles := st.Approvals(), st.MCPTasks()

	req := handleRequest()
	if err := approvals.Create(ctx, req); err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	h := mcptask.NewHandle("task-1", req, "acct-g", "gleipnir-prod", handleNow)
	if err := handles.Create(ctx, h); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cancelled, err := handles.Cancel(ctx, h.ID, h.AccountID, handleNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if !cancelled.Cancelled() || cancelled.LastStatus != mcptask.StatusCancelled {
		t.Errorf("cancelled handle = %+v, want it marked cancelled", cancelled)
	}

	// The approval Request is untouched: still pending, still decidable, still
	// in the queue for a human.
	after, err := approvals.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("re-read approval request: %v", err)
	}
	if after.State != approval.StatePending {
		t.Fatalf("approval state = %v after a task cancel, want it still pending — "+
			"cancelling a handle must never decide, withdraw, or expire the request", after.State)
	}
	pending, err := approvals.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("approval queue has %d entries after a task cancel, want the request still waiting", len(pending))
	}
}

// TestMCPTask_CancelTwiceIsNotAnError: a client retrying a cancel it already
// sent is not making a mistake worth an error.
func TestMCPTask_CancelTwiceIsNotAnError(t *testing.T) {
	repo, h := handleRepo(t)
	ctx := context.Background()

	first, err := repo.Cancel(ctx, h.ID, h.AccountID, handleNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("first Cancel: %v", err)
	}
	second, err := repo.Cancel(ctx, h.ID, h.AccountID, handleNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Cancel: %v", err)
	}
	if !second.CancelledAt.Equal(first.CancelledAt) {
		t.Errorf("second cancel moved the timestamp to %v, want the original %v — "+
			"when a client withdrew is a fact about the past", second.CancelledAt, first.CancelledAt)
	}

	// And a non-owner still cannot cancel.
	if _, err := repo.Cancel(ctx, h.ID, "acct-other", handleNow); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("Cancel by a non-owner: err = %v, want ErrNotFound", err)
	}
}

// TestMCPTask_OneHandlePerParkedDispatch: a re-drive must re-attach to the
// existing handle rather than mint a second one for the same wait, and the
// schema enforces it rather than trusting callers to check first.
func TestMCPTask_OneHandlePerParkedDispatch(t *testing.T) {
	repo, h := handleRepo(t)
	ctx := context.Background()

	found, err := repo.ByApprovalRequest(ctx, h.ApprovalRequestID)
	if err != nil {
		t.Fatalf("ByApprovalRequest: %v", err)
	}
	if found.ID != h.ID {
		t.Errorf("ByApprovalRequest = %q, want %q", found.ID, h.ID)
	}

	second := mcptask.NewHandle("task-2", handleRequest(), "acct-g", "gleipnir-prod", handleNow)
	if err := repo.Create(ctx, second); err == nil {
		t.Fatal("a second handle for the same parked dispatch was accepted; the mapping is one-to-one")
	}

	if _, err := repo.ByApprovalRequest(ctx, "req-never-parked"); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("ByApprovalRequest(unknown): err = %v, want ErrNotFound", err)
	}
}

// TestMCPTask_BindJobAndRecordStatus: the bookkeeping writes land, and a write
// against a handle that has been swept is reported rather than passing quietly.
func TestMCPTask_BindJobAndRecordStatus(t *testing.T) {
	repo, h := handleRepo(t)
	ctx := context.Background()
	later := handleNow.Add(5 * time.Minute)

	if err := repo.BindJob(ctx, h.ID, "job-1", mcptask.StatusCompleted, later); err != nil {
		t.Fatalf("BindJob: %v", err)
	}
	got, err := repo.Get(ctx, h.ID, h.AccountID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.JobID != "job-1" || got.LastStatus != mcptask.StatusCompleted {
		t.Errorf("handle = %+v, want it bound to job-1 and recorded completed", got)
	}
	if !got.LastUpdatedAt.Equal(later) {
		t.Errorf("last_updated_at = %v, want %v", got.LastUpdatedAt, later)
	}

	if err := repo.RecordStatus(ctx, h.ID, mcptask.StatusFailed, later); err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}

	if err := repo.BindJob(ctx, "task-gone", "job-2", mcptask.StatusCompleted, later); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("BindJob on an unknown handle: err = %v, want ErrNotFound", err)
	}
	if err := repo.RecordStatus(ctx, "task-gone", mcptask.StatusFailed, later); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("RecordStatus on an unknown handle: err = %v, want ErrNotFound", err)
	}
}

// TestMCPTask_StoredStatusIsNeverTheAnswer is the design rule made explicit: a
// handle whose recorded status has gone stale still reports the truth, because
// the truth is recomputed from the approval Request and not read from the row.
func TestMCPTask_StoredStatusIsNeverTheAnswer(t *testing.T) {
	repo, h := handleRepo(t)
	ctx := context.Background()

	// Deliberately record a lie — the state a naive implementation would then
	// keep serving.
	if err := repo.RecordStatus(ctx, h.ID, mcptask.StatusWorking, handleNow); err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}
	stored, err := repo.Get(ctx, h.ID, h.AccountID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.LastStatus != mcptask.StatusWorking {
		t.Fatalf("setup: last_status = %v, want working", stored.LastStatus)
	}

	denied := handleRequest()
	denied.State = approval.StateDenied
	if got := stored.Status(denied, handleNow); got != mcptask.StatusFailed {
		t.Errorf("Status = %v, want failed — the stored column must never be the answer", got)
	}
}

// TestMCPTask_DeleteExpiredSweepsOnlyLapsedHandles.
func TestMCPTask_DeleteExpiredSweeps(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.MCPTasks()

	short := handleRequest()
	short.ID, short.ExpiresAt = "req-short", handleNow.Add(time.Minute)
	long := handleRequest()
	long.ID, long.ExpiresAt = "req-long", handleNow.Add(8*time.Hour)

	for id, req := range map[string]approval.Request{"task-short": short, "task-long": long} {
		if err := repo.Create(ctx, mcptask.NewHandle(id, req, "acct-g", "gleipnir-prod", handleNow)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}

	n, err := repo.DeleteExpired(ctx, handleNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept %d handles, want 1", n)
	}
	if _, err := repo.Get(ctx, "task-short", "acct-g"); !errors.Is(err, mcptask.ErrNotFound) {
		t.Errorf("the lapsed handle survived the sweep: %v", err)
	}
	if _, err := repo.Get(ctx, "task-long", "acct-g"); err != nil {
		t.Errorf("the live handle was swept: %v", err)
	}
}

// TestMCPTask_StoreRefusesAnInvalidHandle: an unowned handle must be impossible
// to STORE, not merely impossible to mint through today's code path.
func TestMCPTask_StoreRefusesAnInvalidHandle(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.MCPTasks()

	h := mcptask.NewHandle("task-1", handleRequest(), "", "", handleNow)
	if err := repo.Create(context.Background(), h); !errors.Is(err, mcptask.ErrInvalid) {
		t.Fatalf("Create of an unowned handle: err = %v, want ErrInvalid", err)
	}
}
