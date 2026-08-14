package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)

func approvalStore(t *testing.T) approval.Repository {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.Approvals()
}

var storeNow = time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)

func pendingRequest(id, planHash string, count int, ttl time.Duration) approval.Request {
	return approval.NewRequest(id, planHash, "acct-g", "gleipnir-prod",
		approval.PlanSummary{}, []string{"rule-a"},
		approval.Requirement{Count: count, RequesterAllowed: true, Channel: approval.ChannelOutOfBand, TTL: ttl},
		storeNow)
}

func TestApprovalRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	want := pendingRequest("req-1", "hash-a", 2, time.Hour)
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PlanHash != want.PlanHash || got.RequestedBy != want.RequestedBy || got.State != approval.StatePending {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if got.Require.Count != 2 || got.Require.Channel != approval.ChannelOutOfBand || got.Require.TTL != time.Hour {
		t.Errorf("requirement did not round-trip: %+v", got.Require)
	}
	if len(got.MatchedRules) != 1 || got.MatchedRules[0] != "rule-a" {
		t.Errorf("MatchedRules = %v, want [rule-a] — a park must keep saying why it fired", got.MatchedRules)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}

	if _, err := repo.Get(ctx, "nope"); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("Get(missing) = %v, want ErrNotFound", err)
	}
}

// TestRecordDecisionPersistsQuorumProgress walks a count:2 Request through both
// approvals and checks the state transition is durable at every step.
func TestRecordDecisionPersistsQuorumProgress(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 2, time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dec := func(id, name string, at time.Time) approval.Decision {
		return approval.Decision{AccountID: id, Account: name, Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: at}
	}

	r, err := repo.RecordDecision(ctx, "req-1", dec("acct-ana", "ana", storeNow.Add(time.Minute)), storeNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	if r.State != approval.StatePending || r.Progress() != "1 of 2" {
		t.Errorf("after 1 of 2: state=%v progress=%q", r.State, r.Progress())
	}

	// The partial state must survive a re-read, not just live in the returned value.
	reread, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(reread.Decisions) != 1 || reread.Progress() != "1 of 2" {
		t.Errorf("partial quorum did not persist: %+v", reread)
	}

	r, err = repo.RecordDecision(ctx, "req-1", dec("acct-bo", "bo", storeNow.Add(2*time.Minute)), storeNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second decision: %v", err)
	}
	if r.State != approval.StateApproved {
		t.Fatalf("after 2 of 2: state = %v, want approved", r.State)
	}
	if !r.Satisfied(storeNow.Add(3 * time.Minute)) {
		t.Error("a fully approved, unexpired Request must be satisfied")
	}
}

// TestRecordDecisionRejectsDuplicateDecider checks the guard holds through the
// store, where the UNIQUE(request_id, account_id) constraint backs it up.
func TestRecordDecisionRejectsDuplicateDecider(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 2, time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(time.Minute)}

	if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(time.Minute)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(2*time.Minute)); !errors.Is(err, approval.ErrDuplicateDecider) {
		t.Fatalf("second by the same account: err = %v, want ErrDuplicateDecider", err)
	}

	// And the rejected decision must not have been written.
	r, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(r.Decisions) != 1 {
		t.Errorf("stored %d decisions, want 1 — a rejected decision must not be persisted", len(r.Decisions))
	}
}

// TestExpirePendingRetiresOnlyLapsedRequests is the sweeper's contract.
func TestExpirePendingRetiresOnlyLapsedRequests(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	if err := repo.Create(ctx, pendingRequest("short", "hash-short", 1, time.Minute)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Create(ctx, pendingRequest("long", "hash-long", 1, 8*time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	expired, err := repo.ExpirePending(ctx, storeNow.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("ExpirePending: %v", err)
	}
	if len(expired) != 1 || expired[0].ID != "short" {
		t.Fatalf("expired = %v, want just the lapsed one", expired)
	}
	if expired[0].State != approval.StateExpired {
		t.Errorf("State = %v, want expired", expired[0].State)
	}

	// A second sweep must be a no-op — otherwise every sweep would emit a
	// duplicate audit record for the same expiry.
	again, err := repo.ExpirePending(ctx, storeNow.Add(31*time.Minute))
	if err != nil {
		t.Fatalf("second ExpirePending: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second sweep expired %d requests, want 0", len(again))
	}

	pending, err := repo.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "long" {
		t.Errorf("Pending = %v, want only the unexpired one", pending)
	}
}

// TestExpiredRequestIsNotDecidable closes the loop: once retired, a Request
// cannot be approved retroactively.
func TestExpiredRequestIsNotDecidable(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Minute)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.ExpirePending(ctx, storeNow.Add(time.Hour)); err != nil {
		t.Fatalf("ExpirePending: %v", err)
	}

	d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(2 * time.Hour)}
	if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(2*time.Hour)); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("deciding an expired Request: err = %v, want ErrNotPending", err)
	}
}

// TestByPlanHashReturnsTheMostRecent is what the dispatch path relies on to
// release an approved Plan.
func TestByPlanHashReturnsTheMostRecent(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	older := pendingRequest("older", "hash-a", 1, time.Hour)
	newer := pendingRequest("newer", "hash-a", 1, time.Hour)
	newer.CreatedAt = storeNow.Add(time.Hour)
	newer.ExpiresAt = newer.CreatedAt.Add(time.Hour)
	if err := repo.Create(ctx, older); err != nil {
		t.Fatalf("Create older: %v", err)
	}
	if err := repo.Create(ctx, newer); err != nil {
		t.Fatalf("Create newer: %v", err)
	}

	got, err := repo.ByPlanHash(ctx, "hash-a")
	if err != nil {
		t.Fatalf("ByPlanHash: %v", err)
	}
	if got.ID != "newer" {
		t.Errorf("ByPlanHash returned %q, want the most recent (%q)", got.ID, "newer")
	}

	if _, err := repo.ByPlanHash(ctx, "hash-absent"); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("ByPlanHash(absent) = %v, want ErrNotFound", err)
	}
}

// TestBindJobJoinsApprovalToExecution: audit must be able to answer "who
// approved what actually ran" without correlating by timestamp.
func TestBindJobJoinsApprovalToExecution(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.BindJob(ctx, "req-1", "job-42"); err != nil {
		t.Fatalf("BindJob: %v", err)
	}

	got, err := repo.ByJob(ctx, "job-42")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if got.ID != "req-1" {
		t.Errorf("ByJob returned %q, want req-1", got.ID)
	}
	if err := repo.BindJob(ctx, "absent", "job-42"); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("BindJob(absent) = %v, want ErrNotFound", err)
	}
}
