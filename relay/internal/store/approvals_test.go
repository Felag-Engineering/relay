package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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

var storeAction = jobs.Action{
	Kind:          jobs.ActionOperation,
	OperationName: "service.restart",
	OperationArgs: map[string]string{"service": "nginx"},
	RiskClass:     jobs.RiskClassMutate,
}

func pendingRequest(id, planHash string, ttl time.Duration) approval.Request {
	return approval.NewRequest(id, planHash, "acct-g", "gleipnir-prod",
		storeAction, []string{"node-a"}, []string{"rule-a"},
		approval.Requirement{TTL: ttl},
		storeNow)
}

func TestApprovalRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	want := pendingRequest("req-1", "hash-a", time.Hour)
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
	// A forgotten column in approvalSelect or a scan out of lockstep with it
	// shows up here first, because these strings sit next to each other.
	if got.RequestedByID != want.RequestedByID || got.Summary != want.Summary {
		t.Errorf("RequestedByID, Summary = %q, %q, want %q, %q", got.RequestedByID, got.Summary, want.RequestedByID, want.Summary)
	}
	if got.Require.TTL != time.Hour {
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

// TestRecordDecision_SecondDecisionIsNotPending: the first Decision ends a
// request through the store, and a second one, from any Account, is refused as
// not pending and writes nothing.
//
// Proves AP-82.
func TestRecordDecision_SecondDecisionIsNotPending(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	dec := func(id, name string, at time.Time) approval.Decision {
		return approval.Decision{AccountID: id, Account: name, Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: at}
	}

	r, err := repo.RecordDecision(ctx, "req-1", dec("acct-ana", "ana", storeNow.Add(time.Minute)), storeNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	if r.State != approval.StateApproved || !r.Satisfied(storeNow.Add(2*time.Minute)) {
		t.Fatalf("after one Decision: state = %v, want approved and satisfied", r.State)
	}

	for _, id := range []string{"acct-ana", "acct-bo"} {
		got, err := repo.RecordDecision(ctx, "req-1", dec(id, id, storeNow.Add(2*time.Minute)), storeNow.Add(2*time.Minute))
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("second Decision by %s: err = %v, want ErrNotPending", id, err)
		}
		if len(got.Decisions) != 1 {
			t.Errorf("refusal returned %d decisions, want the one recorded", len(got.Decisions))
		}
	}
	reread, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(reread.Decisions) != 1 {
		t.Errorf("stored %d decisions, want 1: a refused decision must not be persisted", len(reread.Decisions))
	}
}

// TestRecordDecisionReturnsTheCurrentRequestOnRefusal (#724) proves the
// in-transaction read carries job_id and decisions for real, where the
// capability layer's fake only mirrors it (capability.memApprovals).
func TestRecordDecisionReturnsTheCurrentRequestOnRefusal(t *testing.T) {
	ctx := context.Background()

	t.Run("already approved with a bound Job", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(time.Minute)}
		if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(time.Minute)); err != nil {
			t.Fatalf("first decision: %v", err)
		}
		if _, err := repo.BindJob(ctx, "req-1", "job-7", storeNow.Add(time.Minute)); err != nil {
			t.Fatalf("BindJob: %v", err)
		}

		bo := approval.Decision{AccountID: "acct-bo", Account: "bo", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(2 * time.Minute)}
		got, err := repo.RecordDecision(ctx, "req-1", bo, storeNow.Add(2*time.Minute))
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if got.State != approval.StateApproved {
			t.Errorf("State = %v, want approved", got.State)
		}
		if got.JobID != "job-7" {
			t.Errorf("JobID = %q, want job-7", got.JobID)
		}
		if len(got.Decisions) != 1 {
			t.Errorf("Decisions = %d, want 1", len(got.Decisions))
		}

		reread, err := repo.Get(ctx, "req-1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(reread.Decisions) != 1 {
			t.Errorf("a refused decision must not have persisted anything new: %+v", reread)
		}
	})

	t.Run("lapsed but not swept", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-3", "hash-c", time.Minute)); err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-c", At: storeNow.Add(time.Hour)}
		got, err := repo.RecordDecision(ctx, "req-3", d, storeNow.Add(time.Hour))
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if got.State != approval.StatePending {
			t.Errorf("State = %v, want StatePending — no sweeper has run", got.State)
		}
		if len(got.Decisions) != 0 {
			t.Errorf("Decisions = %d, want 0", len(got.Decisions))
		}

		reread, err := repo.Get(ctx, "req-3")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(reread.Decisions) != 0 {
			t.Errorf("a refused decision must not have persisted anything new: %+v", reread)
		}
	})
}

// TestExpirePendingRetiresOnlyLapsedRequests is the sweeper's contract.
func TestExpirePendingRetiresOnlyLapsedRequests(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	if err := repo.Create(ctx, pendingRequest("short", "hash-short", time.Minute)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Create(ctx, pendingRequest("long", "hash-long", 8*time.Hour)); err != nil {
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

func TestApprovals_CountWaitingCountsOnlyAnswerablePending(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	now := storeNow.Add(30 * time.Minute)

	count := func(at time.Time) int {
		t.Helper()
		n, err := repo.CountWaiting(ctx, at)
		if err != nil {
			t.Fatalf("CountWaiting: %v", err)
		}
		return n
	}
	if n := count(now); n != 0 {
		t.Fatalf("empty store: CountWaiting = %d, want 0", n)
	}

	for _, r := range []approval.Request{
		pendingRequest("future", "hash-future", 8*time.Hour),
		pendingRequest("lapsed", "hash-lapsed", time.Minute),
		pendingRequest("approved", "hash-approved", 8*time.Hour),
		pendingRequest("denied", "hash-denied", 8*time.Hour),
		pendingRequest("expired", "hash-expired", time.Minute),
	} {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("Create %s: %v", r.ID, err)
		}
	}
	approveRequest(t, repo, "approved", "hash-approved", storeNow.Add(time.Minute))
	deny := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: false, Reason: "no", Channel: approval.ChannelOutOfBand, PlanHash: "hash-denied", At: storeNow.Add(time.Minute)}
	if _, err := repo.RecordDecision(ctx, "denied", deny, deny.At); err != nil {
		t.Fatalf("deny: %v", err)
	}
	// "lapsed" and "expired" are both pending and past their deadline at now;
	// neither is answerable, whether or not the sweeper has retired it yet.
	if n := count(now); n != 1 {
		t.Errorf("CountWaiting before the sweep = %d, want 1 (only the unexpired pending Request)", n)
	}
	if _, err := repo.ExpirePending(ctx, now); err != nil {
		t.Fatalf("ExpirePending: %v", err)
	}
	if n := count(now); n != 1 {
		t.Errorf("CountWaiting after the sweep = %d, want 1", n)
	}

	// A Request is waiting only while now is strictly before its deadline, as
	// PastDeadline has it.
	if n := count(storeNow.Add(8 * time.Hour)); n != 0 {
		t.Errorf("CountWaiting at the deadline = %d, want 0", n)
	}
}

// TestExpiredRequestIsNotDecidable closes the loop: once retired, a Request
// cannot be approved retroactively.
func TestExpiredRequestIsNotDecidable(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Minute)); err != nil {
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

	older := pendingRequest("older", "hash-a", time.Hour)
	newer := pendingRequest("newer", "hash-a", time.Hour)
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
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// BindJob is the release claim (AP-77): it only binds a Satisfied
	// Request, so this must be approved before binding.
	d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(time.Minute)}
	if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(time.Minute)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := repo.BindJob(ctx, "req-1", "job-42", storeNow.Add(2*time.Minute)); err != nil {
		t.Fatalf("BindJob: %v", err)
	}

	got, err := repo.ByJob(ctx, "job-42")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if got.ID != "req-1" {
		t.Errorf("ByJob returned %q, want req-1", got.ID)
	}
	if _, err := repo.BindJob(ctx, "absent", "job-42", storeNow.Add(2*time.Minute)); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("BindJob(absent) = %v, want ErrNotFound", err)
	}
}

// approveRequest drives id to StateApproved via one out-of-band decision,
// mirroring memApprovals.approve for the tests in this file that need a
// Satisfied Request before they can exercise BindJob's release claim.
func approveRequest(t *testing.T, repo approval.Repository, id, planHash string, at time.Time) {
	t.Helper()
	d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: planHash, At: at}
	if _, err := repo.RecordDecision(context.Background(), id, d, at); err != nil {
		t.Fatalf("approve %s: %v", id, err)
	}
}

// TestBindJob_BindsOnceAndReportsTheBoundJob is AP-77's core store contract:
// the second BindJob on an already-released Request never overwrites the
// first, and reports the Job the caller must re-attach to.
func TestBindJob_BindsOnceAndReportsTheBoundJob(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	approveRequest(t, repo, "req-1", "hash-a", storeNow.Add(time.Minute))

	first, err := repo.BindJob(ctx, "req-1", "job-1", storeNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("first BindJob: %v", err)
	}
	if first.JobID != "job-1" {
		t.Errorf("first BindJob JobID = %q, want job-1", first.JobID)
	}

	second, err := repo.BindJob(ctx, "req-1", "job-2", storeNow.Add(3*time.Minute))
	if !errors.Is(err, approval.ErrAlreadyReleased) {
		t.Fatalf("second BindJob err = %v, want ErrAlreadyReleased", err)
	}
	if second.JobID != "job-1" {
		t.Errorf("second BindJob returned JobID = %q, want the winner's job-1 — the caller must learn who won", second.JobID)
	}

	got, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.JobID != "job-1" {
		t.Errorf("stored JobID = %q, want job-1 — the overwrite must be impossible", got.JobID)
	}
	byJob, err := repo.ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob(job-1): %v", err)
	}
	if byJob.ID != "req-1" {
		t.Errorf("ByJob(job-1) = %q, want req-1", byJob.ID)
	}
	if _, err := repo.ByJob(ctx, "job-2"); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("ByJob(job-2) = %v, want ErrNotFound — job-2 was never actually bound", err)
	}
}

// TestBindJob_RefusesAnUnreleasableRequest covers every Request state
// BindJob must refuse to claim: pending, past its deadline, and denied. An
// absent Request ID is ErrNotFound, not ErrNotReleasable — that is a
// different failure a caller must be able to tell apart.
func TestBindJob_RefusesAnUnreleasableRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("pending", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := repo.BindJob(ctx, "req-1", "job-1", storeNow); !errors.Is(err, approval.ErrNotReleasable) {
			t.Errorf("err = %v, want ErrNotReleasable", err)
		}
		if got, err := repo.Get(ctx, "req-1"); err != nil || got.JobID != "" {
			t.Errorf("Get = %+v, %v — nothing must be bound", got, err)
		}
	})

	t.Run("past its deadline", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Minute)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		approveRequest(t, repo, "req-1", "hash-a", storeNow.Add(30*time.Second))
		if _, err := repo.BindJob(ctx, "req-1", "job-1", storeNow.Add(time.Hour)); !errors.Is(err, approval.ErrNotReleasable) {
			t.Errorf("err = %v, want ErrNotReleasable", err)
		}
	})

	t.Run("denied", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: false, Channel: approval.ChannelOutOfBand, PlanHash: "hash-a", At: storeNow.Add(time.Minute)}
		if _, err := repo.RecordDecision(ctx, "req-1", d, storeNow.Add(time.Minute)); err != nil {
			t.Fatalf("deny: %v", err)
		}
		if _, err := repo.BindJob(ctx, "req-1", "job-1", storeNow.Add(2*time.Minute)); !errors.Is(err, approval.ErrNotReleasable) {
			t.Errorf("err = %v, want ErrNotReleasable", err)
		}
	})

	t.Run("absent", func(t *testing.T) {
		repo := approvalStore(t)
		if _, err := repo.BindJob(ctx, "absent", "job-1", storeNow); !errors.Is(err, approval.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

// TestBindJob_ConcurrentClaimsExactlyOneWins is AP-77's concurrency proof at
// the store layer (#713 plan review S3/Codex HIGH): of many goroutines racing
// to claim the same Satisfied Request's release, exactly one must win, and
// every loser must learn the winner's Job ID rather than silently losing its
// own claim or corrupting the stored row. store.Open's SetMaxOpenConns(1)
// plus BindJob's transaction is the whole safety argument here — this test
// is what falsifies it if either ever regresses.
func TestBindJob_ConcurrentClaimsExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	approveRequest(t, repo, "req-1", "hash-a", storeNow.Add(time.Minute))

	const n = 32
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		winJobID string
		losers   []string
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			jobID := fmt.Sprintf("job-%02d", i)
			r, err := repo.BindJob(ctx, "req-1", jobID, storeNow.Add(2*time.Minute))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
				winJobID = jobID
				return
			}
			if !errors.Is(err, approval.ErrAlreadyReleased) {
				t.Errorf("goroutine %d: err = %v, want nil or ErrAlreadyReleased", i, err)
				return
			}
			losers = append(losers, r.JobID)
		}(i)
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1", wins)
	}
	if len(losers) != n-1 {
		t.Fatalf("losers = %d, want %d", len(losers), n-1)
	}
	for _, got := range losers {
		if got != winJobID {
			t.Errorf("a loser saw JobID %q, want the winner's %q", got, winJobID)
		}
	}

	stored, err := repo.Get(ctx, "req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.JobID != winJobID {
		t.Errorf("stored JobID = %q, want the winner's %q", stored.JobID, winJobID)
	}
}

// TestApprovalRoundTripPreservesTheDecisionFacts is #270's schema half
// (migration 0013).
//
// The three columns it adds are not decoration: action_kind is what the
// decision's role floor is computed from, and decider_human is the verified
// fact behind ADR-0027's human-only self-confirmation rung. A round trip that
// dropped either would move a security decision onto whatever the zero value
// happened to be.
func TestApprovalRoundTripPreservesTheDecisionFacts(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	rawExec := jobs.Action{
		Kind:        jobs.ActionRawExec,
		RawExecArgv: []string{"/usr/bin/systemctl", "restart", "nginx"},
		RiskClass:   jobs.RiskClassMutate,
	}
	want := approval.NewRequest("req-raw", "hash-raw", "acct-g", "gleipnir-prod",
		rawExec, []string{"node-a"}, []string{"raw-exec-always-asks"},
		approval.Requirement{TTL: time.Hour},
		storeNow)
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, "req-raw")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActionKind != jobs.ActionRawExec {
		t.Errorf("ActionKind = %v, want raw exec — the decision's role floor is computed from it", got.ActionKind)
	}
	if got.RiskClass != jobs.RiskClassMutate {
		t.Errorf("RiskClass = %v, want mutate", got.RiskClass)
	}

	updated, err := repo.RecordDecision(ctx, "req-raw", approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-raw",
		DeciderHuman: true, At: storeNow.Add(time.Minute),
	}, storeNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if updated.State != approval.StateApproved {
		t.Fatalf("State = %v, want approved", updated.State)
	}

	reread, err := repo.Get(ctx, "req-raw")
	if err != nil {
		t.Fatalf("Get after decision: %v", err)
	}
	if len(reread.Decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(reread.Decisions))
	}
	if !reread.Decisions[0].DeciderHuman {
		t.Error("DeciderHuman was lost in the round trip; it is the verified fact behind the human-only ladder rung")
	}
	if reread.Decisions[0].Channel != approval.ChannelOutOfBand {
		t.Errorf("Channel = %v, want out-of-band preserved", reread.Decisions[0].Channel)
	}
}

// openStore opens a store and hands back the raw handle too, so a test can
// read or corrupt a column the write path never writes.
func openStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, st.db
}

// TestApprovals_RequireColumnsWrittenAsConstants: the historical require_*
// columns are written as constants and never from the Request (ADR-0047).
func TestApprovals_RequireColumnsWrittenAsConstants(t *testing.T) {
	ctx := context.Background()
	st, db := openStore(t)

	if err := st.Approvals().Create(ctx, pendingRequest("req-new", "hash-new", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var (
		count, allowed, channel int
		audience                string
	)
	if err := db.QueryRow(`SELECT require_count, require_audience, requester_allowed, require_channel
		FROM approval_requests WHERE request_id = ?`, "req-new").Scan(&count, &audience, &allowed, &channel); err != nil {
		t.Fatalf("read columns: %v", err)
	}
	if count != 1 || audience != "" || allowed != 1 || channel != 0 {
		t.Errorf("columns = %d, %q, %d, %d, want 1, \"\", 1, 0", count, audience, allowed, channel)
	}
}

// TestApprovals_HistoricalQuorumAndAudienceRowsReadBack: a row written under
// the old rules, with a quorum, an audience and a channel requirement, reads
// back without error, and the next accepted Decision ends it.
//
// Proves AP-82.
func TestApprovals_HistoricalQuorumAndAudienceRowsReadBack(t *testing.T) {
	ctx := context.Background()
	st, db := openStore(t)
	repo := st.Approvals()

	if err := repo.Create(ctx, pendingRequest("req-old", "hash-old", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := db.Exec(`UPDATE approval_requests
		SET require_count = 2, require_audience = 'ana,bo', requester_allowed = 0, require_channel = 2
		WHERE request_id = ?`, "req-old"); err != nil {
		t.Fatalf("seed historical columns: %v", err)
	}
	// One prior approve: a legacy partial quorum.
	if _, err := db.Exec(`INSERT INTO approval_decisions
		(request_id, account_id, account, approve, reason, channel, plan_hash, decider_human, decided_at)
		VALUES (?, 'acct-ana', 'ana', 1, '', 2, 'hash-old', 1, ?)`,
		"req-old", formatTime(roundTripTime(storeNow.Add(time.Minute)))); err != nil {
		t.Fatalf("seed prior decision: %v", err)
	}

	got, err := repo.Get(ctx, "req-old")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != approval.StatePending || len(got.Decisions) != 1 || got.Require.TTL != time.Hour {
		t.Fatalf("historical row read back as %+v", got)
	}
	pending, err := repo.Pending(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("Pending = %v, %v, want the historical row", pending, err)
	}

	bo := approval.Decision{AccountID: "acct-bo", Account: "bo", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-old", At: storeNow.Add(2 * time.Minute)}
	ended, err := repo.RecordDecision(ctx, "req-old", bo, storeNow.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if ended.State != approval.StateApproved || len(ended.Decisions) != 2 {
		t.Fatalf("after the next Decision: state = %v, decisions = %d, want approved with 2", ended.State, len(ended.Decisions))
	}
	if _, err := repo.RecordDecision(ctx, "req-old", bo, storeNow.Add(3*time.Minute)); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("a further Decision: err = %v, want ErrNotPending", err)
	}
}

// TestApprovals_CreateWritesNoShapeKey (AP-92): a new approval request records
// no shape key; the stored column keeps its default, so a request is addressed
// only by its ID and its plan hash.
func TestApprovals_CreateWritesNoShapeKey(t *testing.T) {
	ctx := context.Background()
	st, db := openStore(t)

	if err := st.Approvals().Create(ctx, pendingRequest("req-new", "hash-new", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var key string
	if err := db.QueryRow(`SELECT shape_key FROM approval_requests WHERE request_id = ?`, "req-new").Scan(&key); err != nil {
		t.Fatalf("read shape_key: %v", err)
	}
	if key != "" {
		t.Errorf("shape_key = %q, want the column default (empty)", key)
	}
}

// TestOpen_LeavesStoredShapeKeysAlone (AP-92): existing data stays. A reopen
// does not rewrite the shape_key column of any row, an empty one included, and
// the retired task-handle table is kept.
func TestOpen_LeavesStoredShapeKeysAlone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	stored := map[string]string{
		"req-hex":    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"req-legacy": "legacy:req-old",
		"req-blank":  "",
	}
	for id, key := range stored {
		if err := st.Approvals().Create(ctx, pendingRequest(id, "hash-"+id, time.Hour)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		if _, err := st.db.Exec(`UPDATE approval_requests SET shape_key = ? WHERE request_id = ?`, key, id); err != nil {
			t.Fatalf("set shape_key for %s: %v", id, err)
		}
	}

	re := reopenStore(t, st, path)
	for id, want := range stored {
		var got string
		if err := re.db.QueryRow(`SELECT shape_key FROM approval_requests WHERE request_id = ?`, id).Scan(&got); err != nil {
			t.Fatalf("read shape_key for %s: %v", id, err)
		}
		if got != want {
			t.Errorf("shape_key for %s = %q after reopen, want %q", id, got, want)
		}
	}
	var n int
	if err := re.db.QueryRow(`SELECT count(*) FROM mcp_task_handles`).Scan(&n); err != nil {
		t.Errorf("mcp_task_handles table is gone: %v", err)
	}
}
