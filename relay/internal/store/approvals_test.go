package store

import (
	"context"
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

// storeSelector is the normalised Selector these fixtures park against, so the
// stored shape key is a real computed one rather than the "no Selector known"
// key the zero SelectorShape produces.
var storeSelector = approval.SelectorShape{
	Known: true,
	Terms: []approval.SelectorTerm{{Namespace: "node", Key: "role", Value: "web"}},
}

func pendingRequest(id, planHash string, count int, ttl time.Duration) approval.Request {
	return approval.NewRequest(id, planHash, "acct-g", "gleipnir-prod",
		storeAction, []string{"node-a"}, storeSelector, []string{"rule-a"},
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
	// A forgotten column in approvalSelect or a scan out of lockstep with it
	// shows up here first, because shape_key sits between two other strings.
	if got.ShapeKey != want.ShapeKey || got.ShapeKey == "" {
		t.Errorf("ShapeKey = %q, want %q", got.ShapeKey, want.ShapeKey)
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

// TestRecordDecisionReturnsTheCurrentRequestOnRefusal (#724) proves the
// in-transaction read carries job_id and decisions for real, where the
// capability layer's fake only mirrors it (capability.memApprovals).
func TestRecordDecisionReturnsTheCurrentRequestOnRefusal(t *testing.T) {
	ctx := context.Background()

	t.Run("already approved with a bound Job", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
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

	t.Run("duplicate decider", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-2", "hash-b", 2, time.Hour)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		d := approval.Decision{AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand, PlanHash: "hash-b", At: storeNow.Add(time.Minute)}
		if _, err := repo.RecordDecision(ctx, "req-2", d, storeNow.Add(time.Minute)); err != nil {
			t.Fatalf("first decision: %v", err)
		}

		got, err := repo.RecordDecision(ctx, "req-2", d, storeNow.Add(2*time.Minute))
		if !errors.Is(err, approval.ErrDuplicateDecider) {
			t.Fatalf("err = %v, want ErrDuplicateDecider", err)
		}
		if got.State != approval.StatePending {
			t.Errorf("State = %v, want it still pending (1 of 2)", got.State)
		}
		if len(got.Decisions) != 1 {
			t.Errorf("Decisions = %d, want 1", len(got.Decisions))
		}

		reread, err := repo.Get(ctx, "req-2")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(reread.Decisions) != 1 {
			t.Errorf("a rejected duplicate must not have persisted anything new: %+v", reread)
		}
	})

	t.Run("lapsed but not swept", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-3", "hash-c", 1, time.Minute)); err != nil {
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

// --- #608: a blank audience entry must never be storable, and a stored row
// that somehow carries one must fail closed rather than read back
// unrestricted ---

// TestCreateRefusesBlankAudienceEntry: the comma-joined require_audience
// column cannot represent a lone blank entry, so Create must refuse rather
// than write a row that would read back unrestricted.
func TestCreateRefusesBlankAudienceEntry(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	for _, tc := range []struct {
		name     string
		audience []string
	}{
		{name: "lone blank", audience: []string{""}},
		{name: "named account plus blank", audience: []string{"ana", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pendingRequest("req-blank", "hash-blank", 1, time.Hour)
			r.Require.Audience = tc.audience

			if err := repo.Create(ctx, r); !errors.Is(err, approval.ErrAudienceBlankEntry) {
				t.Fatalf("Create: err = %v, want errors.Is(err, ErrAudienceBlankEntry)", err)
			}
			if _, err := repo.Get(ctx, "req-blank"); !errors.Is(err, approval.ErrNotFound) {
				t.Fatalf("Get after a refused Create: err = %v, want ErrNotFound — nothing must have been written", err)
			}
		})
	}
}

// TestStoredAudienceWithBlankEntryFailsClosed simulates a row Create can no
// longer produce (a prior build, or an ApprovalGate implementation other than
// *approval.Gate): the require_audience column corrupted directly via SQL.
// The read must PRESERVE the blank entry rather than filter it, and every
// decision path must fail closed on it.
func TestStoredAudienceWithBlankEntryFailsClosed(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		column string
	}{
		// "ana," and "ana, ,bo" are the sharpest proofs that a malformed
		// stored audience admits NO decider: both scan to an audience
		// containing a previously-named account plus a blank, and pre-fix a
		// decision by that named account would have gone through unrefused.
		// They do not reproduce this issue's own worked example, though: a
		// column of exactly "" (from a stored Audience of [""]) scans back
		// byte-identical to a genuinely unrestricted audience, so that legacy
		// row can never be distinguished from an intentionally unrestricted
		// one by any read, so it is not — and cannot be — exercised here;
		// operators who had such a rule should revoke any outstanding
		// Approval grants approved under it (#608). "," and " " also fail
		// closed, but their stored column scans to an audience with no
		// named account at all either way.
		{name: "trailing comma", column: "ana,"},
		{name: "lone comma", column: ","},
		{name: "lone space", column: " "},
		{name: "named plus two blanks", column: "ana, ,bo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, db := openStore(t)
			repo := st.Approvals()

			r := pendingRequest("req-corrupt", "hash-corrupt", 1, time.Hour)
			r.Require.Audience = []string{"ana"}
			if err := repo.Create(ctx, r); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := db.ExecContext(ctx,
				`UPDATE approval_requests SET require_audience = ? WHERE request_id = ?`,
				tc.column, "req-corrupt"); err != nil {
				t.Fatalf("corrupt require_audience: %v", err)
			}

			got, err := repo.Get(ctx, "req-corrupt")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !got.Require.AudienceMalformed() {
				t.Fatalf("AudienceMalformed() = false for stored column %q, want true (audience preserved as %v)",
					tc.column, got.Require.Audience)
			}

			d := approval.Decision{
				AccountID: "acct-ana", Account: "ana", Approve: true,
				Channel: approval.ChannelOutOfBand, PlanHash: "hash-corrupt", At: storeNow.Add(time.Minute),
			}
			if _, err := repo.RecordDecision(ctx, "req-corrupt", d, storeNow.Add(time.Minute)); !errors.Is(err, approval.ErrNotInAudience) {
				t.Fatalf("RecordDecision by a previously-named account: err = %v, want ErrNotInAudience", err)
			}

			reread, err := repo.Get(ctx, "req-corrupt")
			if err != nil {
				t.Fatalf("Get after refused decision: %v", err)
			}
			if len(reread.Decisions) != 0 || reread.State != approval.StatePending {
				t.Fatalf("a refused decision must not be recorded: decisions=%d state=%v", len(reread.Decisions), reread.State)
			}

			// A malformed pending Request must still be able to expire — the
			// read never errors on it, and the sweeper must not be able to
			// get stuck on a row it cannot parse.
			expired, err := repo.ExpirePending(ctx, storeNow.Add(2*time.Hour))
			if err != nil {
				t.Fatalf("ExpirePending: %v", err)
			}
			if len(expired) != 1 || expired[0].ID != "req-corrupt" || expired[0].State != approval.StateExpired {
				t.Fatalf("ExpirePending = %v, want the corrupted row to expire normally", expired)
			}
		})
	}
}

// TestUnrestrictedAudienceStillRoundTripsAsUnrestricted is the regression
// guard on the fix itself: a genuinely empty audience (the documented
// "unrestricted") must still round-trip as empty and admit any decider, the
// exact behaviour a malformed-audience check must not disturb.
func TestUnrestrictedAudienceStillRoundTripsAsUnrestricted(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	r := pendingRequest("req-open", "hash-open", 1, time.Hour)
	r.Require.Audience = nil
	if err := repo.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, "req-open")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Require.Audience) != 0 {
		t.Fatalf("Audience = %v, want empty", got.Require.Audience)
	}
	if got.Require.AudienceMalformed() {
		t.Fatal("AudienceMalformed() = true for a genuinely empty audience, want false")
	}

	d := approval.Decision{
		AccountID: "acct-cy", Account: "cy", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-open", At: storeNow.Add(time.Minute),
	}
	if _, err := repo.RecordDecision(ctx, "req-open", d, storeNow.Add(time.Minute)); err != nil {
		t.Fatalf("RecordDecision by an unlisted account against an unrestricted audience: %v", err)
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
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
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
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
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
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Minute)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		approveRequest(t, repo, "req-1", "hash-a", storeNow.Add(30*time.Second))
		if _, err := repo.BindJob(ctx, "req-1", "job-1", storeNow.Add(time.Hour)); !errors.Is(err, approval.ErrNotReleasable) {
			t.Errorf("err = %v, want ErrNotReleasable", err)
		}
	})

	t.Run("denied", func(t *testing.T) {
		repo := approvalStore(t)
		if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
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
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", 1, time.Hour)); err != nil {
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
		rawExec, []string{"node-a"}, storeSelector, []string{"raw-exec-always-asks"},
		approval.Requirement{Count: 1, RequesterAllowed: false, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
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

// TestLastApprovedByShape is the store half of the anti-fatigue read: the
// newest RESOLVED approved record with this key, excluding the one being
// rendered, and nothing at all for a key that was never computed.
//
// The three approved records are separated by SECONDS, not fractions: the
// stored timestamps are RFC3339Nano text and Format trims trailing fractional
// zeroes, so a sub-second ordering assertion would be flaky by construction.
func TestLastApprovedByShape(t *testing.T) {
	ctx := context.Background()
	repo := approvalStore(t)

	shape := approval.HashPlanShape(storeAction, storeSelector)

	approveAt := func(id string, at time.Time) approval.Request {
		r := pendingRequest(id, "hash-"+id, 1, time.Hour)
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("Create(%s): %v", id, err)
		}
		out, err := repo.RecordDecision(ctx, id, approval.Decision{
			AccountID: "acct-ana", Account: "ana", Approve: true,
			Channel: approval.ChannelOutOfBand, PlanHash: "hash-" + id, At: at,
		}, at)
		if err != nil {
			t.Fatalf("RecordDecision(%s): %v", id, err)
		}
		return out
	}

	approveAt("req-old", storeNow.Add(10*time.Second))
	newest := approveAt("req-new", storeNow.Add(30*time.Second))
	rendering := approveAt("req-rendering", storeNow.Add(50*time.Second))

	// A DENIED and an EXPIRED record of the same shape, both resolved AFTER
	// req-new. They are the reason the query filters on state rather than on
	// "resolved": a state predicate of "anything terminal" would return one of
	// these, and the callout would render a refusal as "what you approved last
	// time" on the one screen whose job is telling a human the truth.
	denied := pendingRequest("req-denied", "hash-denied", 1, time.Hour)
	if err := repo.Create(ctx, denied); err != nil {
		t.Fatalf("Create(req-denied): %v", err)
	}
	if _, err := repo.RecordDecision(ctx, "req-denied", approval.Decision{
		AccountID: "acct-bo", Account: "bo", Approve: false,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-denied", At: storeNow.Add(40 * time.Second),
	}, storeNow.Add(40*time.Second)); err != nil {
		t.Fatalf("deny req-denied: %v", err)
	}

	expired := pendingRequest("req-expired", "hash-expired", 1, time.Second)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create(req-expired): %v", err)
	}
	if _, err := repo.ExpirePending(ctx, storeNow.Add(45*time.Second)); err != nil {
		t.Fatalf("ExpirePending: %v", err)
	}

	if rendering.ShapeKey != shape {
		t.Fatalf("stored shape key %q is not the one HashPlanShape computes (%q)", rendering.ShapeKey, shape)
	}

	got, err := repo.LastApprovedByShape(ctx, shape, "req-rendering")
	if err != nil {
		t.Fatalf("LastApprovedByShape: %v", err)
	}
	if got.ID != newest.ID {
		t.Errorf("got %q, want the newest approved record of the same shape (%q)", got.ID, newest.ID)
	}
	if len(got.Decisions) != 1 {
		t.Errorf("decisions did not load: %+v", got.Decisions)
	}

	// A pending record of the same shape is never a comparable prior either.
	if err := repo.Create(ctx, pendingRequest("req-pending", "hash-pending", 1, time.Hour)); err != nil {
		t.Fatalf("Create(req-pending): %v", err)
	}
	if got, err := repo.LastApprovedByShape(ctx, shape, "req-rendering"); err != nil || got.ID != newest.ID {
		t.Errorf("a pending record changed the answer: %q, %v", got.ID, err)
	}

	// Every non-approved record of this shape resolved after req-new, so any
	// weakening of the state predicate returns one of them by name.
	for _, id := range []string{"req-denied", "req-expired", "req-pending"} {
		if got, err := repo.LastApprovedByShape(ctx, shape, "req-rendering"); err != nil || got.ID == id {
			t.Errorf("LastApprovedByShape returned %q, which is not approved (checking %q): %v", got.ID, id, err)
		}
	}

	// The ordering is by resolved_at DESC: excluding nothing returns the truly
	// newest, which is the record the assertion above proved is excluded when
	// it is the one being rendered.
	if got, err := repo.LastApprovedByShape(ctx, shape, ""); err != nil || got.ID != rendering.ID {
		t.Errorf("LastApprovedByShape excluding nothing = %q, %v; want %q", got.ID, err, rendering.ID)
	}
	// Excluding a middle record does not disturb the ordering either.
	if got, err := repo.LastApprovedByShape(ctx, shape, newest.ID); err != nil || got.ID != rendering.ID {
		t.Errorf("LastApprovedByShape excluding %q = %q, %v; want %q", newest.ID, got.ID, err, rendering.ID)
	}

	// Uncomparable and unknown keys.
	for _, key := range []string{"", approval.LegacyShapeKey("req-old"), "0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, err := repo.LastApprovedByShape(ctx, key, ""); !errors.Is(err, approval.ErrNotFound) {
			t.Errorf("LastApprovedByShape(%q) = %v, want ErrNotFound", key, err)
		}
	}
}
