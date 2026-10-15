package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// grantStore returns a grant repository plus the approval repository behind
// the same database, so a test can create the authorizing Request a Grant is
// only claimable under.
func grantStore(t *testing.T) (approval.GrantRepository, approval.Repository) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.Grants(), st.Approvals()
}

// authorize creates the approval Request for a Grant and drives it to approved,
// which is what makes the Grant claimable at all.
func authorize(t *testing.T, repo approval.Repository, requestID string) {
	t.Helper()
	ctx := context.Background()
	r := approval.NewRequest(requestID, "hash-"+requestID, "acct-g", "gleipnir-prod",
		storeAction, []string{"node-a"}, approval.SelectorShape{}, []string{"batch-rule"},
		approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		gNow.Add(-time.Minute))
	if err := repo.Create(ctx, r); err != nil {
		t.Fatalf("create authorizing request: %v", err)
	}
	if _, err := repo.RecordDecision(ctx, requestID, approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-" + requestID,
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("approve authorizing request: %v", err)
	}
}

var gNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func storeGrant(id string, maxUses int) approval.Grant {
	s := approval.Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  10,
		Operations: []string{"service.restart", "pkg.install"},
	}
	return approval.Grant{
		ID: id, RequestID: "req-" + id,
		Scope:    s,
		StartsAt: gNow.Add(-time.Minute), ExpiresAt: gNow.Add(time.Hour),
		MaxUses:   maxUses,
		Summary:   approval.SummarizeScope(s, gNow, gNow.Add(time.Hour), maxUses),
		CreatedAt: gNow,
	}
}

func storeDispatch() approval.Dispatch {
	return approval.Dispatch{
		RiskClass: jobs.RiskClassMutate,
		FanOut:    3,
		Account:   "gleipnir-prod",
		Operation: "service.restart",
	}
}

func TestGrantRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo, _ := grantStore(t)

	want := storeGrant("grant-1", 5)
	if err := repo.CreateGrant(ctx, want); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	got, err := repo.GetGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if got.RequestID != want.RequestID || got.MaxUses != want.MaxUses {
		t.Errorf("got %+v, want the stored identity and bound", got)
	}
	if len(got.Scope.Operations) != 2 {
		t.Errorf("Operations = %v, want both round-tripped", got.Scope.Operations)
	}
	if got.Scope.MaxFanOut != 10 || got.Scope.RiskClass != jobs.RiskClassMutate {
		t.Errorf("Scope = %+v, want the ceiling and class preserved", got.Scope)
	}
	if got.Summary != want.Summary {
		t.Errorf("Summary = %q, want what the approver was shown, verbatim", got.Summary)
	}
	if got.Revoked() {
		t.Error("a fresh grant reads back revoked")
	}
}

// TestCreateGrantRefusesAnUnboundedGrant: the store validates too, so an
// unbounded grant is impossible to WRITE — not merely impossible to create
// through today's API.
func TestCreateGrantRefusesAnUnboundedGrant(t *testing.T) {
	ctx := context.Background()
	repo, _ := grantStore(t)

	bad := storeGrant("grant-bad", 5)
	bad.Scope.MaxFanOut = 0

	if err := repo.CreateGrant(ctx, bad); err == nil {
		t.Fatal("an unbounded grant was stored; the walls must not be bypassable by a future surface")
	}
}

func TestClaimGrantMatchesAndConsumes(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 2)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	g, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow)
	if err != nil || !ok {
		t.Fatalf("ClaimGrant: ok=%v err=%v, want a claim", ok, err)
	}
	if g.Uses != 1 {
		t.Errorf("Uses = %d, want 1 consumed", g.Uses)
	}

	stored, err := repo.GetGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if stored.Uses != 1 {
		t.Errorf("stored Uses = %d, want the consumption durable", stored.Uses)
	}
}

// TestClaimGrantHonoursTheDomainMatcher: SQL narrows, the domain decides. Each
// case here is refused by Grant.Covers, not by the query, which is exactly the
// property that keeps a second matcher from existing.
func TestClaimGrantHonoursTheDomainMatcher(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	cases := map[string]func(*approval.Dispatch){
		"above the fan-out ceiling": func(d *approval.Dispatch) { d.FanOut = 11 },
		"operation not on the list": func(d *approval.Dispatch) { d.Operation = "file.read" },
		"raw exec without opt-in":   func(d *approval.Dispatch) { d.RawExec = true; d.Operation = "" },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			d := storeDispatch()
			break_(&d)
			_, ok, err := repo.ClaimGrant(ctx, d, gNow)
			if err != nil {
				t.Fatalf("ClaimGrant: %v", err)
			}
			if ok {
				t.Fatalf("claimed a grant for a dispatch %s", name)
			}
		})
	}

	// None of the refusals may have spent a use.
	stored, err := repo.GetGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if stored.Uses != 0 {
		t.Errorf("Uses = %d after only-refused claims, want 0", stored.Uses)
	}
}

func TestClaimGrantRefusesOutsideTheWindow(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow.Add(2*time.Hour)); err != nil || ok {
		t.Fatalf("claimed after expiry: ok=%v err=%v", ok, err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow.Add(-time.Hour)); err != nil || ok {
		t.Fatalf("claimed before the window opened: ok=%v err=%v", ok, err)
	}
}

// TestClaimGrantNeverExceedsItsBoundUnderConcurrency is the test the whole
// transaction design exists for.
//
// A grant bounded at N releasing N+1 dispatches would not read as a counting
// bug — it would be a human's stated limit being wrong, which is the one thing
// this mechanism promises. Separate find-and-increment calls would let
// concurrent claimers both observe the last remaining use.
func TestClaimGrantNeverExceedsItsBoundUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)

	const limit = 5
	const claimers = 20
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", limit)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		granted  int
		firstErr error
	)
	for i := 0; i < claimers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if ok {
				granted++
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		t.Fatalf("ClaimGrant: %v", firstErr)
	}
	if granted != limit {
		t.Fatalf("granted %d of %d concurrent claims, want exactly the grant's limit of %d", granted, claimers, limit)
	}

	stored, err := repo.GetGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if stored.Uses != limit {
		t.Errorf("stored Uses = %d, want %d", stored.Uses, limit)
	}
}

func TestRevokeGrantStopsTheNextClaim(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || !ok {
		t.Fatalf("pre-revocation claim: ok=%v err=%v", ok, err)
	}

	revoked, err := repo.RevokeGrant(ctx, "grant-1", "ana", "incident 41", gNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if !revoked.Revoked() || revoked.RevokedBy != "ana" {
		t.Errorf("revoked = %+v, want the revocation attributed", revoked)
	}

	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow.Add(2*time.Minute)); err != nil || ok {
		t.Fatalf("claimed a revoked grant: ok=%v err=%v", ok, err)
	}
}

// TestRevokeGrantTwiceIsNotASilentNoOp: an operator reaching for revocation is
// usually mid-incident and needs to know whether they actually closed the
// window or were looking at a stale queue.
func TestRevokeGrantTwiceIsNotASilentNoOp(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")

	if _, err := repo.RevokeGrant(ctx, "grant-1", "ana", "incident 41", gNow); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	_, err := repo.RevokeGrant(ctx, "grant-1", "bo", "again", gNow.Add(time.Minute))
	if !errors.Is(err, approval.ErrGrantNotActive) {
		t.Fatalf("second revoke: err = %v, want ErrGrantNotActive", err)
	}
}

func TestRevokeUnknownGrantIsNotFound(t *testing.T) {
	repo, _ := grantStore(t)
	_, err := repo.RevokeGrant(context.Background(), "grant-nope", "ana", "", gNow)
	if !errors.Is(err, approval.ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
}

func TestActiveGrantsExcludesSpentAndRevoked(t *testing.T) {
	ctx := context.Background()
	repo, _ := grantStore(t)

	live := storeGrant("grant-live", 5)
	other := storeGrant("grant-other", 5)
	gone := storeGrant("grant-revoked", 5)
	for _, g := range []approval.Grant{live, other, gone} {
		if err := repo.CreateGrant(ctx, g); err != nil {
			t.Fatalf("CreateGrant(%s): %v", g.ID, err)
		}
	}
	if _, err := repo.RevokeGrant(ctx, "grant-revoked", "ana", "incident", gNow); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	got, err := repo.ActiveGrants(ctx, gNow)
	if err != nil {
		t.Fatalf("ActiveGrants: %v", err)
	}
	for _, g := range got {
		if g.ID == "grant-revoked" {
			t.Error("a revoked grant appeared in the active list")
		}
	}
	if len(got) != 2 {
		t.Errorf("active = %d, want the two unrevoked grants", len(got))
	}
}

// TestGrantIsNotClaimableBeforeItsRequestIsApproved is the authorization link.
//
// A grant row exists from the moment one is REQUESTED, so without the EXISTS
// clause in ClaimGrant a pending — or outright denied — grant request would be
// live the instant it was written. That would let a requester grant themselves
// a window by asking for one.
func TestGrantIsNotClaimableBeforeItsRequestIsApproved(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)

	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	// No authorizing request at all.
	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || ok {
		t.Fatalf("claimed a grant with no authorizing request: ok=%v err=%v", ok, err)
	}

	// A PENDING request is not authorization either.
	pending := approval.NewRequest("req-grant-1", "hash-req-grant-1", "acct-g", "gleipnir-prod",
		storeAction, []string{"node-a"}, approval.SelectorShape{}, []string{"batch-rule"},
		approval.Requirement{Count: 2, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		gNow.Add(-time.Minute))
	if err := approvals.Create(ctx, pending); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || ok {
		t.Fatalf("claimed a grant whose request is still pending: ok=%v err=%v", ok, err)
	}

	// One approval short of the count:2 quorum is still not authorization —
	// the gate rule's quorum applies to granting exactly as it does to a
	// single dispatch.
	if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-req-grant-1",
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || ok {
		t.Fatalf("claimed a grant at 1 of 2 approvals: ok=%v err=%v", ok, err)
	}

	// The second distinct approver completes it.
	if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
		AccountID: "acct-bo", Account: "bo", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-req-grant-1",
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || !ok {
		t.Fatalf("a fully approved grant was not claimable: ok=%v err=%v", ok, err)
	}
}

// TestDeniedGrantRequestIsNeverClaimable: deny beats approve and is terminal,
// so a refused grant request must never become live.
func TestDeniedGrantRequestIsNeverClaimable(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)

	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	r := approval.NewRequest("req-grant-1", "hash-req-grant-1", "acct-g", "gleipnir-prod",
		storeAction, []string{"node-a"}, approval.SelectorShape{}, []string{"batch-rule"},
		approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		gNow.Add(-time.Minute))
	if err := approvals.Create(ctx, r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: false, Reason: "too broad",
		Channel: approval.ChannelOutOfBand, PlanHash: "hash-req-grant-1",
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("deny: %v", err)
	}

	if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || ok {
		t.Fatalf("claimed a grant whose request was DENIED: ok=%v err=%v", ok, err)
	}
}

// TestGrantByRequestFindsARevokedGrant is why GrantByRequest is not a copy of
// ClaimGrant's query. The approval object renders a Grant that has already been
// closed, spent or lapsed — "what did that window cover, and who closed it" is
// the question asked after the fact — so a `revoked_at IS NULL` or an
// Active(now) filter here would tell a human nothing like this was ever
// approved about a window they themselves revoked yesterday.
func TestGrantByRequestFindsARevokedGrant(t *testing.T) {
	ctx := context.Background()
	repo, approvals := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	authorize(t, approvals, "req-grant-1")
	if _, err := repo.RevokeGrant(ctx, "grant-1", "ana", "incident 41", gNow); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	got, err := repo.GrantByRequest(ctx, "req-grant-1")
	if err != nil {
		t.Fatalf("GrantByRequest after revocation: %v", err)
	}
	if got.ID != "grant-1" {
		t.Errorf("GrantByRequest returned %q, want grant-1", got.ID)
	}
	if !got.Revoked() || got.RevokedBy != "ana" {
		t.Errorf("GrantByRequest lost the revocation: %+v", got)
	}
}

// TestGrantByRequestIsNotFoundForAPlainRequest: most approval Requests are for
// one Plan and authorize no Grant at all, and the surface has to be able to
// tell the two apart by the sentinel rather than by an empty struct.
func TestGrantByRequestIsNotFoundForAPlainRequest(t *testing.T) {
	repo, _ := grantStore(t)
	_, err := repo.GrantByRequest(context.Background(), "req-that-is-a-plan")
	if !errors.Is(err, approval.ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
}

// TestLegacyNamespacePinnedGrantReleasesNoDispatch is #482's primary proof,
// against a real SQLite store: a Grant written before namespace pinning was
// removed from a Scope — here reproducing the issue's worked example, a
// dispatch whose Selector used both relay: and node: — must release nothing,
// even though it was approved and would have released it under the old
// containment semantics (Grant.Covers used to admit any dispatch whose
// namespace list merely CONTAINED the pinned one).
//
// The unpinned control below is the same Grant, the same dispatch, and the
// same approved Request, minus the UPDATE that pins it — it must release. That
// is what proves the refusal above is caused by the pin and not by something
// else about this Scope or dispatch.
func TestLegacyNamespacePinnedGrantReleasesNoDispatch(t *testing.T) {
	t.Run("pinned", func(t *testing.T) {
		ctx := context.Background()
		st, db := openStore(t)
		repo, approvals := st.Grants(), st.Approvals()

		if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		authorize(t, approvals, "req-grant-1")

		if _, err := db.Exec(
			`UPDATE approval_grants SET scope_selector_namespace = 'node' WHERE grant_id = 'grant-1'`,
		); err != nil {
			t.Fatalf("pin the stored grant: %v", err)
		}

		d := storeDispatch()
		d.Namespaces = []string{"relay", "node"}

		if _, ok, err := repo.ClaimGrant(ctx, d, gNow); err != nil {
			t.Fatalf("ClaimGrant: %v", err)
		} else if ok {
			t.Fatal("a legacy namespace-pinned grant released a dispatch outside its priced namespace")
		}

		stored, err := repo.GetGrant(ctx, "grant-1")
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}
		if stored.Uses != 0 {
			t.Errorf("Uses = %d, want 0 — a refused claim must not spend a use", stored.Uses)
		}
		if stored.LegacyNamespacePin != "node" {
			t.Errorf("LegacyNamespacePin = %q, want %q", stored.LegacyNamespacePin, "node")
		}

		active, err := repo.ActiveGrants(ctx, gNow)
		if err != nil {
			t.Fatalf("ActiveGrants: %v", err)
		}
		for _, g := range active {
			if g.ID == "grant-1" {
				t.Error("a legacy namespace-pinned grant appeared in the active list")
			}
		}

		// The operator can still revoke it for the record.
		if _, err := repo.RevokeGrant(ctx, "grant-1", "ana", "closing a dead pinned grant", gNow); err != nil {
			t.Errorf("RevokeGrant on a legacy-pinned grant: %v", err)
		}
	})

	t.Run("unpinned control", func(t *testing.T) {
		ctx := context.Background()
		repo, approvals := grantStore(t)

		if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		authorize(t, approvals, "req-grant-1")

		d := storeDispatch()
		d.Namespaces = []string{"relay", "node"}

		if _, ok, err := repo.ClaimGrant(ctx, d, gNow); err != nil {
			t.Fatalf("ClaimGrant: %v", err)
		} else if !ok {
			t.Fatal("an unpinned grant of the identical Scope did not release the identical dispatch — the pin, not the dispatch, must be what refuses the pinned case")
		}

		stored, err := repo.GetGrant(ctx, "grant-1")
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}
		if stored.Uses != 1 {
			t.Errorf("Uses = %d, want 1", stored.Uses)
		}
	})
}

// TestWorkedExample482ReleasesOnlyAtTwoApprovals is the issue's worked
// example end to end, against a real SQLite store: a Scope that could cover a
// dispatch whose Selector uses BOTH relay: and node: is priced by
// RequirementForScope at the STRICTEST rule any single-namespace probe would
// face — here, a gate rule demanding 2 approvals for relay: and only 1
// otherwise — so the derived Requirement is Count 2. ClaimGrant must refuse
// the relay+node dispatch after only one approval and release it only once
// the second lands. This is the property #482 restores: before it, the same
// Scope pinned to "node" would have priced at Count 1 (the "any" rule alone)
// while still covering this dispatch by containment.
func TestWorkedExample482ReleasesOnlyAtTwoApprovals(t *testing.T) {
	ctx := context.Background()
	st, _ := openStore(t)
	repo, approvals := st.Grants(), st.Approvals()

	gate, err := approval.NewGate([]approval.Rule{
		{Name: "relay-two", Match: approval.Match{SelectorNamespace: "relay"}, Require: approval.Requirement{Count: 2}},
		{Name: "any", Match: approval.Match{}, Require: approval.Requirement{Count: 1}},
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	g := storeGrant("grant-1", 5)
	requirement, rules, gated := approval.RequirementForScope(g.Scope, gate.Evaluate)
	if !gated || requirement.Count != 2 {
		t.Fatalf("RequirementForScope = (%+v, %v, gated=%v), want Count 2, gated true", requirement, rules, gated)
	}
	if err := repo.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	r := approval.NewGrantRequest(g, "acct-g", "gleipnir-prod", rules,
		approval.Requirement{Count: requirement.Count, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		gNow.Add(-time.Minute))
	if err := approvals.Create(ctx, r); err != nil {
		t.Fatalf("create authorizing request: %v", err)
	}

	d := storeDispatch()
	d.Namespaces = []string{"relay", "node"}

	// One approval short of the count:2 quorum is not authorization yet.
	if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: r.PlanHash,
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, d, gNow); err != nil || ok {
		t.Fatalf("ClaimGrant at 1 of 2 approvals: ok=%v err=%v, want a park", ok, err)
	}

	// The second distinct approver completes the quorum, and only then does
	// the relay+node dispatch release.
	if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
		AccountID: "acct-bo", Account: "bo", Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: r.PlanHash,
		DeciderHuman: true, At: gNow.Add(-time.Minute),
	}, gNow.Add(-time.Minute)); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if _, ok, err := repo.ClaimGrant(ctx, d, gNow); err != nil || !ok {
		t.Fatalf("ClaimGrant at 2 of 2 approvals: ok=%v err=%v, want a release", ok, err)
	}
}

// TestCreateGrantRefusesALegacyNamespacePin: the store validates too, so a
// Grant carrying a legacy namespace pin is impossible to WRITE going forward —
// only the read path (scanGrant) may ever populate LegacyNamespacePin.
func TestCreateGrantRefusesALegacyNamespacePin(t *testing.T) {
	ctx := context.Background()
	repo, _ := grantStore(t)

	bad := storeGrant("grant-bad", 5)
	bad.LegacyNamespacePin = "node"

	if err := repo.CreateGrant(ctx, bad); !errors.Is(err, approval.ErrGrantInvalid) {
		t.Fatalf("CreateGrant: err = %v, want ErrGrantInvalid", err)
	}
	if _, err := repo.GetGrant(ctx, "grant-bad"); !errors.Is(err, approval.ErrGrantNotFound) {
		t.Errorf("GetGrant: err = %v, want ErrGrantNotFound — the refused write must not land", err)
	}
}

// TestGrantWhoseStoredAudienceHasABlankEntryAuthorizesNothing is #608's
// Approval-grant-path regression. An Approval grant's own approver audience
// lives on its authorizing Request, which Create can no longer write with a
// blank entry
// (TestCreateRefusesBlankAudienceEntry, on the approvals side) — so this
// simulates a row from before that fix, corrupted directly via SQL.
//
// The control case (no corruption) proves the assertion below is not
// vacuously true: without it, ClaimGrant returning false after corruption
// would pass on main too, since ClaimGrant already requires an approved
// Request regardless of audience.
func TestGrantWhoseStoredAudienceHasABlankEntryAuthorizesNothing(t *testing.T) {
	ctx := context.Background()

	newAuthorizedGrant := func(t *testing.T) (approval.GrantRepository, approval.Repository, *sql.DB) {
		t.Helper()
		st, db := openStore(t)
		repo, approvals := st.Grants(), st.Approvals()
		if err := repo.CreateGrant(ctx, storeGrant("grant-1", 2)); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		r := approval.NewRequest("req-grant-1", "hash-req-grant-1", "acct-g", "gleipnir-prod",
			storeAction, []string{"node-a"}, approval.SelectorShape{}, []string{"batch-rule"},
			approval.Requirement{Count: 1, Audience: []string{"ana"}, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
			gNow.Add(-time.Minute))
		if err := approvals.Create(ctx, r); err != nil {
			t.Fatalf("create authorizing request: %v", err)
		}
		return repo, approvals, db
	}

	t.Run("control: an uncorrupted named audience authorizes the grant normally", func(t *testing.T) {
		repo, approvals, _ := newAuthorizedGrant(t)
		if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
			AccountID: "acct-ana", Account: "ana", Approve: true,
			Channel: approval.ChannelOutOfBand, PlanHash: "hash-req-grant-1",
			DeciderHuman: true, At: gNow.Add(-time.Minute),
		}, gNow.Add(-time.Minute)); err != nil {
			t.Fatalf("RecordDecision by the named approver: %v", err)
		}
		if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || !ok {
			t.Fatalf("ClaimGrant: ok=%v err=%v, want a claim — an approved Approval grant with a well-formed audience must be claimable", ok, err)
		}
	})

	t.Run("corrupted: a blank audience entry refuses the decision and the grant is never claimable", func(t *testing.T) {
		repo, approvals, db := newAuthorizedGrant(t)
		if _, err := db.ExecContext(ctx,
			`UPDATE approval_requests SET require_audience = ? WHERE request_id = ?`,
			"ana,", "req-grant-1"); err != nil {
			t.Fatalf("corrupt require_audience: %v", err)
		}

		if _, err := approvals.RecordDecision(ctx, "req-grant-1", approval.Decision{
			AccountID: "acct-ana", Account: "ana", Approve: true,
			Channel: approval.ChannelOutOfBand, PlanHash: "hash-req-grant-1",
			DeciderHuman: true, At: gNow.Add(-time.Minute),
		}, gNow.Add(-time.Minute)); !errors.Is(err, approval.ErrNotInAudience) {
			t.Fatalf("RecordDecision against a malformed audience: err = %v, want ErrNotInAudience", err)
		}

		if _, ok, err := repo.ClaimGrant(ctx, storeDispatch(), gNow); err != nil || ok {
			t.Fatalf("ClaimGrant: ok=%v err=%v, want no claim — the authorizing request was never approved", ok, err)
		}
	})
}
