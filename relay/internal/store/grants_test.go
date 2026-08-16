package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

func grantStore(t *testing.T) approval.GrantRepository {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.Grants()
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
	repo := grantStore(t)

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
	repo := grantStore(t)

	bad := storeGrant("grant-bad", 5)
	bad.Scope.MaxFanOut = 0

	if err := repo.CreateGrant(ctx, bad); err == nil {
		t.Fatal("an unbounded grant was stored; the walls must not be bypassable by a future surface")
	}
}

func TestClaimGrantMatchesAndConsumes(t *testing.T) {
	ctx := context.Background()
	repo := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 2)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

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
	repo := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

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
	repo := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

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
	repo := grantStore(t)

	const limit = 5
	const claimers = 20
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", limit)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

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
	repo := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

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
	repo := grantStore(t)
	if err := repo.CreateGrant(ctx, storeGrant("grant-1", 5)); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	if _, err := repo.RevokeGrant(ctx, "grant-1", "ana", "incident 41", gNow); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	_, err := repo.RevokeGrant(ctx, "grant-1", "bo", "again", gNow.Add(time.Minute))
	if !errors.Is(err, approval.ErrGrantNotActive) {
		t.Fatalf("second revoke: err = %v, want ErrGrantNotActive", err)
	}
}

func TestRevokeUnknownGrantIsNotFound(t *testing.T) {
	_, err := grantStore(t).RevokeGrant(context.Background(), "grant-nope", "ana", "", gNow)
	if !errors.Is(err, approval.ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
}

func TestActiveGrantsExcludesSpentAndRevoked(t *testing.T) {
	ctx := context.Background()
	repo := grantStore(t)

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
