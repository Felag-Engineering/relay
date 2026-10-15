package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

var idemNow = time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)

func idemRec(account, key, job string, at time.Time) jobs.IdempotencyRecord {
	return jobs.IdempotencyRecord{AccountID: account, Key: key, RequestDigest: "digest-" + job, JobID: job, CreatedAt: at}
}

func idemRows(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM dispatch_idempotency_keys`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func TestIdempotency_SecondClaimReturnsTheExistingRow(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()
	nb := idemNow.Add(-24 * time.Hour)

	if _, won, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-1", idemNow), nb); err != nil || !won {
		t.Fatalf("first Claim: won=%v err=%v", won, err)
	}
	got, won, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-2", idemNow.Add(time.Second)), nb)
	if err != nil || won {
		t.Fatalf("second Claim: won=%v err=%v; want it to lose", won, err)
	}
	if got.JobID != "job-1" || got.RequestDigest != "digest-job-1" || !got.CreatedAt.Equal(idemNow) {
		t.Errorf("existing = %+v, want the first claim's row intact", got)
	}
}

func TestIdempotency_ClaimSweepsExpiredRows(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()

	for i, k := range []string{"old-1", "old-2", "old-3"} {
		old := idemNow.Add(-48*time.Hour + time.Duration(i)*time.Minute)
		if _, won, err := repo.Claim(ctx, idemRec("acct-1", k, "job-"+k, old), old.Add(-24*time.Hour)); err != nil || !won {
			t.Fatalf("seed %s: won=%v err=%v", k, won, err)
		}
	}
	if n := idemRows(t, st); n != 3 {
		t.Fatalf("seeded rows = %d, want 3", n)
	}
	if _, won, err := repo.Claim(ctx, idemRec("acct-1", "fresh", "job-fresh", idemNow), idemNow.Add(-24*time.Hour)); err != nil || !won {
		t.Fatalf("fresh Claim: won=%v err=%v", won, err)
	}
	if n := idemRows(t, st); n != 1 {
		t.Errorf("rows after a Claim past the window = %d, want only the fresh one", n)
	}
}

func TestIdempotency_AnExpiredRowForTheSameKeyIsReplaced(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()
	old := idemNow.Add(-25 * time.Hour)

	if _, won, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-old", old), old.Add(-24*time.Hour)); err != nil || !won {
		t.Fatalf("seed: won=%v err=%v", won, err)
	}
	got, won, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-new", idemNow), idemNow.Add(-24*time.Hour))
	if err != nil || !won || got.JobID != "job-new" {
		t.Fatalf("Claim over an expired row: %+v won=%v err=%v; want it won", got, won, err)
	}
}

func TestIdempotency_LookupRespectsTheWindowAndTheAccount(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()
	if _, _, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-1", idemNow), idemNow.Add(-time.Hour)); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if _, ok, _ := repo.Lookup(ctx, "acct-1", "k", idemNow.Add(-time.Hour)); !ok {
		t.Error("Lookup inside the window found nothing")
	}
	if _, ok, _ := repo.Lookup(ctx, "acct-1", "k", idemNow.Add(time.Nanosecond)); ok {
		t.Error("Lookup past the window found the row")
	}
	if _, ok, _ := repo.Lookup(ctx, "acct-2", "k", idemNow.Add(-time.Hour)); ok {
		t.Error("Lookup under another Account found the row")
	}
}

// Times are exact: two claims 500ms apart inside one second order correctly at
// the window edge, which an RFC3339-trimmed text comparison would not.
func TestIdempotency_SubSecondOrderingAtTheWindowEdge(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()
	base := idemNow.Truncate(time.Second)
	if _, _, err := repo.Claim(ctx, idemRec("acct-1", "early", "job-e", base), base.Add(-time.Hour)); err != nil {
		t.Fatalf("Claim early: %v", err)
	}
	if _, _, err := repo.Claim(ctx, idemRec("acct-1", "late", "job-l", base.Add(500*time.Millisecond)), base.Add(-time.Hour)); err != nil {
		t.Fatalf("Claim late: %v", err)
	}

	edge := base.Add(250 * time.Millisecond)
	if _, ok, _ := repo.Lookup(ctx, "acct-1", "early", edge); ok {
		t.Error("the row 250ms before the edge is inside the window")
	}
	if _, ok, _ := repo.Lookup(ctx, "acct-1", "late", edge); !ok {
		t.Error("the row 250ms after the edge is outside the window")
	}
}

func TestIdempotency_RebindAndReleaseAreConditionalOnTheJob(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.IdempotencyKeys()
	ctx := context.Background()
	nb := idemNow.Add(-time.Hour)
	if _, _, err := repo.Claim(ctx, idemRec("acct-1", "k", "job-1", idemNow), nb); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if err := repo.Rebind(ctx, "acct-1", "k", "job-other", "job-2"); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if rec, _, _ := repo.Lookup(ctx, "acct-1", "k", nb); rec.JobID != "job-1" {
		t.Errorf("a Rebind from the wrong Job changed the row to %s", rec.JobID)
	}
	if err := repo.Rebind(ctx, "acct-1", "k", "job-1", "job-2"); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if rec, _, _ := repo.Lookup(ctx, "acct-1", "k", nb); rec.JobID != "job-2" {
		t.Errorf("row job = %s after a matching Rebind, want job-2", rec.JobID)
	}

	if err := repo.Release(ctx, "acct-1", "k", "job-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok, _ := repo.Lookup(ctx, "acct-1", "k", nb); !ok {
		t.Error("a Release naming the wrong Job deleted the row")
	}
	if err := repo.Release(ctx, "acct-1", "k", "job-2"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok, _ := repo.Lookup(ctx, "acct-1", "k", nb); ok {
		t.Error("a matching Release left the row")
	}
}
