package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// openBenchStore is openTestStore's benchmark-scoped twin: *testing.B has its
// own TempDir/Cleanup, but is not a *testing.T, so it cannot share that
// helper's signature. Unlike openTestStore, no caller here needs the db
// path, so it returns only the Store.
func openBenchStore(b *testing.B) *Store {
	b.Helper()
	path := filepath.Join(b.TempDir(), "relay.db")
	st, err := Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { st.Close() })
	return st
}

// TestAudit_AppendAll_PersistsEveryRecord is the happy path: every Record in
// one AppendAll call is persisted, attribution and all.
func TestAudit_AppendAll_PersistsEveryRecord(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	want := []audit.Record{
		attributedRecord("aa1", "acct-a", "ops-team"),
		attributedRecord("aa2", "acct-b", "platform-team"),
		attributedRecord("aa3", "acct-c", "ops-team"),
	}
	if err := repo.AppendAll(ctx, want); err != nil {
		t.Fatalf("AppendAll: %v", err)
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("List returned %d records, want %d", len(got), len(want))
	}
	byID := make(map[string]audit.Record, len(got))
	for _, r := range got {
		byID[r.ID] = r
	}
	for _, w := range want {
		g, ok := byID[w.ID]
		if !ok {
			t.Fatalf("List missing record %q", w.ID)
		}
		if g.Attribution != w.Attribution {
			t.Errorf("%s: attribution mismatch:\n got %+v\nwant %+v", w.ID, g.Attribution, w.Attribution)
		}
		if g.NodeID != w.NodeID {
			t.Errorf("%s: NodeID = %q, want %q", w.ID, g.NodeID, w.NodeID)
		}
		if g.Kind != w.Kind {
			t.Errorf("%s: Kind = %q, want %q", w.ID, g.Kind, w.Kind)
		}
		if g.Reason != w.Reason {
			t.Errorf("%s: Reason = %q, want %q", w.ID, g.Reason, w.Reason)
		}
	}
}

// TestAudit_AppendAll_IsAllOrNothing proves the rollback the cascade's
// shortfall count relies on: when one record in a call collides on the
// audit_id PRIMARY KEY, the WHOLE call fails and NONE of its records are
// persisted — not even the ones that would have inserted cleanly.
func TestAudit_AppendAll_IsAllOrNothing(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	dup := attributedRecord("dup", "acct-a", "ops-team")
	if err := repo.Append(ctx, dup); err != nil {
		t.Fatalf("Append(dup): %v", err)
	}

	x1 := attributedRecord("x1", "acct-a", "ops-team")
	x2 := attributedRecord("x2", "acct-a", "ops-team")
	err := repo.AppendAll(ctx, []audit.Record{x1, x2, dup})
	if err == nil {
		t.Fatal("AppendAll with a duplicate ID returned nil error, want non-nil")
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].ID != "dup" {
		t.Fatalf("List = %+v, want only the pre-existing %q record — x1 and x2 must not "+
			"have survived the rolled-back transaction", got, "dup")
	}
}

// TestAudit_AppendAll_ExpiredContextWritesNothing covers a context whose
// deadline is already in the past, passed to AppendAll: it fails BEFORE any
// transaction work and writes nothing. This is the before-the-call case, the
// only one that reliably satisfies errors.Is(err, context.DeadlineExceeded)
// — database/sql does not guarantee that wrapping for a context that expires
// DURING the call (see TestAudit_AppendAll_CancelDuringCallIsAllOrNothing for
// that case).
func TestAudit_AppendAll_ExpiredContextWritesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Audit()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	err := repo.AppendAll(ctx, []audit.Record{attributedRecord("expired", "acct-a", "ops-team")})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AppendAll error = %v, want errors.Is(err, context.DeadlineExceeded)", err)
	}

	got, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List = %+v, want none — an expired context must write nothing", got)
	}
}

// TestAudit_AppendAll_CancelDuringCallIsAllOrNothing covers a budget running
// out MID-CHUNK: a context canceled from another goroutine while AppendAll is
// running a few thousand inserts must still leave the store in an
// all-or-nothing state. The exact error database/sql or the driver surfaces
// when a transaction is interrupted mid-flight is not portable
// (sql.ErrTxDone, ctx.Err(), or a driver-specific interrupted error), so this
// only asserts the property that matters to the cascade's shortfall count:
// either every record landed, or none did — never some.
//
// This test is PROBABILISTIC: the goroutine racing to call cancel() may well
// lose to BeginTx, in which case this run only re-exercises the
// before-the-call case. It goes red on neither outcome, so it never asserts
// that the cancellation actually landed mid-transaction. The deterministic
// proof of the all-or-nothing property is
// TestAudit_AppendAll_IsAllOrNothing; this test is extra coverage for the
// timing this issue is actually about, not the property's proof.
func TestAudit_AppendAll_CancelDuringCallIsAllOrNothing(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Audit()

	const n = 3000
	recs := make([]audit.Record, n)
	for i := range recs {
		recs[i] = attributedRecord(fmt.Sprintf("cancel-%04d", i), "acct-a", "ops-team")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go cancel()

	err := repo.AppendAll(ctx, recs)

	got, listErr := repo.List(context.Background())
	if listErr != nil {
		t.Fatalf("List: %v", listErr)
	}

	if err == nil {
		if len(got) != n {
			t.Fatalf("AppendAll returned nil error but List has %d records, want all %d", len(got), n)
		}
		return
	}
	if len(got) != 0 {
		t.Fatalf("AppendAll returned an error (%v) but List has %d records, want 0 — "+
			"all-or-nothing was violated", err, len(got))
	}
}

// TestAudit_AppendAll_EmptyIsNoOp asserts a nil or empty slice returns nil
// without opening a transaction, and writes nothing.
func TestAudit_AppendAll_EmptyIsNoOp(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	if err := repo.AppendAll(ctx, nil); err != nil {
		t.Errorf("AppendAll(nil): %v, want nil error", err)
	}
	if err := repo.AppendAll(ctx, []audit.Record{}); err != nil {
		t.Errorf("AppendAll(empty slice): %v, want nil error", err)
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List = %+v, want none", got)
	}
}

// BenchmarkAudit_Append1000 and BenchmarkAudit_AppendAll1000 are evidence for
// the commit-cost claim in #563's PR body: N autocommit inserts vs. one
// transaction for the same N records. Both build their 1000 records per
// iteration OUTSIDE the timed section, so the two numbers are a fair
// comparison of commit cost alone. Not run by make verify.
func BenchmarkAudit_Append1000(b *testing.B) {
	st := openBenchStore(b)
	ctx := context.Background()
	repo := st.Audit()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		recs := make([]audit.Record, 1000)
		for j := range recs {
			recs[j] = attributedRecord(fmt.Sprintf("bench-append-%d-%d", i, j), "acct-a", "ops-team")
		}
		b.StartTimer()
		for _, r := range recs {
			if err := repo.Append(ctx, r); err != nil {
				b.Fatalf("Append: %v", err)
			}
		}
	}
}

func BenchmarkAudit_AppendAll1000(b *testing.B) {
	st := openBenchStore(b)
	ctx := context.Background()
	repo := st.Audit()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		recs := make([]audit.Record, 1000)
		for j := range recs {
			recs[j] = attributedRecord(fmt.Sprintf("bench-appendall-%d-%d", i, j), "acct-a", "ops-team")
		}
		b.StartTimer()
		if err := repo.AppendAll(ctx, recs); err != nil {
			b.Fatalf("AppendAll: %v", err)
		}
	}
}
