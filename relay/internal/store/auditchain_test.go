package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// withoutAppendOnlyTriggers lifts the two #896 triggers, runs fn, and puts
// them back from the production constants. It is the test-only stand-in for
// anyone holding the file: the triggers are a guardrail, not a boundary.
func withoutAppendOnlyTriggers(t *testing.T, db *sql.DB, fn func()) {
	t.Helper()
	ctx := context.Background()
	for _, name := range []string{"audit_append_only_no_update", "audit_append_only_no_delete"} {
		if _, err := db.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+name); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
	}
	fn()
	for _, ddl := range []string{auditNoUpdateTriggerSQL, auditNoDeleteTriggerSQL} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("recreate trigger: %v", err)
		}
	}
}

func chainTestRecord(i int) audit.Record {
	return audit.Record{
		ID:        fmt.Sprintf("row%02d", i),
		Timestamp: time.Date(2026, 10, 7, 12, 0, i, 123, time.UTC),
		Kind:      audit.KindDispatch,
		Principal: "gleipnir:operator",
		Selector:  "relay:env=prod",
		JobID:     "job-1",
		NodeID:    "node-1",
		Reason:    fmt.Sprintf("reason %d", i),
		Outcome:   jobs.OutcomeSuccess,
		Stdout:    []byte("out"),
	}
}

func appendChainRows(t *testing.T, st *Store, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if err := st.Audit().Append(context.Background(), chainTestRecord(i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func verify(t *testing.T, path string, anchors ...audit.ChainAnchor) audit.ChainVerdict {
	t.Helper()
	v, err := VerifyAuditChain(context.Background(), path, anchors)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	return v
}

func execRaw(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func headAt(t *testing.T, st *Store) audit.ChainHead {
	t.Helper()
	h, err := st.AuditChain().ChainHead(context.Background())
	if err != nil {
		t.Fatalf("ChainHead: %v", err)
	}
	return h
}

func TestAuditChain_TriggerRefusesUpdateAndDelete(t *testing.T) {
	st, _ := openTestStore(t)
	appendChainRows(t, st, 1)
	ctx := context.Background()

	_, err := st.db.ExecContext(ctx, `UPDATE audit SET reason = 'x' WHERE audit_id = 'row01'`)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE error = %v, want an append-only refusal", err)
	}
	_, err = st.db.ExecContext(ctx, `DELETE FROM audit WHERE audit_id = 'row01'`)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("DELETE error = %v, want an append-only refusal", err)
	}

	rows, err := st.Audit().List(ctx)
	if err != nil || len(rows) != 1 || rows[0].Reason != "reason 1" {
		t.Errorf("row after refused writes = %+v, %v; want it unchanged", rows, err)
	}
}

func TestAuditChain_VerifierNamesTheEditedRow(t *testing.T) {
	t.Run("intact", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 5)
		v := verify(t, path)
		if !v.Intact() || v.Head.Seq != 5 || v.Rows != 5 || v.Head.Hash != headAt(t, st).Hash {
			t.Errorf("verdict = %+v", v)
		}
	})

	t.Run("edited row", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 5)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET reason = 'rewritten' WHERE audit_id = 'row03'`)
		})
		v := verify(t, path)
		if !v.Tampered() || v.Break.Reason != audit.BreakHashMismatch || v.Break.Seq != 3 || v.Break.AuditID != "row03" {
			t.Errorf("verdict = %+v break=%+v", v, v.Break)
		}
	})

	t.Run("deleted middle row", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 5)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `DELETE FROM audit WHERE audit_id = 'row03'`)
		})
		v := verify(t, path)
		// Reported against the row after the gap, naming the seq that is missing.
		if !v.Tampered() || v.Break.Reason != audit.BreakSeqGap || v.Break.Seq != 4 || v.Break.AuditID != "row04" ||
			!strings.Contains(v.Break.Detail, "expected seq 3, found 4") {
			t.Errorf("break = %+v", v.Break)
		}
	})

	t.Run("undecodable row is named", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 4)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET args = 'not json' WHERE audit_id = 'row03'`)
		})
		v := verify(t, path)
		if !v.Tampered() || v.Break.Reason != audit.BreakMalformed || v.Break.Seq != 3 || v.Break.AuditID != "row03" {
			t.Errorf("break = %+v", v.Break)
		}
	})

	t.Run("insert outside the chain", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 2)
		insertLegacyAuditRow(t, st.db, "stray", "2026-10-07T12:00:00.000000000Z")
		v := verify(t, path)
		if v.Tampered() || v.Intact() || v.Unchained != 1 || v.FirstUnchainedID != "stray" || v.Head.Seq != 2 {
			t.Errorf("verdict = %+v", v)
		}
	})

	t.Run("unchained row that carries a hash is tampering", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 3)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET seq = NULL, reason = 'edited' WHERE audit_id = 'row03'`)
		})
		v := verify(t, path)
		if !v.Tampered() || v.Break.Reason != audit.BreakMalformed || v.Break.AuditID != "row03" || v.Unchained != 1 {
			t.Errorf("verdict = %+v break=%+v", v, v.Break)
		}
	})

	t.Run("NULL hash column is a break, not an error", func(t *testing.T) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 3)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET hash = NULL WHERE audit_id = 'row02'`)
		})
		v := verify(t, path)
		if !v.Tampered() || v.Break.Reason != audit.BreakMalformed || v.Break.Seq != 2 || v.Break.AuditID != "row02" {
			t.Errorf("break = %+v", v.Break)
		}
	})
}

func TestVerifyAuditChain_Anchors(t *testing.T) {
	// Five rows, with the head recorded after the third as a checkpoint would.
	setup := func(t *testing.T) (*Store, string, audit.ChainAnchor) {
		st, path := openTestStore(t)
		appendChainRows(t, st, 3)
		h3 := headAt(t, st)
		for i := 4; i <= 5; i++ {
			if err := st.Audit().Append(context.Background(), chainTestRecord(i)); err != nil {
				t.Fatal(err)
			}
		}
		return st, path, audit.ChainAnchor(h3)
	}

	// rechain recomputes seq from..5 over the (possibly edited) rows, the way
	// an attacker with the file would.
	rechain := func(t *testing.T, st *Store, from uint64) {
		recs, err := st.Audit().List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]audit.Record{}
		for _, r := range recs {
			byID[r.ID] = r
		}
		var prev audit.ChainHash
		if from > 1 {
			var hx string
			if err := st.db.QueryRow(`SELECT hash FROM audit WHERE seq = ?`, from-1).Scan(&hx); err != nil {
				t.Fatal(err)
			}
			if prev, err = audit.ParseChainHash(hx); err != nil {
				t.Fatal(err)
			}
		}
		for seq := from; seq <= 5; seq++ {
			r := byID[fmt.Sprintf("row%02d", seq)]
			h := audit.ComputeChainHash(seq, prev, r)
			execRaw(t, st.db, `UPDATE audit SET prev_hash = ?, hash = ? WHERE seq = ?`, prev.Hex(), h.Hex(), seq)
			prev = h
		}
	}

	t.Run("correct anchor", func(t *testing.T) {
		_, path, a := setup(t)
		v := verify(t, path, a)
		if !v.Intact() || v.AnchorsChecked != 1 {
			t.Errorf("verdict = %+v", v)
		}
	})

	t.Run("tail truncated past the anchor", func(t *testing.T) {
		st, path, a := setup(t)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `DELETE FROM audit WHERE seq >= 3`)
		})
		if v := verify(t, path); !v.Intact() {
			t.Fatalf("without an anchor the shortened chain looks intact, got %+v", v)
		}
		v := verify(t, path, a)
		if !v.Tampered() || v.Break.Reason != audit.BreakAnchorBeyondHead || v.Break.Seq != 3 {
			t.Errorf("break = %+v", v.Break)
		}
	})

	t.Run("re-chained from before the anchor", func(t *testing.T) {
		st, path, a := setup(t)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET reason = 'rewritten' WHERE audit_id = 'row02'`)
			rechain(t, st, 2)
		})
		if v := verify(t, path); !v.Intact() {
			t.Fatalf("an honest re-chain is invisible without an anchor, got %+v", v)
		}
		v := verify(t, path, a)
		if !v.Tampered() || v.Break.Reason != audit.BreakAnchorMismatch || v.Break.Seq != 3 {
			t.Errorf("break = %+v", v.Break)
		}
	})

	t.Run("re-chained after the anchor is the documented limit", func(t *testing.T) {
		st, path, a := setup(t)
		withoutAppendOnlyTriggers(t, st.db, func() {
			execRaw(t, st.db, `UPDATE audit SET reason = 'rewritten' WHERE audit_id = 'row04'`)
			rechain(t, st, 4)
		})
		if v := verify(t, path, a); !v.Intact() {
			t.Errorf("a re-chain from k=4 is beyond an anchor at 3 and cannot be seen, got %+v", v)
		}
	})

	t.Run("contradictory anchors", func(t *testing.T) {
		_, path, a := setup(t)
		b := a
		b.Hash[0] ^= 1
		if _, err := VerifyAuditChain(context.Background(), path, []audit.ChainAnchor{a, b}); err == nil {
			t.Error("contradictory anchors accepted")
		}
	})
}

func TestMigration0028_BackfillsExistingRowsFromRowOne(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pre28.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 28)

	// Out of ts order, one pre-0024 trimmed ts, NULL args, retained output.
	insertLegacyAuditRow(t, db, "old-c", "2026-09-21T12:00:05.5Z")
	insertLegacyAuditRow(t, db, "old-a", "2026-09-21T12:00:09.000000000Z")
	insertLegacyAuditRow(t, db, "old-b", "2026-09-21T12:00:01Z")
	execRaw(t, db, `UPDATE audit SET stdout = x'00ff41', stderr = x'', args = '{"k":"v"}' WHERE audit_id = 'old-a'`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	rows, err := st.db.QueryContext(ctx, `SELECT audit_id, seq, prev_hash, hash FROM audit ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	wantPrev := audit.GenesisPrevHash.Hex()
	n := 0
	for rows.Next() {
		var id, p, h string
		var seq int
		if err := rows.Scan(&id, &seq, &p, &h); err != nil {
			t.Fatal(err)
		}
		n++
		if seq != n || p != wantPrev {
			t.Errorf("row %s: seq=%d prev=%s, want seq=%d prev=%s", id, seq, p, n, wantPrev)
		}
		wantPrev, prev = h, h
	}
	rows.Close()
	if n != 3 || prev == "" {
		t.Fatalf("chained %d rows, want 3", n)
	}

	if got := storedTS(t, st.db, "old-c"); got != "2026-09-21T12:00:05.500000000Z" {
		t.Errorf("trimmed ts = %q, want the canonical 9-digit form", got)
	}
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 3 {
		t.Errorf("verdict = %+v", v)
	}
	var triggers int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'audit_append_only_%'`).Scan(&triggers); err != nil || triggers != 2 {
		t.Errorf("triggers = %d, %v; want 2", triggers, err)
	}

	appendChainRows(t, st, 1)
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 4 {
		t.Errorf("after an Append: %+v", v)
	}
}

func TestMigration0028_FailedBackfillRollsBackAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 28)
	insertLegacyAuditRow(t, db, "good", "2026-09-21T12:00:00.000000000Z")
	insertLegacyAuditRow(t, db, "garbled", "not a timestamp")

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "garbled") {
		t.Fatalf("Open error = %v, want one naming the undecodable audit_id", err)
	}

	var applied, hasSeq int
	execQ := func(q string, dst *int) {
		if err := db.QueryRow(q).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	execQ(`SELECT COUNT(*) FROM schema_migrations WHERE version = 28`, &applied)
	execQ(`SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name = 'seq'`, &hasSeq)
	if applied != 0 || hasSeq != 0 {
		t.Errorf("after the failed Open: version recorded=%d seq column=%d, want neither", applied, hasSeq)
	}

	execRaw(t, db, `UPDATE audit SET ts = '2026-09-21T12:00:01.000000000Z' WHERE audit_id = 'garbled'`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open after the fix: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 2 {
		t.Errorf("verdict = %+v", v)
	}
}

func TestAuditChain_AppendedRecordVerifiesAfterReadBack(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	awkward := func(id string) audit.Record {
		return audit.Record{
			ID:        id,
			Timestamp: time.Now().In(time.FixedZone("far", 9*3600)), // carries a monotonic reading
			Kind:      audit.KindDispatch,
			Principal: "p\xffq",
			Selector:  "sel\x00ector",
			JobID:     "job",
			// Two keys differing only in invalid UTF-8 collapse to one in JSON.
			Args:        map[string]string{"a\xfe": "1", "a\xff": "2", "ok": "v\xfa"},
			RawExecArgv: []string{"/bin/echo", "\xc3\x28", ""},
			Reason:      "r\xffeason\x00",
			Stdout:      []byte("o\xff\x00ut"),
			Stderr:      []byte{},
		}
	}
	empty := audit.Record{ID: "empty", Timestamp: time.Now(), Kind: audit.KindDispatch, Args: map[string]string{}, RawExecArgv: []string{}, Stdout: []byte{}}

	if err := st.Audit().Append(ctx, awkward("a1")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := st.Audit().AppendAll(ctx, []audit.Record{awkward("a2"), empty, awkward("a3")}); err != nil {
		t.Fatalf("AppendAll: %v", err)
	}
	admin, err := st.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rec := awkward("a4")
	if err := st.SetPasswordRecorded(ctx, admin.ID, hashOf(t, "a strong console passphrase"), rec); err != nil {
		t.Fatalf("SetPasswordRecorded: %v", err)
	}

	if v := verify(t, path); !v.Intact() || v.Rows != 5 {
		t.Errorf("verdict = %+v break=%+v", v, v.Break)
	}
}

func TestAuditChain_ConcurrentAppendsStayContiguous(t *testing.T) {
	st, path := openTestStore(t)
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })

	const workers, each = 6, 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		s := st
		if w%2 == 1 {
			s = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				r := chainTestRecord(0)
				id, err := audit.NewID()
				if err != nil {
					errs <- err
					return
				}
				r.ID = id
				errs <- s.Audit().Append(context.Background(), r)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if v := verify(t, path); !v.Intact() || v.Rows != workers*each || v.Head.Seq != workers*each {
		t.Errorf("verdict = %+v break=%+v", v, v.Break)
	}
}

func TestVerifyAuditChain_WhileStoreOpen(t *testing.T) {
	st, path := openTestStore(t)
	appendChainRows(t, st, 3)
	if v := verify(t, path); !v.Intact() {
		t.Fatalf("verdict = %+v", v)
	}
	if err := st.Audit().Append(context.Background(), chainTestRecord(4)); err != nil {
		t.Fatalf("the Store stopped appending after a verify: %v", err)
	}
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 4 {
		t.Errorf("verdict = %+v", v)
	}
}

func TestVerifyAuditChain_NeverWritesOrCreates(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.db")
	if _, err := VerifyAuditChain(context.Background(), missing, nil); err == nil {
		t.Error("a missing store verified")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("VerifyAuditChain created %d files", len(entries))
	}

	old := filepath.Join(dir, "pre28.db")
	db, err := sql.Open("sqlite", old)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 28)
	_, err = VerifyAuditChain(context.Background(), old, nil)
	if err == nil || !strings.Contains(err.Error(), "predates the audit chain") {
		t.Errorf("error = %v, want the predates refusal", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 28`).Scan(&n); err != nil || n != 0 {
		t.Errorf("migration 28 recorded=%d, %v; the verifier must never migrate", n, err)
	}
	db.Close()
}

func TestMigrationGoSteps_EveryVersionIsEmbedded(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	have := map[int]bool{}
	for _, m := range ms {
		have[m.version] = true
	}
	for v := range migrationGoSteps {
		if !have[v] {
			t.Errorf("migrationGoSteps[%d] has no embedded migration file: it would never run", v)
		}
	}
}
