package store

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// zeroWaitDB opens path the way the store does, but with busy_timeout(0), so
// a second "process" fails at once instead of waiting.
func zeroWaitDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatalf("sqliteDSN: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %q: %v", dsn, err)
	}
	q := u.Query()
	var pragmas []string
	for _, p := range q["_pragma"] {
		if strings.HasPrefix(p, "busy_timeout(") {
			p = "busy_timeout(0)"
		}
		pragmas = append(pragmas, p)
	}
	q["_pragma"] = pragmas
	u.RawQuery = q.Encode()
	dsn = u.String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// holdWriteLock plays another process holding the write lock: it begins an
// IMMEDIATE transaction and writes. The caller releases it with COMMIT; a
// ROLLBACK is registered so a failed test never leaves the file locked.
func holdWriteLock(t *testing.T, path string) *sql.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := zeroWaitDB(t, path).Conn(ctx)
	if err != nil {
		t.Fatalf("holder conn: %v", err)
	}
	t.Cleanup(func() {
		conn.ExecContext(ctx, "ROLLBACK")
		conn.Close()
	})
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("holder BEGIN IMMEDIATE: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "UPDATE nodes SET daemon_version = daemon_version"); err != nil {
		t.Fatalf("holder UPDATE: %v", err)
	}
	return conn
}

// assertLockHeld proves the write lock really is held before the code under
// test runs: a third connection with no busy wait cannot begin a write.
func assertLockHeld(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	conn, err := zeroWaitDB(t, path).Conn(ctx)
	if err != nil {
		t.Fatalf("probe conn: %v", err)
	}
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE")
	if err == nil {
		conn.ExecContext(ctx, "ROLLBACK")
		t.Fatal("probe BEGIN IMMEDIATE succeeded: the write lock is not held")
	}
	if !strings.Contains(err.Error(), "SQLITE_BUSY") && !strings.Contains(err.Error(), "database is locked") {
		t.Fatalf("probe failed with %v, want a busy/locked error", err)
	}
}

func TestSqliteDSN_WritesBeginImmediate(t *testing.T) {
	dsn, err := sqliteDSN(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatalf("sqliteDSN: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %q: %v", dsn, err)
	}
	vals := u.Query()
	if got := vals["_txlock"]; len(got) != 1 || got[0] != "immediate" {
		t.Errorf("_txlock = %v, want [immediate]", got)
	}
	if got := vals["_pragma"]; len(got) != 2 {
		t.Errorf("_pragma = %v, want foreign_keys and busy_timeout", got)
	}
}

// TestUpsert_WaitsOutAnotherProcessesWriteLock is #833: a Hello upsert racing
// another process's write used to fail at once with SQLITE_BUSY.
func TestUpsert_WaitsOutAnotherProcessesWriteLock(t *testing.T) {
	st, path := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}

	holder := holdWriteLock(t, path)
	assertLockHeld(t, path)

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := reg.Upsert(registry.Report{NodeID: "node-a", DaemonVersion: "1.0.0", PolicyFingerprint: "fp"})
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := holder.ExecContext(context.Background(), "COMMIT"); err != nil {
		t.Fatalf("holder COMMIT: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Errorf("Upsert returned after %v: it did not wait for the lock", elapsed)
	}
	if elapsed >= busyTimeoutMillis*time.Millisecond {
		t.Errorf("Upsert took %v, want under the busy timeout", elapsed)
	}
	n, ok := reg.Get("node-a")
	if !ok || n.DaemonVersion != "1.0.0" || n.PolicyFingerprint != "fp" {
		t.Errorf("Get = %+v, %v; want the upserted version and fingerprint", n, ok)
	}
}

// TestUpsert_DeferredTxFailsFastUnderAnotherWriter is the permanent negative
// control. It pins the reason sqliteDSN carries _txlock=immediate: a deferred
// transaction's read-to-write upgrade does not wait on busy_timeout. If a
// driver upgrade ever makes deferred transactions wait, this fails and the
// comment in sqliteDSN must be revisited. Never delete it.
func TestUpsert_DeferredTxFailsFastUnderAnotherWriter(t *testing.T) {
	path := t.TempDir() + "/relay.db"
	st, err := Open(path) // applies the schema
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatalf("sqliteDSN: %v", err)
	}
	base, rawQuery, _ := strings.Cut(dsn, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	q.Del("_txlock")
	db, err := sql.Open("sqlite", base+"?"+q.Encode())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	reg := &sqliteRegistry{db: db, connected: map[string]struct{}{}}

	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	holdWriteLock(t, path)
	assertLockHeld(t, path)

	start := time.Now()
	_, err = reg.Upsert(registry.Report{NodeID: "node-a", DaemonVersion: "1.0.0", PolicyFingerprint: "fp"})
	if err == nil {
		t.Fatal("deferred Upsert succeeded under another writer; the premise of _txlock is gone")
	}
	if !strings.Contains(err.Error(), "SQLITE_BUSY") && !strings.Contains(err.Error(), "locked") {
		t.Errorf("err = %v, want SQLITE_BUSY or locked", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("failed after %v, want fast failure well under the busy timeout", elapsed)
	}
}

// TestJobQuery_CountMatchingTakesNoWriteLock proves the ReadOnly opt-out: the
// count snapshot must not queue behind, or block, a writer.
func TestJobQuery_CountMatchingTakesNoWriteLock(t *testing.T) {
	st, path := openTestStore(t)
	holdWriteLock(t, path)

	start := time.Now()
	if _, err := st.JobQueries().QueryJobs(context.Background(), jobs.JobQuery{CountMatching: true}, 10, ""); err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("QueryJobs took %v under a held write lock, want a lock-free read", elapsed)
	}
}
