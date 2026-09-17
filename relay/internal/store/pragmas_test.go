package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sqlite "modernc.org/sqlite"
)

// cancelInFlight holds a context.CancelFunc that
// relay_test_cancel_in_flight, a SQL scalar function registered below, calls
// exactly once when invoked. It exists so a test can cancel its own context
// from INSIDE a running statement — the one event that reliably makes
// modernc.org/sqlite discard the connection (see the doc comment on
// TestOpen_ReplacedConnectionKeepsPragmas).
var cancelInFlight atomic.Pointer[context.CancelFunc]

// init registers relay_test_cancel_in_flight before any test in this package
// opens a connection. modernc.org/sqlite's RegisterScalarFunction writes a
// driver-global map and only affects connections opened afterwards, so
// registering here — rather than inside a test — guarantees every store
// connection in this binary has the function, and never races the
// t.Parallel tests elsewhere in this package (registry_test.go,
// labelscan_test.go) under -race. The function is otherwise inert: it does
// nothing unless a test has stored a cancel func in cancelInFlight.
func init() {
	sqlite.MustRegisterScalarFunction("relay_test_cancel_in_flight", 1, cancelInFlightUDF)
}

func cancelInFlightUDF(_ *sqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
	if cancel := cancelInFlight.Swap(nil); cancel != nil {
		(*cancel)()
	}
	return int64(1), nil
}

// connPragmas reads the per-connection foreign_keys and busy_timeout pragma
// values off whichever connection the pool hands back for this query.
func connPragmas(t *testing.T, db *sql.DB) (foreignKeys, busyTimeout int) {
	t.Helper()
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	return foreignKeys, busyTimeout
}

// markConn creates a TEMP table that exists only on the connection that
// created it, so connMarked can later prove whether the pool handed back the
// same underlying connection or a replacement.
func markConn(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TEMP TABLE conn_identity_marker (x INTEGER)`); err != nil {
		t.Fatalf("mark connection: %v", err)
	}
}

// connMarked reports whether the connection the pool hands back for this
// query still has the TEMP table markConn created.
func connMarked(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM temp.sqlite_master WHERE name = 'conn_identity_marker'`).Scan(&n); err != nil {
		t.Fatalf("check connection marker: %v", err)
	}
	return n == 1
}

// TestOpen_ReplacedConnectionKeepsPragmas is the regression test for a bug in
// store.Open: it used to apply foreign_keys and busy_timeout once, through
// db.Exec, onto whichever connection the pool happened to hold. Both are
// per-connection SQLite settings, so a connection database/sql opens to
// replace one it discarded came up with foreign keys off and no busy
// timeout.
//
// The trigger is a context cancelled WHILE a statement is running outside a
// transaction — not a context cancelled mid-transaction, which might look
// like the obvious trigger. With modernc.org/sqlite v1.53.0, cancelling
// mid-transaction does not replace the connection: the Tx's ROLLBACK runs on
// the connection first and clears SQLite's interrupt flag, so database/sql's
// IsValid check sees a usable connection and returns it to the pool. A test
// built on that event would pass vacuously — on both the old code and the
// new. A statement cancelled outside a transaction (for example, a request
// context cancelled by a client disconnect while a query runs) does not get
// that ROLLBACK, so the interrupt flag is still set when the connection is
// checked in, and the pool discards it. Conn.Raw returning driver.ErrBadConn
// is database/sql's own, timing-independent discard path, and is tested as a
// second trigger.
//
// Proof that the connection was actually replaced is a TEMP table (markConn/
// connMarked): TEMP tables are visible only on the connection that created
// them, and db.Stats() does not count either of these discards.
func TestOpen_ReplacedConnectionKeepsPragmas(t *testing.T) {
	forceReplacement := map[string]func(t *testing.T, db *sql.DB){
		"context cancelled mid-statement": func(t *testing.T, db *sql.DB) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cancelInFlight.Store(&cancel)
			t.Cleanup(func() { cancelInFlight.Store(nil) })

			_, err := db.ExecContext(ctx, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c WHERE relay_test_cancel_in_flight(x)`)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ExecContext error = %v, want context.Canceled", err)
			}
		},
		"driver reports bad connection": func(t *testing.T, db *sql.DB) {
			t.Helper()
			ctx := context.Background()
			c, err := db.Conn(ctx)
			if err != nil {
				t.Fatalf("Conn: %v", err)
			}
			err = c.Raw(func(any) error { return driver.ErrBadConn })
			if !errors.Is(err, driver.ErrBadConn) {
				t.Fatalf("Raw error = %v, want driver.ErrBadConn", err)
			}
			c.Close() //nolint:errcheck // sql.ErrConnDone after ErrBadConn; nothing to act on
		},
	}

	for name, force := range forceReplacement {
		t.Run(name, func(t *testing.T) {
			st, _ := openTestStore(t)

			// Sanity: the marker and pragmas both read as expected on the
			// first connection, before anything forces a replacement.
			markConn(t, st.db)
			if !connMarked(t, st.db) {
				t.Fatal("connection marker missing before forcing a replacement")
			}
			if fk, bt := connPragmas(t, st.db); fk != 1 || bt != busyTimeoutMillis {
				t.Fatalf("pragmas before replacement = (foreign_keys=%d, busy_timeout=%d), want (1, %d)", fk, bt, busyTimeoutMillis)
			}

			force(t, st.db)

			if connMarked(t, st.db) {
				t.Fatal("connection was not replaced; the test would pass vacuously")
			}
			fk, bt := connPragmas(t, st.db)
			if fk != 1 {
				t.Errorf("foreign_keys on replacement connection = %d, want 1 (replacement connection lost it)", fk)
			}
			if bt != busyTimeoutMillis {
				t.Errorf("busy_timeout on replacement connection = %d, want %d (replacement connection lost it)", bt, busyTimeoutMillis)
			}
		})
	}
}

// TestOpen_PathWithURIMetacharacters asserts that Open creates exactly the
// file named by a path containing "?", "#", "%", and a space — not a
// truncated or differently-escaped one — and that the resulting connection
// still has both pragmas.
func TestOpen_PathWithURIMetacharacters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a?b#c%d e", "relay.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	if _, err := os.Stat(path); err != nil {
		t.Errorf("os.Stat(%q): %v", path, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "a?b#c%d e" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("os.ReadDir(%q) entries = %v, want exactly [\"a?b#c%%d e\"]", dir, names)
	}

	if fk, bt := connPragmas(t, st.db); fk != 1 || bt != busyTimeoutMillis {
		t.Errorf("pragmas = (foreign_keys=%d, busy_timeout=%d), want (1, %d)", fk, bt, busyTimeoutMillis)
	}
}

// TestOpen_RelativePathResolvesAgainstWorkingDir guards against the
// URI-authority trap: url.URL.String() renders a relative path as
// "file://relay-data/...", which SQLite reads as a URI authority rather than
// part of the path. sqliteDSN uses EscapedPath after filepath.Abs instead, so
// a relative path (the shape of main.go's default "./relay-data/relay.db")
// still resolves against the working directory, exactly as it did before
// this change.
//
// Not run in parallel: it changes the process's working directory via
// t.Chdir.
func TestOpen_RelativePathResolvesAgainstWorkingDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	st, err := Open(filepath.Join("relay-data", "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	if _, err := os.Stat(filepath.Join(dir, "relay-data", "relay.db")); err != nil {
		t.Errorf("os.Stat: %v", err)
	}
}
