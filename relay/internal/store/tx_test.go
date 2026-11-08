package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestInTx(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE t (v INTEGER)`); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("commits when fn succeeds", func(t *testing.T) {
		err := inTx(ctx, db, "b", "c", func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO t VALUES (1)`)
			return err
		})
		if err != nil || count() != 1 {
			t.Fatalf("err=%v count=%d, want nil and 1", err, count())
		}
	})

	t.Run("rolls back and returns fn's error unchanged", func(t *testing.T) {
		sentinel := errors.New("sentinel")
		err := inTx(ctx, db, "b", "c", func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES (2)`); err != nil {
				return err
			}
			return sentinel
		})
		if err != sentinel { //nolint:errorlint // the contract is that the error is not wrapped
			t.Fatalf("err=%v, want the sentinel itself", err)
		}
		if count() != 1 {
			t.Fatalf("count=%d, want 1: the insert must roll back", count())
		}
	})

	t.Run("names the operation when begin fails", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		called := false
		err := inTx(cctx, db, "my op", "c", func(*sql.Tx) error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("err=%v called=%v, want a begin error and fn not run", err, called)
		}
		if got, want := err.Error()[:len("begin my op: ")], "begin my op: "; got != want {
			t.Fatalf("err=%q, want prefix %q", err, want)
		}
	})
}
