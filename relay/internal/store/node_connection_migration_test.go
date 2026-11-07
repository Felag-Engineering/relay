package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestMigration0036_BackfillsFirstConnectedAtFromAnEarlierConnect drives the
// real upgrade path: a database seeded without migration 36 holds Nodes
// written the old way. A Node with a stored daemon version or Policy
// fingerprint connected before, so its first_connected_at is backfilled from
// last_seen (an upper bound). A Node with neither is the stated gap: it reads
// as never connected.
func TestMigration0036_BackfillsFirstConnectedAtFromAnEarlierConnect(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema35.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 36)
	if name := migrationByVersion(t, 36).name; !strings.Contains(name, "node_connection") {
		t.Fatalf("migration 36 is %q, want the node connection observations migration", name)
	}

	policyFP := strings.Repeat("ab", 32)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rows := []struct {
		id, policy, version string
		lastSeen            time.Time
	}{
		{"has-version", "", "1.0.0", base.Add(1 * time.Hour)},
		{"has-policy", policyFP, "", base.Add(2 * time.Hour)},
		{"enrolled-only", "", "", base.Add(3 * time.Hour)},
	}
	for _, r := range rows {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO nodes (node_id, cert_fingerprint, hostname, os, kernel, arch,
				enrolling_token_id, policy_fingerprint, daemon_version, last_seen)
			VALUES (?, 'fp', 'h', 'linux', 'k', 'amd64', 'tok', ?, ?, ?)`,
			r.id, r.policy, r.version, formatTime(r.lastSeen)); err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-0036 database: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for _, r := range rows {
		n, ok := st.Registry().Get(r.id)
		if !ok {
			t.Fatalf("Get %s: not found", r.id)
		}
		wantFirst := r.lastSeen
		if r.id == "enrolled-only" {
			wantFirst = time.Time{}
		}
		if !n.FirstConnectedAt.Equal(wantFirst) {
			t.Errorf("%s FirstConnectedAt = %v, want %v", r.id, n.FirstConnectedAt, wantFirst)
		}
		if n.ReportedRawExec != registry.RawExecNotReported {
			t.Errorf("%s ReportedRawExec = %v, want not reported", r.id, n.ReportedRawExec)
		}
		if n.ClockSkewKnown() {
			t.Errorf("%s clock skew reads as known after the migration", r.id)
		}
	}
}

// TestMigration0036_ColumnsAreNullable pins that NULL stays the honest "not
// reported", "never connected" and "not measured": no NOT NULL, no default.
func TestMigration0036_ColumnsAreNullable(t *testing.T) {
	st, _ := openTestStore(t)

	rows, err := st.db.Query(`PRAGMA table_info(nodes)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()

	want := map[string]bool{
		"reported_raw_exec": false, "first_connected_at": false,
		"clock_skew_ms": false, "clock_skew_measured_at": false,
	}
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, ok := want[name]; !ok {
			continue
		}
		want[name] = true
		if notNull != 0 || dflt.Valid {
			t.Errorf("column %s: notnull=%d default=%v, want nullable with no default", name, notNull, dflt)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("column %s is missing from nodes", name)
		}
	}
}
