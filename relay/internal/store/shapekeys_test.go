package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

var backfillNow = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)

// openStore opens a store and hands back the raw handle too, so a backfill test
// can simulate a pre-#415 row (an empty shape_key) the write path can no longer
// produce.
func openStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, st.db
}

func blankShapeKeys(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`UPDATE approval_requests SET shape_key = ''`); err != nil {
		t.Fatalf("blank shape keys: %v", err)
	}
}

func shapeKeyOf(t *testing.T, db *sql.DB, requestID string) string {
	t.Helper()
	var key string
	if err := db.QueryRow(`SELECT shape_key FROM approval_requests WHERE request_id = ?`, requestID).Scan(&key); err != nil {
		t.Fatalf("read shape key for %q: %v", requestID, err)
	}
	return key
}

// seedGrantRequest creates a Grant and its authorizing Request through the
// normal write path, so the row the backfill later repairs is a real one.
func seedGrantRequest(t *testing.T, st *Store, requestID, grantID string, scope approval.Scope) approval.Grant {
	t.Helper()
	ctx := context.Background()
	g := approval.Grant{
		ID:        grantID,
		RequestID: requestID,
		Scope:     scope,
		StartsAt:  backfillNow,
		ExpiresAt: backfillNow.Add(2 * time.Hour),
		MaxUses:   20,
		Summary:   approval.SummarizeScope(scope, backfillNow, backfillNow.Add(2*time.Hour), 20),
		CreatedAt: backfillNow,
	}
	r := approval.NewGrantRequest(g, "acct-g", "gleipnir-prod", []string{"batch-rule"},
		approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour}, backfillNow)
	if err := st.Approvals().Create(ctx, r); err != nil {
		t.Fatalf("create grant request: %v", err)
	}
	if err := st.Grants().CreateGrant(ctx, g); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	return g
}

func backfillScope() approval.Scope {
	return approval.Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  10,
		Operations: []string{"service.restart", "pkg.install"},
		RawExec:    true,
	}
}

// TestBackfill_RecomputesGrantRequestsExactly is acceptance 5 for the case
// where the truth survives: a Grant's Scope is fully stored, so its shape key
// is recomputed rather than guessed — and it comes out equal to what a freshly
// created identical Grant gets, because the backfill calls the SAME function
// the write path calls.
func TestBackfill_RecomputesGrantRequestsExactly(t *testing.T) {
	st, db := openStore(t)
	scope := backfillScope()
	g := seedGrantRequest(t, st, "req-grant", "grant-1", scope)

	fresh := shapeKeyOf(t, db, "req-grant")
	blankShapeKeys(t, db)
	if err := backfillShapeKeys(context.Background(), db); err != nil {
		t.Fatalf("backfillShapeKeys: %v", err)
	}

	restored := shapeKeyOf(t, db, "req-grant")
	if restored != approval.HashGrantShape(scope) {
		t.Errorf("restored key = %q, want HashGrantShape(scope) = %q", restored, approval.HashGrantShape(scope))
	}
	if restored != g.ShapeKey() {
		t.Errorf("restored key = %q, want the Grant's own key %q", restored, g.ShapeKey())
	}
	if restored != fresh {
		t.Errorf("restored key = %q, want the key a fresh write produced %q", restored, fresh)
	}
	if approval.IsLegacyShapeKey(restored) {
		t.Error("a recomputable grant request was stamped legacy")
	}
}

// TestBackfill_RecomputesALegacyPinnedGrantRequestExactly is
// TestBackfill_RecomputesGrantRequestsExactly's sibling for a pre-#482 row: a
// Grant stored with a namespace pin (scope_selector_namespace still holding a
// value) must recompute to exactly the shape key a Grant carrying that value
// as LegacyNamespacePin would produce — because that is what scanGrant reads
// it back as.
func TestBackfill_RecomputesALegacyPinnedGrantRequestExactly(t *testing.T) {
	st, db := openStore(t)
	scope := backfillScope()
	seedGrantRequest(t, st, "req-grant", "grant-1", scope)
	if _, err := db.Exec(`UPDATE approval_grants SET scope_selector_namespace = 'node' WHERE grant_id = 'grant-1'`); err != nil {
		t.Fatalf("pin the stored grant: %v", err)
	}

	blankShapeKeys(t, db)
	if err := backfillShapeKeys(context.Background(), db); err != nil {
		t.Fatalf("backfillShapeKeys: %v", err)
	}

	restored := shapeKeyOf(t, db, "req-grant")
	want := approval.Grant{Scope: scope, LegacyNamespacePin: "node"}.ShapeKey()
	if restored != want {
		t.Errorf("restored key = %q, want the legacy-pinned Grant's own key %q", restored, want)
	}
}

// TestBackfill_IsIdempotent: every key is byte-identical after a re-run, and a
// row that already has a key is never rewritten — the empty-shape_key WHERE
// guard is what makes running this on every Open safe.
func TestBackfill_IsIdempotent(t *testing.T) {
	st, db := openStore(t)
	seedGrantRequest(t, st, "req-grant", "grant-1", backfillScope())
	if err := st.Approvals().Create(context.Background(),
		pendingRequest("req-plan", "hash-plan", 1, time.Hour)); err != nil {
		t.Fatalf("create plan request: %v", err)
	}
	blankShapeKeys(t, db)

	ctx := context.Background()
	if err := backfillShapeKeys(ctx, db); err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	first := map[string]string{
		"req-grant": shapeKeyOf(t, db, "req-grant"),
		"req-plan":  shapeKeyOf(t, db, "req-plan"),
	}

	for run := range 2 {
		if err := backfillShapeKeys(ctx, db); err != nil {
			t.Fatalf("re-run %d: %v", run, err)
		}
		for id, want := range first {
			if got := shapeKeyOf(t, db, id); got != want {
				t.Errorf("re-run %d changed %s: %q, want %q", run, id, got, want)
			}
		}
	}

	// A record written by TODAY's write path must survive the backfill
	// untouched: it already has a real key, and overwriting it with a legacy
	// stamp would destroy a shape that IS known.
	if err := st.Approvals().Create(ctx, pendingRequest("req-fresh", "hash-fresh", 1, time.Hour)); err != nil {
		t.Fatalf("create fresh request: %v", err)
	}
	fresh := shapeKeyOf(t, db, "req-fresh")
	if err := backfillShapeKeys(ctx, db); err != nil {
		t.Fatalf("backfill after a fresh write: %v", err)
	}
	if got := shapeKeyOf(t, db, "req-fresh"); got != fresh {
		t.Errorf("the backfill rewrote a row that already had a key: %q, want %q", got, fresh)
	}
}

// TestBackfill_PlanRequestsGetUniqueLegacyKeys: a pre-#415 Plan record's true
// shape cannot be recomputed — approval_requests never stored the Selector or
// the arguments — so each becomes ITS OWN shape. A shared constant here would
// put every historical record into one bogus "same shape" bucket, which is
// exactly the "materially different action reads as routine" failure.
func TestBackfill_PlanRequestsGetUniqueLegacyKeys(t *testing.T) {
	st, db := openStore(t)
	ctx := context.Background()
	for _, id := range []string{"req-a", "req-b"} {
		if err := st.Approvals().Create(ctx, pendingRequest(id, "hash-"+id, 1, time.Hour)); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	blankShapeKeys(t, db)
	if err := backfillShapeKeys(ctx, db); err != nil {
		t.Fatalf("backfillShapeKeys: %v", err)
	}

	a, b := shapeKeyOf(t, db, "req-a"), shapeKeyOf(t, db, "req-b")
	if a == b {
		t.Error("two legacy records share a key; every historical record would read as the same shape")
	}
	for id, got := range map[string]string{"req-a": a, "req-b": b} {
		if want := approval.LegacyShapeKey(id); got != want {
			t.Errorf("%s: shape key = %q, want %q — the SQL literal and approval.LegacyShapePrefix have drifted", id, got, want)
		}
	}

	// And the read seam refuses them, so no diff is ever rendered against a
	// record whose shape nobody knows.
	if _, err := st.Approvals().LastApprovedByShape(ctx, a, ""); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("LastApprovedByShape(legacy key) = %v, want ErrNotFound", err)
	}
}

// TestBackfill_GrantRequestsAreNotLegacyStamped: with both kinds present, Pass
// A wins for the grant request. Reordering or merging the two passes would let
// the legacy fill consume the rows that CAN be recomputed.
func TestBackfill_GrantRequestsAreNotLegacyStamped(t *testing.T) {
	st, db := openStore(t)
	ctx := context.Background()
	seedGrantRequest(t, st, "req-grant", "grant-1", backfillScope())
	if err := st.Approvals().Create(ctx, pendingRequest("req-plan", "hash-plan", 1, time.Hour)); err != nil {
		t.Fatalf("create plan request: %v", err)
	}
	blankShapeKeys(t, db)
	if err := backfillShapeKeys(ctx, db); err != nil {
		t.Fatalf("backfillShapeKeys: %v", err)
	}

	if got, want := shapeKeyOf(t, db, "req-grant"), approval.HashGrantShape(backfillScope()); got != want {
		t.Errorf("grant request key = %q, want the recomputed %q", got, want)
	}
	if got, want := shapeKeyOf(t, db, "req-plan"), approval.LegacyShapeKey("req-plan"); got != want {
		t.Errorf("plan request key = %q, want %q", got, want)
	}
}

// TestOpen_AppliesMigration0022AndBackfills drives the real upgrade path: a
// database built at schema 21 — the highest version before this change — is
// reopened by today's Open.
//
// Seeding at schema 21 rather than opening a fresh database is what makes this
// the UPGRADE path: on a fresh database migrate applies every embedded file
// regardless of numbering, so nothing there can distinguish a well-numbered
// migration from a mis-numbered one. Selection is by per-version presence in
// schema_migrations, not by comparison against the highest version recorded
// (#492) — so what actually exercises the upgrade path here is that only
// versions 1-21 are recorded as applied; migrate finds 22 absent and applies
// it regardless of how it compares numerically to 21. The seed loop's
// `applied != 21` assertion no longer guards against a silent skip (that
// failure mode no longer exists); it now guards the test's own seeding
// assumption — that the pre-#415 schema really is 21 files — so a stray or
// missing migration in that range fails loudly here instead of quietly
// changing what this test seeds.
func TestOpen_AppliesMigration0022AndBackfills(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema21.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	applied := 0
	for _, m := range migrations {
		if m.version > 21 {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
		applied++
	}
	if applied != 21 {
		t.Fatalf("applied %d migrations, want 21 — the pre-#415 schema is not what this test assumes", applied)
	}

	// Two pre-#415 rows written by hand, because the schema they live in has no
	// shape_key column for the write path to fill.
	insert := func(requestID string) {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO approval_requests (
				request_id, plan_hash, requested_by_id, requested_by, plan_summary,
				matched_rules, action_kind, risk_class,
				require_count, require_audience, requester_allowed, require_channel, require_ttl_ns,
				state, created_at, expires_at, resolved_at
			) VALUES (?, ?, 'acct-g', 'gleipnir-prod', 'something old', 'rule-a', 'operation', 'mutate',
			          1, '', 0, 2, 3600000000000, 0, ?, ?, '')`,
			requestID, "hash-"+requestID,
			backfillNow.Format(time.RFC3339Nano), backfillNow.Add(time.Hour).Format(time.RFC3339Nano),
		); err != nil {
			t.Fatalf("insert %s: %v", requestID, err)
		}
	}
	insert("req-old-a")
	insert("req-old-b")
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a schema-21 database: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	a, b := shapeKeyOf(t, st.db, "req-old-a"), shapeKeyOf(t, st.db, "req-old-b")
	if a == "" || b == "" {
		t.Fatalf("Open left an empty shape key: %q, %q", a, b)
	}
	if a == b {
		t.Error("two pre-#415 records share a shape key")
	}
	if !approval.IsLegacyShapeKey(a) || !approval.IsLegacyShapeKey(b) {
		t.Errorf("pre-#415 Plan records got non-legacy keys (%q, %q); their true shape is not recoverable", a, b)
	}
}
