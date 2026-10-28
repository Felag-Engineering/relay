package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// grant_history_test.go proves that history written while approval grants
// existed survives their removal: the audit records keep their grant_id and
// the chain over them verifies, and the approval_grants table is left in place.

// insertHistoricalGrant writes an approval_grants row by raw SQL, as one
// written while grants existed. No current code path writes one.
func insertHistoricalGrant(t *testing.T, db *sql.DB, requestID, grantID string) {
	t.Helper()
	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`
		INSERT INTO approval_grants (
			grant_id, request_id, scope_account, scope_risk_class, scope_max_fan_out,
			scope_operations, scope_raw_exec, starts_at, expires_at, max_uses, uses,
			summary, created_at
		) VALUES (?, ?, 'gleipnir-prod', 'mutate', 10, 'service.restart', 0, ?, ?, 20, 3, 'a historical grant', ?)`,
		grantID, requestID, formatTime(at), formatTime(at.Add(2*time.Hour)), formatTime(at),
	); err != nil {
		t.Fatalf("insert historical grant: %v", err)
	}
}

// TestStore_GrantLinkedHistoryVerifiesAndReadsBack: records carrying a grant_id
// are chained, read back by the grant and approval lanes, and verify after the
// store is reopened (which runs migrate and the backfill), with the
// approval_grants row and its authorizing request untouched.
func TestStore_GrantLinkedHistoryVerifiesAndReadsBack(t *testing.T) {
	ctx := context.Background()
	st, path := openTestStore(t)

	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	grantRecords := []audit.Record{
		approvalLinkedRecord("g1", audit.KindApprovalGrantRequested, "appr-g", "g-1", at),
		approvalLinkedRecord("g2", audit.KindDispatch, "appr-g", "g-1", at.Add(time.Minute)),
		approvalLinkedRecord("g3", audit.KindDispatch, "appr-g", "g-1", at.Add(2*time.Minute)),
		approvalLinkedRecord("g4", audit.KindDispatchIntent, "appr-g", "g-1", at.Add(3*time.Minute)),
		approvalLinkedRecord("g5", audit.KindApprovalDecided, "appr-g", "g-1", at.Add(4*time.Minute)),
	}
	for _, r := range grantRecords {
		if err := st.Audit().Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}
	if err := st.Approvals().Create(ctx, pendingRequest("appr-g", "grant-subject-hash", 1, time.Hour)); err != nil {
		t.Fatalf("create request: %v", err)
	}
	insertHistoricalGrant(t, st.db, "appr-g", "g-1")

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	verdict, err := VerifyAuditChain(ctx, path, nil)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !verdict.Intact() {
		t.Errorf("chain over grant-linked records is not intact: %+v", verdict)
	}

	byGrant, err := st.Audit().ByGrant(ctx, "g-1")
	if err != nil {
		t.Fatalf("ByGrant: %v", err)
	}
	if len(byGrant) != len(grantRecords) {
		t.Fatalf("ByGrant returned %d records, want %d", len(byGrant), len(grantRecords))
	}
	for _, r := range byGrant {
		if r.GrantID != "g-1" {
			t.Errorf("ByGrant returned record %q with grant %q", r.ID, r.GrantID)
		}
	}

	byApproval, err := st.Audit().ByApproval(ctx, "appr-g")
	if err != nil {
		t.Fatalf("ByApproval: %v", err)
	}
	if len(byApproval) != len(grantRecords) {
		t.Errorf("ByApproval returned %d records, want %d", len(byApproval), len(grantRecords))
	}

	page, err := st.AuditQueries().Query(ctx, audit.Query{GrantID: "g-1"}, 0, "")
	if err != nil {
		t.Fatalf("Query by grant: %v", err)
	}
	if len(page.Rows) != len(grantRecords) {
		t.Errorf("audit-query lane returned %d rows for the grant, want %d", len(page.Rows), len(grantRecords))
	}
	for _, row := range page.Rows {
		if row.GrantID != "g-1" {
			t.Errorf("audit-query row %q has grant %q, want g-1", row.ID, row.GrantID)
		}
	}

	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM approval_grants WHERE grant_id = 'g-1'`).Scan(&n); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if n != 1 {
		t.Errorf("approval_grants rows for g-1 = %d, want 1: the table must be left in place", n)
	}
	if _, err := st.Approvals().Get(ctx, "appr-g"); err != nil {
		t.Errorf("Approvals().Get(appr-g): %v, want the request to read back", err)
	}
}
