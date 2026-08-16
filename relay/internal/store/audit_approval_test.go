package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// audit_approval_test.go covers the approval link on the audit trail (#378,
// ADR-0027): the columns that turn "which Jobs did that approval release" from
// a grep over free text into a WHERE clause.

func approvalLinkedRecord(id, kind, approvalID, grantID string, at time.Time) audit.Record {
	return audit.Record{
		ID:         id,
		Timestamp:  at,
		Kind:       kind,
		Principal:  "gleipnir:operator",
		Selector:   "tag:batch=nginx",
		JobID:      "job-" + id,
		ActionKind: "operation",
		ApprovalID: approvalID,
		GrantID:    grantID,
	}
}

// TestAudit_ApprovalLinkRoundTrips: both columns survive a write and a read,
// and an unlinked record reads back empty rather than as some sentinel — empty
// means "no approval was involved", never "unknown".
func TestAudit_ApprovalLinkRoundTrips(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	linked := approvalLinkedRecord("a1", audit.KindDispatch, "appr-1", "grant-1", at)
	unlinked := approvalLinkedRecord("a2", audit.KindDispatch, "", "", at.Add(time.Minute))

	for _, r := range []audit.Record{linked, unlinked} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %v (%d records)", err, len(got))
	}
	if got[0].ApprovalID != "appr-1" || got[0].GrantID != "grant-1" {
		t.Errorf("linked record = approval %q grant %q, want appr-1/grant-1", got[0].ApprovalID, got[0].GrantID)
	}
	if got[1].ApprovalID != "" || got[1].GrantID != "" {
		t.Errorf("unlinked record = approval %q grant %q, want both empty", got[1].ApprovalID, got[1].GrantID)
	}
}

// TestAudit_ByApprovalAnswersTheWholeStory is the ROADMAP's acceptance
// criterion for grants: "every covered Job auditing to the same approval ID".
//
// One query over the grant's authorizing Request returns the park, the
// decision, and every dispatch the window released — the whole story in one
// place, which is the point of the column existing at all.
func TestAudit_ByApprovalAnswersTheWholeStory(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	records := []audit.Record{
		approvalLinkedRecord("r1", audit.KindApprovalRequested, "appr-1", "grant-1", at),
		approvalLinkedRecord("r2", audit.KindApprovalDecided, "appr-1", "grant-1", at.Add(time.Minute)),
		approvalLinkedRecord("r3", audit.KindDispatch, "appr-1", "grant-1", at.Add(2*time.Minute)),
		approvalLinkedRecord("r4", audit.KindDispatch, "appr-1", "grant-1", at.Add(3*time.Minute)),
		// A different approval entirely, and an unapproved dispatch: neither
		// may appear in the answer.
		approvalLinkedRecord("r5", audit.KindDispatch, "appr-2", "", at.Add(4*time.Minute)),
		approvalLinkedRecord("r6", audit.KindDispatch, "", "", at.Add(5*time.Minute)),
	}
	for _, r := range records {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	got, err := repo.ByApproval(ctx, "appr-1")
	if err != nil {
		t.Fatalf("ByApproval: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("ByApproval returned %d records, want 4 (the park, the decision, and both released dispatches)", len(got))
	}
	for i, want := range []string{"r1", "r2", "r3", "r4"} {
		if got[i].ID != want {
			t.Errorf("record %d = %q, want %q in timestamp order", i, got[i].ID, want)
		}
	}

	// ByGrant is the narrower question — what the window actually released —
	// and here it happens to include the park and decision because those were
	// written against the grant too. What matters is that it never crosses to
	// another grant, and never picks up an unapproved dispatch.
	byGrant, err := repo.ByGrant(ctx, "grant-1")
	if err != nil {
		t.Fatalf("ByGrant: %v", err)
	}
	for _, r := range byGrant {
		if r.GrantID != "grant-1" {
			t.Errorf("ByGrant returned record %q with grant %q", r.ID, r.GrantID)
		}
	}
	if len(byGrant) != 4 {
		t.Errorf("ByGrant returned %d records, want 4", len(byGrant))
	}

	// An unknown ID is an empty answer, not an error and not everything —
	// a query that silently degraded to "no filter" would be the worst possible
	// failure mode for an audit trail.
	none, err := repo.ByGrant(ctx, "grant-nope")
	if err != nil {
		t.Fatalf("ByGrant(unknown): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("ByGrant(unknown) returned %d records, want 0", len(none))
	}
}
