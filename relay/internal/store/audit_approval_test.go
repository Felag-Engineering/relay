package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
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

// TestAudit_ByApprovalAnswersTheWholeStory is docs/specs/approval.md's acceptance
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

// TestAudit_DecisionAnswerRoundTrips (#545): approval_answer, decision_channel,
// and plan_hash survive a write and a read, and an answerless row — a grant
// revocation, or a row written before this migration — reads back "" on all
// three, never something that reads as a denial (the #487 lesson).
func TestAudit_DecisionAnswerRoundTrips(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	approved := audit.Record{
		ID: "d1", Timestamp: at, Kind: audit.KindApprovalDecided,
		Principal: "ana:operator", ApprovalID: "appr-1",
		ApprovalAnswer: audit.ApprovalAnswerApproved, DecisionChannel: "out_of_band", PlanHash: "hash-1",
	}
	denied := audit.Record{
		ID: "d2", Timestamp: at.Add(time.Minute), Kind: audit.KindApprovalDecided,
		Principal: "bo:operator", ApprovalID: "appr-2",
		ApprovalAnswer: audit.ApprovalAnswerDenied, DecisionChannel: "in_band", PlanHash: "hash-2",
	}
	answerless := audit.Record{
		ID: "d3", Timestamp: at.Add(2 * time.Minute), Kind: audit.KindApprovalDecided,
		Principal: "ops-console:admin", ApprovalID: "appr-3", GrantID: "grant-1",
	}

	for _, r := range []audit.Record{approved, denied, answerless} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("list: %v (%d records)", err, len(got))
	}
	byID := map[string]audit.Record{}
	for _, r := range got {
		byID[r.ID] = r
	}

	if got := byID["d1"]; got.ApprovalAnswer != audit.ApprovalAnswerApproved || got.DecisionChannel != "out_of_band" || got.PlanHash != "hash-1" {
		t.Errorf("approved record = %+v, want answer/channel/hash from the write", got)
	}
	if got := byID["d2"]; got.ApprovalAnswer != audit.ApprovalAnswerDenied || got.DecisionChannel != "in_band" || got.PlanHash != "hash-2" {
		t.Errorf("denied record = %+v, want answer/channel/hash from the write", got)
	}
	if got := byID["d3"]; got.ApprovalAnswer != "" || got.DecisionChannel != "" || got.PlanHash != "" {
		t.Errorf("answerless record = %+v, want all three empty — a NULL row must never read back as denied", got)
	}
}
