package auditquery

import (
	"context"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// TestQueryAudit_AProtocolViolationIsQueryableByKind is #638's headline
// acceptance test: "no queryable event exists" was the issue's first
// measured gap, so this proves the opposite — a Kind filter over the real
// capability.Service.QueryAudit seam, the one every trail surface reads
// through, returns the violation row with the facts an operator or
// AI-agent needs and with no authenticated actor attached to the Node.
func TestQueryAudit_AProtocolViolationIsQueryableByKind(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	sink := auditsink.New(st.Audit())
	q := New(st.AuditQueries(), st.JobQueries())
	svc := capability.New(registry.NewInMemory(),
		capability.WithAuditSink(sink),
		capability.WithQueries(q, q))

	if err := sink.RecordProtocolViolation(ctx, jobs.ProtocolViolationEvent{
		NodeID:        "node-1",
		TaskID:        "task-1",
		JobID:         "job-1",
		OperationName: "list_files",
		Violation: jobs.ProtocolViolation{
			Rule:            jobs.ViolationRelayOnlyOutcome,
			ReportedOutcome: "OUTCOME_VERSION_REFUSED",
		},
	}); err != nil {
		t.Fatalf("RecordProtocolViolation: %v", err)
	}
	// An unrelated record, so the Kind filter has something to exclude.
	if err := sink.RecordRead(ctx, capability.Principal{Account: "alice"}, "query_audit", "", "", ""); err != nil {
		t.Fatalf("RecordRead: %v", err)
	}

	principal := capability.Principal{Account: "alice", Role: "operator"}
	page, err := svc.QueryAudit(ctx, principal,
		capability.AuditFilter{Kinds: []string{audit.KindProtocolViolation}},
		capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("QueryAudit returned %d rows, want exactly 1", len(page.Rows))
	}
	row := page.Rows[0]
	if row.Kind != audit.KindProtocolViolation {
		t.Errorf("row.Kind = %q, want %q", row.Kind, audit.KindProtocolViolation)
	}
	if row.NodeID != "node-1" {
		t.Errorf("row.NodeID = %q, want node-1", row.NodeID)
	}
	if !strings.Contains(row.Reason, "rule=relay_only_outcome") {
		t.Errorf("row.Reason = %q, want it to contain rule=relay_only_outcome", row.Reason)
	}
	if !strings.Contains(row.Reason, "reported_outcome=OUTCOME_VERSION_REFUSED") {
		t.Errorf("row.Reason = %q, want it to contain reported_outcome=OUTCOME_VERSION_REFUSED", row.Reason)
	}
	if !strings.Contains(row.Reason, "task_id=task-1") {
		t.Errorf("row.Reason = %q, want it to contain task_id=task-1", row.Reason)
	}
	if row.Principal != "" {
		t.Errorf("row.Principal = %q, want empty — the Node is never rendered as an authenticated actor", row.Principal)
	}
	if row.Verified.AccountID != "" {
		t.Errorf("row.Verified.AccountID = %q, want empty", row.Verified.AccountID)
	}
}
