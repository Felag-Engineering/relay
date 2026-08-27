package auditquery

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// openQueryStore opens a temp SQLite store, mirroring auditsink_test.go's
// openSinkStore.
func openQueryStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st
}

// TestQueries_QueryAudit_RoundTrips is the mapping's audit half: a Record
// written through the real store comes back through Queries.QueryAudit with
// every AuditRow field intact, and every field of the capability.AuditFilter
// that was passed reaches the store (proven by the filter actually
// selecting/excluding the right rows).
func TestQueries_QueryAudit_RoundTrips(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rec := audit.Record{
		ID:        "audit-1",
		Timestamp: ts,
		Kind:      audit.KindRead,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID: "acct-1", AccountName: "gleipnir", Role: "operator",
				TokenID: "tok-1", Method: "api_token", Source: "10.0.0.1",
			},
			Asserted: audit.Asserted{
				OnBehalfOf: "ops-team", Traceparent: "00-trace", SessionRef: "sess-1", ChangeRef: "CHG-1",
			},
		},
		Selector:      "relay:env=prod",
		JobID:         "job-1",
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "file.read",
		Args:          map[string]string{"path": "/etc/hosts"},
		RawExecArgv:   nil,
		Outcome:       jobs.OutcomeSuccess,
		Reason:        "",
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",
	}
	if err := st.Audit().Append(ctx, rec); err != nil {
		t.Fatalf("append: %v", err)
	}

	decoy := rec
	decoy.ID = "audit-2"
	decoy.Kind = audit.KindDispatch
	decoy.Attribution.Verified.AccountID = "acct-2"
	if err := st.Audit().Append(ctx, decoy); err != nil {
		t.Fatalf("append decoy: %v", err)
	}

	q := New(st.AuditQueries(), st.JobQueries())

	page, err := q.QueryAudit(ctx, capability.AuditFilter{
		Kinds:     []string{audit.KindRead},
		AccountID: "acct-1",
	}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("Rows = %d, want 1", len(page.Rows))
	}
	got := page.Rows[0]

	want := capability.AuditRow{
		ID:        "audit-1",
		Timestamp: ts,
		Kind:      audit.KindRead,
		Principal: "gleipnir:operator",
		Verified: capability.VerifiedIdentity{
			AccountID: "acct-1", AccountName: "gleipnir", Role: "operator",
			TokenID: "tok-1", Method: "api_token", Source: "10.0.0.1",
		},
		Asserted: capability.Assertions{
			OnBehalfOf: "ops-team", Traceparent: "00-trace", SessionRef: "sess-1", ChangeRef: "CHG-1",
		},
		Selector:      "relay:env=prod",
		JobID:         "job-1",
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "file.read",
		Args:          map[string]string{"path": "/etc/hosts"},
		Outcome:       jobs.OutcomeSuccess,
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",
	}
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
	got.Timestamp = want.Timestamp
	if !reflect.DeepEqual(got, want) {
		t.Errorf("QueryAudit row =\n%+v, want\n%+v", got, want)
	}
}

// TestQueries_AuditCounts_AuditReach exercises the two aggregate methods
// through the real store.
func TestQueries_AuditCounts_AuditReach(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for i, nodeID := range []string{"node-1", "node-2"} {
		rec := audit.Record{
			ID: "audit-" + nodeID, Timestamp: base.Add(time.Duration(i) * time.Minute),
			Kind:      audit.KindRead,
			Principal: "gleipnir:operator",
			Attribution: audit.Attribution{
				Verified: audit.Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator"},
			},
			NodeID:        nodeID,
			OperationName: "file.read",
			Args:          map[string]string{"path": "/etc/hosts"},
		}
		if err := st.Audit().Append(ctx, rec); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	q := New(st.AuditQueries(), st.JobQueries())

	buckets, err := q.AuditCounts(ctx, capability.AuditFilter{}, time.Hour)
	if err != nil {
		t.Fatalf("AuditCounts: %v", err)
	}
	if len(buckets) != 1 || buckets[0].Count != 2 || buckets[0].AccountID != "acct-1" {
		t.Fatalf("buckets = %+v, want one bucket, AccountID=acct-1, Count=2", buckets)
	}

	reach, err := q.AuditReach(ctx, capability.AuditFilter{})
	if err != nil {
		t.Fatalf("AuditReach: %v", err)
	}
	if reach.Calls != 2 || reach.DistinctTargets != 1 || reach.DistinctNodes != 2 {
		t.Fatalf("reach = %+v, want Calls=2 DistinctTargets=1 DistinctNodes=2", reach)
	}
}

// TestQueries_QueryJobs_QueryTasks_RoundTrip is the mapping's Job/Task half.
func TestQueries_QueryJobs_QueryTasks_RoundTrip(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: base}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	task := jobs.Task{
		ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1",
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassMutate},
		CreatedAt: base,
	}
	if err := st.Tasks().CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.Tasks().MarkDispatched(ctx, "task-1", base); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if err := st.Tasks().Resolve(ctx, "task-1", jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte("hello")}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	q := New(st.AuditQueries(), st.JobQueries())

	jobPage, err := q.QueryJobs(ctx, capability.JobFilter{}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(jobPage.Jobs) != 1 || jobPage.Jobs[0].JobID != "job-1" {
		t.Fatalf("QueryJobs = %+v, want exactly [job-1]", jobPage.Jobs)
	}
	if jobPage.Jobs[0].State != jobs.JobStateComplete {
		t.Errorf("Job state = %v, want Complete", jobPage.Jobs[0].State)
	}
	if jobPage.Jobs[0].RiskClass != jobs.RiskClassMutate {
		t.Errorf("Job risk class = %v, want Mutate", jobPage.Jobs[0].RiskClass)
	}

	taskPage, err := q.QueryTasks(ctx, capability.TaskFilter{JobID: "job-1"}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryTasks: %v", err)
	}
	if len(taskPage.Tasks) != 1 {
		t.Fatalf("QueryTasks = %+v, want exactly 1 Task", taskPage.Tasks)
	}
	got := taskPage.Tasks[0]
	if got.TaskID != "task-1" || got.NodeID != "node-1" || got.Outcome != jobs.OutcomeSuccess ||
		got.RiskClass != jobs.RiskClassMutate || string(got.Stdout) != "hello" {
		t.Errorf("QueryTasks row = %+v, want task-1/node-1/Success/Mutate/hello", got)
	}
}

// TestQueries_InvalidCursor_MapsToCapabilitySentinel asserts a malformed
// cursor surfaces as capability.ErrInvalidCursor, never a store-package
// sentinel a caller of the capability layer should not have to know about.
func TestQueries_InvalidCursor_MapsToCapabilitySentinel(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()
	q := New(st.AuditQueries(), st.JobQueries())

	if _, err := q.QueryAudit(ctx, capability.AuditFilter{}, capability.PageRequest{Cursor: "not-a-cursor!!"}); err != capability.ErrInvalidCursor {
		t.Errorf("QueryAudit: err = %v, want capability.ErrInvalidCursor", err)
	}
	if _, err := q.QueryJobs(ctx, capability.JobFilter{}, capability.PageRequest{Cursor: "not-a-cursor!!"}); err != capability.ErrInvalidCursor {
		t.Errorf("QueryJobs: err = %v, want capability.ErrInvalidCursor", err)
	}
}
