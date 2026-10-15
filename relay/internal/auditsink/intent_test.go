package auditsink

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// intentJob creates a Job and Stage in st and returns one Pending Task per node.
func intentJob(t *testing.T, st *store.Store, jobID string, class jobs.RiskClass, nodes ...string) []jobs.Task {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: jobID + "-stage", JobID: jobID}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	var tasks []jobs.Task
	for _, n := range nodes {
		tasks = append(tasks, jobs.Task{
			ID: jobID + "-" + n, JobID: jobID, StageID: jobID + "-stage", NodeID: n, CreatedAt: at,
			Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: class},
		})
	}
	return tasks
}

func intentEntry(jobID string, class jobs.RiskClass, capCleared int) capability.AuditEntry {
	return capability.AuditEntry{
		Kind: capability.AuditKindDispatchIntent,
		Principal: capability.Principal{
			Account: "alice", AccountID: "acct-1", Role: "operator",
			AuthMethod: "api_token", Source: "mcp",
		},
		Selector: capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}},
		Action: jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: class,
			OperationArgs: map[string]string{"unit": "nginx"},
		},
		JobID:      jobID,
		ApprovalID: "appr-1",
		GrantID:    "grant-1",
		CapCleared: capCleared,
	}
}

func TestRecordIntent_WritesOneIntentRecordWithItsTasks(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	tasks := intentJob(t, st, "job-1", jobs.RiskClassMutate, "node-a", "node-b")

	if err := sink.RecordIntent(context.Background(), intentEntry("job-1", jobs.RiskClassMutate, 2), tasks); err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}

	recs, err := repo.ByJob(context.Background(), "job-1")
	if err != nil || len(recs) != 1 {
		t.Fatalf("ByJob = %d records, err %v; want exactly 1", len(recs), err)
	}
	r := recs[0]
	if r.Kind != audit.KindDispatchIntent || r.JobID != "job-1" || r.NodeID != "" ||
		r.ApprovalID != "appr-1" || r.GrantID != "grant-1" || r.OperationName != "service.restart" || r.Args["unit"] != "nginx" {
		t.Errorf("record = %+v", r)
	}
	if !strings.Contains(r.Principal, "alice") {
		t.Errorf("principal = %q", r.Principal)
	}
	persisted, err := st.Tasks().ByJob(context.Background(), "job-1")
	if err != nil || len(persisted) != 2 {
		t.Fatalf("Tasks = %d, err %v; want 2 persisted with the intent", len(persisted), err)
	}
}

func TestRecordIntent_ReasonCarriesNodeSetClassAndCapDecisionButNoCapValue(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	// Three Tasks, two cleared by the cap: one is a Template-excluded Node.
	tasks := intentJob(t, st, "job-1", jobs.RiskClassRead, "node-x", "node-a", "node-b")

	if err := sink.RecordIntent(context.Background(), intentEntry("job-1", jobs.RiskClassRead, 2), tasks); err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	recs, _ := repo.ByJob(context.Background(), "job-1")
	want := "risk_class=read blast_cap=passed cap_cleared=2 excluded=1 node_count=3 node_ids=node-x,node-a,node-b"
	if len(recs) != 1 || recs[0].Reason != want {
		t.Fatalf("Reason = %q, want %q", recs[0].Reason, want)
	}
	// The exact match above is also the proof that no cap limit appears
	// (invariant 11): blast_cap=passed is the only statement about the cap.
}

func TestRecordIntent_RecordsSurfaceInTheVerifiedLane(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	tasks := intentJob(t, st, "job-1", jobs.RiskClassMutate, "node-a")
	if err := sink.RecordIntent(context.Background(), intentEntry("job-1", jobs.RiskClassMutate, 1), tasks); err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	recs, _ := repo.ByJob(context.Background(), "job-1")
	v := recs[0].Attribution.Verified
	if v.Method != "api_token" || v.Source != "mcp" || v.AccountID != "acct-1" {
		t.Errorf("verified lane = %+v, want the surface in Method/Source", v)
	}
}

func TestRecordIntent_NeverCarriesOutput(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	tasks := intentJob(t, st, "job-1", jobs.RiskClassMutate, "node-a")
	e := intentEntry("job-1", jobs.RiskClassMutate, 1)
	e.Results = []capability.NodeResult{{NodeID: "node-a", Stdout: []byte("secret out"), Stderr: []byte("secret err"), Truncated: true}}
	if err := sink.RecordIntent(context.Background(), e, tasks); err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	recs, _ := repo.ByJob(context.Background(), "job-1")
	if len(recs[0].Stdout) != 0 || len(recs[0].Stderr) != 0 || recs[0].Truncated {
		t.Errorf("intent record carries output: %+v", recs[0])
	}
}

func TestRecord_RefusesADispatchIntentEntry(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	if err := sink.Record(context.Background(), intentEntry("job-1", jobs.RiskClassMutate, 1)); err == nil {
		t.Fatal("Record accepted a dispatch intent entry")
	}
	if recs, _ := repo.List(context.Background()); len(recs) != 0 {
		t.Errorf("%d records written for a refused intent entry", len(recs))
	}
}

func TestRecordIntent_RefusesTheWrongKindAndNoTasks(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	tasks := intentJob(t, st, "job-1", jobs.RiskClassMutate, "node-a")

	wrong := intentEntry("job-1", jobs.RiskClassMutate, 1)
	wrong.Kind = capability.AuditKindDispatch
	if err := sink.RecordIntent(context.Background(), wrong, tasks); err == nil {
		t.Error("RecordIntent accepted a non-intent entry")
	}
	if err := sink.RecordIntent(context.Background(), intentEntry("job-1", jobs.RiskClassMutate, 1), nil); err == nil {
		t.Error("RecordIntent accepted an intent with no Tasks")
	}
}

func TestRecordIntent_LogsNoNodeIDsOrArgs(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	var buf bytes.Buffer
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	tasks := intentJob(t, st, "job-1", jobs.RiskClassMutate, "node-secret-a", "node-secret-b")
	if err := sink.RecordIntent(context.Background(), intentEntry("job-1", jobs.RiskClassMutate, 2), tasks); err != nil {
		t.Fatalf("RecordIntent: %v", err)
	}
	line := buf.String()
	if strings.Count(line, "audit decision") != 1 || !strings.Contains(line, "kind=dispatch_intent") ||
		!strings.Contains(line, "job_id=job-1") || !strings.Contains(line, "node_count=2") {
		t.Errorf("decision line = %q", line)
	}
	for _, leak := range []string{"node-secret", "nginx", "node_ids"} {
		if strings.Contains(line, leak) {
			t.Errorf("decision line leaked %q: %q", leak, line)
		}
	}
}
