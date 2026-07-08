package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// openTestStore opens a Store at a fresh path inside t.TempDir() and closes
// it on test cleanup. It returns the path so the caller can reopen it (e.g.
// to test the restart round trip).
func openTestStore(t *testing.T, opts ...Option) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := Open(path, opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st, path
}

// TestRestartRoundTrip is acceptance #1: Nodes, Jobs, Tasks, and audit rows
// must survive a Relay restart (a Close followed by a fresh Open of the same
// path). It writes every field — including both the nil and non-nil
// Facts.IPAddresses cases — and asserts the reloaded state is byte-identical.
func TestRestartRoundTrip(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	reg := st.Registry()
	jobRepo := st.Jobs()
	taskRepo := st.Tasks()
	auditRepo := st.Audit()

	// Node with non-nil Facts.IPAddresses, node + relay labels, and revocation.
	_, err := reg.Upsert(registry.Report{
		NodeID:            "node-a",
		CertFingerprint:   "fp-a",
		Facts:             registry.Facts{Hostname: "host-a", OS: "linux", Kernel: "6.1", Arch: "amd64", IPAddresses: []string{"10.0.0.1", "10.0.0.2"}},
		NodeLabels:        map[string]string{"role": "web"},
		EnrollingTokenID:  "tok-a",
		PolicyFingerprint: "fp-policy-a",
	})
	if err != nil {
		t.Fatalf("Upsert node-a: %v", err)
	}
	if err := reg.SetRelayLabels("node-a", map[string]string{"quarantine": "true"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}
	revokedAt := time.Date(2026, 7, 2, 3, 4, 5, 6000, time.UTC)
	if err := reg.SetRevoked("node-a", revokedAt); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}
	nodeA, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get node-a after SetRelayLabels/SetRevoked: not found")
	}

	// Node with nil Facts.IPAddresses — the nil-vs-empty fidelity case.
	nodeB, err := reg.Upsert(registry.Report{
		NodeID:            "node-b",
		CertFingerprint:   "fp-b",
		Facts:             registry.Facts{Hostname: "host-b", OS: "linux", Kernel: "6.1", Arch: "arm64"},
		EnrollingTokenID:  "tok-b",
		PolicyFingerprint: "fp-policy-b",
	})
	if err != nil {
		t.Fatalf("Upsert node-b: %v", err)
	}
	if nodeB.Facts.IPAddresses != nil {
		t.Fatalf("nodeB.Facts.IPAddresses: got %#v, want nil before round trip", nodeB.Facts.IPAddresses)
	}

	// Node with a non-nil but empty Facts.IPAddresses slice.
	nodeC, err := reg.Upsert(registry.Report{
		NodeID: "node-c",
		Facts:  registry.Facts{IPAddresses: []string{}},
	})
	if err != nil {
		t.Fatalf("Upsert node-c: %v", err)
	}
	if nodeC.Facts.IPAddresses == nil {
		t.Fatal("nodeC.Facts.IPAddresses: got nil, want non-nil empty slice before round trip")
	}

	job := jobs.Job{ID: "job-1", CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	if err := jobRepo.CreateJob(ctx, job); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	stage := jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}
	if err := jobRepo.AddStage(ctx, stage); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	task := jobs.Task{
		ID:      "task-1",
		JobID:   "job-1",
		StageID: "stage-1",
		NodeID:  "node-a",
		Action: jobs.Action{
			Kind:          jobs.ActionOperation,
			OperationName: "system.facts",
			OperationArgs: map[string]string{"k": "v"},
			RiskClass:     jobs.RiskClassRead,
		},
		TimeoutSeconds: 30,
		CreatedAt:      time.Date(2026, 7, 1, 0, 0, 1, 0, time.UTC),
	}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := taskRepo.MarkDispatched(ctx, "task-1", time.Date(2026, 7, 1, 0, 0, 2, 0, time.UTC)); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	// A second, resolved Task with a Raw Exec Action, to exercise that path too.
	task2 := jobs.Task{
		ID:      "task-2",
		JobID:   "job-1",
		StageID: "stage-1",
		NodeID:  "node-b",
		Action: jobs.Action{
			Kind:        jobs.ActionRawExec,
			RawExecArgv: []string{"/bin/sleep", "1"},
			RiskClass:   jobs.RiskClassMutate,
		},
		CreatedAt: time.Date(2026, 7, 1, 0, 0, 3, 0, time.UTC),
	}
	if err := taskRepo.CreateTask(ctx, task2); err != nil {
		t.Fatalf("CreateTask task-2: %v", err)
	}
	if err := taskRepo.MarkDispatched(ctx, "task-2", time.Date(2026, 7, 1, 0, 0, 4, 0, time.UTC)); err != nil {
		t.Fatalf("MarkDispatched task-2: %v", err)
	}
	if err := taskRepo.Resolve(ctx, "task-2", jobs.Result{
		Outcome:  jobs.OutcomeSuccess,
		ExitCode: 0,
		Stdout:   []byte("ok"),
		Stderr:   []byte{},
	}); err != nil {
		t.Fatalf("Resolve task-2: %v", err)
	}
	resolvedTask2, err := taskRepo.Get(ctx, "task-2")
	if err != nil {
		t.Fatalf("Get task-2 before restart: %v", err)
	}

	record := audit.Record{
		ID:            "audit-1",
		Timestamp:     time.Date(2026, 7, 1, 0, 0, 5, 0, time.UTC),
		Kind:          audit.KindDispatch,
		Principal:     "operator:alice",
		Selector:      "node:role=web",
		JobID:         "job-1",
		NodeID:        "node-a",
		ActionKind:    "operation",
		OperationName: "system.facts",
		Args:          map[string]string{"k": "v"},
		Outcome:       jobs.OutcomeUnspecified,
		Reason:        "",
	}
	if err := auditRepo.Append(ctx, record); err != nil {
		t.Fatalf("Append audit record: %v", err)
	}

	// Restart: close and reopen the same path.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { st2.Close() }) //nolint:errcheck

	reg2 := st2.Registry()
	jobRepo2 := st2.Jobs()
	taskRepo2 := st2.Tasks()
	auditRepo2 := st2.Audit()

	gotA, ok := reg2.Get("node-a")
	if !ok {
		t.Fatal("reload: node-a not found")
	}
	if !reflect.DeepEqual(gotA, nodeA) {
		t.Errorf("reload node-a mismatch:\n got  %#v\n want %#v", gotA, nodeA)
	}

	gotB, ok := reg2.Get("node-b")
	if !ok {
		t.Fatal("reload: node-b not found")
	}
	if gotB.Facts.IPAddresses != nil {
		t.Errorf("reload node-b Facts.IPAddresses: got %#v, want nil (fidelity across restart)", gotB.Facts.IPAddresses)
	}
	if !reflect.DeepEqual(gotB, nodeB) {
		t.Errorf("reload node-b mismatch:\n got  %#v\n want %#v", gotB, nodeB)
	}

	gotC, ok := reg2.Get("node-c")
	if !ok {
		t.Fatal("reload: node-c not found")
	}
	if gotC.Facts.IPAddresses == nil {
		t.Errorf("reload node-c Facts.IPAddresses: got nil, want non-nil empty slice (fidelity across restart)")
	}
	if !reflect.DeepEqual(gotC, nodeC) {
		t.Errorf("reload node-c mismatch:\n got  %#v\n want %#v", gotC, nodeC)
	}

	gotJob, err := jobRepo2.GetJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("reload GetJob: %v", err)
	}
	if !reflect.DeepEqual(gotJob, job) {
		t.Errorf("reload job mismatch:\n got  %#v\n want %#v", gotJob, job)
	}

	gotStages, err := jobRepo2.Stages(ctx, "job-1")
	if err != nil {
		t.Fatalf("reload Stages: %v", err)
	}
	if len(gotStages) != 1 || gotStages[0] != stage {
		t.Errorf("reload stages: got %#v, want [%#v]", gotStages, stage)
	}

	gotTask1, err := taskRepo2.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("reload Get task-1: %v", err)
	}
	if gotTask1.State != jobs.DispatchStateDispatched {
		t.Errorf("reload task-1 State: got %v, want DispatchStateDispatched", gotTask1.State)
	}
	if !gotTask1.ResolvedAt.IsZero() {
		t.Errorf("reload task-1 ResolvedAt: got %v, want zero (still in flight)", gotTask1.ResolvedAt)
	}

	gotTask2, err := taskRepo2.Get(ctx, "task-2")
	if err != nil {
		t.Fatalf("reload Get task-2: %v", err)
	}
	if !reflect.DeepEqual(gotTask2, resolvedTask2) {
		t.Errorf("reload task-2 mismatch:\n got  %#v\n want %#v", gotTask2, resolvedTask2)
	}

	inFlight, err := taskRepo2.InFlight(ctx)
	if err != nil {
		t.Fatalf("reload InFlight: %v", err)
	}
	if len(inFlight) != 1 || inFlight[0].ID != "task-1" {
		t.Errorf("reload InFlight: got %#v, want [task-1] (crash-across-restart precondition)", inFlight)
	}

	records, err := auditRepo2.List(ctx)
	if err != nil {
		t.Fatalf("reload List audit: %v", err)
	}
	if len(records) != 1 || !reflect.DeepEqual(records[0], record) {
		t.Errorf("reload audit records: got %#v, want [%#v]", records, record)
	}

	nodeRecords, err := auditRepo2.ByNode(ctx, "node-a")
	if err != nil {
		t.Fatalf("reload ByNode audit: %v", err)
	}
	if len(nodeRecords) != 1 || !reflect.DeepEqual(nodeRecords[0], record) {
		t.Errorf("reload ByNode(node-a) audit records: got %#v, want [%#v]", nodeRecords, record)
	}
}
