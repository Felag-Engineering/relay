package auditsink

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// openSinkStore opens a temp SQLite store and returns its audit.Repository
// and its path, so tests can Close and re-Open to exercise restart
// durability.
func openSinkStore(t *testing.T) (*store.Store, audit.Repository, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st, st.Audit(), path
}

// sequentialIDs returns an idGen that yields prefix+"1", prefix+"2", ... in
// call order, so tests can assert exact IDs deterministically.
func sequentialIDs(prefix string) idGen {
	n := 0
	return func() (string, error) {
		n++
		return prefix + strconv.Itoa(n), nil
	}
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestRecordDispatchFanOutOnePerNodeResult(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: principal,
		Selector:  sel,
		Action:    act,
		JobID:     "job-1",
		Results: []capability.NodeResult{
			{NodeID: "node-ok", Outcome: jobs.OutcomeSuccess, Stdout: []byte("node-ok stdout"), Stderr: []byte(""), Truncated: false},
			{NodeID: "node-denied", Outcome: jobs.OutcomeDeniedByPolicy},
			{NodeID: "node-offline", Outcome: jobs.OutcomeUnreachable},
			{NodeID: "node-cancelled", Outcome: jobs.OutcomeCancelled, Stdout: []byte(""), Stderr: []byte("cancelled mid-run"), Truncated: true},
		},
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	byJob, err := repo.ByJob(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(byJob) != 4 {
		t.Fatalf("ByJob(job-1) returned %d records, want 4", len(byJob))
	}

	wantOutcomes := map[string]jobs.Outcome{
		"node-ok":        jobs.OutcomeSuccess,
		"node-denied":    jobs.OutcomeDeniedByPolicy,
		"node-offline":   jobs.OutcomeUnreachable,
		"node-cancelled": jobs.OutcomeCancelled,
	}
	// wantOutput covers #185's full-output-always mapping: each NodeResult's
	// Stdout/Stderr/Truncated must round-trip through the REAL SQLite-backed
	// audit.Repository exactly.
	wantOutput := map[string]struct {
		stdout, stderr string
		truncated      bool
	}{
		"node-ok":        {"node-ok stdout", "", false},
		"node-denied":    {"", "", false},
		"node-offline":   {"", "", false},
		"node-cancelled": {"", "cancelled mid-run", true},
	}
	seen := map[string]bool{}
	for _, rec := range byJob {
		if rec.Kind != audit.KindDispatch {
			t.Errorf("record for %q Kind = %q, want %q", rec.NodeID, rec.Kind, audit.KindDispatch)
		}
		if rec.JobID != "job-1" {
			t.Errorf("record for %q JobID = %q, want job-1", rec.NodeID, rec.JobID)
		}
		want, ok := wantOutcomes[rec.NodeID]
		if !ok {
			t.Errorf("unexpected NodeID %q in ByJob results", rec.NodeID)
			continue
		}
		if rec.Outcome != want {
			t.Errorf("record for %q Outcome = %v, want %v", rec.NodeID, rec.Outcome, want)
		}
		if rec.Principal != principal.Attribution() {
			t.Errorf("record for %q Principal = %q, want %q", rec.NodeID, rec.Principal, principal.Attribution())
		}
		if rec.Selector != sel.String() {
			t.Errorf("record for %q Selector = %q, want %q", rec.NodeID, rec.Selector, sel.String())
		}
		wantOut := wantOutput[rec.NodeID]
		if string(rec.Stdout) != wantOut.stdout || string(rec.Stderr) != wantOut.stderr || rec.Truncated != wantOut.truncated {
			t.Errorf("record for %q Stdout/Stderr/Truncated = %q/%q/%v, want %q/%q/%v",
				rec.NodeID, rec.Stdout, rec.Stderr, rec.Truncated, wantOut.stdout, wantOut.stderr, wantOut.truncated)
		}
		seen[rec.NodeID] = true
	}
	if len(seen) != 4 {
		t.Errorf("saw %d distinct NodeIDs, want 4: %v", len(seen), seen)
	}

	// ByNode: querying one Node returns exactly its own record.
	byNode, err := repo.ByNode(context.Background(), "node-denied")
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	if len(byNode) != 1 || byNode[0].Outcome != jobs.OutcomeDeniedByPolicy {
		t.Errorf("ByNode(node-denied) = %+v, want a single DeniedByPolicy record", byNode)
	}
}

// TestRecordDispatchLogsDecisionLine is #181's DoD #3 for the dispatch Kind:
// Record emits exactly one structured decision line summarizing the whole
// fan-out (aggregate matched + per-outcome counts), and — DoD #2 — that line
// never contains any NodeResult's captured Stdout/Stderr bytes.
func TestRecordDispatchLogsDecisionLine(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	var buf bytes.Buffer
	sink := New(repo,
		WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
	)

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: principal,
		Selector:  sel,
		Action:    act,
		JobID:     "job-1",
		Results: []capability.NodeResult{
			{NodeID: "node-ok", Outcome: jobs.OutcomeSuccess, Stdout: []byte("node-ok stdout"), Stderr: []byte(""), Truncated: false},
			{NodeID: "node-denied", Outcome: jobs.OutcomeDeniedByPolicy},
			{NodeID: "node-offline", Outcome: jobs.OutcomeUnreachable},
			{NodeID: "node-cancelled", Outcome: jobs.OutcomeCancelled, Stdout: []byte(""), Stderr: []byte("cancelled mid-run"), Truncated: true},
		},
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("Record emitted %d log lines, want 1: %q", len(lines), buf.String())
	}
	line := lines[0]

	for attr, want := range map[string]string{
		"msg":         "audit decision",
		"kind":        "dispatch",
		"principal":   principal.Attribution(),
		"selector":    sel.String(),
		"action_kind": "operation",
		"operation":   "service.restart",
		"job_id":      "job-1",
		"matched":     "4",
	} {
		if !strings.Contains(line, attr+"="+want) && !strings.Contains(line, attr+"=\""+want+"\"") {
			t.Errorf("decision line missing %s=%s: %q", attr, want, line)
		}
	}
	wantCounts := "success=1,denied_by_policy=1,cancelled=1,unreachable=1"
	if !strings.Contains(line, wantCounts) {
		t.Errorf("decision line missing outcome_counts %q: %q", wantCounts, line)
	}

	if strings.Contains(line, "node-ok stdout") || strings.Contains(line, "cancelled mid-run") {
		t.Fatalf("decision line leaked NodeResult Stdout/Stderr: %q", line)
	}
}

func TestRecordDispatchZeroMatchOneJobLevelRow(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: capability.Principal{Account: "alice"},
		Selector:  capability.Selector{},
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
		JobID:     "job-empty",
		Results:   nil,
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	byJob, err := repo.ByJob(context.Background(), "job-empty")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(byJob) != 1 {
		t.Fatalf("ByJob(job-empty) returned %d records, want 1", len(byJob))
	}
	if byJob[0].NodeID != "" {
		t.Errorf("zero-match record NodeID = %q, want empty", byJob[0].NodeID)
	}
	if byJob[0].Kind != audit.KindDispatch {
		t.Errorf("zero-match record Kind = %q, want %q", byJob[0].Kind, audit.KindDispatch)
	}
}

func TestRecordRefusalOneRowNoNodeID(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	entry := capability.AuditEntry{
		Kind:      capability.AuditKindRefusal,
		Principal: capability.Principal{Account: "alice"},
		Selector:  capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceRelay, Key: "quarantine", Value: "on"}}},
		Action:    jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/rm", "-rf", "/"}, RiskClass: jobs.RiskClassMutate},
		Reason:    "blast radius exceeded",
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("List returned %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Kind != audit.KindRefusal {
		t.Errorf("Kind = %q, want %q", rec.Kind, audit.KindRefusal)
	}
	if rec.Reason != "blast radius exceeded" {
		t.Errorf("Reason = %q, want %q", rec.Reason, "blast radius exceeded")
	}
	if rec.NodeID != "" {
		t.Errorf("NodeID = %q, want empty (refusal never reaches a Node)", rec.NodeID)
	}
	if rec.JobID != "" {
		t.Errorf("JobID = %q, want empty (refusal never reaches the dispatcher)", rec.JobID)
	}
	if rec.Outcome != jobs.OutcomeUnspecified {
		t.Errorf("Outcome = %v, want OutcomeUnspecified", rec.Outcome)
	}
}

// TestRecordRefusalLogsDecisionLine is #181's DoD #3 for the refusal Kind:
// Record emits exactly one structured decision line carrying the refusal
// Reason, and — DoD #2 — that line never contains the raw-exec argv (the
// only fixture that sets RawExecArgv, since a refusal never reaches
// e.Results, so it cannot structurally carry NodeResult output).
func TestRecordRefusalLogsDecisionLine(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	var buf bytes.Buffer
	sink := New(repo,
		WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
	)

	principal := capability.Principal{Account: "alice"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceRelay, Key: "quarantine", Value: "on"}}}
	entry := capability.AuditEntry{
		Kind:      capability.AuditKindRefusal,
		Principal: principal,
		Selector:  sel,
		Action:    jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/rm", "-rf", "/"}, RiskClass: jobs.RiskClassMutate},
		Reason:    "blast radius exceeded",
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("Record emitted %d log lines, want 1: %q", len(lines), buf.String())
	}
	line := lines[0]

	for attr, want := range map[string]string{
		"msg":         "audit decision",
		"kind":        "refusal",
		"principal":   principal.Attribution(),
		"selector":    sel.String(),
		"action_kind": "raw_exec",
		"reason":      "blast radius exceeded",
	} {
		if !strings.Contains(line, attr+"="+want) && !strings.Contains(line, attr+"=\""+want+"\"") {
			t.Errorf("decision line missing %s=%s: %q", attr, want, line)
		}
	}
	if strings.Contains(line, "job_id=") {
		t.Errorf("refusal decision line has job_id, want none: %q", line)
	}

	if strings.Contains(line, "/bin/rm") || strings.Contains(line, "-rf") {
		t.Fatalf("decision line leaked raw-exec argv: %q", line)
	}
}

// TestRecordPlanOneRowNoJobOrNode is #119's audit acceptance line: an
// AuditKindPlan entry writes exactly one KindPlan row, with Principal/
// Selector/Action set and JobID/NodeID/Outcome empty — a Plan creates no
// Job/Task, so there is nothing to reference by ID.
func TestRecordPlanOneRowNoJobOrNode(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	entry := capability.AuditEntry{Kind: capability.AuditKindPlan, Principal: principal, Selector: sel, Action: act}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("List returned %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Kind != audit.KindPlan {
		t.Errorf("Kind = %q, want %q", rec.Kind, audit.KindPlan)
	}
	if rec.Principal != principal.Attribution() {
		t.Errorf("Principal = %q, want %q", rec.Principal, principal.Attribution())
	}
	if rec.Selector != sel.String() {
		t.Errorf("Selector = %q, want %q", rec.Selector, sel.String())
	}
	if rec.ActionKind != "operation" || rec.OperationName != "service.restart" {
		t.Errorf("Action fields = {%q %q}, want {operation service.restart}", rec.ActionKind, rec.OperationName)
	}
	if rec.JobID != "" {
		t.Errorf("JobID = %q, want empty (a Plan creates no Job)", rec.JobID)
	}
	if rec.NodeID != "" {
		t.Errorf("NodeID = %q, want empty (a Plan creates no Task)", rec.NodeID)
	}
	if rec.Outcome != jobs.OutcomeUnspecified {
		t.Errorf("Outcome = %v, want OutcomeUnspecified", rec.Outcome)
	}
}

// TestRecordPlanLogsDecisionLine is #181's DoD #3 for the plan Kind: Record
// emits exactly one structured decision line carrying Principal/Selector/
// Action, with no job_id (a Plan creates no Job).
func TestRecordPlanLogsDecisionLine(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	var buf bytes.Buffer
	sink := New(repo,
		WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
	)

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	entry := capability.AuditEntry{Kind: capability.AuditKindPlan, Principal: principal, Selector: sel, Action: act}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("Record emitted %d log lines, want 1: %q", len(lines), buf.String())
	}
	line := lines[0]

	for attr, want := range map[string]string{
		"msg":         "audit decision",
		"kind":        "plan",
		"principal":   principal.Attribution(),
		"selector":    sel.String(),
		"action_kind": "operation",
		"operation":   "service.restart",
	} {
		if !strings.Contains(line, attr+"="+want) && !strings.Contains(line, attr+"=\""+want+"\"") {
			t.Errorf("decision line missing %s=%s: %q", attr, want, line)
		}
	}
	if strings.Contains(line, "job_id=") {
		t.Errorf("plan decision line has job_id, want none: %q", line)
	}
}

func TestRecordFreezeEngageAndRelease(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	engage := capability.FreezeEvent{Principal: capability.Principal{Account: "ops-bot"}, Engage: true, Reason: "suspected incident"}
	if err := sink.RecordFreeze(context.Background(), engage); err != nil {
		t.Fatalf("RecordFreeze(engage): %v", err)
	}

	release := capability.FreezeEvent{Principal: capability.Principal{Account: "alice", Role: "operator"}, Engage: false, Reason: "incident resolved"}
	if err := sink.RecordFreeze(context.Background(), release); err != nil {
		t.Fatalf("RecordFreeze(release): %v", err)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("List returned %d records, want 2", len(records))
	}

	if records[0].Kind != audit.KindFreezeEngage {
		t.Errorf("records[0].Kind = %q, want %q", records[0].Kind, audit.KindFreezeEngage)
	}
	if records[0].Principal != "ops-bot" {
		t.Errorf("records[0].Principal = %q, want ops-bot", records[0].Principal)
	}
	if records[0].Reason != "suspected incident" {
		t.Errorf("records[0].Reason = %q, want %q", records[0].Reason, "suspected incident")
	}

	if records[1].Kind != audit.KindFreezeRelease {
		t.Errorf("records[1].Kind = %q, want %q", records[1].Kind, audit.KindFreezeRelease)
	}
	if records[1].Principal != "alice:operator" {
		t.Errorf("records[1].Principal = %q, want alice:operator", records[1].Principal)
	}
	if records[1].Reason != "incident resolved" {
		t.Errorf("records[1].Reason = %q, want %q", records[1].Reason, "incident resolved")
	}
}

// TestRecordCancelAttributesPrincipal is v0.0.6 [5/8]'s owner DECISION 2:
// RecordCancel writes exactly one KindJobCancel row, attributed to the
// cancelling Principal, carrying the target JobID and no Selector/NodeID/
// Action (a cancel targets an existing Job by ID, not a fresh dispatch).
func TestRecordCancelAttributesPrincipal(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	principal := capability.Principal{Account: "alice", Role: "operator"}
	if err := sink.RecordCancel(context.Background(), principal, "job-1"); err != nil {
		t.Fatalf("RecordCancel: %v", err)
	}

	records, err := repo.ByJob(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ByJob(job-1) returned %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Kind != audit.KindJobCancel {
		t.Errorf("Kind = %q, want %q", rec.Kind, audit.KindJobCancel)
	}
	if rec.Principal != principal.Attribution() {
		t.Errorf("Principal = %q, want %q", rec.Principal, principal.Attribution())
	}
	if rec.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1", rec.JobID)
	}
	if rec.NodeID != "" {
		t.Errorf("NodeID = %q, want empty (a cancel targets a Job, not a Node)", rec.NodeID)
	}
}

// TestRecordRestartDurability is acceptance #2: audit rows survive a Relay
// restart (a Close followed by a fresh Open of the same path).
func TestRecordRestartDurability(t *testing.T) {
	st, repo, path := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: capability.Principal{Account: "alice"},
		Selector:  capability.Selector{},
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
		JobID:     "job-restart",
		Results:   []capability.NodeResult{{NodeID: "node-1", Outcome: jobs.OutcomeSuccess}},
	}
	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { st2.Close() }) //nolint:errcheck

	records, err := st2.Audit().ByJob(context.Background(), "job-restart")
	if err != nil {
		t.Fatalf("reload ByJob: %v", err)
	}
	if len(records) != 1 || records[0].NodeID != "node-1" || records[0].Outcome != jobs.OutcomeSuccess {
		t.Errorf("reload ByJob(job-restart) = %+v, want a single node-1/OutcomeSuccess record", records)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it, so tests can assert Record/RecordFreeze never
// log field values (redaction guarantee).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return buf.String()
}

// TestRecordRedactsTokensAndKeys is acceptance #4: enrollment tokens and key
// material never appear in an audit row, or in anything logged during
// Record, for a representative dispatch flow.
func TestRecordRedactsTokensAndKeys(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	// A representative secret an operator's Principal/session might be
	// carrying — the enrollment bearer token — and a private-key PEM block,
	// held only in local test variables. Neither is a field on AuditEntry,
	// so the adapter has no path to persist or log them; this test locks
	// that in as a regression guard.
	const secretToken = "enroll-token-8f3a9c2e5b7d4f1a6c8e0d2b4f6a8c0e"
	const secretKeyPEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----"

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: principal,
		Selector:  sel,
		Action:    act,
		JobID:     "job-secret",
		Results:   []capability.NodeResult{{NodeID: "node-1", Outcome: jobs.OutcomeSuccess}},
	}

	logged := captureStderr(t, func() {
		if err := sink.Record(context.Background(), entry); err != nil {
			t.Fatalf("Record: %v", err)
		}
	})

	if strings.Contains(logged, secretToken) || strings.Contains(logged, secretKeyPEM) {
		t.Fatalf("Record logged secret material to stderr: %q", logged)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("List returned no records")
	}
	for _, rec := range records {
		for _, field := range []string{rec.ID, rec.Principal, rec.Selector, rec.JobID, rec.NodeID, rec.ActionKind, rec.OperationName, rec.Reason} {
			if strings.Contains(field, secretToken) || strings.Contains(field, secretKeyPEM) {
				t.Fatalf("audit record %+v contains secret material in field %q", rec, field)
			}
		}
		for _, v := range rec.Args {
			if strings.Contains(v, secretToken) || strings.Contains(v, secretKeyPEM) {
				t.Fatalf("audit record %+v contains secret material in Args", rec)
			}
		}
		for _, v := range rec.RawExecArgv {
			if strings.Contains(v, secretToken) || strings.Contains(v, secretKeyPEM) {
				t.Fatalf("audit record %+v contains secret material in RawExecArgv", rec)
			}
		}
	}
}

// TestRecordDispatchDecisionLineExcludesOperationArgs is issue #222's audit
// coverage for logDecision's "never OperationArgs/RawExecArgv/output" claim:
// no existing test set Action.OperationArgs, so the exclusion was previously
// unverified. The decision line must omit the secret-bearing arg value and
// the captured Stdout/Stderr, while the store — by the accepted verbatim-
// audit-output decision (not a bug) — still retains all three.
func TestRecordDispatchDecisionLineExcludesOperationArgs(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	var buf bytes.Buffer
	sink := New(repo,
		WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
	)

	principal := capability.Principal{Account: "alice", Role: "operator"}
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "service.restart",
		OperationArgs: map[string]string{"password": "hunter2-SENTINEL"},
		RiskClass:     jobs.RiskClassMutate,
	}
	entry := capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: principal,
		Selector:  sel,
		Action:    act,
		JobID:     "job-args",
		Results: []capability.NodeResult{
			{NodeID: "node-1", Outcome: jobs.OutcomeSuccess, Stdout: []byte("STDOUT-SENTINEL"), Stderr: []byte("STDERR-SENTINEL"), Truncated: false},
		},
	}

	if err := sink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("Record emitted %d log lines, want 1: %q", len(lines), buf.String())
	}
	line := lines[0]

	for attr, want := range map[string]string{
		"kind":        "dispatch",
		"action_kind": "operation",
		"operation":   "service.restart",
		"matched":     "1",
	} {
		if !strings.Contains(line, attr+"="+want) && !strings.Contains(line, attr+"=\""+want+"\"") {
			t.Errorf("decision line missing %s=%s: %q", attr, want, line)
		}
	}

	if strings.Contains(line, "hunter2-SENTINEL") {
		t.Fatalf("decision line leaked OperationArgs value: %q", line)
	}
	if strings.Contains(line, "STDOUT-SENTINEL") || strings.Contains(line, "STDERR-SENTINEL") {
		t.Fatalf("decision line leaked NodeResult Stdout/Stderr: %q", line)
	}

	// The verbatim-audit-output decision (ADR-0002/-0004; accepted, not a
	// bug) means the store retains what the decision line omits.
	byJob, err := repo.ByJob(context.Background(), "job-args")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(byJob) != 1 {
		t.Fatalf("ByJob(job-args) returned %d records, want 1", len(byJob))
	}
	if got := byJob[0].Args["password"]; got != "hunter2-SENTINEL" {
		t.Errorf("stored Args[password] = %q, want hunter2-SENTINEL", got)
	}
	if got := string(byJob[0].Stdout); got != "STDOUT-SENTINEL" {
		t.Errorf("stored Stdout = %q, want STDOUT-SENTINEL", got)
	}
	if got := string(byJob[0].Stderr); got != "STDERR-SENTINEL" {
		t.Errorf("stored Stderr = %q, want STDERR-SENTINEL", got)
	}
}

// #288 / ADR-0025: a read-class dispatch records WHAT was read, never what
// came back. The mutate case in the same test is the control — without it,
// this would pass just as well against a sink that stored nothing at all.
func TestRecordDispatchReadClassRetainsNoOutput(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC))))

	principal := capability.Principal{Account: "gleipnir", Role: "operator"}
	secret := []byte("PGPASSWORD=hunter2 /usr/bin/psql -h db.internal")

	entry := func(jobID string, class jobs.RiskClass, op string) capability.AuditEntry {
		return capability.AuditEntry{
			Kind:      capability.AuditKindDispatch,
			Principal: principal,
			Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: op, RiskClass: class},
			JobID:     jobID,
			Results: []capability.NodeResult{
				{NodeID: "node-1", Outcome: jobs.OutcomeSuccess, Stdout: secret, Stderr: []byte("stderr too"), Truncated: true},
			},
		}
	}

	ctx := context.Background()
	if err := sink.Record(ctx, entry("job-read", jobs.RiskClassRead, "proc.list")); err != nil {
		t.Fatalf("Record(read): %v", err)
	}
	if err := sink.Record(ctx, entry("job-mutate", jobs.RiskClassMutate, "service.restart")); err != nil {
		t.Fatalf("Record(mutate): %v", err)
	}

	read, err := repo.ByJob(ctx, "job-read")
	if err != nil || len(read) != 1 {
		t.Fatalf("ByJob(job-read): %v (%d records)", err, len(read))
	}
	r := read[0]
	if len(r.Stdout) != 0 || len(r.Stderr) != 0 {
		t.Errorf("a read-class audit record retained output: stdout=%q stderr=%q", r.Stdout, r.Stderr)
	}
	if r.Truncated {
		t.Error("a read-class audit record retained the truncated flag, which describes output it no longer holds")
	}

	// The access record itself is intact: who, what, where, when, and how it
	// turned out. That is the whole point — less content, not less accounting.
	if r.OperationName != "proc.list" || r.NodeID != "node-1" || r.Outcome != jobs.OutcomeSuccess {
		t.Errorf("read record = %+v, want the access still fully recorded", r)
	}
	if r.Principal != "gleipnir:operator" {
		t.Errorf("read record principal = %q, want the acting Account", r.Principal)
	}

	// Control: mutate-class output is unchanged (#122 still stands there).
	mutate, err := repo.ByJob(ctx, "job-mutate")
	if err != nil || len(mutate) != 1 {
		t.Fatalf("ByJob(job-mutate): %v (%d records)", err, len(mutate))
	}
	if string(mutate[0].Stdout) != string(secret) {
		t.Errorf("mutate-class stdout = %q, want it retained verbatim", mutate[0].Stdout)
	}
	if !mutate[0].Truncated {
		t.Error("mutate-class truncated flag was dropped")
	}
}

// A read-access record for a non-dispatching tool: metadata only, attributed,
// and carrying no result field at all (the method signature has none).
func TestRecordRead(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC))))

	p := capability.Principal{
		AccountID: "acct-1", Account: "gleipnir", Role: "viewer", TokenID: "tok-9",
	}
	ctx := capability.WithAssertions(context.Background(), capability.Assertions{OnBehalfOf: "ops-team"})

	if err := sink.RecordRead(ctx, p, "describe_node", "", "node-42", ""); err != nil {
		t.Fatalf("RecordRead: %v", err)
	}
	if err := sink.RecordRead(ctx, p, "get_job", "", "", "job-7"); err != nil {
		t.Fatalf("RecordRead(get_job): %v", err)
	}

	got, err := repo.ByAccount(ctx, "acct-1")
	if err != nil || len(got) != 2 {
		t.Fatalf("ByAccount: %v (%d records)", err, len(got))
	}

	first := got[0]
	if first.Kind != audit.KindRead {
		t.Errorf("Kind = %q, want %q", first.Kind, audit.KindRead)
	}
	if first.OperationName != "describe_node" || first.NodeID != "node-42" {
		t.Errorf("record = %+v, want the tool and its target", first)
	}
	if len(first.Stdout) != 0 || len(first.Stderr) != 0 {
		t.Error("a read-access record carries output; it must be metadata only")
	}
	// Both attribution lanes apply to read records exactly as to dispatches
	// (#288 question 3, now that #300's lanes exist).
	if first.Attribution.Verified.AccountID != "acct-1" || first.Attribution.Verified.TokenID != "tok-9" {
		t.Errorf("verified lane = %+v, want the acting Account and its token", first.Attribution.Verified)
	}
	if first.Attribution.Asserted.OnBehalfOf != "ops-team" {
		t.Errorf("asserted lane = %+v, want the caller's claim carried through", first.Attribution.Asserted)
	}

	// get_job records the Job it read back — the sharpest case, since that
	// tool returns previously-captured command output.
	if got[1].JobID != "job-7" {
		t.Errorf("get_job record JobID = %q, want job-7", got[1].JobID)
	}
}
