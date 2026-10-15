package auditsink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
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
	t.Cleanup(func() { st.Close() })
	return st, st.Audit(), path
}

// sequentialIDs returns an idGen that yields prefix+"0001", prefix+"0002",
// ... in call order, so tests can assert exact IDs deterministically.
//
// ZERO-PADDED, which is load-bearing rather than tidy. Production ids sort in
// mint order (audit.NewID), and the trail's order is (ts, audit_id) — so a
// test seam whose ids do NOT sort in call order stops modelling production.
// Several tests here index records[i] against cases[i] and rely on the
// tie-break equalling insertion order. The unpadded helper made that true
// only up to nine records: "audit-10" sorts before "audit-2", so a tenth case
// would have produced a baffling failure in a test that had nothing to do
// with ids. That is the #656 landmine.
func sequentialIDs(prefix string) idGen {
	n := 0
	return func() (string, error) {
		n++
		return fmt.Sprintf("%s%04d", prefix, n), nil
	}
}

// TestSequentialIDs_SortInCallOrderPastTen guards the helper above at the
// boundary that used to break it.
func TestSequentialIDs_SortInCallOrderPastTen(t *testing.T) {
	gen := sequentialIDs("audit-")
	ids := make([]string, 12)
	for i := range ids {
		id, err := gen()
		if err != nil {
			t.Fatalf("gen(): %v", err)
		}
		ids[i] = id
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("sequentialIDs(\"audit-\") ids do not sort in call order: %q then %q — tests here index records[i] against cases[i] and rely on the (ts, audit_id) tie-break equalling insertion order. This is the #656 landmine: with an unpadded helper \"audit-10\" sorts before \"audit-2\".", ids[i-1], ids[i])
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("12 sequentialIDs are not sorted: %v", ids)
	}
}

// TestSink_SameTimestampRecordsReturnInAppendOrder is #656's end-to-end
// proof, and the only test here that uses the PRODUCTION id generator: a
// frozen clock puts every record at one ts, so the trail's order is entirely
// audit_id order. It fails on a build without the tie-break AND on one
// without monotonic ids — two independent reasons.
func TestSink_SameTimestampRecordsReturnInAppendOrder(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))
	principal := capability.Principal{Account: "alice", Role: "operator"}

	const n = 12
	var want []string
	for i := 0; i < n; i++ {
		reason := fmt.Sprintf("refusal-%02d", i)
		want = append(want, reason)
		if err := sink.Record(context.Background(), capability.AuditEntry{
			Kind:      capability.AuditKindRefusal,
			Principal: principal,
			Reason:    reason,
		}); err != nil {
			t.Fatalf("Record %s: %v", reason, err)
		}
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, r := range records {
		got = append(got, r.Reason)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records came back [%v], want append order [%v] — with every row sharing a timestamp the trail's order is audit_id order, so audit_id must be minted monotonically (#656 option 3)", got, want)
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

	// The real-world same-ts case, and the reason audit.NewID takes its time
	// component from MINT time rather than from the Record's Timestamp: one
	// baseRecord's single clock reading is copied onto every per-Node Record,
	// so the whole fan-out shares a ts and its order is audit_id order (#656).
	var gotNodeOrder []string
	for _, rec := range byJob {
		gotNodeOrder = append(gotNodeOrder, rec.NodeID)
	}
	wantNodeOrder := []string{"node-ok", "node-denied", "node-offline", "node-cancelled"}
	if !reflect.DeepEqual(gotNodeOrder, wantNodeOrder) {
		t.Errorf("fan-out came back as %v, want e.Results order %v — every per-Node Record carries the same ts, so the tie-break is the only thing ordering them", gotNodeOrder, wantNodeOrder)
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

// TestRecordZeroMatchRefusalRecordsActorOperationAndSelector is #571's audit
// acceptance line: a zero-match dispatch arrives at the AuditSink as a
// Refusal entry (capability.Execution.Run refuses it before any Job exists),
// and is recorded as one KindRefusal row carrying the actor, the Selector,
// and the Action — never a job-level KindDispatch row.
func TestRecordZeroMatchRefusalRecordsActorOperationAndSelector(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "db"}}}
	principal := capability.Principal{Account: "alice", Role: "operator"}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	nnmErr := &capability.NoNodesMatchedError{Selector: sel.String()}

	entry := capability.AuditEntry{
		Kind:      capability.AuditKindRefusal,
		Principal: principal,
		Selector:  sel,
		Action:    act,
		Reason:    nnmErr.Error(),
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
		t.Errorf("Kind = %q, want %q (not %q)", rec.Kind, audit.KindRefusal, audit.KindDispatch)
	}
	if rec.Principal != principal.Attribution() {
		t.Errorf("Principal = %q, want %q", rec.Principal, principal.Attribution())
	}
	if rec.Selector != "node:role=db" {
		t.Errorf("Selector = %q, want %q", rec.Selector, "node:role=db")
	}
	if rec.OperationName != "system.facts" {
		t.Errorf("OperationName = %q, want %q", rec.OperationName, "system.facts")
	}
	if rec.ActionKind != "operation" {
		t.Errorf("ActionKind = %q, want %q", rec.ActionKind, "operation")
	}
	if !strings.Contains(rec.Reason, "no_nodes_matched") {
		t.Errorf("Reason = %q, want it to contain %q", rec.Reason, "no_nodes_matched")
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

// TestRecordRefusalPersistsJobIDWhenSet is #614's regression test for the
// refusal branch dropping e.JobID: Execution.CancelJob's machine-Account
// scoping (authorizeMachineCancel/refuseCancel) attributes a refusal to a
// real, already-resolved Job by setting AuditEntry.JobID, and that value
// must reach the PERSISTED audit.Record — not just be accepted by the
// in-memory capability.AuditEntry shape — or "which Job did this Account's
// refused cancel target" is unanswerable from the trail.
func TestRecordRefusalPersistsJobIDWhenSet(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))))

	entry := capability.AuditEntry{
		Kind:      capability.AuditKindRefusal,
		Principal: capability.Principal{Account: "gleipnir-prod", Kind: "machine"},
		Reason:    "capability: cancel refused: this Job was not requested by the caller, or its requester is not recorded",
		JobID:     "job-resolved-not-mine",
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
	if rec.JobID != entry.JobID {
		t.Errorf("JobID = %q, want %q — the machine-scoping refusal's resolved Job ID must be persisted", rec.JobID, entry.JobID)
	}
	if rec.NodeID != "" {
		t.Errorf("NodeID = %q, want empty (refusal never reaches a Node)", rec.NodeID)
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

// TestSink_RecordProtocolViolationWritesTheRowAndNoOutput is #638's trail
// acceptance test: a KindProtocolViolation row over a real store, with no
// Principal, no Outcome, and no Stdout/Stderr/Truncated — every field is
// Relay-authored or Relay-minted, and none of it is Node output.
func TestSink_RecordProtocolViolationWritesTheRowAndNoOutput(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	ev := jobs.ProtocolViolationEvent{
		NodeID:        "node-1",
		TaskID:        "task-1",
		JobID:         "job-1",
		OperationName: "list_files",
		Violation: jobs.ProtocolViolation{
			Rule:            jobs.ViolationRelayOnlyOutcome,
			ReportedOutcome: "OUTCOME_VERSION_REFUSED",
		},
	}
	if err := sink.RecordProtocolViolation(context.Background(), ev); err != nil {
		t.Fatalf("RecordProtocolViolation: %v", err)
	}

	records, err := repo.ByNode(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ByNode(node-1) returned %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Kind != audit.KindProtocolViolation {
		t.Errorf("Kind = %q, want %q", rec.Kind, audit.KindProtocolViolation)
	}
	if rec.Principal != "" {
		t.Errorf("Principal = %q, want empty — no Account did this", rec.Principal)
	}
	if rec.Outcome != jobs.OutcomeUnspecified {
		t.Errorf("Outcome = %v, want jobs.OutcomeUnspecified", rec.Outcome)
	}
	if rec.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want node-1", rec.NodeID)
	}
	if rec.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1", rec.JobID)
	}
	if rec.OperationName != "list_files" {
		t.Errorf("OperationName = %q, want list_files", rec.OperationName)
	}
	if len(rec.Stdout) != 0 || len(rec.Stderr) != 0 || rec.Truncated {
		t.Errorf("record carries Stdout/Stderr/Truncated: %+v", rec)
	}
	wantReason := "rule=relay_only_outcome reported_outcome=OUTCOME_VERSION_REFUSED task_id=task-1"
	if rec.Reason != wantReason {
		t.Errorf("Reason = %q, want %q", rec.Reason, wantReason)
	}
}

// TestProtocolViolationReason_Fields pins the exact
// "rule=... reported_outcome=... task_id=..." rendering (a stable,
// greppable contract), and the "unnamed" fallback for an empty
// ReportedOutcome.
func TestProtocolViolationReason_Fields(t *testing.T) {
	cases := []struct {
		name string
		ev   jobs.ProtocolViolationEvent
		want string
	}{
		{
			name: "relay only outcome",
			ev: jobs.ProtocolViolationEvent{
				TaskID:    "task-1",
				Violation: jobs.ProtocolViolation{Rule: jobs.ViolationRelayOnlyOutcome, ReportedOutcome: "OUTCOME_VERSION_REFUSED"},
			},
			want: "rule=relay_only_outcome reported_outcome=OUTCOME_VERSION_REFUSED task_id=task-1",
		},
		{
			name: "unresolved outcome with no reported name",
			ev: jobs.ProtocolViolationEvent{
				TaskID:    "task-2",
				Violation: jobs.ProtocolViolation{Rule: jobs.ViolationUnresolvedOutcome},
			},
			want: "rule=unresolved_outcome reported_outcome=unnamed task_id=task-2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := protocolViolationReason(tc.ev); got != tc.want {
				t.Errorf("protocolViolationReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSink_RecordAccountAdminMapsEveryKind is #653's mapping proof: every
// capability.AccountAdminKind this package knows about maps to its own
// audit.Kind* string (audit.KindAccountCreate/Role/Enable/Disable,
// audit.KindAPITokenMint/Revoke), attributed to the acting Principal, with
// Reason carrying the field-per-kind strings recordLifecycle wrote directly
// before #653 moved this surface into the capability layer.
//
// records[i] is indexed against cases[i], which rests on two things now
// tested rather than assumed (#656): List orders by (ts, audit_id), and under
// fixedClock all six rows share a ts — so this is also a tie-break proof. The
// ids come from sequentialIDs, which sorts in call order past ten precisely so
// a seventh case here cannot break this alignment.
func TestSink_RecordAccountAdminMapsEveryKind(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))
	principal := capability.Principal{Account: "admin-1", Role: "admin"}

	cases := []struct {
		kind       capability.AccountAdminKind
		event      capability.AccountAdminEvent
		wantKind   string
		wantReason string
	}{
		{capability.AccountAdminCreate,
			capability.AccountAdminEvent{Kind: capability.AccountAdminCreate, AccountID: "acct-1", AccountName: "gleipnir", AccountKind: "machine", Role: "operator"},
			audit.KindAccountCreate, "account_id=acct-1 name=gleipnir kind=machine role=operator"},
		{capability.AccountAdminRole,
			capability.AccountAdminEvent{Kind: capability.AccountAdminRole, AccountID: "acct-1", Role: "admin"},
			audit.KindAccountRole, "account_id=acct-1 role=admin"},
		{capability.AccountAdminEnable,
			capability.AccountAdminEvent{Kind: capability.AccountAdminEnable, AccountID: "acct-1"},
			audit.KindAccountEnable, "account_id=acct-1"},
		{capability.AccountAdminDisable,
			capability.AccountAdminEvent{Kind: capability.AccountAdminDisable, AccountID: "acct-1"},
			audit.KindAccountDisable, "account_id=acct-1"},
		{capability.AccountAdminTokenMint,
			capability.AccountAdminEvent{Kind: capability.AccountAdminTokenMint, AccountID: "acct-1", TokenID: "tok-1"},
			audit.KindAPITokenMint, "account_id=acct-1 api_token_id=tok-1"},
		{capability.AccountAdminTokenRevoke,
			capability.AccountAdminEvent{Kind: capability.AccountAdminTokenRevoke, TokenID: "tok-1"},
			audit.KindAPITokenRevoke, "api_token_id=tok-1"},
	}

	for _, tc := range cases {
		t.Run(tc.wantKind, func(t *testing.T) {
			if err := sink.RecordAccountAdmin(context.Background(), principal, tc.event); err != nil {
				t.Fatalf("RecordAccountAdmin: %v", err)
			}
		})
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != len(cases) {
		t.Fatalf("List returned %d records, want %d", len(records), len(cases))
	}
	for i, tc := range cases {
		rec := records[i]
		if rec.Kind != tc.wantKind {
			t.Errorf("record %d: Kind = %q, want %q", i, rec.Kind, tc.wantKind)
		}
		if rec.Principal != principal.Attribution() {
			t.Errorf("record %d: Principal = %q, want %q", i, rec.Principal, principal.Attribution())
		}
		if rec.Reason != tc.wantReason {
			t.Errorf("record %d: Reason = %q, want %q", i, rec.Reason, tc.wantReason)
		}
	}
}

// TestSink_RecordAccountAdminMintCarriesNoSecret is #653's acceptance
// criterion expressed against the real sink: the mint audit row has no field
// a Plaintext could occupy. AccountAdminEvent structurally has no such field
// (seams.go); this proves the RENDERED Record carries only the token's id.
func TestSink_RecordAccountAdminMintCarriesNoSecret(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC))))

	const secret = "glp_deadbeef.super-secret-value"
	event := capability.AccountAdminEvent{
		Kind: capability.AccountAdminTokenMint, AccountID: "acct-1", TokenID: "tok-1",
	}
	if err := sink.RecordAccountAdmin(context.Background(), capability.Principal{Account: "admin"}, event); err != nil {
		t.Fatalf("RecordAccountAdmin: %v", err)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("List returned %d records, want 1", len(records))
	}
	rec := records[0]
	if strings.Contains(rec.Reason, secret) {
		t.Errorf("Reason %q contains the plaintext credential", rec.Reason)
	}
	if string(rec.Stdout) != "" || string(rec.Stderr) != "" {
		t.Errorf("mint record carries Stdout/Stderr, which a Plaintext could occupy: %+v", rec)
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
	t.Cleanup(func() { st2.Close() })

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

// The capability layer mirrors internal/audit's asserted-attribution type
// rather than importing it, because capability's import allowlist is
// deliberately narrow. That mirroring is correct, but it leaves a hand-written
// mapping (attribution) as the single point where the two must agree — and a
// field added to one side would simply stop being recorded, silently, with
// every existing test still green.
//
// This pins the two shapes together. It is not a style check: an unrecorded
// asserted field is an audit record that quietly says less than the caller
// said, which is the exact failure the verified/asserted split exists to
// prevent.
func TestAssertedLaneShapesAgree(t *testing.T) {
	capType := reflect.TypeOf(capability.Assertions{})
	auditType := reflect.TypeOf(audit.Asserted{})

	if capType.NumField() != auditType.NumField() {
		t.Fatalf("capability.Assertions has %d fields, audit.Asserted has %d — the mapping in attribution() cannot be total",
			capType.NumField(), auditType.NumField())
	}
	for i := 0; i < capType.NumField(); i++ {
		c, a := capType.Field(i), auditType.Field(i)
		if c.Name != a.Name || c.Type != a.Type {
			t.Errorf("field %d differs: capability.%s %s vs audit.%s %s", i, c.Name, c.Type, a.Name, a.Type)
		}
	}
}

// The same guard for the verified lane: every field the Principal carries that
// belongs in audit must actually reach it. Asserted by round-tripping a fully
// populated Principal and checking nothing arrived empty, so a new Principal
// field that attribution() forgets shows up as a zero value here.
func TestVerifiedLaneMappingIsTotal(t *testing.T) {
	p := capability.Principal{
		AccountID:  "acct-1",
		Account:    "gleipnir",
		Role:       "operator",
		TokenID:    "tok-1",
		AuthMethod: capability.AuthMethodAPIToken,
		Source:     "198.51.100.7",
	}
	got := attribution(p, capability.Assertions{})

	v := reflect.ValueOf(got.Verified)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("audit.Verified.%s is empty after mapping a fully-populated Principal — attribution() does not carry it",
				v.Type().Field(i).Name)
		}
	}
}

// TestRecordCarriesTheApprovalLinkOnEveryKind is the property that makes
// "what ran under this approval" a truthful query (#378, ADR-0027).
//
// The link is copied once, above the Kind branches, precisely so it cannot be
// per-branch. A query that silently returns a SMALLER set than the truth is the
// worst way for an audit trail to be wrong, and that is exactly what a branch
// added later without the copy would produce — so this test walks every Kind
// that can carry a link rather than sampling one.
func TestRecordCarriesTheApprovalLinkOnEveryKind(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	p := capability.Principal{Account: "gleipnir", Role: "operator"}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}

	kinds := []capability.AuditKind{
		capability.AuditKindApprovalRequested,
		capability.AuditKindApprovalGrantRequested,
		capability.AuditKindApprovalPendingObserved,
		capability.AuditKindApprovalDecided,
		capability.AuditKindDispatch,
	}
	for _, kind := range kinds {
		entry := capability.AuditEntry{
			Kind: kind, Principal: p, Action: act,
			ApprovalID: "appr-1", GrantID: "grant-1",
			// Reason is set for every kind so the assertion below can hold the
			// per-kind branches to carrying it. Dropping base.Reason from one
			// of them stores a record whose prose is blank, which on the
			// approvals detail page means the ask no longer says what was
			// asked for -- and nothing else in the suite looks at it.
			Reason: fmt.Sprintf("linked-%v", kind),
		}
		if kind == capability.AuditKindDispatch {
			entry.JobID = "job-1"
			entry.Results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeSuccess}}
		}
		if err := sink.Record(context.Background(), entry); err != nil {
			t.Fatalf("Record(%v): %v", kind, err)
		}
	}

	got, err := repo.ByApproval(context.Background(), "appr-1")
	if err != nil {
		t.Fatalf("ByApproval: %v", err)
	}
	if len(got) != len(kinds) {
		t.Fatalf("ByApproval returned %d records, want %d — one per Kind that can carry a link", len(got), len(kinds))
	}
	for _, r := range got {
		if r.GrantID != "grant-1" {
			t.Errorf("record %q (kind %s) has grant %q, want grant-1", r.ID, r.Kind, r.GrantID)
		}
	}
	// Each capability Kind must land under its own audit kind — in particular a
	// re-drive (#379) must not fall through to the dispatch branch and be
	// recorded as something that ran.
	wantKinds := map[string]bool{
		audit.KindApprovalRequested:       true,
		audit.KindApprovalGrantRequested:  true,
		audit.KindApprovalPendingObserved: true,
		audit.KindApprovalDecided:         true,
		audit.KindDispatch:                true,
	}
	// Reason is asserted for the APPROVAL kinds only. Each of their branches
	// copies e.Reason explicitly, and dropping that line stores a record whose
	// prose is blank — on the approvals detail page, an ask that no longer says
	// what was asked for. A dispatch is excluded deliberately: it carries
	// results rather than a sentence, and its branch does not set Reason at all.
	reasonKinds := map[string]bool{
		audit.KindApprovalRequested:       true,
		audit.KindApprovalGrantRequested:  true,
		audit.KindApprovalPendingObserved: true,
		audit.KindApprovalDecided:         true,
	}
	for _, r := range got {
		if reasonKinds[r.Kind] && r.Reason == "" {
			t.Errorf("record %q (kind %s) lost its Reason — the branch that maps this kind "+
				"is not copying it, and the ask stops saying what was asked for", r.ID, r.Kind)
		}
		if !wantKinds[r.Kind] {
			t.Errorf("record %q stored under kind %q, not one of the linked kinds", r.ID, r.Kind)
		}
		delete(wantKinds, r.Kind)
	}
	if len(wantKinds) != 0 {
		t.Errorf("missing audit kinds in the linked set: %v", wantKinds)
	}

	// A dispatch with no approval in its history reads back empty, so the
	// column means "no approval was involved" rather than "unknown".
	if err := sink.Record(context.Background(), capability.AuditEntry{
		Kind: capability.AuditKindDispatch, Principal: p, Action: act, JobID: "job-2",
		Results: []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeSuccess}},
	}); err != nil {
		t.Fatalf("Record(unapproved): %v", err)
	}
	unlinked, err := repo.ByJob(context.Background(), "job-2")
	if err != nil || len(unlinked) != 1 {
		t.Fatalf("ByJob: %v (%d records)", err, len(unlinked))
	}
	if unlinked[0].ApprovalID != "" || unlinked[0].GrantID != "" {
		t.Errorf("unapproved dispatch = approval %q grant %q, want both empty",
			unlinked[0].ApprovalID, unlinked[0].GrantID)
	}
}

// TestRecord_ApprovalDecidedCarriesTheAnswerChannelAndPlanHash (#545): a
// decision's structured answer and Channel, and PlanHash on every Kind that
// carries one, survive a REAL Sink.Record call and read back off the store —
// not a mock, so a dropped mapping between AuditEntry and audit.Record would
// fail here even if a narrower unit test missed it.
func TestRecord_ApprovalDecidedCarriesTheAnswerChannelAndPlanHash(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")),
		WithClock(fixedClock(time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC))),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	approver := capability.Principal{Account: "ana", Role: "operator"}
	denier := capability.Principal{Account: "bo", Role: "operator"}
	revoker := capability.Principal{Account: "ops-console", Role: "admin"}

	if err := sink.Record(context.Background(), capability.AuditEntry{
		Kind: capability.AuditKindApprovalDecided, Principal: approver,
		ApprovalID: "appr-approved", PlanHash: "hash-approved",
		ApprovalAnswer: capability.ApprovalAnswerApproved, DecisionChannel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("Record(approved): %v", err)
	}
	if err := sink.Record(context.Background(), capability.AuditEntry{
		Kind: capability.AuditKindApprovalDecided, Principal: denier,
		ApprovalID: "appr-denied", PlanHash: "hash-denied",
		ApprovalAnswer: capability.ApprovalAnswerDenied, DecisionChannel: approval.ChannelInBand,
	}); err != nil {
		t.Fatalf("Record(denied): %v", err)
	}
	if err := sink.Record(context.Background(), capability.AuditEntry{
		Kind: capability.AuditKindApprovalDecided, Principal: revoker,
		ApprovalID: "appr-revoked", GrantID: "grant-1", PlanHash: "hash-revoked",
		// ApprovalAnswer and DecisionChannel deliberately left zero: RevokeGrant
		// never sets them.
	}); err != nil {
		t.Fatalf("Record(revocation): %v", err)
	}

	approved, err := repo.ByApproval(context.Background(), "appr-approved")
	if err != nil || len(approved) != 1 {
		t.Fatalf("ByApproval(appr-approved): %v (%d records)", err, len(approved))
	}
	if approved[0].ApprovalAnswer != audit.ApprovalAnswerApproved {
		t.Errorf("approved record ApprovalAnswer = %q, want %q", approved[0].ApprovalAnswer, audit.ApprovalAnswerApproved)
	}
	if approved[0].DecisionChannel != approval.ChannelOutOfBand.String() {
		t.Errorf("approved record DecisionChannel = %q, want %q", approved[0].DecisionChannel, approval.ChannelOutOfBand.String())
	}
	if approved[0].PlanHash != "hash-approved" {
		t.Errorf("approved record PlanHash = %q, want %q", approved[0].PlanHash, "hash-approved")
	}

	denied, err := repo.ByApproval(context.Background(), "appr-denied")
	if err != nil || len(denied) != 1 {
		t.Fatalf("ByApproval(appr-denied): %v (%d records)", err, len(denied))
	}
	if denied[0].ApprovalAnswer != audit.ApprovalAnswerDenied {
		t.Errorf("denied record ApprovalAnswer = %q, want %q", denied[0].ApprovalAnswer, audit.ApprovalAnswerDenied)
	}
	if denied[0].DecisionChannel != approval.ChannelInBand.String() {
		t.Errorf("denied record DecisionChannel = %q, want %q", denied[0].DecisionChannel, approval.ChannelInBand.String())
	}

	revoked, err := repo.ByApproval(context.Background(), "appr-revoked")
	if err != nil || len(revoked) != 1 {
		t.Fatalf("ByApproval(appr-revoked): %v (%d records)", err, len(revoked))
	}
	// The revocation's three are "" and NOT "unspecified": empty means "not
	// recorded", and a fourth spelling nothing else understands would defeat
	// the point of a fixed vocabulary.
	if revoked[0].ApprovalAnswer != "" {
		t.Errorf("revocation ApprovalAnswer = %q, want empty", revoked[0].ApprovalAnswer)
	}
	if revoked[0].DecisionChannel != "" {
		t.Errorf("revocation DecisionChannel = %q, want empty, not %q", revoked[0].DecisionChannel, "unspecified")
	}
	if revoked[0].PlanHash != "hash-revoked" {
		t.Errorf("revocation PlanHash = %q, want %q", revoked[0].PlanHash, "hash-revoked")
	}
}

// TestApprovalAnswerVocabularyMatchesTheDomain pins capability.ApprovalAnswer*,
// audit.ApprovalAnswer*, and approval.State*.String() equal — auditsink is the
// one package that imports all three, so this is the one place the mirrored
// vocabulary (capability may not import internal/audit) can be checked
// against its source rather than trusted by convention.
// TestApprovalAnswerFailsClosedOnAnUnknownValue pins the whitelist added after
// the #545 security review. No caller can produce an unknown answer today --
// approvalAnswerOf is total over a bool -- so this guards the direction a
// future producer would break: the audit column has no CHECK constraint, and
// an unrecognised value would reach the Activity CSV export verbatim while the
// Console's approvalStateChip refused to render it, putting a value on the
// evidence export that the screen denies. Empty is the third state and the
// safe landing place.
func TestApprovalAnswerFailsClosedOnAnUnknownValue(t *testing.T) {
	for _, unknown := range []capability.ApprovalAnswer{"yes", "no", "APPROVED", "refused", "denied "} {
		if got := approvalAnswer(unknown); got != "" {
			t.Errorf("approvalAnswer(%q) = %q, want %q — an unrecognised answer must fail "+
				"closed onto the unrecorded third state, not reach the trail verbatim",
				unknown, got, "")
		}
	}
	// And the two real values still pass through, so the whitelist did not
	// close over everything.
	if got := approvalAnswer(capability.ApprovalAnswerApproved); got != audit.ApprovalAnswerApproved {
		t.Errorf("approvalAnswer(Approved) = %q, want %q", got, audit.ApprovalAnswerApproved)
	}
	if got := approvalAnswer(capability.ApprovalAnswerDenied); got != audit.ApprovalAnswerDenied {
		t.Errorf("approvalAnswer(Denied) = %q, want %q", got, audit.ApprovalAnswerDenied)
	}
}

func TestApprovalAnswerVocabularyMatchesTheDomain(t *testing.T) {
	if string(capability.ApprovalAnswerApproved) != audit.ApprovalAnswerApproved {
		t.Errorf("capability.ApprovalAnswerApproved = %q, audit.ApprovalAnswerApproved = %q — the mirrored vocabularies disagree",
			capability.ApprovalAnswerApproved, audit.ApprovalAnswerApproved)
	}
	if audit.ApprovalAnswerApproved != approval.StateApproved.String() {
		t.Errorf("audit.ApprovalAnswerApproved = %q, approval.StateApproved.String() = %q — disagree",
			audit.ApprovalAnswerApproved, approval.StateApproved.String())
	}
	if string(capability.ApprovalAnswerDenied) != audit.ApprovalAnswerDenied {
		t.Errorf("capability.ApprovalAnswerDenied = %q, audit.ApprovalAnswerDenied = %q — the mirrored vocabularies disagree",
			capability.ApprovalAnswerDenied, audit.ApprovalAnswerDenied)
	}
	if audit.ApprovalAnswerDenied != approval.StateDenied.String() {
		t.Errorf("audit.ApprovalAnswerDenied = %q, approval.StateDenied.String() = %q — disagree",
			audit.ApprovalAnswerDenied, approval.StateDenied.String())
	}
	if decisionChannel(approval.ChannelInBand) != approval.ChannelInBand.String() {
		t.Errorf("decisionChannel(ChannelInBand) = %q, want %q", decisionChannel(approval.ChannelInBand), approval.ChannelInBand.String())
	}
}

// ADR-0042: retention is decided PER RESULT from the class that Node's Task
// ran under. A Template dispatch whose resolved class is mutate (one Node
// reported mutate) must still retain nothing from a Node that reported read —
// otherwise one Node could cause every other Node's read output to be kept
// (ADR-0025). The mutate Node's own output is the control.
func TestRecordDispatchRetentionFollowsEachResultsOwnClass(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))))
	ctx := context.Background()

	secret := []byte("PGPASSWORD=hunter2 /usr/bin/psql -h db.internal")
	if err := sink.Record(ctx, capability.AuditEntry{
		Kind:      capability.AuditKindDispatch,
		Principal: capability.Principal{Account: "gleipnir", Role: "operator"},
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "proc.list", RiskClass: jobs.RiskClassMutate},
		JobID:     "job-mixed",
		Results: []capability.NodeResult{
			{NodeID: "honest", Outcome: jobs.OutcomeSuccess, Stdout: secret, RiskClass: jobs.RiskClassRead},
			{NodeID: "says-mutate", Outcome: jobs.OutcomeSuccess, Stdout: []byte("its own output"), RiskClass: jobs.RiskClassMutate},
		},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	recs, err := repo.ByJob(ctx, "job-mixed")
	if err != nil || len(recs) != 2 {
		t.Fatalf("ByJob(job-mixed): %v (%d records)", err, len(recs))
	}
	for _, r := range recs {
		switch r.NodeID {
		case "honest":
			if len(r.Stdout) != 0 {
				t.Errorf("the read-reporting Node's output was retained under the dispatch's mutate class: %q", r.Stdout)
			}
		case "says-mutate":
			if string(r.Stdout) != "its own output" {
				t.Errorf("the mutate-reporting Node's own output = %q, want it retained", r.Stdout)
			}
		}
	}
}
