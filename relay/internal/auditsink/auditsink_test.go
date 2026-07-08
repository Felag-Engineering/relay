package auditsink

import (
	"bytes"
	"context"
	"io"
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
			{NodeID: "node-ok", Outcome: jobs.OutcomeSuccess},
			{NodeID: "node-denied", Outcome: jobs.OutcomeDeniedByPolicy},
			{NodeID: "node-offline", Outcome: jobs.OutcomeUnreachable},
			{NodeID: "node-cancelled", Outcome: jobs.OutcomeCancelled},
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
