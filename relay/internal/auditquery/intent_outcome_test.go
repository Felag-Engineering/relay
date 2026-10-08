package auditquery

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// killBeforeOutcome models the Relay dying between dispatch and the outcome
// append (#887): AppendWithTasks passes through, and Append of a dispatch
// outcome row succeeds allow times and then fails — the process is gone.
type killBeforeOutcome struct {
	audit.Repository
	allow int

	mu sync.Mutex
	n  int
}

func (k *killBeforeOutcome) Append(ctx context.Context, r audit.Record) error {
	if r.Kind == audit.KindDispatch {
		k.mu.Lock()
		k.n++
		dead := k.n > k.allow
		k.mu.Unlock()
		if dead {
			return errors.New("killed before the outcome append")
		}
	}
	return k.Repository.Append(ctx, r)
}

var intentTestRequester = capability.Principal{
	AccountID: "acct-1", Account: "agent-1", Role: "operator", Kind: "machine",
	AuthMethod: "api_token", Source: "mcp",
}

// runWithRepo dispatches one read Operation to two Nodes through a real store
// whose audit repository is wrap(st.Audit()), and returns the store's path
// and Run's error.
func runWithRepo(t *testing.T, wrap func(audit.Repository) audit.Repository) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close() //nolint:errcheck

	reg := registry.NewInMemory()
	for _, id := range []string{"node-1", "node-2"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	svc := capability.New(reg,
		capability.WithAuthorizer(authz.NewRoleGate()),
		capability.WithCapChecker(capability.NewBlastCap(10, 10)),
		capability.WithAuditSink(auditsink.New(wrap(st.Audit()))),
		capability.WithFreeze(st.Freeze()),
		capability.WithExecution(st.Jobs(), st.Tasks(), &probeConduit{probe: func() {}}, capability.WithExecNewID(counterID("id-"))),
	)
	sel := capability.Selector{Predicates: []capability.Predicate{{Namespace: capability.NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	_, runErr := svc.Run(context.Background(), intentTestRequester, sel, act)
	return path, runErr
}

// afterRestart reopens path and returns a Service over it with the read lane.
func afterRestart(t *testing.T, path string) (*capability.Service, *store.Store) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	q := New(st.AuditQueries(), st.JobQueries())
	svc := capability.New(registry.NewInMemory(),
		capability.WithAuthorizer(authz.NewRoleGate()),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithQueries(q, q),
	)
	return svc, st
}

func queryRows(t *testing.T, svc *capability.Service, kind string) []capability.AuditRow {
	t.Helper()
	page, err := svc.QueryAudit(context.Background(), intentTestRequester,
		capability.AuditFilter{Kinds: []string{kind}, JobID: "job-id-1"}, capability.PageRequest{Limit: 50})
	if err != nil {
		t.Fatalf("QueryAudit(%s): %v", kind, err)
	}
	return page.Rows
}

func jobSummary(t *testing.T, svc *capability.Service) capability.JobSummary {
	t.Helper()
	page, err := svc.QueryJobs(context.Background(), intentTestRequester,
		capability.JobFilter{JobID: "job-id-1"}, capability.PageRequest{Limit: 1})
	if err != nil || len(page.Jobs) != 1 {
		t.Fatalf("QueryJobs: %v (%d jobs)", err, len(page.Jobs))
	}
	return page.Jobs[0]
}

// TestIntentSurvivesACrashBeforeTheOutcomeAppend is #887's second acceptance
// line: the engine dies between dispatch and the outcome append, and after a
// restart the intent row is on the trail and the read lane reports "intent
// recorded, outcome unknown" rather than a Job with no audit record.
func TestIntentSurvivesACrashBeforeTheOutcomeAppend(t *testing.T) {
	path, runErr := runWithRepo(t, func(r audit.Repository) audit.Repository {
		return &killBeforeOutcome{Repository: r, allow: 0}
	})
	if runErr == nil {
		t.Fatal("Run succeeded although the outcome append was killed")
	}

	svc, st := afterRestart(t, path)

	sum := jobSummary(t, svc)
	if sum.State != jobs.JobStateComplete || sum.Recording != jobs.JobRecordingIntentOnly || !sum.OutcomeUnrecorded() {
		t.Errorf("summary = state %v recording %v unrecorded %v, want Complete/IntentOnly/true",
			sum.State, sum.Recording, sum.OutcomeUnrecorded())
	}

	intent := queryRows(t, svc, audit.KindDispatchIntent)
	if len(intent) != 1 {
		t.Fatalf("%d dispatch_intent rows, want 1", len(intent))
	}
	r := intent[0]
	if r.Principal == "" || r.Verified.Method != "api_token" || r.Verified.Source != "mcp" ||
		r.Selector != "node:role=web" || r.OperationName != "system.facts" {
		t.Errorf("intent row = %+v", r)
	}
	for _, want := range []string{"cap_cleared=2", "node_count=2", "node-1", "node-2"} {
		if !strings.Contains(r.Reason, want) {
			t.Errorf("intent Reason %q lacks %q", r.Reason, want)
		}
	}
	if got := queryRows(t, svc, audit.KindDispatch); len(got) != 0 {
		t.Errorf("%d dispatch outcome rows, want none", len(got))
	}

	st.Close() //nolint:errcheck
	v, err := store.VerifyAuditChain(context.Background(), path, nil)
	if err != nil || !v.Intact() {
		t.Errorf("chain verdict = %+v, err %v; want intact", v, err)
	}
}

// TestPartialOutcomeAppendIsReportedAsUnknown: a crash partway through the
// per-Node outcome appends leaves some rows, which the count comparison
// reports as partial rather than as fully recorded.
func TestPartialOutcomeAppendIsReportedAsUnknown(t *testing.T) {
	path, runErr := runWithRepo(t, func(r audit.Repository) audit.Repository {
		return &killBeforeOutcome{Repository: r, allow: 1}
	})
	if runErr == nil {
		t.Fatal("Run succeeded although an outcome append was killed")
	}
	svc, _ := afterRestart(t, path)

	sum := jobSummary(t, svc)
	if sum.Recording != jobs.JobRecordingOutcomePartial || !sum.OutcomeUnrecorded() {
		t.Errorf("recording = %v unrecorded = %v, want OutcomePartial/true", sum.Recording, sum.OutcomeUnrecorded())
	}
}

// TestOutcomeRowsShareTheIntentRowsJob is the happy path: one intent, one
// outcome row per Node, all under the same job_id, the intent first.
func TestOutcomeRowsShareTheIntentRowsJob(t *testing.T) {
	path, runErr := runWithRepo(t, func(r audit.Repository) audit.Repository { return r })
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	svc, st := afterRestart(t, path)

	recs, err := st.Audit().ByJob(context.Background(), "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	intents, outcomes := 0, 0
	for _, r := range recs {
		switch r.Kind {
		case audit.KindDispatchIntent:
			intents++
		case audit.KindDispatch:
			outcomes++
		}
	}
	// The doc promises the intent's chain seq is lower than every outcome's;
	// ByJob orders by timestamp, so check seq directly.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck
	rows, err := db.QueryContext(context.Background(), `SELECT kind FROM audit WHERE job_id = ? ORDER BY seq`, "job-id-1")
	if err != nil {
		t.Fatalf("query by seq: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	seenIntent := false
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case audit.KindDispatchIntent:
			seenIntent = true
		case audit.KindDispatch:
			if !seenIntent {
				t.Error("an outcome row has a lower seq than the intent row")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || outcomes != 2 {
		t.Errorf("intent rows = %d, outcome rows = %d; want 1 and 2", intents, outcomes)
	}
	sum := jobSummary(t, svc)
	if sum.Recording != jobs.JobRecordingOutcome || sum.OutcomeUnrecorded() {
		t.Errorf("recording = %v unrecorded = %v, want Outcome/false", sum.Recording, sum.OutcomeUnrecorded())
	}
}
