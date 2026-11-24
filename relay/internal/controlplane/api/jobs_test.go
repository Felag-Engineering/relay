package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// -----------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------

// readRecord is one captured RecordRead call.
type readRecord struct {
	Principal  capability.Principal
	Capability string
	JobID      string
}

// fakeReadAuditor is the capability.AuditSink behind the Job route's read
// lane: it records every RecordRead, and log (when set) interleaves it with the
// Job source's reads so a test can assert the record came first.
type fakeReadAuditor struct {
	mu      sync.Mutex
	records []readRecord
	err     error
	log     *eventLog
}

func (*fakeReadAuditor) Record(context.Context, capability.AuditEntry) error        { return nil }
func (*fakeReadAuditor) RecordFreeze(context.Context, capability.FreezeEvent) error { return nil }
func (*fakeReadAuditor) RecordCancel(context.Context, capability.Principal, string) error {
	return nil
}
func (*fakeReadAuditor) RecordAccountAdmin(context.Context, capability.Principal, capability.AccountAdminEvent) error {
	return nil
}

// eventLog is an ordered log shared by a sink and a Job source.
type eventLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *eventLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, s)
}

func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

// loggingJobs wraps a JobResultReader, logging each read.
type loggingJobs struct {
	JobResultReader
	log *eventLog
}

func (l loggingJobs) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	l.log.add("GetJob")
	return l.JobResultReader.GetJob(ctx, id)
}

func (l loggingJobs) TasksByJob(ctx context.Context, id string) ([]jobs.Task, error) {
	l.log.add("TasksByJob")
	return l.JobResultReader.TasksByJob(ctx, id)
}

// countingJobs holds a Task with output and counts every read: a route that
// reads it around the read lane is the fallback these tests forbid.
type countingJobs struct {
	mu    sync.Mutex
	calls int
}

func (c *countingJobs) GetJob(context.Context, string) (jobs.Job, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return jobs.Job{ID: "job-1"}, nil
}

func (c *countingJobs) TasksByJob(context.Context, string) ([]jobs.Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess, Stdout: []byte("SECRET-OUTPUT")}}, nil
}

func (c *countingJobs) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (f *fakeReadAuditor) RecordRead(_ context.Context, p capability.Principal, tool, _, _, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, readRecord{Principal: p, Capability: tool, JobID: jobID})
	if f.log != nil {
		f.log.add("record")
	}
	return f.err
}

func (f *fakeReadAuditor) all() []readRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]readRecord(nil), f.records...)
}

// newJobFixture mounts the routes with a chosen role, executor, Job reader and
// audit sink. The Job route reads through a real capability read lane over jr
// and reads, as the composition root wires it.
func newJobFixture(t *testing.T, role accounts.Role, exec *fakeExecutor, jr JobResultReader, reads capability.AuditSink) http.Handler {
	t.Helper()
	exec.gate = authz.NewRoleGate()
	lane := newCapService(t, capSeams{reg: registry.NewInMemory(), audit: reads, jobResults: jr}).ReadLane
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role})
	mux := http.NewServeMux()
	Register(mux, Deps{Exec: exec, Jobs: jr, JobReader: lane})
	return authn.Middleware(mux)
}

// -----------------------------------------------------------------------
// GET /api/v1/jobs/{id}
// -----------------------------------------------------------------------

// TestGetJob_RendersTruthfulPerNodeOutcomes is the acceptance line: a
// dispatched Job is re-readable by id, and each Node's outcome is reported as
// it really was — including the exit_code presence discipline that keeps
// "did not run" from reading as "ran and succeeded" (#207/#253).
func TestGetJob_RendersTruthfulPerNodeOutcomes(t *testing.T) {
	created := time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC)
	jr := fakeJobs{
		job: jobs.Job{ID: "job-1", CreatedAt: created},
		tasks: []jobs.Task{
			{NodeID: "n-ok", Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte("hello")},
			{NodeID: "n-fail", Outcome: jobs.OutcomeFailure, ExitCode: 2},
			{NodeID: "n-denied", Outcome: jobs.OutcomeDeniedByPolicy, ExitCode: -1},
			{NodeID: "n-cancelled", Outcome: jobs.OutcomeCancelled, ExitCode: -1},
			{NodeID: "n-offline", Outcome: jobs.OutcomeUnreachable},
		},
	}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var body struct {
		JobID     string            `json:"job_id"`
		CreatedAt string            `json:"created_at"`
		Results   []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.JobID != "job-1" {
		t.Errorf("job_id = %q, want job-1", body.JobID)
	}
	if body.CreatedAt != created.Format(time.RFC3339) {
		t.Errorf("created_at = %q, want %q", body.CreatedAt, created.Format(time.RFC3339))
	}

	wantOutcome := map[string]string{
		"n-cancelled": "cancelled", "n-denied": "denied_by_policy", "n-fail": "failure",
		"n-offline": "unreachable", "n-ok": "success",
	}
	wantExitCode := map[string]bool{ // node -> exit_code key expected
		"n-cancelled": false, "n-denied": false, "n-fail": true,
		"n-offline": false, "n-ok": true,
	}
	if len(body.Results) != len(wantOutcome) {
		t.Fatalf("%d results, want %d", len(body.Results), len(wantOutcome))
	}
	// Results are sorted by node_id for a stable response across polls.
	var prev string
	for _, raw := range body.Results {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		var nodeID, outcome string
		_ = json.Unmarshal(m["node_id"], &nodeID)
		_ = json.Unmarshal(m["outcome"], &outcome)
		if outcome != wantOutcome[nodeID] {
			t.Errorf("%s: outcome = %q, want %q", nodeID, outcome, wantOutcome[nodeID])
		}
		if _, present := m["exit_code"]; present != wantExitCode[nodeID] {
			t.Errorf("%s: exit_code present = %v, want %v (raw %s)", nodeID, present, wantExitCode[nodeID], raw)
		}
		if nodeID < prev {
			t.Errorf("results not sorted by node_id: %q after %q", nodeID, prev)
		}
		prev = nodeID
	}
}

// A Job that does not exist — including the id a Plan would have had, since a
// Plan creates no Job — is a legible 404, not a 500 and not an empty 200.
func TestGetJob_UnknownIDIsA404(t *testing.T) {
	jr := fakeJobs{getErr: jobs.ErrJobNotFound}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-never-existed", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// -----------------------------------------------------------------------
// Read auditing (#288, ADR-0025)
// -----------------------------------------------------------------------

// TestGetJob_IsReadAudited pins the reason this route is audited at all:
// reading a Job returns captured Task output, so the REST twin must leave the
// same trail the MCP tool does. Without this, /api/v1/jobs/{id} would be an
// unaudited back door to material get_job records.
func TestGetJob_IsReadAudited(t *testing.T) {
	reads := &fakeReadAuditor{}
	jr := fakeJobs{job: jobs.Job{ID: "job-1"}, tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess}}}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, reads)

	if rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := reads.all()
	if len(got) != 1 {
		t.Fatalf("%d read records, want 1", len(got))
	}
	if got[0].JobID != "job-1" {
		t.Errorf("recorded job_id = %q, want job-1", got[0].JobID)
	}
	if got[0].Capability != "get_job" {
		t.Errorf("recorded capability = %q, want %q (one name across surfaces)", got[0].Capability, "get_job")
	}
	if got[0].Principal.Role != string(accounts.RoleViewer) {
		t.Errorf("recorded principal role = %q, want the authenticated caller's", got[0].Principal.Role)
	}
}

// An attempted read of a Job that does not exist is still recorded: "who tried
// to read what" is exactly what an incident reviewer wants, and recording only
// successful reads would leave probing invisible.
func TestGetJob_AuditsEvenWhenTheJobIsMissing(t *testing.T) {
	reads := &fakeReadAuditor{}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, fakeJobs{getErr: jobs.ErrJobNotFound}, reads)

	if rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-x", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := reads.all(); len(got) != 1 || got[0].JobID != "job-x" {
		t.Errorf("read records = %+v, want one for job-x", got)
	}
}

// TestGetJob_FailsClosedWhenUnauditable is ADR-0025's cost, stated plainly: a
// Relay that cannot write its access trail stops answering the read rather than
// answering it invisibly. The response must carry no Job content.
func TestGetJob_FailsClosedWhenUnauditable(t *testing.T) {
	reads := &fakeReadAuditor{err: errors.New("audit store down")}
	jr := fakeJobs{
		job:   jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess, Stdout: []byte("SECRET-OUTPUT")}},
	}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, reads)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (an unauditable read must not be served)", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "SECRET-OUTPUT") {
		t.Errorf("unauditable read leaked Job output: %s", body)
	}
}

// A route mounted with no read lane has no sink to record into, so it refuses
// the read rather than falling back to the Job reader it was also given.
func TestGetJob_AMissingSinkRefusesTheRead(t *testing.T) {
	jr := &countingJobs{}
	exec := &fakeExecutor{gate: authz.NewRoleGate()}
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleViewer})
	mux := http.NewServeMux()
	Register(mux, Deps{Exec: exec, Jobs: jr, JobReader: nil})
	h := authn.Middleware(mux)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SECRET-OUTPUT") {
		t.Errorf("a refused read leaked Job output: %s", rec.Body.String())
	}
	if n := jr.count(); n != 0 {
		t.Errorf("the route read the Job store %d times around the read lane, want 0", n)
	}
}

func TestGetJob_AFailingRecordRefusesTheRead(t *testing.T) {
	reads := &fakeReadAuditor{err: errors.New("audit store down")}
	jr := &countingJobs{}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, reads)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "read audit failed") {
		t.Errorf("body = %s, want the read audit failed problem", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SECRET-OUTPUT") || strings.Contains(rec.Body.String(), "audit store down") {
		t.Errorf("a refused read leaked content or the store's error: %s", rec.Body.String())
	}
	if n := jr.count(); n != 0 {
		t.Errorf("the Job store was read %d times after a failed record, want 0", n)
	}
}

func TestGetJob_RecordsOnceBeforeTheResult(t *testing.T) {
	log := &eventLog{}
	reads := &fakeReadAuditor{log: log}
	created := time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC)
	jr := loggingJobs{
		JobResultReader: fakeJobs{
			job:   jobs.Job{ID: "job-1", CreatedAt: created},
			tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess, Stdout: []byte("hello")}},
		},
		log: log,
	}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, reads)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got, want := strings.Join(log.all(), ","), "record,GetJob,TasksByJob"; got != want {
		t.Errorf("event order = %s, want %s", got, want)
	}
	if n := len(reads.all()); n != 1 {
		t.Errorf("%d read records, want exactly 1", n)
	}
	var body struct {
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.CreatedAt != created.Format(time.RFC3339) {
		t.Errorf("created_at = %q, want %q", body.CreatedAt, created.Format(time.RFC3339))
	}
}

// An id no Relay-issued Job can have is answered like any unknown Job and is
// not recorded, so a probe cannot use the trail as storage.
func TestGetJob_AnOverlongIdIsA404AndIsNotRecorded(t *testing.T) {
	reads := &fakeReadAuditor{}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, fakeJobs{job: jobs.Job{ID: "x"}}, reads)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/"+strings.Repeat("a", 129), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	if got := reads.all(); len(got) != 0 {
		t.Errorf("%d read records for an overlong id, want 0", len(got))
	}
}

// A read lane built with no Job store answers the route's own legible 500 and
// never echoes the lane's text.
func TestGetJob_WithNoJobStoreIsALegible500(t *testing.T) {
	reads := &fakeReadAuditor{}
	lane := newCapService(t, capSeams{reg: registry.NewInMemory(), audit: reads}).ReadLane
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleViewer})
	mux := http.NewServeMux()
	Register(mux, Deps{Exec: &fakeExecutor{gate: authz.NewRoleGate()}, JobReader: lane})
	h := authn.Middleware(mux)

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "execution unavailable") {
		t.Errorf("body = %s, want the execution unavailable problem", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "capability:") {
		t.Errorf("the lane's text reached the problem detail: %s", rec.Body.String())
	}
	if got := reads.all(); len(got) != 0 {
		t.Errorf("%d read records with no Job store, want 0", len(got))
	}
}

// -----------------------------------------------------------------------
// POST /api/v1/jobs/{id}/cancel
// -----------------------------------------------------------------------

// A cancel reaches the capability layer with the caller's Principal and the
// requested id — the Relay-side cancel path (ADR-0013), not a local shortcut.
func TestCancelJob_ReachesTheCapabilityLayer(t *testing.T) {
	exec := &fakeExecutor{}
	h := newJobFixture(t, accounts.RoleOperator, exec, fakeJobs{}, &fakeReadAuditor{})

	rec := do(t, h, http.MethodPost, "/api/v1/jobs/job-7/cancel", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body cancelJobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.JobID != "job-7" {
		t.Errorf("job_id = %q, want job-7 echoed back", body.JobID)
	}
	if got := exec.cancelCalls(); len(got) != 1 || got[0] != "job-7" {
		t.Errorf("CancelJob calls = %v, want [job-7]", got)
	}
}

// Cancelling an already-finished Job is a clean 200 no-op: every Task is
// terminal and none is touched, so there is nothing to report as an error. The
// capability layer returns nil in exactly that case.
func TestCancelJob_FinishedJobIsACleanNoOp(t *testing.T) {
	exec := &fakeExecutor{cancelErr: nil} // all Tasks resolved -> capability returns nil
	h := newJobFixture(t, accounts.RoleOperator, exec, fakeJobs{}, &fakeReadAuditor{})

	if rec := do(t, h, http.MethodPost, "/api/v1/jobs/job-done/cancel", nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an already-finished Job", rec.Code)
	}
}

// An unknown Job id is a 404 rather than a fabricated success: pretending a
// cancel worked on a Job that never existed is the more dangerous answer.
func TestCancelJob_UnknownIDIsA404(t *testing.T) {
	exec := &fakeExecutor{cancelErr: jobs.ErrJobNotFound}
	h := newJobFixture(t, accounts.RoleOperator, exec, fakeJobs{}, &fakeReadAuditor{})

	rec := do(t, h, http.MethodPost, "/api/v1/jobs/nope/cancel", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// A cancel refused by the capability layer's role floor (#595) renders 403,
// not 500 — writeJobError recognizes authz.ErrUnauthorized exactly like
// writeFreezeError and writeExecutionError do.
func TestCancelJob_ARefusalIsA403(t *testing.T) {
	refusal := authz.NewRoleGate().AuthorizeControl(context.Background(),
		capability.Principal{Account: "eve", Role: string(accounts.RoleViewer)}, capability.ControlCancelJob)
	if refusal == nil {
		t.Fatal("a viewer's AuthorizeControl(cancel_job) returned nil; this test's premise is wrong")
	}
	exec := &fakeExecutor{cancelErr: refusal}
	h := newJobFixture(t, accounts.RoleViewer, exec, fakeJobs{}, &fakeReadAuditor{})

	rec := do(t, h, http.MethodPost, "/api/v1/jobs/job-7/cancel", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "operator") {
		t.Errorf("body = %q, want it to name the required role %q", rec.Body.String(), "operator")
	}
}

// TestCancelJob_MachineScopingRefusalIsA403 is TestCancelJob_ARefusalIsA403's
// sibling for the OTHER cancel refusal the capability layer can return
// (#614): a machine Account's Job-scoping refusal, capability.
// ErrJobNotRequestedByCaller — writeJobError must recognize it exactly like
// authz.ErrUnauthorized, not fall through to the default 500.
func TestCancelJob_MachineScopingRefusalIsA403(t *testing.T) {
	exec := &fakeExecutor{cancelErr: capability.ErrJobNotRequestedByCaller}
	h := newJobFixture(t, accounts.RoleOperator, exec, fakeJobs{}, &fakeReadAuditor{})

	rec := do(t, h, http.MethodPost, "/api/v1/jobs/job-7/cancel", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "requested") {
		t.Errorf("body = %q, want it to carry ErrJobNotRequestedByCaller's reason", rec.Body.String())
	}
}

// A cancel is NOT read-audited: it changes state and is recorded by the
// capability layer's own RecordCancel, so recording it here too would
// double-audit the same act.
func TestCancelJob_IsNotReadAudited(t *testing.T) {
	reads := &fakeReadAuditor{}
	h := newJobFixture(t, accounts.RoleOperator, &fakeExecutor{}, fakeJobs{}, reads)

	do(t, h, http.MethodPost, "/api/v1/jobs/job-1/cancel", nil)

	if got := reads.all(); len(got) != 0 {
		t.Errorf("%d read records for a cancel, want 0 (capability.RecordCancel owns it)", len(got))
	}
}

// -----------------------------------------------------------------------
// Wiring / defensive shape
// -----------------------------------------------------------------------

func TestJobRoutes_UnwiredDependenciesAreALegible500(t *testing.T) {
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleAdmin})
	mux := http.NewServeMux()
	Register(mux, Deps{}) // no Exec, no Jobs
	h := authn.Middleware(mux)

	if rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("GET job: status = %d, want 500", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/v1/jobs/job-1/cancel", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("cancel job: status = %d, want 500", rec.Code)
	}
}

// Both routes sit behind the same Authenticator as every other /api/v1 route.
func TestJobRoutes_RequireAuthentication(t *testing.T) {
	h := newJobFixture(t, accounts.RoleAdmin, &fakeExecutor{}, fakeJobs{}, &fakeReadAuditor{})

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/jobs/job-1"},
		{http.MethodPost, "/api/v1/jobs/job-1/cancel"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, nil) // no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
}

// haltedFakeJobs is a Job the capability layer halted on node-1, with one
// halt-cancelled sibling.
func haltedFakeJobs(resolved bool) fakeJobs {
	h := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeFailure, Resolved: resolved}
	return fakeJobs{
		job: jobs.Job{ID: "job-1", Halt: h},
		tasks: []jobs.Task{
			{NodeID: "node-1", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeFailure, ExitCode: 1},
			{NodeID: "node-2", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeCancelled, Stderr: []byte(h.Reason())},
		},
	}
}

// decodeHalt returns the "halt" object of a response body, or nil if the key is
// absent.
func decodeHalt(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	halt, ok := m["halt"]
	if !ok {
		return nil
	}
	obj, ok := halt.(map[string]any)
	if !ok {
		t.Fatalf("halt = %#v, want an object", halt)
	}
	return obj
}

// TestGetJob_ReportsTheHalt: #1150, a halted Job's halt reaches the caller as
// exactly node_id, outcome, resolved and reason.
func TestGetJob_ReportsTheHalt(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		jr := haltedFakeJobs(resolved)
		h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

		rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
		}
		halt := decodeHalt(t, rec.Body.Bytes())
		want := map[string]any{
			"node_id": "node-1", "outcome": "failure", "resolved": resolved, "reason": jr.job.Halt.Reason(),
		}
		if !reflect.DeepEqual(halt, want) {
			t.Errorf("resolved=%v: halt = %#v, want %#v", resolved, halt, want)
		}
	}
}

func TestGetJob_NoHaltKeyWhenTheJobDidNotHalt(t *testing.T) {
	jr := fakeJobs{job: jobs.Job{ID: "job-1"}, tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess}}}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if halt := decodeHalt(t, rec.Body.Bytes()); halt != nil {
		t.Errorf("halt = %#v, want the key absent", halt)
	}
}

// job_status tells a poller when to stop: running while any Task is
// unresolved, complete once every Task is, and present in both.
//
// Proves EX-57.
func TestGetJob_ReportsJobStatus(t *testing.T) {
	for _, tt := range []struct {
		name  string
		state jobs.DispatchState
		want  string
	}{
		{"one Task dispatched", jobs.DispatchStateDispatched, "running"},
		{"every Task resolved", jobs.DispatchStateResolved, "complete"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jr := fakeJobs{job: jobs.Job{ID: "job-1"}, tasks: []jobs.Task{{NodeID: "n1", State: tt.state}}}
			h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

			rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := string(raw["job_status"]); got != `"`+tt.want+`"` {
				t.Errorf("job_status = %s, want %q", got, tt.want)
			}
		})
	}
}

func decodeOutcomeAuditFailure(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	f, ok := m["outcome_audit_failure"]
	if !ok {
		return nil
	}
	obj, ok := f.(map[string]any)
	if !ok {
		t.Fatalf("outcome_audit_failure = %#v, want an object", f)
	}
	return obj
}

func failedOutcomeFakeJobs() fakeJobs {
	return fakeJobs{
		job:   jobs.Job{ID: "job-1", OutcomeAuditFailedAt: time.Date(2026, 11, 17, 12, 30, 0, 0, time.UTC)},
		tasks: []jobs.Task{{NodeID: "node-1", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess}},
	}
}

var wantOutcomeAuditFailure = map[string]any{"at": "2026-11-17T12:30:00Z", "reason": jobs.OutcomeAuditFailureReason}

// Proves EX-66.
func TestGetJob_ReportsTheOutcomeAuditFailure(t *testing.T) {
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, failedOutcomeFakeJobs(), &fakeReadAuditor{})

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := decodeOutcomeAuditFailure(t, rec.Body.Bytes()); !reflect.DeepEqual(got, wantOutcomeAuditFailure) {
		t.Errorf("outcome_audit_failure = %#v, want %#v", got, wantOutcomeAuditFailure)
	}
}

func TestGetJob_NoOutcomeAuditFailureKeyWhenNoneWasRecorded(t *testing.T) {
	jr := fakeJobs{job: jobs.Job{ID: "job-1"}, tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess}}}
	h := newJobFixture(t, accounts.RoleViewer, &fakeExecutor{}, jr, &fakeReadAuditor{})

	rec := do(t, h, http.MethodGet, "/api/v1/jobs/job-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := decodeOutcomeAuditFailure(t, rec.Body.Bytes()); got != nil {
		t.Errorf("outcome_audit_failure = %#v, want the key absent", got)
	}
}
