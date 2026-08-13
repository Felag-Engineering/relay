package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// -----------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------

// readRecord is one captured ReadAuditor call.
type readRecord struct {
	Principal  capability.Principal
	Capability string
	JobID      string
}

type fakeReadAuditor struct {
	mu      sync.Mutex
	records []readRecord
	err     error
}

func (f *fakeReadAuditor) RecordRead(_ context.Context, p capability.Principal, tool, _, _, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, readRecord{Principal: p, Capability: tool, JobID: jobID})
	return f.err
}

func (f *fakeReadAuditor) all() []readRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]readRecord(nil), f.records...)
}

// newJobFixture mounts the routes with a chosen role, executor, job reader and
// read auditor.
func newJobFixture(t *testing.T, role accounts.Role, exec *fakeExecutor, jr JobResultReader, reads ReadAuditor) http.Handler {
	t.Helper()
	exec.gate = authz.NewRoleGate()
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role})
	mux := http.NewServeMux()
	Register(mux, Deps{Exec: exec, Jobs: jr, Reads: reads, Now: fixedNow})
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
	if got[0].Capability != readCapabilityGetJob {
		t.Errorf("recorded capability = %q, want %q (one name across surfaces)", got[0].Capability, readCapabilityGetJob)
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
	Register(mux, Deps{Now: fixedNow}) // no Exec, no Jobs
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
