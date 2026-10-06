package api

import (
	"context"
	"encoding/json"
	"net/http"
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
// Execution-route fakes.
//
// The Executor fake runs the REAL authz.RoleGate before returning its canned
// result. That is deliberate: the acceptance criterion "raw_exec requires
// admin; an operator is refused" is about the central role ladder, so proving
// it against a fake that merely returns a canned 403 would prove only that
// this file can spell errors. Delegating to the production gate pins the two
// things this issue actually owns — that the route hands the capability layer
// the right Action (Kind=ActionRawExec) and Principal, and that the refusal
// the gate returns renders as 403 rather than a 500.
//
// What it does NOT claim to prove is that capability.Service calls the
// Authorizer at all; that is capability's own test's job and is already
// covered there.
// -----------------------------------------------------------------------

type recordedCall struct {
	Principal capability.Principal
	Selector  capability.Selector
	Action    jobs.Action
}

type fakeExecutor struct {
	mu    sync.Mutex
	runs  []recordedCall
	plans []recordedCall

	// gate, when set, authorizes each call before the canned result is
	// returned — wired to the production authz.RoleGate by newExecFixture.
	gate capability.Authorizer

	runResults []capability.NodeResult
	runErr     error
	planResult capability.PlanResult
	planErr    error

	// cancels records every CancelJob call; cancelErr is what it returns.
	cancels   []string
	cancelErr error
}

func (f *fakeExecutor) CancelJob(_ context.Context, _ capability.Principal, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels = append(f.cancels, jobID)
	return f.cancelErr
}

func (f *fakeExecutor) cancelCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cancels...)
}

func (f *fakeExecutor) Run(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) ([]capability.NodeResult, error) {
	f.mu.Lock()
	f.runs = append(f.runs, recordedCall{Principal: p, Selector: sel, Action: act})
	f.mu.Unlock()
	if f.gate != nil {
		if err := f.gate.Authorize(ctx, p, act, sel); err != nil {
			return nil, err
		}
	}
	return f.runResults, f.runErr
}

func (f *fakeExecutor) Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error) {
	f.mu.Lock()
	f.plans = append(f.plans, recordedCall{Principal: p, Selector: sel, Action: act})
	f.mu.Unlock()
	if f.gate != nil {
		if err := f.gate.Authorize(ctx, p, act, sel); err != nil {
			return capability.PlanResult{}, err
		}
	}
	return f.planResult, f.planErr
}

func (f *fakeExecutor) runCalls() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.runs...)
}

func (f *fakeExecutor) planCalls() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.plans...)
}

// fakeJobs is a JobResultReader over in-memory Tasks.
type fakeJobs struct {
	job     jobs.Job
	tasks   []jobs.Task
	getErr  error
	taskErr error
}

func (f fakeJobs) GetJob(_ context.Context, _ string) (jobs.Job, error) {
	return f.job, f.getErr
}

func (f fakeJobs) TasksByJob(_ context.Context, _ string) ([]jobs.Task, error) {
	return f.tasks, f.taskErr
}

// roleVerifier authenticates testCredential as an Account with a chosen role,
// so a route can be exercised as viewer/operator/admin. (api_test.go's
// staticVerifier is admin-only by design.)
//
// kind is left empty by the execution routes, which do not care: authority is
// the Role everywhere except Freeze engage (#397). It defaults to machine —
// the AI-agent case, and the restrictive one.
type roleVerifier struct {
	credential string
	role       accounts.Role
	kind       accounts.Kind
}

func (v roleVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	kind := v.kind
	if kind == "" {
		kind = accounts.KindMachine
	}
	return accounts.Account{
		Name:    "caller-" + string(v.role),
		Kind:    kind,
		Role:    v.role,
		Enabled: true,
	}, accounts.APIToken{ID: testTokenID}, nil
}

// newExecFixture mounts the execution routes behind a real Authenticator that
// authenticates as role, with the production RoleGate wired into the Executor.
func newExecFixture(t *testing.T, role accounts.Role, exec *fakeExecutor, jr JobResultReader) http.Handler {
	t.Helper()
	exec.gate = authz.NewRoleGate()
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role})
	mux := http.NewServeMux()
	Register(mux, Deps{Exec: exec, Jobs: jr, Now: fixedNow})
	return authn.Middleware(mux)
}

// -----------------------------------------------------------------------
// Acceptance: raw_exec requires admin; an operator is refused.
// -----------------------------------------------------------------------

// TestRawExec_RequiresAdmin is the issue's headline acceptance. The refusal
// comes from the production authz.RoleGate (ActionRawExec -> RoleAdmin), NOT
// from a check in this package: the Control API must inherit the same answer
// MCP gets, and a surface that gated Raw Exec itself would be the second
// control path ADR-0010 forbids.
func TestRawExec_RequiresAdmin(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role), func(t *testing.T) {
			exec := &fakeExecutor{}
			h := newExecFixture(t, role, exec, fakeJobs{})

			rec := do(t, h, http.MethodPost, "/api/v1/raw-exec",
				rawExecRequest{Argv: []string{"/bin/echo", "hi"}})

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
			}
			// The Action really did carry the Raw Exec kind — that is what the
			// ladder keyed on, and it is this route's responsibility.
			calls := exec.runCalls()
			if len(calls) != 1 {
				t.Fatalf("Run called %d times, want 1 (the gate must decide, not this package)", len(calls))
			}
			if calls[0].Action.Kind != jobs.ActionRawExec {
				t.Errorf("Action.Kind = %v, want ActionRawExec", calls[0].Action.Kind)
			}
		})
	}

	// ...and an admin is not refused: the gate is a ladder, not a wall.
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job:   jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess, ExitCode: 0}},
	})
	rec := do(t, h, http.MethodPost, "/api/v1/raw-exec",
		rawExecRequest{Argv: []string{"/bin/echo", "hi"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin raw-exec: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

// An operator MAY run a structured Operation — the same ladder that refuses
// them Raw Exec permits the typed path (ActionOperation -> RoleOperator).
func TestRunOperation_OperatorIsPermitted(t *testing.T) {
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleOperator, exec, fakeJobs{
		job:   jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess}},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations",
		runOperationRequest{Operation: "system.facts"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// A viewer, one rung lower, is refused the same call.
	execV := &fakeExecutor{}
	hv := newExecFixture(t, accounts.RoleViewer, execV, fakeJobs{})
	if rec := do(t, hv, http.MethodPost, "/api/v1/operations",
		runOperationRequest{Operation: "system.facts"}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer run_operation: status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
}

// -----------------------------------------------------------------------
// Acceptance: plan=true executes nothing.
// -----------------------------------------------------------------------

// TestPlanMode_QueriesAndNeverDispatches pins ADR-0011's core property on this
// surface: plan=true reaches Plan, never Run, so no Job/Task/dedup entry can
// exist, and the response carries verdicts with no job_id.
func TestPlanMode_QueriesAndNeverDispatches(t *testing.T) {
	exec := &fakeExecutor{planResult: capability.PlanResult{
		Matched: 2,
		Verdicts: []capability.NodeVerdict{
			{NodeID: "n2", Status: capability.VerdictDeny, DecidingRule: "denied by rule"},
			{NodeID: "n1", Status: capability.VerdictAllow},
		},
	}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	for _, rt := range []struct {
		path string
		body any
	}{
		{"/api/v1/operations", runOperationRequest{Operation: "system.facts", Plan: true}},
		{"/api/v1/raw-exec", rawExecRequest{Argv: []string{"/bin/echo", "hi"}, Plan: true}},
	} {
		rec := do(t, h, http.MethodPost, rt.path, rt.body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body %s", rt.path, rec.Code, rec.Body.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("%s: decode: %v", rt.path, err)
		}
		if _, present := raw["job_id"]; present {
			t.Errorf("%s: plan response carries a job_id; a Plan creates no Job", rt.path)
		}
		var plan planResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
			t.Fatalf("%s: decode plan: %v", rt.path, err)
		}
		if plan.Matched != 2 || len(plan.Verdicts) != 2 {
			t.Errorf("%s: plan = %+v, want matched=2 with 2 verdicts", rt.path, plan)
		}
		// Verdicts are sorted by NodeID for a stable response.
		if plan.Verdicts[0].NodeID != "n1" || plan.Verdicts[1].NodeID != "n2" {
			t.Errorf("%s: verdicts not sorted by node_id: %+v", rt.path, plan.Verdicts)
		}
		if plan.Advisory == "" {
			t.Errorf("%s: plan response must carry the point-in-time advisory (ADR-0011)", rt.path)
		}
	}

	if got := len(exec.runCalls()); got != 0 {
		t.Errorf("Run called %d times during plan mode, want 0 — a Plan must execute nothing", got)
	}
	if got := len(exec.planCalls()); got != 2 {
		t.Errorf("Plan called %d times, want 2", got)
	}
}

// An over-cap Plan reports would_be_rejected INSIDE a 200 response rather than
// erroring: learning the answer is the entire point of plan mode (ADR-0011).
func TestPlanMode_OverCapReportsWouldBeRejectedNotAnError(t *testing.T) {
	exec := &fakeExecutor{planResult: capability.PlanResult{
		Matched:     500,
		CapExceeded: &capability.CapExceededError{Class: jobs.RiskClassMutate, Matched: 500, Cap: 50},
	}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	rec := do(t, h, http.MethodPost, "/api/v1/operations",
		runOperationRequest{Operation: "service.restart", Args: map[string]string{"unit": "nginx"}, Plan: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an over-cap Plan is a successful query); body %s", rec.Code, rec.Body.String())
	}
	var plan planResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if plan.WouldBeRejected == nil {
		t.Fatal("plan response has no would_be_rejected, want the cap rejection reported")
	}
	if plan.WouldBeRejected.Reason != "exceeds_cap" || plan.WouldBeRejected.Cap != 50 || plan.WouldBeRejected.Class != "mutate" {
		t.Errorf("would_be_rejected = %+v, want exceeds_cap/cap=50/class=mutate", *plan.WouldBeRejected)
	}
}

// A zero-match Policy preflight reports would_be_rejected{no_nodes_matched}
// INSIDE a 200 response rather than erroring — the same guardrail-reports-
// not-refuses posture as the over-cap case (ADR-0011), for both execution
// routes.
func TestPlanMode_ZeroMatchReportsWouldBeRejectedNotAnError(t *testing.T) {
	exec := &fakeExecutor{planResult: capability.PlanResult{Matched: 0, NoNodesMatched: true}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	for _, rt := range []struct {
		path string
		body any
	}{
		{"/api/v1/operations", runOperationRequest{Operation: "system.facts", Plan: true}},
		{"/api/v1/raw-exec", rawExecRequest{Argv: []string{"/bin/true"}, Plan: true}},
	} {
		rec := do(t, h, http.MethodPost, rt.path, rt.body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (a zero-match Policy preflight is a successful query); body %s", rt.path, rec.Code, rec.Body.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("%s: decode: %v", rt.path, err)
		}
		if _, present := raw["job_id"]; present {
			t.Errorf("%s: plan response carries a job_id; a Plan creates no Job", rt.path)
		}
		if _, present := raw["verdicts"]; !present {
			t.Errorf("%s: plan response has no verdicts key, want an explicit empty array", rt.path)
		}
		var plan planResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
			t.Fatalf("%s: decode plan: %v", rt.path, err)
		}
		if len(plan.Verdicts) != 0 {
			t.Errorf("%s: plan.verdicts = %+v, want empty (no Node to ask)", rt.path, plan.Verdicts)
		}
		if plan.WouldBeRejected == nil || plan.WouldBeRejected.Reason != "no_nodes_matched" {
			t.Fatalf("%s: would_be_rejected = %+v, want {reason: no_nodes_matched}", rt.path, plan.WouldBeRejected)
		}
	}
}

// TestRenderPlan_NoNodesMatchedTakesPrecedence is #571's would_be_rejected
// precedence line, the Control API twin of the MCP test of the same name:
// NoNodesMatched wins over Frozen, and Matched/Cap/Class stay zero since
// no_nodes_matched carries neither.
func TestRenderPlan_NoNodesMatchedTakesPrecedence(t *testing.T) {
	both := renderPlan(capability.PlanResult{NoNodesMatched: true, Frozen: true})
	if both.WouldBeRejected == nil || both.WouldBeRejected.Reason != "no_nodes_matched" {
		t.Fatalf("renderPlan(NoNodesMatched+Frozen).WouldBeRejected = %+v, want {reason: no_nodes_matched}", both.WouldBeRejected)
	}
	if both.WouldBeRejected.Matched != 0 || both.WouldBeRejected.Cap != 0 || both.WouldBeRejected.Class != "" {
		t.Errorf("renderPlan(NoNodesMatched+Frozen).WouldBeRejected = %+v, want Matched/Cap/Class all zero", both.WouldBeRejected)
	}

	frozenOnly := renderPlan(capability.PlanResult{Frozen: true})
	if frozenOnly.WouldBeRejected == nil || frozenOnly.WouldBeRejected.Reason != "frozen" {
		t.Fatalf("renderPlan(Frozen only).WouldBeRejected = %+v, want {reason: frozen}", frozenOnly.WouldBeRejected)
	}
}

// -----------------------------------------------------------------------
// Refusal rendering: each capability-layer refusal gets a truthful status.
// -----------------------------------------------------------------------

func TestExecutionRefusals_RenderTruthfulStatuses(t *testing.T) {
	tests := []struct {
		name    string
		runErr  error
		want    int
		wantSub string
	}{
		{
			name:    "freeze engaged is a state conflict, not a client error",
			runErr:  &capability.FrozenError{},
			want:    http.StatusConflict,
			wantSub: "frozen",
		},
		{
			name:    "blast cap is a guardrail rejection of a well-formed request",
			runErr:  &capability.CapExceededError{Class: jobs.RiskClassRead, Matched: 900, Cap: 100},
			want:    http.StatusUnprocessableEntity,
			wantSub: "cap",
		},
		{
			name:    "no nodes matched is a guardrail rejection of a well-formed request",
			runErr:  &capability.NoNodesMatchedError{Selector: "node:role=db"},
			want:    http.StatusUnprocessableEntity,
			wantSub: "no_nodes_matched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &fakeExecutor{runErr: tt.runErr}
			h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

			rec := do(t, h, http.MethodPost, "/api/v1/operations",
				runOperationRequest{Operation: "system.facts"})
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.want, rec.Body.String())
			}
			if !strings.Contains(strings.ToLower(rec.Body.String()), tt.wantSub) {
				t.Errorf("body %s must mention %q", rec.Body.String(), tt.wantSub)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", ct)
			}
		})
	}
}

// TestRunOperation_NoNodesMatchedIs422WithTitleAndSelector decodes the
// problem body: title distinguishes the no-Nodes-matched 422 from the cap's
// 422 (TestExecutionRefusals_RenderTruthfulStatuses's "cap" case), and detail
// carries the canonical Selector so a typo is visible.
func TestRunOperation_NoNodesMatchedIs422WithTitleAndSelector(t *testing.T) {
	exec := &fakeExecutor{runErr: &capability.NoNodesMatchedError{Selector: "node:role=db"}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	rec := do(t, h, http.MethodPost, "/api/v1/operations",
		runOperationRequest{Operation: "system.facts", Selector: "node:role=db"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Title != "no nodes matched" {
		t.Errorf("title = %q, want %q", p.Title, "no nodes matched")
	}
	if !strings.Contains(p.Detail, "node:role=db") {
		t.Errorf("detail = %q, want it to contain the Selector %q", p.Detail, "node:role=db")
	}
}

// -----------------------------------------------------------------------
// Input validation: malformed is 400, never a dispatch (and never a
// denied_by_policy — #345's trap, on this surface too).
// -----------------------------------------------------------------------

// TestRunOperation_TemplateNameReachesTheCapabilityLayerWithNoClass pins
// this adapter's half of ADR-0042 (invariant 10): a name outside the Native
// vocabulary is a Template Operation, and the adapter forwards it with its
// arguments untouched and NO risk class — the capability layer decides the
// class over the matched Nodes' own reports, and checks the argument names
// against their slots. The adapter neither classifies nor rejects it.
func TestRunOperation_TemplateNameReachesTheCapabilityLayerWithNoClass(t *testing.T) {
	exec := &fakeExecutor{}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{
		Selector: "node:role=web", Operation: "svc.status", Args: map[string]string{"unit": "nginx"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	calls := exec.runCalls()
	if len(calls) != 1 {
		t.Fatalf("%d Run calls, want 1", len(calls))
	}
	act := calls[0].Action
	if act.Kind != jobs.ActionOperation || act.OperationName != "svc.status" || act.OperationArgs["unit"] != "nginx" {
		t.Errorf("Action = %+v, want the Template name and its arguments forwarded unchanged", act)
	}
	if act.RiskClass != jobs.RiskClassUnspecified {
		t.Errorf("Action.RiskClass = %s, want unspecified — only the capability layer decides a Template's class", jobs.RiskClassName(act.RiskClass))
	}
}

// TestRunOperation_TemplateRefusalsAreBadRequests: the capability layer's
// unknown-operation and malformed-call refusals (ADR-0042) are malformed
// input, rendered as the same 400 this adapter gives an unknown Native
// argument — never a 500, and never a Policy verdict (#345).
func TestRunOperation_TemplateRefusalsAreBadRequests(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		wantSub string
	}{
		{"unknown operation", &capability.UnknownOperationError{Operation: "nope.notreal", Matched: 2}, "unknown operation"},
		{"malformed call", &capability.MalformedCallError{Operation: "log.tail", Reason: "unknown argument(s) [unitt]"}, "unitt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exec := &fakeExecutor{runErr: tt.err}
			h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})
			rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Selector: "node:role=web", Operation: "nope.notreal"})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantSub) {
				t.Errorf("body %s must carry %q", rec.Body.String(), tt.wantSub)
			}
		})
	}
}

func TestRunOperation_MalformedInputIsRejectedBeforeDispatch(t *testing.T) {
	tests := []struct {
		name    string
		body    runOperationRequest
		wantSub string
	}{
		{
			name:    "misspelled required argument (#345)",
			body:    runOperationRequest{Operation: "service.restart", Args: map[string]string{"unitt": "nginx"}},
			wantSub: "unitt",
		},
		{
			name:    "unknown extra argument on an otherwise valid call",
			body:    runOperationRequest{Operation: "file.read", Args: map[string]string{"path": "/etc/os-release", "bogus": "x"}},
			wantSub: "bogus",
		},
		{
			name:    "missing required argument",
			body:    runOperationRequest{Operation: "service.restart"},
			wantSub: "unit",
		},
		{
			name:    "negative timeout",
			body:    runOperationRequest{Operation: "system.facts", TimeoutSeconds: -1},
			wantSub: "timeout_seconds",
		},
		{
			name:    "timeout past the 24h bound",
			body:    runOperationRequest{Operation: "system.facts", TimeoutSeconds: controlplane.MaxTimeoutSeconds + 1},
			wantSub: "timeout_seconds",
		},
		{
			name:    "selector term without a namespace prefix",
			body:    runOperationRequest{Selector: "role=web", Operation: "system.facts"},
			wantSub: "selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &fakeExecutor{}
			h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

			rec := do(t, h, http.MethodPost, "/api/v1/operations", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(tt.wantSub)) {
				t.Errorf("body %s must mention %q so the caller can correct it", rec.Body.String(), tt.wantSub)
			}
			// The load-bearing half: nothing was dispatched, so a malformed call
			// can never come back as a Policy verdict (#345).
			if got := len(exec.runCalls()) + len(exec.planCalls()); got != 0 {
				t.Errorf("%d capability calls for a malformed request, want 0", got)
			}
		})
	}
}

// raw_exec's argv is mandatory and is never split client-side (ADR-0001):
// an empty argv is a 400 before any dispatch.
func TestRawExec_EmptyArgvIsRejected(t *testing.T) {
	exec := &fakeExecutor{}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	rec := do(t, h, http.MethodPost, "/api/v1/raw-exec", rawExecRequest{Argv: nil})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if got := len(exec.runCalls()); got != 0 {
		t.Errorf("Run called %d times for an empty argv, want 0", got)
	}
}

// -----------------------------------------------------------------------
// Action construction: what the routes hand the capability layer.
// -----------------------------------------------------------------------

// TestRunOperation_BuildsTheActionTheCapabilityLayerExpects pins the fields the
// capability layer keys on — risk class picks the blast cap (ADR-0012) and the
// kind picks the role floor (authz) — so a wiring slip cannot silently send a
// mutate down the read-cap.
func TestRunOperation_BuildsTheActionTheCapabilityLayerExpects(t *testing.T) {
	exec := &fakeExecutor{}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{
		Selector:       "node:role=web",
		Operation:      "service.restart",
		Args:           map[string]string{"unit": "nginx"},
		TimeoutSeconds: 30,
	})

	calls := exec.runCalls()
	if len(calls) != 1 {
		t.Fatalf("Run called %d times, want 1", len(calls))
	}
	act := calls[0].Action
	if act.Kind != jobs.ActionOperation {
		t.Errorf("Kind = %v, want ActionOperation", act.Kind)
	}
	if act.OperationName != "service.restart" {
		t.Errorf("OperationName = %q, want service.restart", act.OperationName)
	}
	if act.RiskClass != jobs.RiskClassUnspecified {
		t.Errorf("RiskClass = %v, want unspecified: the adapter sets no class; the capability layer derives it (invariant 13)", act.RiskClass)
	}
	if act.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds = %d, want 30", act.TimeoutSeconds)
	}
	if act.OperationArgs["unit"] != "nginx" {
		t.Errorf("OperationArgs = %v, want unit=nginx passed through unchanged", act.OperationArgs)
	}
	if calls[0].Principal.Role != string(accounts.RoleAdmin) {
		t.Errorf("Principal.Role = %q, want the authenticated caller's role", calls[0].Principal.Role)
	}
}

// The Raw Exec route sets no class: the capability layer fixes Raw Exec to
// mutate (ADR-0012, invariant 13; proven in capability's riskclass_test.go),
// and no adapter may set it.
func TestRawExec_AdapterSetsNoClass(t *testing.T) {
	exec := &fakeExecutor{}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	do(t, h, http.MethodPost, "/api/v1/raw-exec", rawExecRequest{Argv: []string{"/bin/cat", "/etc/hostname"}})

	calls := exec.runCalls()
	if len(calls) != 1 {
		t.Fatalf("Run called %d times, want 1", len(calls))
	}
	if calls[0].Action.RiskClass != jobs.RiskClassUnspecified {
		t.Errorf("RiskClass = %v, want unspecified: the adapter sets no class (invariant 13)", calls[0].Action.RiskClass)
	}
	if got := calls[0].Action.RawExecArgv; len(got) != 2 || got[0] != "/bin/cat" {
		t.Errorf("RawExecArgv = %v, want the argv verbatim", got)
	}
}

// -----------------------------------------------------------------------
// Response shape (#207/#253 parity with MCP).
// -----------------------------------------------------------------------

// TestExecutionResponse_ExitCodeAndJobIDShape pins the did-it-run
// disambiguation on this surface: exit_code appears only when a process really
// exited with a status, and job_id only when a Job was created. Both must match
// what MCP renders for the same Task — the same Job read through either door
// has to tell the same story.
func TestExecutionResponse_ExitCodeAndJobIDShape(t *testing.T) {
	t.Run("exit_code presence by outcome", func(t *testing.T) {
		tasks := []jobs.Task{
			{NodeID: "n-success", Outcome: jobs.OutcomeSuccess, ExitCode: 0},
			{NodeID: "n-failure", Outcome: jobs.OutcomeFailure, ExitCode: 2},
			{NodeID: "n-denied", Outcome: jobs.OutcomeDeniedByPolicy, ExitCode: -1},
			{NodeID: "n-timeout", Outcome: jobs.OutcomeTimeout, ExitCode: -1},
			{NodeID: "n-unreachable", Outcome: jobs.OutcomeUnreachable, ExitCode: 0},
		}
		exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n-success", JobID: "job-1"}}}
		h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{job: jobs.Job{ID: "job-1"}, tasks: tasks})

		rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
		}

		var body struct {
			JobID   string            `json:"job_id"`
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.JobID != "job-1" {
			t.Errorf("job_id = %q, want job-1", body.JobID)
		}
		want := map[string]bool{ // node_id -> exit_code key expected present
			"n-denied": false, "n-failure": true, "n-success": true,
			"n-timeout": false, "n-unreachable": false,
		}
		if len(body.Results) != len(want) {
			t.Fatalf("%d results, want %d", len(body.Results), len(want))
		}
		for _, raw := range body.Results {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			var nodeID string
			_ = json.Unmarshal(m["node_id"], &nodeID)
			_, present := m["exit_code"]
			if present != want[nodeID] {
				t.Errorf("%s: exit_code present = %v, want %v (raw %s)", nodeID, present, want[nodeID], raw)
			}
		}
	})

	t.Run("an Executor returning no results renders no job_id and an empty array", func(t *testing.T) {
		exec := &fakeExecutor{runResults: nil} // out-of-contract: *capability.Service refuses zero-match as no_nodes_matched
		h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

		rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
		}
		got := strings.TrimSpace(rec.Body.String())
		if got != `{"results":[]}` {
			t.Errorf("body = %s, want {\"results\":[]} (no job_id key: nothing was dispatched; results never null)", got)
		}
	})
}

// Results are sorted by node_id so a caller polling twice sees a stable order.
func TestExecutionResponse_ResultsAreSortedByNodeID(t *testing.T) {
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n-c", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job: jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{
			{NodeID: "n-c", Outcome: jobs.OutcomeSuccess},
			{NodeID: "n-a", Outcome: jobs.OutcomeSuccess},
			{NodeID: "n-b", Outcome: jobs.OutcomeSuccess},
		},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
	var body executionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := []string{body.Results[0].NodeID, body.Results[1].NodeID, body.Results[2].NodeID}
	if got[0] != "n-a" || got[1] != "n-b" || got[2] != "n-c" {
		t.Errorf("result order = %v, want sorted by node_id", got)
	}
}

// Output past the render cap is truncated with the flag set, so a Raw Exec
// Task's unbounded output cannot inflate the response.
func TestExecutionResponse_TruncatesLargeOutput(t *testing.T) {
	big := strings.Repeat("x", controlplane.MaxRenderedOutputBytes+100)
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job:   jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{{NodeID: "n1", Outcome: jobs.OutcomeSuccess, Stdout: []byte(big)}},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
	var body executionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Results) != 1 {
		t.Fatalf("%d results, want 1", len(body.Results))
	}
	if len(body.Results[0].Stdout) != controlplane.MaxRenderedOutputBytes || !body.Results[0].StdoutTruncated {
		t.Errorf("stdout len = %d truncated = %v, want %d and true",
			len(body.Results[0].Stdout), body.Results[0].StdoutTruncated, controlplane.MaxRenderedOutputBytes)
	}
}

// Duration is only computed from real timestamps: a Task that was never
// dispatched reports 0, never a fabricated value.
func TestExecutionResponse_DurationOnlyFromRealTimestamps(t *testing.T) {
	start := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	ran := perNodeResultFromTask(jobs.Task{
		NodeID: "n1", Outcome: jobs.OutcomeSuccess,
		DispatchedAt: start, ResolvedAt: start.Add(1500 * time.Millisecond),
	})
	if ran.DurationMS != 1500 {
		t.Errorf("DurationMS = %d, want 1500", ran.DurationMS)
	}
	never := perNodeResultFromTask(jobs.Task{NodeID: "n2", Outcome: jobs.OutcomeUnreachable})
	if never.DurationMS != 0 {
		t.Errorf("DurationMS = %d for a never-dispatched Task, want 0", never.DurationMS)
	}
}

// An api mounted without its execution dependencies answers a legible 500
// rather than panicking into a bare connection reset. Unreachable in
// production (apiSurface.Mount always supplies both) — this pins the failure
// SHAPE of a composition mistake, mirroring principal()'s defensive 500.
func TestExecutionRoutes_UnwiredDependenciesAreALegible500(t *testing.T) {
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleAdmin})
	mux := http.NewServeMux()
	Register(mux, Deps{Now: fixedNow}) // no Exec, no Jobs
	h := authn.Middleware(mux)

	for _, rt := range []struct {
		path string
		body any
	}{
		{"/api/v1/operations", runOperationRequest{Operation: "system.facts"}},
		{"/api/v1/raw-exec", rawExecRequest{Argv: []string{"/bin/echo", "hi"}}},
	} {
		rec := do(t, h, http.MethodPost, rt.path, rt.body)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500; body %s", rt.path, rec.Code, rec.Body.String())
		}
	}
}

// -----------------------------------------------------------------------
// #454: refusal_explanation — the API mirrors of mcp/tools_legibility_test.go's
// TestMCP_PolicyDenyNamesItsBoundary / TestMCP_PlanDenyNamesItsBoundary /
// TestMCP_VersionRefusedCarriesFullExplanation / TestMCP_ExplanationAbsentWhenNotRefused.
// Names kept parallel to the MCP ones so the parity intent is legible.
// -----------------------------------------------------------------------

// TestAPI_PolicyDenyNamesItsBoundary is #454's apply-path route seam: a
// denied_by_policy Task renders stderr as the daemon's own reason verbatim
// AND a new refusal_explanation naming the boundary.
func TestAPI_PolicyDenyNamesItsBoundary(t *testing.T) {
	const daemonReason = "no allow rule matched args [\"sshd\"] for operation 'service.restart' (allow rules exist for other arguments)"
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job: jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{
			{NodeID: "n1", Outcome: jobs.OutcomeDeniedByPolicy, ExitCode: -1, Stderr: []byte(daemonReason)},
		},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body executionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Results) != 1 {
		t.Fatalf("results = %+v, want 1", body.Results)
	}
	r := body.Results[0]
	if r.Outcome != "denied_by_policy" {
		t.Errorf("outcome = %q, want denied_by_policy", r.Outcome)
	}
	if r.ExitCode != nil {
		t.Errorf("exit_code = %v, want absent (nothing executed)", *r.ExitCode)
	}
	if r.Stderr != daemonReason {
		t.Errorf("stderr = %q, want the daemon's reason verbatim and unmodified: %q", r.Stderr, daemonReason)
	}
	if r.RefusalExplanation != capability.PolicyDenyExplanation {
		t.Errorf("refusal_explanation = %q, want capability.PolicyDenyExplanation", r.RefusalExplanation)
	}
}

// TestAPI_PlanDenyNamesItsBoundary is TestAPI_PolicyDenyNamesItsBoundary's
// plan-mode counterpart: a deny verdict carries deciding_rule (the daemon's
// rule text, unchanged) AND refusal_explanation (the Relay's plan-mode
// framing); the allow verdict carries no explanation at all.
func TestAPI_PlanDenyNamesItsBoundary(t *testing.T) {
	exec := &fakeExecutor{planResult: capability.PlanResult{
		Matched: 2,
		Verdicts: []capability.NodeVerdict{
			{NodeID: "n2", Status: capability.VerdictDeny, DecidingRule: "denied by rule"},
			{NodeID: "n1", Status: capability.VerdictAllow},
		},
	}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts", Plan: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var plan planResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(plan.Verdicts) != 2 {
		t.Fatalf("verdicts = %+v, want 2", plan.Verdicts)
	}
	byNode := map[string]perNodeVerdict{}
	for _, v := range plan.Verdicts {
		byNode[v.NodeID] = v
	}
	deny := byNode["n2"]
	if deny.Verdict != "deny" {
		t.Errorf("n2 verdict = %q, want deny", deny.Verdict)
	}
	if deny.DecidingRule != "denied by rule" {
		t.Errorf("n2 deciding_rule = %q, want unchanged (\"denied by rule\")", deny.DecidingRule)
	}
	if deny.RefusalExplanation != capability.PolicyDenyVerdictExplanation {
		t.Errorf("n2 refusal_explanation = %q, want capability.PolicyDenyVerdictExplanation", deny.RefusalExplanation)
	}
	if allow := byNode["n1"]; allow.RefusalExplanation != "" {
		t.Errorf("n1 (allow) refusal_explanation = %q, want empty", allow.RefusalExplanation)
	}
}

// TestAPI_VersionRefusedCarriesFullExplanation: on a version_refused row the
// Relay authored both stderr and refusal_explanation, so they must be
// byte-identical to jobs.VersionRefusedMessage.
func TestAPI_VersionRefusedCarriesFullExplanation(t *testing.T) {
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job: jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{
			{NodeID: "n1", Outcome: jobs.OutcomeVersionRefused, Stderr: []byte(jobs.VersionRefusedMessage)},
		},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body executionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Results) != 1 {
		t.Fatalf("results = %+v, want 1", body.Results)
	}
	r := body.Results[0]
	if r.Outcome != "version_refused" {
		t.Errorf("outcome = %q, want version_refused", r.Outcome)
	}
	if r.Stderr != jobs.VersionRefusedMessage {
		t.Errorf("stderr = %q, want jobs.VersionRefusedMessage", r.Stderr)
	}
	if r.RefusalExplanation != jobs.VersionRefusedMessage {
		t.Errorf("refusal_explanation = %q, want jobs.VersionRefusedMessage (the Relay authored both fields here)", r.RefusalExplanation)
	}
}

// TestAPI_ExplanationAbsentWhenNotRefused pins the other half of the field's
// meaning: a success and a failure row must both carry an EMPTY
// refusal_explanation.
func TestAPI_ExplanationAbsentWhenNotRefused(t *testing.T) {
	exec := &fakeExecutor{runResults: []capability.NodeResult{{NodeID: "n1", JobID: "job-1"}}}
	h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{
		job: jobs.Job{ID: "job-1"},
		tasks: []jobs.Task{
			{NodeID: "n-success", Outcome: jobs.OutcomeSuccess},
			{NodeID: "n-failure", Outcome: jobs.OutcomeFailure, Stderr: []byte("spawn systemctl: No such file or directory")},
		},
	})

	rec := do(t, h, http.MethodPost, "/api/v1/operations", runOperationRequest{Operation: "system.facts"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body executionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byNode := map[string]perNodeResult{}
	for _, r := range body.Results {
		byNode[r.NodeID] = r
	}
	if got := byNode["n-success"].RefusalExplanation; got != "" {
		t.Errorf("n-success refusal_explanation = %q, want empty", got)
	}
	if got := byNode["n-failure"].RefusalExplanation; got != "" {
		t.Errorf("n-failure refusal_explanation = %q, want empty", got)
	}
}
