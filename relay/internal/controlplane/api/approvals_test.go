package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// -----------------------------------------------------------------------
// Fixture
// -----------------------------------------------------------------------

var apiNow = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

// fakeApprovals is a hand-rolled ApprovalService. It records what the handler
// passed down, because most of what this file is testing is what the ROUTE
// hands the capability layer — the eligibility rules themselves are the
// domain's and are tested there.
type fakeApprovals struct {
	pending []approval.Request
	byID    map[string]approval.Request

	lastPrincipal capability.Principal
	lastDecision  capability.ApprovalDecision
	decideErr     error
	listErr       error
}

func (f *fakeApprovals) PendingApprovals(context.Context) ([]approval.Request, error) {
	return f.pending, f.listErr
}

func (f *fakeApprovals) Approval(_ context.Context, id string) (approval.Request, error) {
	r, ok := f.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	return r, nil
}

func (f *fakeApprovals) DecideApproval(_ context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error) {
	f.lastPrincipal = p
	f.lastDecision = in
	if f.decideErr != nil {
		return approval.Request{}, f.decideErr
	}
	r, ok := f.byID[in.RequestID]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	r.Decisions = append(r.Decisions, approval.Decision{
		AccountID: p.AccountID, Account: p.Account, Approve: in.Approve,
		Reason: in.Reason, Channel: in.Channel, PlanHash: in.PlanHash,
		DeciderHuman: p.Human(), At: apiNow,
	})
	if in.Approve {
		r.State = approval.StateApproved
	} else {
		r.State = approval.StateDenied
	}
	f.byID[in.RequestID] = r
	return r, nil
}

func testApprovalRequest(id string, act jobs.Action) approval.Request {
	return approval.NewRequest(id, "hash-"+id, "acct-g", "gleipnir-prod", act,
		[]string{"node-a", "node-b"}, []string{"prod-mutates"},
		approval.Requirement{Count: 2, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		apiNow)
}

func newApprovalFixture(t *testing.T, role accounts.Role, ap *fakeApprovals) http.Handler {
	t.Helper()
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role})
	mux := http.NewServeMux()
	Register(mux, Deps{Approvals: ap, Now: fixedNow})
	return authn.Middleware(mux)
}

func decodeApproval(t *testing.T, body []byte) approvalResponse {
	t.Helper()
	var out approvalResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode approval response: %v; body = %s", err, body)
	}
	return out
}

// -----------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------

func TestListApprovals_RendersTheQueue(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"service": "nginx"}, RiskClass: jobs.RiskClassMutate,
	})
	ap := &fakeApprovals{pending: []approval.Request{req}, byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleViewer, ap)

	rec := do(t, h, http.MethodGet, "/api/v1/approvals", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}

	var out listApprovalsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Approvals) != 1 {
		t.Fatalf("approvals = %d, want 1", len(out.Approvals))
	}
	got := out.Approvals[0]
	if got.Summary != req.Summary {
		t.Errorf("summary = %q, want the stored Relay-authored text %q verbatim", got.Summary, req.Summary)
	}
	if got.PlanHash != req.PlanHash {
		t.Errorf("plan_hash = %q, want %q — a decider cannot answer without it", got.PlanHash, req.PlanHash)
	}
	if got.ActionKind != "operation" || got.RiskClass != "mutate" {
		t.Errorf("action_kind/risk_class = %q/%q, want operation/mutate", got.ActionKind, got.RiskClass)
	}
	if got.Progress != "0 of 2" || got.RequiredCount != 2 {
		t.Errorf("progress = %q, required_count = %d, want partial quorum visible", got.Progress, got.RequiredCount)
	}
	if len(got.MatchedRules) != 1 || got.MatchedRules[0] != "prod-mutates" {
		t.Errorf("matched_rules = %v, want the rule that parked it named", got.MatchedRules)
	}
}

// TestListApprovals_ViewerMayRead: the audience restricts who may DECIDE, not
// who may see that a decision is owed.
func TestListApprovals_ViewerMayRead(t *testing.T) {
	ap := &fakeApprovals{byID: map[string]approval.Request{}}
	h := newApprovalFixture(t, accounts.RoleViewer, ap)

	if rec := do(t, h, http.MethodGet, "/api/v1/approvals", nil); rec.Code != http.StatusOK {
		t.Fatalf("viewer list status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
}

func TestGetApproval_UnknownIDIs404(t *testing.T) {
	ap := &fakeApprovals{byID: map[string]approval.Request{}}
	h := newApprovalFixture(t, accounts.RoleOperator, ap)

	rec := do(t, h, http.MethodGet, "/api/v1/approvals/req-nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body)
	}
}

func TestApprovalRoutes_RequireACredential(t *testing.T) {
	ap := &fakeApprovals{byID: map[string]approval.Request{}}
	h := newApprovalFixture(t, accounts.RoleAdmin, ap)

	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/approvals"},
		{http.MethodGet, "/api/v1/approvals/req-1"},
		{http.MethodPost, "/api/v1/approvals/req-1/decision"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, nil) // no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a credential: status = %d, want 401", rt.method, rt.path, rec.Code)
		}
	}
}

// -----------------------------------------------------------------------
// Decisions
// -----------------------------------------------------------------------

// TestDecideApproval_StampsOutOfBand is the file's most important assertion:
// the channel comes from the DOOR, not from the body. A caller that could name
// its own channel could satisfy an out-of-band rule from the AI's session.
func TestDecideApproval_StampsOutOfBand(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate})
	ap := &fakeApprovals{byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleOperator, ap)

	rec := do(t, h, http.MethodPost, "/api/v1/approvals/req-1/decision",
		decideApprovalRequest{Approve: true, PlanHash: req.PlanHash, Reason: "ticket OPS-91"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}

	if ap.lastDecision.Channel != approval.ChannelOutOfBand {
		t.Errorf("channel = %v, want out-of-band stamped by the surface", ap.lastDecision.Channel)
	}
	if ap.lastDecision.RequestID != "req-1" || ap.lastDecision.PlanHash != req.PlanHash {
		t.Errorf("decision = %+v, want the path id and the cited plan hash", ap.lastDecision)
	}
	if !ap.lastDecision.Approve || ap.lastDecision.Reason != "ticket OPS-91" {
		t.Errorf("decision = %+v, want the caller's answer and note carried through", ap.lastDecision)
	}
	if ap.lastPrincipal.Account != "caller-operator" {
		t.Errorf("principal = %+v, want the authenticated decider", ap.lastPrincipal)
	}

	out := decodeApproval(t, rec.Body.Bytes())
	if out.State != "approved" || len(out.Decisions) != 1 {
		t.Errorf("response = %+v, want the resulting state and the recorded decision", out)
	}
	if out.Decisions[0].Channel != "out-of-band" {
		t.Errorf("rendered channel = %q, want out-of-band", out.Decisions[0].Channel)
	}
}

// TestDecideApproval_BodyCannotNameAChannel: the request schema has no channel
// field, and an attempt to supply one is a 400 rather than being ignored —
// decodeJSON rejects unknown fields, so a client believing it chose in-band is
// told otherwise instead of silently getting out-of-band.
func TestDecideApproval_BodyCannotNameAChannel(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{Kind: jobs.ActionOperation, RiskClass: jobs.RiskClassMutate})
	ap := &fakeApprovals{byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleOperator, ap)

	rec := doRaw(t, h, http.MethodPost, "/api/v1/approvals/req-1/decision",
		`{"approve":true,"plan_hash":"`+req.PlanHash+`","channel":"in-band"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown `channel` field; body = %s", rec.Code, rec.Body)
	}
}

// TestDecideApproval_PlanHashIsRequired: an approval binds to the Plan it was
// shown. A decision without one would be an answer to "whatever this means now".
func TestDecideApproval_PlanHashIsRequired(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{Kind: jobs.ActionOperation, RiskClass: jobs.RiskClassMutate})
	ap := &fakeApprovals{byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleOperator, ap)

	rec := do(t, h, http.MethodPost, "/api/v1/approvals/req-1/decision", decideApprovalRequest{Approve: true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body)
	}
	if ap.lastDecision.RequestID != "" {
		t.Error("the capability layer must not be reached without a plan hash")
	}
}

// TestDecideApproval_ErrorStatuses pins the mapping. The eligibility refusals
// are 409, not 403: the caller's credential is fine and the REQUEST'S STATE
// refuses. A 403 would tell an approver to go find a bigger token.
func TestDecideApproval_ErrorStatuses(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{Kind: jobs.ActionOperation, RiskClass: jobs.RiskClassMutate})

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"role floor", authz.ErrUnauthorized, http.StatusForbidden},
		{"audience", approval.ErrNotInAudience, http.StatusForbidden},
		{"already terminal", approval.ErrNotPending, http.StatusConflict},
		{"requester excluded", approval.ErrRequesterExcluded, http.StatusConflict},
		{"machine self-decision", approval.ErrMachineSelfDecision, http.StatusConflict},
		{"duplicate decider", approval.ErrDuplicateDecider, http.StatusConflict},
		{"plan changed", approval.ErrPlanChanged, http.StatusConflict},
		{"weak channel", approval.ErrWeakChannel, http.StatusConflict},
		{"unknown request", approval.ErrNotFound, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := &fakeApprovals{byID: map[string]approval.Request{"req-1": req}, decideErr: tc.err}
			h := newApprovalFixture(t, accounts.RoleOperator, ap)

			rec := do(t, h, http.MethodPost, "/api/v1/approvals/req-1/decision",
				decideApprovalRequest{Approve: true, PlanHash: req.PlanHash})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body)
			}
			var p problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if p.Detail == "" {
				t.Error("detail is empty; an approver who cannot tell why their answer bounced will stop answering")
			}
		})
	}
}

// TestDecideApproval_ReasonIsBounded: the note lands in an audit Record, so an
// unbounded one lets a caller size a row in the trail.
func TestDecideApproval_ReasonIsBounded(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{Kind: jobs.ActionOperation, RiskClass: jobs.RiskClassMutate})
	ap := &fakeApprovals{byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleOperator, ap)

	long := make([]byte, maxDecisionReasonLen+1)
	for i := range long {
		long[i] = 'x'
	}
	rec := do(t, h, http.MethodPost, "/api/v1/approvals/req-1/decision",
		decideApprovalRequest{Approve: true, PlanHash: req.PlanHash, Reason: string(long)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body)
	}
}

// TestApprovalRoutes_UnwiredDependency: a Deps without Approvals is a
// composition mistake, and it must read as a legible 500 rather than a panic
// reaching the caller as a connection reset.
func TestApprovalRoutes_UnwiredDependency(t *testing.T) {
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleAdmin})
	mux := http.NewServeMux()
	Register(mux, Deps{Now: fixedNow})
	h := authn.Middleware(mux)

	if rec := do(t, h, http.MethodGet, "/api/v1/approvals", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
