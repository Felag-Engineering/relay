// Package main: approval_e2e_test.go drives v0.5.0 [3/6] (#270, ADR-0027)
// through the REAL composition root — real approval-gate file, real store, real
// control-plane listener, real Account authentication.
//
// It deliberately needs no daemon. ADR-0027 makes exactly that point about the
// out-of-band channel: "Testing the universal path needs no MCP client at all:
// park a Job, POST a decision, watch it run." A registered-but-disconnected
// Node gives a truthful `unreachable` result, which is enough to prove the
// dispatch actually happened after the approval — the per-Node execution path
// itself is covered by the daemon-backed suites.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// writeGateConfig writes a root-owned-shaped approval-gate file that parks
// every mutate dispatch, and returns its path.
func writeGateConfig(t *testing.T, rules string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approval-gates.json")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatalf("write gate config: %v", err)
	}
	return path
}

const gateAllMutates = `{
  "rules": [
    {
      "name": "all-mutates-need-a-human",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": false, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`

// startGatedRelay boots the composition root with approval gating on and one
// Node in the registry, so a dispatch resolves to a real fan-out.
//
// extra is appended to the startRelay call — opt-in and source-compatible,
// so existing callers of this function are untouched.
// approval_console_absent_e2e_test.go passes
// WithConfig(func(c *Config) { c.ConsoleEnabled = true }): without it,
// cfg.ConsoleEnabled defaults false (main.go) and consoleSurface{} is never
// appended (main.go), so every /console/ request would 404.
func startGatedRelay(t *testing.T, rules string, extra ...FixtureOption) *relayFixture {
	t.Helper()
	path := writeGateConfig(t, rules)
	opts := append([]FixtureOption{WithControlPlane(), WithConfig(func(c *Config) {
		c.ApprovalGatePath = path
	})}, extra...)
	f := startRelay(t, opts...)
	if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: "node-e2e-1"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return f
}

// parkedBody is the 202 shape a gated dispatch returns.
type parkedBody struct {
	Status       string   `json:"status"`
	RequestID    string   `json:"request_id"`
	PlanHash     string   `json:"plan_hash"`
	Summary      string   `json:"summary"`
	MatchedRules []string `json:"matched_rules"`
	Progress     string   `json:"progress"`
	DecisionPath string   `json:"decision_path"`
}

// approvalBody mirrors the API's approval shape, decoded as an outside caller
// would rather than by importing package api's internal types.
type approvalBody struct {
	RequestID     string `json:"request_id"`
	State         string `json:"state"`
	PlanHash      string `json:"plan_hash"`
	Summary       string `json:"summary"`
	Progress      string `json:"progress"`
	RequiredCount int    `json:"required_count"`
	Decisions     []struct {
		Account string `json:"account"`
		Approve bool   `json:"approve"`
		Channel string `json:"channel"`
		Human   bool   `json:"human"`
		// IdentifiedBy is how the Relay identified an in-band decider (AP-88).
		IdentifiedBy string `json:"identified_by"`
	} `json:"decisions"`
}

type approvalListBody struct {
	Approvals []approvalBody `json:"approvals"`
}

// restartMutate drives the gated dispatch. Returns the response for the caller
// to interpret — a 202 park or a 200 execution.
func restartMutate(t *testing.T, f *relayFixture, credential string) *http.Response {
	t.Helper()
	return controlAPIRequest(t, f.ClientFor(credential), http.MethodPost,
		f.ControlBase+"/api/v1/operations", credential, map[string]any{
			"operation": "service.restart",
			"args":      map[string]string{"unit": "nginx"},
		})
}

// mintAccount creates an Account with the given kind/role and returns a token
// for it, so a test can act as somebody other than the founding admin.
func mintAccount(t *testing.T, f *relayFixture, name string, kind accounts.Kind, role accounts.Role) string {
	t.Helper()
	ctx := context.Background()
	acct, err := f.Deps.store.Accounts().Create(ctx, accounts.Account{Name: name, Kind: kind, Role: role, Enabled: true})
	if err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	svc := accounts.NewTokenService(f.Deps.store.APITokens(), f.Deps.store.Accounts(), nil)
	_, plaintext, err := svc.Mint(ctx, acct.ID, name+"-token", 0)
	if err != nil {
		t.Fatalf("mint token for %s: %v", name, err)
	}
	return plaintext.Reveal()
}

// TestApprovalCallout_ParkDecideRun is #270's headline acceptance: a gated
// dispatch parks, an approver answers on the authenticated endpoint, and the
// same dispatch then runs — with audit answering who asked and who approved.
func TestApprovalCallout_ParkDecideRun(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	// The founding admin is the REQUESTER here, and the rule sets
	// requester_allowed: false, so a second person is needed.
	requester := f.Credential
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	// 1. The dispatch parks. Nothing ran.
	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 — a park is not a failure and not a completion", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}
	if parked.Status != "pending_approval" || parked.RequestID == "" || parked.PlanHash == "" {
		t.Fatalf("park body = %+v, want a decidable request", parked)
	}
	if len(parked.MatchedRules) != 1 || parked.MatchedRules[0] != "all-mutates-need-a-human" {
		t.Errorf("matched_rules = %v, want the rule that parked it named", parked.MatchedRules)
	}
	if !strings.Contains(parked.Summary, "service.restart") {
		t.Errorf("summary = %q, want the Relay-authored description of what is waiting", parked.Summary)
	}

	// 2. It is in the queue any authenticated caller can read.
	listResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals", requester, nil)
	defer listResp.Body.Close()
	var list approvalListBody
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode queue: %v", err)
	}
	if len(list.Approvals) != 1 || list.Approvals[0].RequestID != parked.RequestID {
		t.Fatalf("queue = %+v, want exactly the parked request", list.Approvals)
	}

	// 3. The REQUESTER cannot answer their own request (requester_allowed:
	//    false). This is the second-person rung, over the real HTTP surface.
	selfResp := controlAPIRequest(t, f.Client(), http.MethodPost,
		f.ControlBase+parked.DecisionPath, requester,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer selfResp.Body.Close()
	if selfResp.StatusCode != http.StatusConflict {
		t.Fatalf("self-approval status = %d, want 409", selfResp.StatusCode)
	}

	// 4. A stale plan hash cannot be replayed onto this request.
	staleResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+parked.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": "not-the-plan-you-were-shown"})
	defer staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusConflict {
		t.Fatalf("plan-hash mismatch status = %d, want 409", staleResp.StatusCode)
	}

	// 5. The approver answers on the authenticated out-of-band endpoint.
	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+parked.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash, "reason": "change ticket OPS-91"})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}
	var decided approvalBody
	if err := json.NewDecoder(decideResp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decided.State != "approved" {
		t.Fatalf("state = %q, want approved", decided.State)
	}
	if len(decided.Decisions) != 1 {
		t.Fatalf("decisions = %+v, want one", decided.Decisions)
	}
	if got := decided.Decisions[0]; got.Account != "ana" || got.Channel != "out-of-band" || !got.Human {
		t.Errorf("decision = %+v, want ana's human out-of-band answer", got)
	}

	// 6. The SAME dispatch, re-driven, now runs. The Node is registered but
	//    has no Tunnel, so `unreachable` is the truthful outcome — what matters
	//    is that a Job exists, which it could not before the approval.
	runResp := restartMutate(t, f, requester)
	defer runResp.Body.Close()
	if runResp.StatusCode != http.StatusOK {
		t.Fatalf("re-drive status = %d, want 200 after approval", runResp.StatusCode)
	}
	var ran struct {
		JobID   string `json:"job_id"`
		Results []struct {
			NodeID  string `json:"node_id"`
			Outcome string `json:"outcome"`
		} `json:"results"`
	}
	if err := json.NewDecoder(runResp.Body).Decode(&ran); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if ran.JobID == "" {
		t.Fatal("no job_id after approval; the approved Plan must actually dispatch")
	}
	if len(ran.Results) != 1 || ran.Results[0].NodeID != "node-e2e-1" {
		t.Fatalf("results = %+v, want the approved fan-out", ran.Results)
	}

	// 7. Audit answers "who asked / who approved / what ran" — the park, the
	//    decision, and the dispatch are three records of one exchange.
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var sawPark, sawDecision, sawDispatch bool
	for _, r := range records {
		switch r.Kind {
		case audit.KindApprovalRequested:
			sawPark = true
			if !strings.Contains(r.Reason, parked.RequestID) {
				t.Errorf("park record does not name the request: %q", r.Reason)
			}
		case audit.KindApprovalDecided:
			sawDecision = true
			if r.Attribution.Verified.AccountName != "ana" {
				t.Errorf("decision attributed to %q, want the DECIDER", r.Attribution.Verified.AccountName)
			}
			if !strings.Contains(r.Reason, "change ticket OPS-91") {
				t.Errorf("decision record loses the approver's reason: %q", r.Reason)
			}
		case audit.KindDispatch:
			if r.JobID == ran.JobID {
				sawDispatch = true
			}
		}
	}
	if !sawPark || !sawDecision || !sawDispatch {
		t.Errorf("audit trail incomplete: park=%v decision=%v dispatch=%v", sawPark, sawDecision, sawDispatch)
	}
}

// TestApprovalCallout_MachineCannotSatisfyItsOwnGate is docs/specs/approval.md's acceptance
// "a machine Account can never satisfy its own gate on any channel", proven
// against the most permissive rule the config language can express:
// requester_allowed: true, and the machine holding the admin role.
func TestApprovalCallout_MachineCannotSatisfyItsOwnGate(t *testing.T) {
	const permissive = `{
  "rules": [
    {
      "name": "self-confirmation-allowed",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": true, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`
	f := startGatedRelay(t, permissive)
	machine := mintAccount(t, f, "gleipnir-prod", accounts.KindMachine, accounts.RoleAdmin)

	parkResp := restartMutate(t, f, machine)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	selfResp := controlAPIRequest(t, f.ClientFor(machine), http.MethodPost,
		f.ControlBase+parked.DecisionPath, machine,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer selfResp.Body.Close()
	if selfResp.StatusCode != http.StatusConflict {
		t.Fatalf("machine self-approval status = %d, want 409 even under requester_allowed: true", selfResp.StatusCode)
	}

	// And it really did not run: the dispatch still parks.
	retry := restartMutate(t, f, machine)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusAccepted {
		t.Fatalf("re-drive status = %d, want it still parked", retry.StatusCode)
	}
}

// TestApprovalCallout_OperatorCannotReleaseARawExec is the escalation guard:
// the floor for DECIDING is the floor the Action needed to be REQUESTED, so an
// operator who cannot ask for Raw Exec cannot release an admin's.
func TestApprovalCallout_OperatorCannotReleaseARawExec(t *testing.T) {
	const gateRawExec = `{
  "rules": [
    {
      "name": "raw-exec-always-asks",
      "match": { "raw_exec": true },
      "require": { "count": 1, "requester_allowed": false, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`
	f := startGatedRelay(t, gateRawExec)
	operator := mintAccount(t, f, "opie", accounts.KindHuman, accounts.RoleOperator)

	// The founding admin (admin role) parks a Raw Exec.
	parkResp := controlAPIRequest(t, f.Client(), http.MethodPost, f.ControlBase+"/api/v1/raw-exec",
		f.Credential, map[string]any{"argv": []string{"/bin/echo", "hi"}})
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body decode follows", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	resp := controlAPIRequest(t, f.ClientFor(operator), http.MethodPost,
		f.ControlBase+parked.DecisionPath, operator,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator deciding a Raw Exec: status = %d, want 403 — approving must not be a side door around the ladder", resp.StatusCode)
	}
}

// TestApprovalCallout_ReadsAreNotGatedByAMutateRule is the negative control: a
// gate can only ever ADD a reason to stop, and a rule that does not match must
// leave the pre-approval pipeline exactly as it was.
func TestApprovalCallout_ReadsAreNotGatedByAMutateRule(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	resp := controlAPIRequest(t, f.Client(), http.MethodPost, f.ControlBase+"/api/v1/operations",
		f.Credential, map[string]any{"operation": "system.facts"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read-class dispatch status = %d, want 200 — a mutate rule must not park it", resp.StatusCode)
	}
}

// TestApprovalWebhook_AParkNotifiesTheConfiguredEndpoint pins the composition
// root's notifier wiring (#270, ADR-0027): with a webhook configured, a park the
// Relay creates is pushed to that endpoint, naming the same Request the 202
// returned. Nothing else covers it — the unit tests build the Approvals with a
// spy — so a root that dropped the notifier, or always passed nil, would park
// silently and pass every other test.
func TestApprovalWebhook_AParkNotifiesTheConfiguredEndpoint(t *testing.T) {
	bodies := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case bodies <- b:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	f := startGatedRelay(t, gateAllMutates, WithConfig(func(c *Config) {
		c.ApprovalWebhookURL = webhookURLSecret(t, srv.URL)
	}))

	parkResp := restartMutate(t, f, f.Credential)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	select {
	case b := <-bodies:
		var notice struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(b, &notice); err != nil {
			t.Fatalf("decode webhook body %q: %v", b, err)
		}
		if notice.RequestID != parked.RequestID {
			t.Errorf("webhook request_id = %q, want the park's %q", notice.RequestID, parked.RequestID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook POST within 5s of the park")
	}
}
