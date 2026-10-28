// Package main: answered_retry_e2e_test.go is #727's e2e proof — through the
// REAL composition root. Most tests here still reach the answer path only
// through WithMCPServerOptions(mcp.WithApprovalElicitation()) (the #721
// hook, exactly as elicit_e2e_test.go uses it) — redundant since #730 (the
// composition root now passes the option itself) but harmless. The real
// composition root wires the real readAuditor (control_surfaces.go), so an
// answered retry's Job-bound re-attach writes a genuine KindRead record,
// exactly as get_job's own reads do.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// gateCountTwoInBandAskable is gateAllMutatesInBandAskable (elicit_e2e_test.go)
// with count raised to 2 and requester_allowed true — shared by the
// partial-quorum and rescue tests below, both of which need a quorum that
// survives a single answer.
const gateCountTwoInBandAskable = `{
  "rules": [
    {
      "name": "two-approvals-in-band",
      "match": { "risk_class": "mutate" },
      "require": { "count": 2, "requester_allowed": true, "channel": "in-band", "ttl": "1h" }
    }
  ]
}`

// answerRetry wraps relaytest.RetryTool with the answered-retry envelope: one
// InputResponseMap entry keyed reqID, an ElicitResult carrying action and an
// io.gleipnir/responder assertion naming "alice".
func answerRetry(t *testing.T, session *sdkmcp.ClientSession, name string, args map[string]any, state, reqID, action string) *sdkmcp.CallToolResult {
	t.Helper()
	responses := sdkmcp.InputResponseMap{
		reqID: &sdkmcp.ElicitResult{
			Action: action,
			Meta: sdkmcp.Meta{
				"io.gleipnir/responder": map[string]any{"gate": "permission", "username": "alice"},
			},
		},
	}
	return relaytest.RetryTool(t, session, name, args, state, responses)
}

// tamperRequestState flips one middle byte of state, the same way
// tools_approval_test.go's flipMiddleChar does for the mcp-handler-seam
// suite — package main cannot reach that unexported helper directly.
func tamperRequestState(state string) string {
	b := []byte(state)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// auditCounts returns how many audit.KindDispatch and audit.KindRead records
// f's trail holds.
func auditCounts(t *testing.T, f *relayFixture) (dispatch, read int) {
	t.Helper()
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	for _, r := range records {
		switch r.Kind {
		case audit.KindDispatch:
			dispatch++
		case audit.KindRead:
			read++
		}
	}
	return dispatch, read
}

// askQuestionE2E drives the first, parking run_operation call over an
// eliciting session and returns the question, failing the test if it did not
// render one.
func askQuestionE2E(t *testing.T, session *sdkmcp.ClientSession) *sdkmcp.CallToolResult {
	t.Helper()
	q := relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{Name: "run_operation", Arguments: restartNginxArgs()})
	if !q.NeedsInput() {
		t.Fatalf("question: NeedsInput() = false, want true; IsError=%v content=%+v", q.IsError, q.Content)
	}
	return q
}

// TestAnsweredRetry_ApproveRunsTheJobOnce is AP-63/AP-66's e2e proof: an
// approving retry with no Job bound calls the dispatch pipeline exactly once
// and carries the decision alongside the results.
func TestAnsweredRetry_ApproveRunsTheJobOnce(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)
	if requestID == "" {
		t.Fatal("no request id in the question's _meta")
	}

	res := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID == "" {
		t.Fatal("job_id is empty, want a real Job")
	}
	if len(out.Results) != 1 || out.Results[0].NodeID != "node-e2e-1" {
		t.Fatalf("results = %+v, want the one matched Node", out.Results)
	}
	if out.Results[0].Outcome != "unreachable" {
		t.Errorf("outcome = %q, want unreachable — the Node is registered but has no Tunnel (TestApprovalCallout_ParkDecideRun's own baseline)", out.Results[0].Outcome)
	}
	if out.Decision == nil {
		t.Fatalf("decision is nil: %+v", out)
	}
	if out.Decision.State != "approved" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != "alice" {
		t.Errorf("decision = %+v, want approved/in-band/alice", out.Decision)
	}

	dispatchCount, _ := auditCounts(t, f)
	if dispatchCount != 1 {
		t.Errorf("KindDispatch records = %d, want exactly 1", dispatchCount)
	}

	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var sawDecision bool
	for _, r := range records {
		switch r.Kind {
		case audit.KindApprovalDecided:
			sawDecision = true
			if r.Attribution.Asserted.OnBehalfOf != "alice" {
				t.Errorf("decision asserted approver = %q, want alice", r.Attribution.Asserted.OnBehalfOf)
			}
			if r.DecisionChannel != "in-band" {
				t.Errorf("decision channel = %q, want in-band", r.DecisionChannel)
			}
		case audit.KindDispatch:
			if r.JobID != out.JobID {
				t.Errorf("dispatch record JobID = %q, want %q", r.JobID, out.JobID)
			}
		}
	}
	if !sawDecision {
		t.Error("no KindApprovalDecided record found")
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close()
	var approved approvalBody
	if err := json.NewDecoder(getResp.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.State != "approved" {
		t.Errorf("approval state = %q, want approved", approved.State)
	}
}

// TestAnsweredRetry_FleetChangedReParksAndAsksAfresh is AP-66/AP-21's e2e
// proof: an approving retry whose fleet changed since the question re-parks
// (a NEW request id and plan hash), dispatches nothing, and — being a
// created park — is itself askable. The FIRST request, decided against the
// plan the human was actually shown, stays approved.
func TestAnsweredRetry_FleetChangedReParksAndAsksAfresh(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)
	planHash, _ := q.Meta["relay/plan_hash"].(string)

	if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: "node-e2e-2"}); err != nil {
		t.Fatalf("upsert second Node: %v", err)
	}

	res := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "accept")
	if !res.NeedsInput() {
		t.Fatalf("retry after a fleet change: NeedsInput() = false, want true (a fresh, askable park); IsError=%v content=%+v", res.IsError, res.Content)
	}
	newRequestID, _ := res.Meta["relay/request_id"].(string)
	newPlanHash, _ := res.Meta["relay/plan_hash"].(string)
	if newRequestID == "" || newRequestID == requestID {
		t.Errorf("new request id = %q, want a fresh, non-empty id (had %q)", newRequestID, requestID)
	}
	if newPlanHash == "" || newPlanHash == planHash {
		t.Errorf("new plan hash = %q, want a fresh, non-empty hash (had %q)", newPlanHash, planHash)
	}

	dispatchCount, _ := auditCounts(t, f)
	if dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close()
	var first approvalBody
	if err := json.NewDecoder(getResp.Body).Decode(&first); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if first.State != "approved" {
		t.Errorf("first request's state = %q, want approved — the decision was recorded against the plan the human was shown", first.State)
	}
}

// TestAnsweredRetry_BoundJobReAttaches is AP-67's e2e proof: an identical
// retry against an already-bound Job re-attaches — no second Job — and the
// re-attach is an audited KindRead record naming that Job and run_operation.
func TestAnsweredRetry_BoundJobReAttaches(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)

	first := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "accept")
	var firstOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, first, &firstOut)
	if firstOut.JobID == "" {
		t.Fatal("first retry did not mint a Job")
	}

	second := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "accept")
	var secondOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, second, &secondOut)
	if secondOut.JobID != firstOut.JobID {
		t.Errorf("second retry's job_id = %q, want the SAME job %q — no second Job", secondOut.JobID, firstOut.JobID)
	}

	dispatchCount, readCount := auditCounts(t, f)
	if dispatchCount != 1 {
		t.Errorf("KindDispatch records = %d, want exactly 1", dispatchCount)
	}
	if readCount != 1 {
		t.Errorf("KindRead records = %d, want exactly 1 (the re-attach, audited)", readCount)
	}

	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	for _, r := range records {
		if r.Kind != audit.KindRead {
			continue
		}
		if r.JobID != firstOut.JobID {
			t.Errorf("read record JobID = %q, want %q", r.JobID, firstOut.JobID)
		}
		if r.OperationName != "run_operation" {
			t.Errorf("read record tool (OperationName) = %q, want run_operation", r.OperationName)
		}
	}
}

// TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing is AP-68's e2e
// proof: a declining retry is terminal — no dispatch, no Job — and the
// denial is audited both as a decision record and on the Control API.
func TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)

	res := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "decline")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("decline: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.Decision == nil || out.Decision.State != "denied" {
		t.Fatalf("decision = %+v, want denied", out.Decision)
	}
	if len(out.Results) != 0 || out.JobID != "" {
		t.Errorf("out = %+v, want empty results and no job", out)
	}

	dispatchCount, _ := auditCounts(t, f)
	if dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}

	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var sawDeny bool
	for _, r := range records {
		if r.Kind == audit.KindApprovalDecided && r.ApprovalAnswer == audit.ApprovalAnswerDenied {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Error("no KindApprovalDecided/denied record found")
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close()
	var decided approvalBody
	if err := json.NewDecoder(getResp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if decided.State != "denied" {
		t.Errorf("state = %q, want denied", decided.State)
	}
}

// TestAnsweredRetry_PartialQuorumStaysPending: a count-2 rule's first answer
// leaves the request pending — an OBSERVED, non-askable park — dispatches
// nothing, and asks no new question.
func TestAnsweredRetry_PartialQuorumStaysPending(t *testing.T) {
	f := startGatedRelay(t, gateCountTwoInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)

	res := answerRetry(t, session, "run_operation", restartNginxArgs(), q.RequestState, requestID, "accept")
	if res.NeedsInput() {
		t.Fatalf("retry: NeedsInput() = true, want false (a partial quorum's park is OBSERVED, not askable)")
	}
	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("PendingApproval is nil, want a still-pending park: %+v", out)
	}
	if out.Decision == nil || out.Decision.Progress != "1 of 2" {
		t.Errorf("decision = %+v, want progress 1 of 2", out.Decision)
	}

	dispatchCount, _ := auditCounts(t, f)
	if dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}
}

// TestAnsweredRetry_RefusedStateStaysDecidableByTheRescue (suggestion 8): a
// tampered state is refused fail-closed, leaving the request undecided and
// still answerable — first by approve_request, then by a second human on the
// Control API — proving both rescues on one request.
func TestAnsweredRetry_RefusedStateStaysDecidableByTheRescue(t *testing.T) {
	f := startGatedRelay(t, gateCountTwoInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})

	q := askQuestionE2E(t, session)
	requestID, _ := q.Meta["relay/request_id"].(string)
	planHash, _ := q.Meta["relay/plan_hash"].(string)

	tampered := tamperRequestState(q.RequestState)
	res := answerRetry(t, session, "run_operation", restartNginxArgs(), tampered, requestID, "accept")
	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil, want a refusal: %+v", out)
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close()
	var stillPending approvalBody
	if err := json.NewDecoder(getResp.Body).Decode(&stillPending); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if stillPending.State != "pending" || len(stillPending.Decisions) != 0 {
		t.Fatalf("approval = %+v, want pending with no decision recorded", stillPending)
	}

	// Rescue 1: approve_request on the SAME MCP session records 1 of 2.
	approveRes := relaytest.CallTool(t, session, "approve_request", map[string]any{
		"request_id": requestID,
		"plan_hash":  planHash,
		"approve":    true,
		"approver":   "alice",
	})
	if approveRes.IsError {
		t.Fatalf("approve_request: IsError, content=%+v", approveRes.Content)
	}
	var decision1 mcp.ApprovalDecisionOutput
	relaytest.DecodeToolJSON(t, approveRes, &decision1)
	if decision1.Progress != "1 of 2" {
		t.Errorf("progress after the first rescue = %q, want 1 of 2", decision1.Progress)
	}

	// Rescue 2: a second human decides on the Control API's decision endpoint.
	second := mintAccount(t, f, "bianca", accounts.KindHuman, accounts.RoleOperator)
	decideResp := controlAPIRequest(t, f.ClientFor(second), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+requestID+"/decision", second,
		map[string]any{"approve": true, "plan_hash": planHash})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(decideResp.Body)
		t.Fatalf("second decision status = %d; body = %s", decideResp.StatusCode, body)
	}
	var decided approvalBody
	if err := json.NewDecoder(decideResp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decided.State != "approved" {
		t.Errorf("state after 2 of 2 = %q, want approved", decided.State)
	}

	getFinal := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getFinal.Body.Close()
	var final approvalBody
	if err := json.NewDecoder(getFinal.Body).Decode(&final); err != nil {
		t.Fatalf("decode final approval: %v", err)
	}
	if final.State != "approved" {
		t.Errorf("final state = %q, want approved", final.State)
	}
}

// TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields (AP-85, e2e
// half): with NO WithMCPServerOptions hook — exactly what a real deployment
// gets now that control_surfaces.go passes mcp.WithApprovalElicitation()
// itself — a client that cannot be asked (no elicitation capability) still
// gets today's pending_approval for a call carrying a garbage requestState
// and inputResponses, with no answered-retry block at all: clientCanBeAsked
// gates isAnsweredRetry (tools_execution.go), so such a client's retry
// fields are never even read. Renamed from
// TestAnsweredRetry_OptionOffIgnoresRetryFields, whose premise (an
// "option off" composition root) the flip (#730) retires — there is no
// removing Option, and the #721 hook may only add one. Option-off itself
// stays proven at the handler seam by the unit
// TestAnsweredRetry_OptionOffIgnoresRetryFields
// (internal/controlplane/mcp/tools_execution_retry_test.go) and
// TestElicit_OptionOffChangesNothing (internal/controlplane/mcp/elicit_test.go),
// both unchanged.
func TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable) // NO WithMCPServerOptions hook
	session := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client:     &sdkmcp.ClientOptions{MultiRoundTrip: &sdkmcp.MultiRoundTripOptions{Disabled: true}},
		ClientName: relaytest.GleipnirClientName,
	})

	res := relaytest.RetryTool(t, session, "run_operation", restartNginxArgs(), "garbage-request-state",
		sdkmcp.InputResponseMap{"garbage-id": &sdkmcp.ElicitResult{
			Action: "accept",
			Meta:   sdkmcp.Meta{"io.gleipnir/responder": map[string]any{"gate": "permission", "username": "alice"}},
		}})
	if res.NeedsInput() {
		t.Fatal("NeedsInput() = true — a client that cannot be asked must never be asked")
	}
	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("run_operation did not park: %+v", out)
	}
	if out.AnswerRefused != nil || out.Decision != nil {
		t.Errorf("out = %+v, want no answered-retry block for a client that cannot be asked", out)
	}

	// Control: an eliciting client sending the SAME garbage retry over the
	// SAME production wiring must be decided and refused instead — proving
	// the assertions above are not vacuously true of every client.
	auditBefore := auditLen(t, f)
	eliciting := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{Client: relaytest.ElicitingClientOptions(), ClientName: relaytest.GleipnirClientName})
	elicitingRes := relaytest.RetryTool(t, eliciting, "run_operation", restartNginxArgs(), "garbage-request-state",
		sdkmcp.InputResponseMap{"garbage-id": &sdkmcp.ElicitResult{
			Action: "accept",
			Meta:   sdkmcp.Meta{"io.gleipnir/responder": map[string]any{"gate": "permission", "username": "alice"}},
		}})
	assertStateRefusedNothingRecorded(t, f, elicitingRes, requeststate.ErrUnknownVersion.Error(), auditBefore)
}
