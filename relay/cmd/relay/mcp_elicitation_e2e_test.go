// Package main: mcp_elicitation_e2e_test.go is S5 of #646 (v0.7.0). It proves
// AP-60, AP-63, AP-68 and AP-70 end to end through the real composition root,
// using the Gleipnir client contract from #646: a machine Account, a retry
// that re-sends the same name and arguments and echoes requestState
// byte-identically, an inputResponses map keyed by the question's own
// input-request ID, an ElicitResult carrying content {"confirmed": true} only
// on accept (contract §4), and every answer carrying
// _meta["io.gleipnir/responder"] = {"username", "user_id", "gate":
// "permission"}.
//
// The answer path is enabled only by the #721 hook
// (WithMCPServerOptions(mcp.WithApprovalElicitation())); the composition root
// itself still does not pass it (TestCompositionRoot_DoesNotYetEnableElicitation,
// elicit_e2e_test.go, is untouched and must keep passing). This step merges
// dark.
//
// answered_retry_e2e_test.go (#727) is the per-branch proof for the same
// answer path, driven by a human founding admin and a minimal responder.
// This file adds what that one does not: the Gleipnir contract end to end,
// the verified/asserted attribution split, the Job/Task store state, the
// Control API decision view, terminality against a later decision, the
// side-by-side with approve_request, the permission-ask question shape, and
// the non-askable legs (AP-70).
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// elicitRequesterName is the machine Account that plays Gleipnir in these
// tests — the same shape approval_e2e_test.go and approval_console_e2e_test.go
// already use for "a machine Account calling this surface".
const elicitRequesterName = "gleipnir-prod"

// elicitResponderUsername is the human alice's identity, asserted in every
// answer's io.gleipnir/responder _meta.
const elicitResponderUsername = "alice"

// elicitResponderUserID is the shape Gleipnir sends alongside username: a
// well-formed ULID (26 Crockford-base32 characters, leading digit 0-7).
// recognisedResponder (tools_approval.go) reads only "gate" and "username",
// so this value must never appear in either lane of the audit trail.
const elicitResponderUserID = "01J9ZX5K8QH3M4N6P7R2S0T1VW"

// sshdRestartArgs is a second, distinct Plan from restartNginxArgs
// (mrtr_harness_e2e_test.go): approval.go's ByPlanHash dedup would return the
// SAME pending request for two calls sharing a Plan, so wherever a test needs
// two live requests to coexist, one of them asks about sshd instead.
func sshdRestartArgs() map[string]any {
	return map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "sshd"},
	}
}

// startElicitingRelay boots a gated, askable-in-band Relay with the #721 hook
// on, and mints the machine Account ("gleipnir-prod", admin) that plays
// Gleipnir in every test below.
func startElicitingRelay(t *testing.T) (f *relayFixture, token string, accountID string) {
	t.Helper()
	f = startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))
	token = mintAccount(t, f, elicitRequesterName, accounts.KindMachine, accounts.RoleAdmin)
	acct, err := f.Deps.store.Accounts().GetByName(context.Background(), elicitRequesterName)
	if err != nil {
		t.Fatalf("GetByName(%s): %v", elicitRequesterName, err)
	}
	return f, token, acct.ID
}

// connectEliciting opens an MRTR-capable session for token: 2026-07-28, form
// elicitation advertised, the SDK's own answer-fulfilment middleware
// disabled, so the test sees exactly what Relay sent.
func connectEliciting(t *testing.T, f *relayFixture, token string) *sdkmcp.ClientSession {
	t.Helper()
	return relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(token), relaytest.ConnectOptions{
		Client: relaytest.ElicitingClientOptions(),
	})
}

// askApproval drives the first, parking run_operation call over session and
// asserts the full AP-60 wire shape, including the permission-ask question
// shape: a consent-only schema, no vendor _meta on the question itself, and
// an input-request ID that is non-empty, bounded, and equal to the request
// id carried in _meta.
func askApproval(t *testing.T, session *sdkmcp.ClientSession, args map[string]any) (q *sdkmcp.CallToolResult, questionID, requestID, planHash string) {
	t.Helper()
	q = relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{Name: "run_operation", Arguments: args})
	if !q.NeedsInput() {
		t.Fatalf("askApproval: NeedsInput() = false, want true; IsError=%v content=%+v", q.IsError, q.Content)
	}
	if q.IsError {
		t.Fatalf("askApproval: IsError = true unexpectedly; content = %+v", q.Content)
	}
	if len(q.Content) != 0 {
		t.Errorf("askApproval: Content = %+v, want empty", q.Content)
	}
	if q.StructuredContent != nil {
		t.Errorf("askApproval: StructuredContent = %+v, want nil", q.StructuredContent)
	}
	if len(q.InputRequests) != 1 {
		t.Fatalf("askApproval: InputRequests has %d entries, want exactly 1: %+v", len(q.InputRequests), q.InputRequests)
	}
	for k := range q.InputRequests {
		questionID = k
	}
	if questionID == "" {
		t.Fatal("askApproval: the input-request ID is empty")
	}
	// The SEP-2322 input-request-ID bound: requeststate.MaxFieldBytes
	// enforces this at seal time.
	if len(questionID) > 256 {
		t.Errorf("askApproval: the input-request ID is %d bytes, want at most 256", len(questionID))
	}

	entry := q.InputRequests[questionID]
	params, ok := entry.(*sdkmcp.ElicitParams)
	if !ok {
		t.Fatalf("askApproval: InputRequests[%q] = %T, want *sdkmcp.ElicitParams", questionID, entry)
	}
	if params.Mode != "form" {
		t.Errorf("askApproval: Mode = %q, want form", params.Mode)
	}
	if params.Message == "" {
		t.Error("askApproval: Message is empty")
	}
	// No vendor elicitation-kind hint and nothing else in the question's own
	// _meta (elicit.go: "NO ElicitParams.Meta").
	if len(params.Meta) != 0 {
		t.Errorf("askApproval: input-request _meta = %+v, want none", params.Meta)
	}

	// The consent-shaped schema is asserted structurally, through a JSON
	// round trip, rather than by the Go type RequestedSchema happens to
	// decode into on this client — that decoding is an SDK detail this test
	// must not depend on.
	var schema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	schemaJSON, err := json.Marshal(params.RequestedSchema)
	if err != nil {
		t.Fatalf("askApproval: marshal RequestedSchema: %v", err)
	}
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatalf("askApproval: unmarshal RequestedSchema: %v", err)
	}
	if schema.Type != "object" {
		t.Errorf("askApproval: RequestedSchema.type = %q, want object", schema.Type)
	}
	if schema.Properties == nil {
		t.Error("askApproval: RequestedSchema.properties is absent, want present (and empty)")
	}
	if len(schema.Properties) != 0 {
		t.Errorf("askApproval: RequestedSchema.properties = %+v, want empty", schema.Properties)
	}

	requestID, _ = q.Meta["relay/request_id"].(string)
	planHash, _ = q.Meta["relay/plan_hash"].(string)
	if requestID == "" {
		t.Fatal("askApproval: _meta[relay/request_id] is empty")
	}
	if planHash == "" {
		t.Fatal("askApproval: _meta[relay/plan_hash] is empty")
	}
	if questionID != requestID {
		t.Errorf("askApproval: input-request ID %q != _meta request_id %q", questionID, requestID)
	}
	if q.RequestState == "" {
		t.Error("askApproval: RequestState is empty, want the sealed state")
	}
	return q, questionID, requestID, planHash
}

// answerAsResponder retries the parked call, answering questionID as alice
// with action ("accept" or "decline"). Content is present only on accept —
// #646's Gleipnir contract §4: decline and cancel carry none — while the
// io.gleipnir/responder assertion (gate "permission") rides every action.
// The answer path itself reads only Action and this _meta
// (tools_approval.go), so omitting Content on decline changes nothing Relay
// decides; it only keeps this test client honest to the contract.
func answerAsResponder(t *testing.T, session *sdkmcp.ClientSession, args map[string]any, q *sdkmcp.CallToolResult, questionID, action string) *sdkmcp.CallToolResult {
	t.Helper()
	result := &sdkmcp.ElicitResult{
		Action: action,
		Meta: sdkmcp.Meta{
			"io.gleipnir/responder": map[string]any{
				"username": elicitResponderUsername,
				"user_id":  elicitResponderUserID,
				"gate":     "permission",
			},
		},
	}
	if action == "accept" {
		result.Content = map[string]any{"confirmed": true}
	}
	return relaytest.RetryTool(t, session, "run_operation", args, q.RequestState, sdkmcp.InputResponseMap{questionID: result})
}

// fetchApproval GETs one approval as the founding admin. Named fetchApproval
// rather than getApproval because approval_console_e2e_test.go already uses
// getApproval as a local variable, which would shadow a package func of that
// name.
func fetchApproval(t *testing.T, f *relayFixture, requestID string) approvalBody {
	t.Helper()
	resp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetchApproval(%s): status = %d; body = %s", requestID, resp.StatusCode, body)
	}
	var out approvalBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("fetchApproval(%s): decode: %v", requestID, err)
	}
	return out
}

// allJobs returns every Job the store holds.
func allJobs(t *testing.T, f *relayFixture) []jobs.JobSummary {
	t.Helper()
	page, err := f.Deps.store.JobQueries().QueryJobs(context.Background(), jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	return page.Jobs
}

// decisionRecordsFor returns requestID's KindApprovalDecided audit records.
func decisionRecordsFor(t *testing.T, f *relayFixture, requestID string) []audit.Record {
	t.Helper()
	records, err := f.Deps.audit.ByApproval(context.Background(), requestID)
	if err != nil {
		t.Fatalf("ByApproval(%s): %v", requestID, err)
	}
	var decisions []audit.Record
	for _, r := range records {
		if r.Kind == audit.KindApprovalDecided {
			decisions = append(decisions, r)
		}
	}
	return decisions
}

// parkRecordFor returns requestID's single KindApprovalRequested audit
// record, failing the test on zero or more than one.
func parkRecordFor(t *testing.T, f *relayFixture, requestID string) audit.Record {
	t.Helper()
	records, err := f.Deps.audit.ByApproval(context.Background(), requestID)
	if err != nil {
		t.Fatalf("ByApproval(%s): %v", requestID, err)
	}
	var parks []audit.Record
	for _, r := range records {
		if r.Kind == audit.KindApprovalRequested {
			parks = append(parks, r)
		}
	}
	if len(parks) != 1 {
		t.Fatalf("parkRecordFor(%s): %d KindApprovalRequested records, want exactly 1: %+v", requestID, len(parks), parks)
	}
	return parks[0]
}

// elicitDecisionView decodes GET /api/v1/approvals/{id}'s decision list with
// account_id, which approvalBody (approval_e2e_test.go) does not carry and
// must not be changed here to add.
type elicitDecisionView struct {
	Decisions []struct {
		Account   string `json:"account"`
		AccountID string `json:"account_id"`
		Approve   bool   `json:"approve"`
		Channel   string `json:"channel"`
		Human     bool   `json:"human"`
	} `json:"decisions"`
}

// TestMCPElicitation_ApproveRunsTheJobAndReturnsResults is AP-60/AP-63's e2e
// proof: an askable park renders a permission-ask question with no Job and no
// dispatch yet, and an accepting retry runs the Job and returns its per-Node
// results alongside the decision, in that one response.
func TestMCPElicitation_ApproveRunsTheJobAndReturnsResults(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)

	q, qid, requestID, planHash := askApproval(t, session, restartNginxArgs())

	params := q.InputRequests[qid].(*sdkmcp.ElicitParams)
	pending := fetchApproval(t, f, requestID)
	if pending.State != "pending" {
		t.Errorf("approval state = %q, want pending", pending.State)
	}
	if pending.PlanHash != planHash {
		t.Errorf("approval plan_hash = %q, want %q", pending.PlanHash, planHash)
	}
	if pending.Summary != params.Message {
		t.Errorf("approval summary = %q, want the question's own Message %q", pending.Summary, params.Message)
	}

	// No Job and no Tasks yet: Task rows are keyed by Job (QueryTasks takes a
	// JobID), so an empty Job store means no Tasks can exist. The zero
	// dispatch audit count is an independent check that nothing reached the
	// dispatch lane.
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs before the answer = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records before the answer = %d, want 0", dispatchCount)
	}

	res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}
	if res.InputRequests != nil {
		t.Errorf("InputRequests = %+v, want nil", res.InputRequests)
	}
	if res.RequestState != "" {
		t.Errorf("RequestState = %q, want empty", res.RequestState)
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
		t.Errorf("outcome = %q, want unreachable — the Node is registered but has no Tunnel", out.Results[0].Outcome)
	}
	if out.PendingApproval != nil {
		t.Errorf("PendingApproval = %+v, want nil", out.PendingApproval)
	}
	if out.AnswerRefused != nil {
		t.Errorf("AnswerRefused = %+v, want nil", out.AnswerRefused)
	}
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.RequestID != requestID {
		t.Errorf("Decision.RequestID = %q, want %q", out.Decision.RequestID, requestID)
	}
	if out.Decision.State != "approved" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != elicitResponderUsername {
		t.Errorf("Decision = %+v, want approved/in-band/%s", out.Decision, elicitResponderUsername)
	}

	jobList := allJobs(t, f)
	if len(jobList) != 1 {
		t.Fatalf("Jobs after the answer = %d, want exactly 1: %+v", len(jobList), jobList)
	}
	if jobList[0].JobID != out.JobID {
		t.Errorf("Job.JobID = %q, want %q", jobList[0].JobID, out.JobID)
	}
	if jobList[0].ApprovalID != requestID {
		t.Errorf("Job.ApprovalID = %q, want %q", jobList[0].ApprovalID, requestID)
	}

	taskPage, err := f.Deps.store.JobQueries().QueryTasks(context.Background(), jobs.TaskQuery{JobID: out.JobID}, 0, "")
	if err != nil {
		t.Fatalf("QueryTasks: %v", err)
	}
	if len(taskPage.Tasks) != 1 || taskPage.Tasks[0].NodeID != "node-e2e-1" {
		t.Fatalf("Tasks = %+v, want exactly 1 for node-e2e-1", taskPage.Tasks)
	}

	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 1 {
		t.Errorf("KindDispatch records after the answer = %d, want exactly 1", dispatchCount)
	}
	if got := fetchApproval(t, f, requestID); got.State != "approved" {
		t.Errorf("approval state after the answer = %q, want approved", got.State)
	}
}

// TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover is
// AP-63's e2e proof of the two attribution lanes: the verified lane is the
// calling machine Account, the asserted lane is alice, the responder's
// user_id never appears in either, and the SAME Decision shape is what
// approve_request records for the same Account.
func TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover(t *testing.T) {
	f, token, accountID := startElicitingRelay(t)
	session := connectEliciting(t, f, token)

	q, qid, requestID, planHash := askApproval(t, session, restartNginxArgs())
	res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}

	park := parkRecordFor(t, f, requestID)
	if park.Attribution.Verified.AccountID != accountID {
		t.Errorf("park verified account id = %q, want %q", park.Attribution.Verified.AccountID, accountID)
	}
	if park.Attribution.Verified.AccountName != elicitRequesterName {
		t.Errorf("park verified account name = %q, want %q", park.Attribution.Verified.AccountName, elicitRequesterName)
	}

	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
	}
	d := decisions[0]
	if d.DecisionChannel != "in-band" {
		t.Errorf("DecisionChannel = %q, want in-band", d.DecisionChannel)
	}
	if d.ApprovalAnswer != audit.ApprovalAnswerApproved {
		t.Errorf("ApprovalAnswer = %q, want %q", d.ApprovalAnswer, audit.ApprovalAnswerApproved)
	}
	if d.PlanHash != planHash {
		t.Errorf("PlanHash = %q, want %q", d.PlanHash, planHash)
	}
	// The verified lane is the calling Account — the same Account the park
	// itself named.
	if d.Attribution.Verified.AccountID != accountID || d.Attribution.Verified.AccountID != park.Attribution.Verified.AccountID {
		t.Errorf("decision verified account id = %q, want %q (and to match the park record)", d.Attribution.Verified.AccountID, accountID)
	}
	if d.Attribution.Verified.AccountName != elicitRequesterName || d.Attribution.Verified.AccountName != park.Attribution.Verified.AccountName {
		t.Errorf("decision verified account name = %q, want %q (and to match the park record)", d.Attribution.Verified.AccountName, elicitRequesterName)
	}
	// The responder appears ONLY in the asserted lane.
	if d.Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
		t.Errorf("decision asserted on_behalf_of = %q, want %q", d.Attribution.Asserted.OnBehalfOf, elicitResponderUsername)
	}
	if d.Attribution.Verified.AccountName == elicitResponderUsername {
		t.Error("decision verified account name equals the responder's username; the responder must appear only asserted")
	}
	if d.Attribution.Verified.AccountID == elicitResponderUserID {
		t.Error("decision verified account id equals the responder's user_id; the responder must appear only asserted")
	}
	if d.Attribution.Asserted.OnBehalfOf == elicitResponderUserID {
		t.Error("decision asserted on_behalf_of equals the responder's user_id; only the username is recorded")
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close() //nolint:errcheck
	var view elicitDecisionView
	if err := json.NewDecoder(getResp.Body).Decode(&view); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if len(view.Decisions) != 1 {
		t.Fatalf("Control API decisions = %+v, want exactly 1", view.Decisions)
	}
	cd := view.Decisions[0]
	if cd.Account != elicitRequesterName || cd.AccountID != accountID {
		t.Errorf("Control API decision account = %+v, want %s/%s", cd, elicitRequesterName, accountID)
	}
	if !cd.Approve || cd.Channel != "in-band" {
		t.Errorf("Control API decision = %+v, want approve=true channel=in-band", cd)
	}
	if cd.Human {
		t.Error("Control API decision Human = true, want false — the verified lane is a machine, the person is only asserted")
	}

	// The SAME Decision approve_request records, on the same Account, over a
	// second (distinct) Plan so the two requests coexist.
	plain := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))
	plainRes := relaytest.CallTool(t, plain, "run_operation", sshdRestartArgs())
	var plainOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, plainRes, &plainOut)
	if plainOut.PendingApproval == nil {
		t.Fatalf("second plan did not park: %+v", plainOut)
	}
	requestID2 := plainOut.PendingApproval.RequestID
	planHash2 := plainOut.PendingApproval.PlanHash

	approveRes := relaytest.CallTool(t, plain, "approve_request", map[string]any{
		"request_id": requestID2,
		"plan_hash":  planHash2,
		"approve":    true,
		"approver":   elicitResponderUsername,
	})
	if approveRes.IsError {
		t.Fatalf("approve_request: IsError, content=%+v", approveRes.Content)
	}
	var decision2 mcp.ApprovalDecisionOutput
	relaytest.DecodeToolJSON(t, approveRes, &decision2)
	if decision2.State != "approved" || decision2.Channel != "in-band" || decision2.OnBehalfOf != elicitResponderUsername {
		t.Errorf("approve_request decision = %+v, want approved/in-band/%s", decision2, elicitResponderUsername)
	}

	decisions2 := decisionRecordsFor(t, f, requestID2)
	if len(decisions2) != 1 {
		t.Fatalf("decision records for the second request = %d, want exactly 1: %+v", len(decisions2), decisions2)
	}
	d2 := decisions2[0]
	if d.DecisionChannel != d2.DecisionChannel ||
		d.ApprovalAnswer != d2.ApprovalAnswer ||
		d.Attribution.Verified.AccountID != d2.Attribution.Verified.AccountID ||
		d.Attribution.Verified.AccountName != d2.Attribution.Verified.AccountName ||
		d.Attribution.Verified.Role != d2.Attribution.Verified.Role ||
		d.Attribution.Asserted.OnBehalfOf != d2.Attribution.Asserted.OnBehalfOf {
		t.Errorf("the two Decisions disagree — an MRTR answer and approve_request by the same Account should record "+
			"the same shape (ADR-0029's relay exception, approval.go's relaysAnAssertedHuman):\n  MRTR answer:     %+v\n  approve_request: %+v",
			d, d2)
	}
}

// TestMCPElicitation_DeclineIsTerminalAndAudited is AP-68's e2e proof: a
// declining retry carries no content on the wire, is rendered as an ordinary
// tool result rather than a tool error, records exactly one denied decision,
// dispatches nothing, and is terminal — a later decision attempt by a second
// human is refused with a 409 whose problem TITLE, not merely its status,
// names the request as no longer open.
func TestMCPElicitation_DeclineIsTerminalAndAudited(t *testing.T) {
	f, token, accountID := startElicitingRelay(t)
	session := connectEliciting(t, f, token)

	q, qid, requestID, planHash := askApproval(t, session, restartNginxArgs())

	res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "decline")
	if res.IsError {
		t.Fatalf("decline: IsError = true, content=%+v", res.Content)
	}
	if res.NeedsInput() {
		t.Fatalf("decline: NeedsInput() = true, want false")
	}
	if len(res.Content) == 0 {
		t.Error("decline: Content is empty, want the rendered denial")
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.RequestID != requestID {
		t.Errorf("Decision.RequestID = %q, want %q", out.Decision.RequestID, requestID)
	}
	if out.Decision.State != "denied" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != elicitResponderUsername {
		t.Errorf("Decision = %+v, want denied/in-band/%s", out.Decision, elicitResponderUsername)
	}
	if out.JobID != "" {
		t.Errorf("JobID = %q, want empty", out.JobID)
	}
	if len(out.Results) != 0 {
		t.Errorf("Results = %+v, want empty", out.Results)
	}
	if out.PendingApproval != nil {
		t.Errorf("PendingApproval = %+v, want nil", out.PendingApproval)
	}
	if out.AnswerRefused != nil {
		t.Errorf("AnswerRefused = %+v, want nil", out.AnswerRefused)
	}

	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
	}
	d := decisions[0]
	if d.ApprovalAnswer != audit.ApprovalAnswerDenied {
		t.Errorf("ApprovalAnswer = %q, want %q", d.ApprovalAnswer, audit.ApprovalAnswerDenied)
	}
	if d.DecisionChannel != "in-band" {
		t.Errorf("DecisionChannel = %q, want in-band", d.DecisionChannel)
	}
	if d.Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
		t.Errorf("Asserted.OnBehalfOf = %q, want %q", d.Attribution.Asserted.OnBehalfOf, elicitResponderUsername)
	}
	if d.Attribution.Verified.AccountID != accountID {
		t.Errorf("Verified.AccountID = %q, want %q", d.Attribution.Verified.AccountID, accountID)
	}

	// Nothing is dispatched. Task rows are keyed by Job, so an empty Job
	// store means no Tasks can exist either.
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}
	if got := fetchApproval(t, f, requestID); got.State != "denied" {
		t.Errorf("approval state = %q, want denied", got.State)
	}

	// The decline is terminal. Six domain sentinels map to a 409 across five
	// problem titles (ErrNotPending, ErrRequesterExcluded and
	// ErrMachineSelfDecision sharing one, plus ErrDuplicateDecider,
	// ErrPlanChanged and ErrWeakChannel) — checking the status alone would
	// also pass if bianca were refused for an unrelated reason, so only the
	// "not pending" TITLE actually proves this request is closed.
	bianca := mintAccount(t, f, "bianca", accounts.KindHuman, accounts.RoleOperator)
	decideResp := controlAPIRequest(t, f.ClientFor(bianca), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+requestID+"/decision", bianca,
		map[string]any{"approve": true, "plan_hash": planHash})
	defer decideResp.Body.Close() //nolint:errcheck
	if decideResp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(decideResp.Body)
		t.Fatalf("second decision status = %d, want 409; body = %s", decideResp.StatusCode, body)
	}
	if ct := decideResp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(decideResp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Title != "approval request is not pending" {
		t.Errorf("problem title = %q, want %q", problem.Title, "approval request is not pending")
	}
	if !strings.Contains(problem.Detail, "not pending") {
		t.Errorf("problem detail = %q, want it to contain %q", problem.Detail, "not pending")
	}

	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs after the second decision attempt = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records after the second decision attempt = %d, want 0", dispatchCount)
	}
	if got := fetchApproval(t, f, requestID); got.State != "denied" {
		t.Errorf("approval state after the second decision attempt = %q, want still denied", got.State)
	}
}

// TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange is AP-70's e2e
// proof: with the option ON and against the same askable-in-band gate, a
// client that cannot be asked — one advertising no elicitation capability,
// and one on a legacy protocol version — sees today's pending_approval
// unchanged, and both requests are still decidable by approve_request and by
// the Control API's decision endpoint.
func TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange(t *testing.T) {
	f, token, _ := startElicitingRelay(t)

	// Client A: 2026-07-28, but advertises no elicitation capability at all.
	// clientCanBeAsked (elicit.go) returns false at its capability check
	// (caps.Elicitation == nil), so Relay renders today's pending_approval
	// and never builds an input-required result.
	clientA := relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(token), relaytest.ConnectOptions{
		Client: &sdkmcp.ClientOptions{MultiRoundTrip: &sdkmcp.MultiRoundTripOptions{Disabled: true}},
	})
	resA := relaytest.CallTool(t, clientA, "run_operation", sshdRestartArgs())
	if resA.NeedsInput() || resA.IsError {
		t.Fatalf("client A: NeedsInput=%v IsError=%v content=%+v", resA.NeedsInput(), resA.IsError, resA.Content)
	}
	if resA.InputRequests != nil {
		t.Errorf("client A: InputRequests = %+v, want nil", resA.InputRequests)
	}
	if resA.RequestState != "" {
		t.Errorf("client A: RequestState = %q, want empty", resA.RequestState)
	}
	var outA mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, resA, &outA)
	if outA.PendingApproval == nil {
		t.Fatalf("client A: did not park: %+v", outA)
	}
	if outA.PendingApproval.Status != "pending_approval" {
		t.Errorf("client A: Status = %q, want pending_approval", outA.PendingApproval.Status)
	}
	if outA.PendingApproval.RequestID == "" || outA.PendingApproval.PlanHash == "" {
		t.Errorf("client A: pending approval = %+v, want a non-empty request_id and plan_hash", outA.PendingApproval)
	}
	if outA.Decision != nil {
		t.Errorf("client A: Decision = %+v, want nil", outA.Decision)
	}
	if outA.AnswerRefused != nil {
		t.Errorf("client A: AnswerRefused = %+v, want nil", outA.AnswerRefused)
	}
	requestIDA := outA.PendingApproval.RequestID
	planHashA := outA.PendingApproval.PlanHash

	// Client B: legacy protocol, never MRTR — mirrors
	// TestElicit_OutOfBandParkNeverAsks. The claim is about the FULFILMENT
	// BRANCH, not about entering the middleware: go-sdk's
	// serverMultiRoundTripMiddleware (v1.8.0 mcp/mrtr.go) is installed
	// unconditionally and runs on every call, and on a non-MRTR session it
	// would fulfil an input-required result itself with a server-initiated
	// ss.Elicit. That branch is never reached here, because Relay never
	// produces an input-required result for this session: clientCanBeAsked
	// (elicit.go) returns false both because the session's negotiated
	// protocol version is legacy, and because a legacy client never calls
	// injectRequestMeta, so the per-request _meta carries neither the
	// protocol-version nor the clientCapabilities key. The handler's call
	// count is the only client-side observable of that branch.
	var elicitCalls atomic.Int32
	clientB := relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(token), relaytest.ConnectOptions{
		Client: &sdkmcp.ClientOptions{
			Capabilities: &sdkmcp.ClientCapabilities{
				Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
			},
			ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
				elicitCalls.Add(1)
				return &sdkmcp.ElicitResult{Action: "decline"}, nil
			},
		},
		Session: &sdkmcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"},
	})
	resB := relaytest.CallTool(t, clientB, "run_operation", restartNginxArgs())
	var outB mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, resB, &outB)
	if outB.PendingApproval == nil {
		t.Fatalf("client B: did not park: %+v", outB)
	}
	if calls := elicitCalls.Load(); calls != 0 {
		t.Errorf("client B: ElicitationHandler was called %d times, want 0", calls)
	}
	requestIDB := outB.PendingApproval.RequestID
	planHashB := outB.PendingApproval.PlanHash

	if len(decisionRecordsFor(t, f, requestIDA)) != 0 {
		t.Error("a KindApprovalDecided record exists for A's request before any rescue")
	}
	if len(decisionRecordsFor(t, f, requestIDB)) != 0 {
		t.Error("a KindApprovalDecided record exists for B's request before any rescue")
	}
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs before any rescue = %d, want 0", got)
	}

	// approve_request still decides A's request, on A's own session.
	approveRes := relaytest.CallTool(t, clientA, "approve_request", map[string]any{
		"request_id": requestIDA,
		"plan_hash":  planHashA,
		"approve":    true,
		"approver":   elicitResponderUsername,
	})
	if approveRes.IsError {
		t.Fatalf("approve_request: IsError, content=%+v", approveRes.Content)
	}
	var decisionA mcp.ApprovalDecisionOutput
	relaytest.DecodeToolJSON(t, approveRes, &decisionA)
	if decisionA.State != "approved" || decisionA.Channel != "in-band" {
		t.Errorf("A's decision = %+v, want approved/in-band", decisionA)
	}

	rerunA := relaytest.CallTool(t, clientA, "run_operation", sshdRestartArgs())
	var rerunAOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, rerunA, &rerunAOut)
	if rerunAOut.JobID == "" {
		t.Fatal("A's re-drive did not mint a Job")
	}
	if len(rerunAOut.Results) != 1 || rerunAOut.Results[0].NodeID != "node-e2e-1" {
		t.Fatalf("A's re-drive results = %+v, want the one matched Node", rerunAOut.Results)
	}
	if rerunAOut.Decision != nil {
		t.Errorf("A's re-drive Decision = %+v, want nil — this call carried no answer", rerunAOut.Decision)
	}

	// The Control API decision endpoint still decides B's request.
	bianca := mintAccount(t, f, "bianca", accounts.KindHuman, accounts.RoleOperator)
	decideResp := controlAPIRequest(t, f.ClientFor(bianca), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+requestIDB+"/decision", bianca,
		map[string]any{"approve": true, "plan_hash": planHashB})
	defer decideResp.Body.Close() //nolint:errcheck
	if decideResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(decideResp.Body)
		t.Fatalf("B's decision status = %d, want 200; body = %s", decideResp.StatusCode, body)
	}
	var decidedB approvalBody
	if err := json.NewDecoder(decideResp.Body).Decode(&decidedB); err != nil {
		t.Fatalf("decode B's decision: %v", err)
	}
	if decidedB.State != "approved" {
		t.Errorf("B's approval state = %q, want approved", decidedB.State)
	}

	rerunB := relaytest.CallTool(t, clientB, "run_operation", restartNginxArgs())
	var rerunBOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, rerunB, &rerunBOut)
	if rerunBOut.JobID == "" {
		t.Fatal("B's re-drive did not mint a Job")
	}
	if len(rerunBOut.Results) != 1 {
		t.Errorf("B's re-drive results = %+v, want exactly 1", rerunBOut.Results)
	}
	if calls := elicitCalls.Load(); calls != 0 {
		t.Errorf("after B's re-drive, ElicitationHandler was called %d times, want still 0", calls)
	}

	jobList := allJobs(t, f)
	if len(jobList) != 2 {
		t.Fatalf("Jobs = %d, want exactly 2: %+v", len(jobList), jobList)
	}
	gotApprovalIDs := map[string]bool{jobList[0].ApprovalID: true, jobList[1].ApprovalID: true}
	if !gotApprovalIDs[requestIDA] || !gotApprovalIDs[requestIDB] {
		t.Errorf("Job ApprovalIDs = %v, want exactly {%q, %q}", gotApprovalIDs, requestIDA, requestIDB)
	}
}
