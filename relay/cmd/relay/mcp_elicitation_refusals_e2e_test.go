// Package main: mcp_elicitation_refusals_e2e_test.go is S6 of #646 (v0.7.0):
// proof for docs/specs/approval.md AP-62, AP-65, AP-66, AP-67,
// AP-85, AP-87 (and AP-17 kept proven for an MCP-originated request), plus
// the ADR-0040-as-amended rescue: the Control API keeps deciding any parked
// request, including one an MCP client parked, unchanged.
//
// The answer path is reached here only via the #721 hook
// (WithMCPServerOptions(mcp.WithApprovalElicitation())) — redundant since
// #730 (the composition root now passes the option itself) but harmless.
// Proof rows for the claims above are added in #730's own commit, alongside
// its composition-root proof.
//
// No origin check is built here: AP-74..76 were retired by ADR-0040's
// amendment. The Control API decision path is exercised, never narrowed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// -----------------------------------------------------------------------
// Exact strings the model receives (tools_approval.go). Hardcoded here
// because asserting the literal text IS the point: it is the contract the
// model, and a human reading a refusal, actually see. Every AP-65 cause below
// is instead built from requeststate's EXPORTED sentinels, never hardcoded,
// since only the package-mcp texts are this package's to duplicate.
// -----------------------------------------------------------------------

const (
	// refusedStateReason mirrors errAnswerStateRefused (tools_approval.go).
	// An AP-65 Reason is exactly this + ": " + one of the requeststate causes
	// below.
	refusedStateReason = "mcp: the retried call's request state is not valid for this caller, request and call — " +
		"it may be tampered, expired, sealed for another request or call, or the elicitation response is keyed to a different request than the one sealed; " +
		"the request is unchanged and can still be decided on the Control API's decision endpoint"

	// nextStepUnchanged mirrors answerRefusalNextStepUnchanged (tools_approval.go).
	nextStepUnchanged = "this call left the request (if any) unchanged. " +
		"It can still be decided on the Control API's decision endpoint."

	// noNamedApprover mirrors noNamedApproverError.Error (tools_approval.go):
	// AP-87's machine self-decision refusal on a session that needs a responder.
	noNamedApprover = "approver is required: an in-band approval must name the human who made the decision, " +
		"because this call is authenticated as the requesting session and cannot prove one was asked"

	// unusableAnswer mirrors errUnusableAnswer (tools_approval.go): AP-87's
	// refusal of an answer the Relay cannot read on an API-token session.
	unusableAnswer = "mcp: the elicited answer is refused: it was cancelled or " +
		"empty, replayed from an earlier question, or carried an io.gleipnir/responder that is " +
		"not a permission answer naming a user; nothing was recorded, and the request can " +
		"still be decided by answering again or on the Control API's decision endpoint"

	// nextStepRanAndRecorded mirrors nextStepRanThePipeline + " " +
	// nextStepAnswerRecorded (tools_approval.go).
	nextStepRanAndRecorded = "the call was re-entered through the full dispatch pipeline once in this response, and the Job shown ran. Do not re-issue it. " +
		"the answer was recorded."

	// nextStepReattachedNotRecorded mirrors nextStepReattachedExistingJob + " " +
	// nextStepAnswerNotRecordedAlreadyDecided (tools_approval.go).
	nextStepReattachedNotRecorded = "the results shown are the Job this approval already released, re-attached. Nothing new was dispatched. " +
		"your answer was NOT recorded: the request had already reached a resolution (decided, or lapsed) before this call arrived (state shown)."
)

// metaKeyReplayedFrom mirrors elicit's own unexported replayedFromMetaKey —
// duplicated here since this test cannot reach the unexported original.
const metaKeyReplayedFrom = "io.gleipnir/replayed-from"

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// auditLen returns the length of f's whole audit trail.
func auditLen(t *testing.T, f *relayFixture) int {
	t.Helper()
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	return len(records)
}

// acceptResponse is the standard accepting ElicitResult every AP-65 subtest
// below carries: alice's valid permission responder assertion, and the
// accept content #646's Gleipnir contract requires.
func acceptResponse() *sdkmcp.ElicitResult {
	return &sdkmcp.ElicitResult{
		Action:  "accept",
		Content: map[string]any{"confirmed": true},
		Meta: sdkmcp.Meta{
			"io.gleipnir/responder": map[string]any{
				"username": elicitResponderUsername,
				"user_id":  elicitResponderUserID,
				"gate":     "permission",
			},
		},
	}
}

// assertStateRefusedNothingRecorded asserts res is an AP-65 state refusal —
// refused inside OpenFor, before acceptElicitedAnswer's decider is ever
// called — and that the call recorded and dispatched nothing at all: the
// audit trail's total length is unchanged from auditBefore (captured
// immediately before the retried call, never across a Console GET or a
// fetchApproval — both of ADR-0025's audited reads write their own record),
// and every request named in pendingIDs is still pending with zero decisions.
func assertStateRefusedNothingRecorded(t *testing.T, f *relayFixture, res *sdkmcp.CallToolResult, wantCause string, auditBefore int, pendingIDs ...string) {
	t.Helper()
	if res.IsError {
		t.Fatalf("IsError = true, want false (a refusal is an ordinary result, never a tool error): content=%+v", res.Content)
	}
	if res.NeedsInput() {
		t.Fatalf("NeedsInput() = true, want false — a refused state must never render a new question")
	}
	if res.InputRequests != nil {
		t.Errorf("InputRequests = %+v, want nil", res.InputRequests)
	}
	if res.RequestState != "" {
		t.Errorf("RequestState = %q, want empty", res.RequestState)
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil, want a refusal: %+v", out)
	}
	wantReason := refusedStateReason + ": " + wantCause
	if out.AnswerRefused.Reason != wantReason {
		t.Errorf("Reason = %q, want %q", out.AnswerRefused.Reason, wantReason)
	}
	if out.AnswerRefused.NextStep != nextStepUnchanged {
		t.Errorf("NextStep = %q, want %q", out.AnswerRefused.NextStep, nextStepUnchanged)
	}
	if out.AnswerRefused.RequestID != "" || out.AnswerRefused.State != "" || out.AnswerRefused.JobID != "" || out.AnswerRefused.ExpiresAt != "" {
		t.Errorf("AnswerRefused = %+v, want RequestID/State/JobID/ExpiresAt all empty — refused inside OpenFor, before the seal ever opened", out.AnswerRefused)
	}
	if out.Decision != nil {
		t.Errorf("Decision = %+v, want nil", out.Decision)
	}
	if out.PendingApproval != nil {
		t.Errorf("PendingApproval = %+v, want nil", out.PendingApproval)
	}
	if out.JobID != "" {
		t.Errorf("JobID = %q, want empty", out.JobID)
	}
	if len(out.Results) != 0 {
		t.Errorf("Results = %+v, want empty", out.Results)
	}

	if got := auditLen(t, f); got != auditBefore {
		t.Errorf("audit trail length = %d, want unchanged at %d — the refused call must write NO audit record of any kind", got, auditBefore)
	}

	for _, id := range pendingIDs {
		pending := fetchApproval(t, f, id)
		if pending.State != "pending" {
			t.Errorf("approval %s state = %q, want still pending", id, pending.State)
		}
		if len(pending.Decisions) != 0 {
			t.Errorf("approval %s decisions = %+v, want none", id, pending.Decisions)
		}
		if got := decisionRecordsFor(t, f, id); len(got) != 0 {
			t.Errorf("approval %s decision records = %+v, want none", id, got)
		}
	}
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}
}

// assertMachineSelfDecisionRefused asserts res is an AP-87 machine
// self-decision refusal, as a session that needs a responder returns it —
// refused AFTER the seal opened, so RequestID is known and equals requestID —
// recording nothing.
func assertMachineSelfDecisionRefused(t *testing.T, f *relayFixture, res *sdkmcp.CallToolResult, requestID string, auditBefore int) {
	t.Helper()
	assertAnswerRefusedNothingRecorded(t, f, res, requestID, auditBefore, noNamedApprover)
}

// assertUnusableAnswerRefused asserts res is AP-87's refusal of an answer the
// Relay cannot read on an API-token session, recording nothing.
func assertUnusableAnswerRefused(t *testing.T, f *relayFixture, res *sdkmcp.CallToolResult, requestID string, auditBefore int) {
	t.Helper()
	assertAnswerRefusedNothingRecorded(t, f, res, requestID, auditBefore, unusableAnswer)
}

func assertAnswerRefusedNothingRecorded(t *testing.T, f *relayFixture, res *sdkmcp.CallToolResult, requestID string, auditBefore int, wantReason string) {
	t.Helper()
	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	if res.NeedsInput() {
		t.Fatalf("NeedsInput() = true, want false")
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil, want a refusal: %+v", out)
	}
	if out.AnswerRefused.Reason != wantReason {
		t.Errorf("Reason = %q, want %q", out.AnswerRefused.Reason, wantReason)
	}
	if out.AnswerRefused.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", out.AnswerRefused.RequestID, requestID)
	}
	if out.AnswerRefused.State != "" {
		t.Errorf("State = %q, want empty", out.AnswerRefused.State)
	}
	if out.AnswerRefused.NextStep != nextStepUnchanged {
		t.Errorf("NextStep = %q, want %q", out.AnswerRefused.NextStep, nextStepUnchanged)
	}
	if out.Decision != nil {
		t.Errorf("Decision = %+v, want nil", out.Decision)
	}

	if got := auditLen(t, f); got != auditBefore {
		t.Errorf("audit trail length = %d, want unchanged at %d", got, auditBefore)
	}
	pending := fetchApproval(t, f, requestID)
	if pending.State != "pending" || len(pending.Decisions) != 0 {
		t.Errorf("approval %s = %+v, want pending with no decisions", requestID, pending)
	}
	if got := decisionRecordsFor(t, f, requestID); len(got) != 0 {
		t.Errorf("decision records = %+v, want none", got)
	}
}

// postRawToolCall hand-builds a JSON-RPC tools/call POST, mirroring
// TestElicit_ElicitedParkEmitsNoTaskEnvelope_E2E's build (elicit_e2e_test.go),
// but generalized over header/meta/tool/args and — unlike mcp_no_task_handle_e2e_test.go's
// rawToolCall — never failing the test on a non-200 status: this file's
// legacy-header rows are refused with a 400 by the SDK transport itself.
func postRawToolCall(t *testing.T, f *relayFixture, token, header string, meta map[string]any, tool string, args map[string]any) (status int, contentType string, respBody []byte) {
	t.Helper()
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]any{"_meta": meta, "name": tool, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.ControlBase+"/mcp", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if header != "" {
		req.Header.Set("MCP-Protocol-Version", header)
	}
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := f.ClientFor(token).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), respBody
}

// sealUnderAnotherKey mints a SECOND requeststate.Sealer — a different
// process's key, exactly what a restart or a replica with a different key
// produces — and seals a state whose every bound field is correct: the same
// account, request, plan hash, tool and argument digest a real park would
// seal. The CONTROL below opens it under that same second Sealer to prove the
// state is correctly SHAPED; it is not proof the state would be accepted by
// the server under test; the refusal there is the key alone (plan review
// suggestion 1) — MAC verification happens before Bind, so a state sealed
// under a different key is cryptographically indistinguishable from a
// tampered one (requeststate.ErrTampered) regardless of how well-formed its
// fields are.
func sealUnderAnotherKey(t *testing.T, accountID, requestID, planHash string, args map[string]any) string {
	t.Helper()
	key, err := requeststate.NewKey()
	if err != nil {
		t.Fatalf("requeststate.NewKey: %v", err)
	}
	sealer, err := requeststate.New(key)
	if err != nil {
		t.Fatalf("requeststate.New: %v", err)
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	digest, err := requeststate.DigestArgs(argsJSON)
	if err != nil {
		t.Fatalf("DigestArgs: %v", err)
	}
	state := requeststate.State{
		AccountID:  accountID,
		RequestID:  requestID,
		PlanHash:   planHash,
		Tool:       "run_operation",
		ArgsDigest: digest,
		ExpiresAt:  time.Now().Add(30 * time.Minute),
	}
	sealed, err := sealer.Seal(state)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// CONTROL: correctly shaped under its OWN sealer.
	if _, err := sealer.OpenFor(sealed, time.Now(), requeststate.Call{
		AccountID: accountID, RequestID: requestID, Tool: "run_operation", ArgsDigest: digest,
	}); err != nil {
		t.Fatalf("control: OpenFor under the SAME sealer that sealed it: %v", err)
	}
	if !strings.HasPrefix(sealed, "rs1.") {
		t.Fatalf("sealed state = %q, want the requeststate version prefix rs1.", sealed)
	}
	return sealed
}

// assertRedriveRuns re-drives the original parked call, carrying no answer
// fields, over session, and asserts it now runs the released Job bound to
// requestID.
func assertRedriveRuns(t *testing.T, f *relayFixture, session *sdkmcp.ClientSession, requestID string) {
	t.Helper()
	res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID == "" {
		t.Fatal("re-drive did not mint a Job")
	}
	if len(out.Results) != 1 || out.Results[0].NodeID != "node-e2e-1" || out.Results[0].Outcome != "unreachable" {
		t.Fatalf("re-drive results = %+v, want one truthful unreachable result for node-e2e-1", out.Results)
	}
	if out.Decision != nil || out.AnswerRefused != nil || out.PendingApproval != nil {
		t.Errorf("re-drive out = %+v, want no answered-retry/pending block — this call carried no answer", out)
	}

	jobList := allJobs(t, f)
	if len(jobList) != 1 {
		t.Fatalf("Jobs = %d, want exactly 1: %+v", len(jobList), jobList)
	}
	if jobList[0].JobID != out.JobID {
		t.Errorf("Job.JobID = %q, want %q", jobList[0].JobID, out.JobID)
	}
	if jobList[0].ApprovalID != requestID {
		t.Errorf("Job.ApprovalID = %q, want %q", jobList[0].ApprovalID, requestID)
	}
}

// -----------------------------------------------------------------------
// AP-65: state refusals
// -----------------------------------------------------------------------

// TestMCPElicitation_TamperedStateIsRefused is AP-65's proof for a tampered
// requestState: refused fail-closed inside OpenFor, recording nothing, and
// the ORIGINAL state — untouched by the refusal — still answers the request.
func TestMCPElicitation_TamperedStateIsRefused(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	q, qid, rid, _ := askApproval(t, session, restartNginxArgs())

	before := auditLen(t, f)
	qt := *q
	qt.RequestState = tamperRequestState(q.RequestState)
	res := answerAsResponder(t, session, restartNginxArgs(), &qt, qid, "accept")
	assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrTampered.Error(), before, rid)

	// The ORIGINAL state is untouched by the refusal above and still answers.
	final := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, final, &out)
	if out.Decision == nil || out.Decision.State != "approved" || out.JobID == "" {
		t.Errorf("final decision = %+v, jobID = %q, want approved with a Job", out.Decision, out.JobID)
	}
}

// TestMCPElicitation_CrossRequestStateIsRefused is AP-65's proof for a state
// sealed to one request retried against another: two DISTINCT parked
// requests coexist (a second Plan, sshdRestartArgs, so approval.go's
// ByPlanHash dedup cannot collapse them into one), and request A's state
// answering request B's question is refused with a request-id binding
// mismatch, leaving BOTH pending.
func TestMCPElicitation_CrossRequestStateIsRefused(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)

	qA, _, ridA, _ := askApproval(t, session, restartNginxArgs())
	_, qidB, ridB, _ := askApproval(t, session, sshdRestartArgs())

	before := auditLen(t, f)
	qx := *qA
	res := answerAsResponder(t, session, sshdRestartArgs(), &qx, qidB, "accept")
	assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrBindingMismatch.Error()+": request id", before, ridA, ridB)
}

// TestMCPElicitation_CrossAccountStateIsRefused is AP-65's proof for a state
// sealed to one Account replayed by a second: identical retry, different
// caller, refused with an account-id binding mismatch.
func TestMCPElicitation_CrossAccountStateIsRefused(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	qA, qidA, ridA, _ := askApproval(t, session, restartNginxArgs())

	tokenB := mintAccount(t, f, "gleipnir-canary", accounts.KindMachine, accounts.RoleAdmin)
	sessionB := connectEliciting(t, f, tokenB)

	before := auditLen(t, f)
	res := answerAsResponder(t, sessionB, restartNginxArgs(), qA, qidA, "accept")
	assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrBindingMismatch.Error()+": account id", before, ridA)
}

// TestMCPElicitation_WrongCallStateIsRefused is AP-65's proof that a sealed
// state is bound to the exact tool AND the exact arguments it was sealed
// for: replaying it onto a different tool, or the same tool with different
// arguments, is refused by the binding check — never reaching Execution.Run,
// so neither retry parks a second request.
func TestMCPElicitation_WrongCallStateIsRefused(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	q, qid, rid, _ := askApproval(t, session, restartNginxArgs())

	t.Run("different tool", func(t *testing.T) {
		before := auditLen(t, f)
		res := relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{
			Name:           "raw_exec",
			Arguments:      map[string]any{"argv": []string{"systemctl", "restart", "nginx"}},
			RequestState:   q.RequestState,
			InputResponses: sdkmcp.InputResponseMap{qid: acceptResponse()},
		})
		assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrBindingMismatch.Error()+": tool", before, rid)
	})

	t.Run("different arguments", func(t *testing.T) {
		before := auditLen(t, f)
		res := answerAsResponder(t, session, sshdRestartArgs(), q, qid, "accept")
		assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrBindingMismatch.Error()+": args digest", before, rid)
	})

	// The refused retries never reached Execution.Run: no sshd or raw_exec
	// request was ever parked, so the queue still holds exactly the one
	// original request.
	listResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals", f.Credential, nil)
	defer listResp.Body.Close()
	var list approvalListBody
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode approvals: %v", err)
	}
	if len(list.Approvals) != 1 || list.Approvals[0].RequestID != rid {
		t.Fatalf("approvals = %+v, want exactly the one original request %q", list.Approvals, rid)
	}
}

// TestMCPElicitation_ExpiredStateIsRefused is AP-65's proof for a state past
// its sealed expiry: mcp.WithClock (a documented test seam, mcp.go) lets this
// test skew the SEALED clock past the gate's 1h TTL while the approval
// store's own clock stays real, isolating the seal's own expiry check from
// approval.Request's separate lapse check (that leg is
// TestAnsweredRetry_LapsedRequestReParks at the handler seam).
func TestMCPElicitation_ExpiredStateIsRefused(t *testing.T) {
	var skew atomic.Int64
	clock := func() time.Time { return time.Now().UTC().Add(time.Duration(skew.Load())) }
	f, token, _ := startElicitingRelayWith(t, gateAllMutates, WithMCPServerOptions(mcp.WithClock(clock)))
	session := connectEliciting(t, f, token)
	q, qid, rid, _ := askApproval(t, session, restartNginxArgs())

	skew.Store(int64(2 * time.Hour))
	before := auditLen(t, f)
	res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrExpired.Error(), before, rid)
}

// -----------------------------------------------------------------------
// AP-87: unusable answers
// -----------------------------------------------------------------------

// TestMCPElicitation_AnUnusableAnswerIsRefusedAndRecordsNothing is AP-87's
// e2e proof on an API-token session: an accept with gate "information",
// carrying io.gleipnir/replayed-from (on the answer or on the call), or
// action "cancel" is refused with text that is true on a token session, and
// records nothing — the full table of forms lives at the mcp handler seam
// (tools_approval_test.go); this proves one representative row per form end
// to end and that the SAME state stays valid across all four refusals. An
// accept with no responder at all is accepted here
// (TestMCPElicitation_MachineAPITokenAnswerIsMachineSelfConfirmation).
//
// Proves AP-87.
func TestMCPElicitation_AnUnusableAnswerIsRefusedAndRecordsNothing(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	q, qid, rid, _ := askApproval(t, session, restartNginxArgs())

	retry := func(t *testing.T, r *sdkmcp.ElicitResult) *sdkmcp.CallToolResult {
		t.Helper()
		return relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{
			Name:           "run_operation",
			Arguments:      restartNginxArgs(),
			RequestState:   q.RequestState,
			InputResponses: sdkmcp.InputResponseMap{qid: r},
		})
	}

	t.Run("information gate", func(t *testing.T) {
		before := auditLen(t, f)
		res := retry(t, &sdkmcp.ElicitResult{
			Action:  "accept",
			Content: map[string]any{"confirmed": true},
			Meta: sdkmcp.Meta{
				"io.gleipnir/responder": map[string]any{
					"username": elicitResponderUsername, "user_id": elicitResponderUserID, "gate": "information",
				},
			},
		})
		assertUnusableAnswerRefused(t, f, res, rid, before)
	})

	t.Run("replayed-from on the answer", func(t *testing.T) {
		before := auditLen(t, f)
		res := retry(t, &sdkmcp.ElicitResult{
			Action:  "accept",
			Content: map[string]any{"confirmed": true},
			Meta: sdkmcp.Meta{
				"io.gleipnir/responder": map[string]any{
					"username": elicitResponderUsername, "user_id": elicitResponderUserID, "gate": "permission",
				},
				metaKeyReplayedFrom: "01J9ZX5K8QH3M4N6P7R2S0T1VX",
			},
		})
		assertUnusableAnswerRefused(t, f, res, rid, before)
	})

	t.Run("replayed-from on the call", func(t *testing.T) {
		before := auditLen(t, f)
		res := relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{
			Name:           "run_operation",
			Arguments:      restartNginxArgs(),
			RequestState:   q.RequestState,
			InputResponses: sdkmcp.InputResponseMap{qid: acceptResponse()},
			Meta:           sdkmcp.Meta{metaKeyReplayedFrom: "01J9ZX5K8QH3M4N6P7R2S0T1VX"},
		})
		assertUnusableAnswerRefused(t, f, res, rid, before)
	})

	t.Run("cancel", func(t *testing.T) {
		before := auditLen(t, f)
		res := retry(t, &sdkmcp.ElicitResult{
			Action: "cancel",
			Meta: sdkmcp.Meta{
				"io.gleipnir/responder": map[string]any{
					"username": elicitResponderUsername, "user_id": elicitResponderUserID, "gate": "permission",
				},
			},
		})
		assertUnusableAnswerRefused(t, f, res, rid, before)
	})

	pending := fetchApproval(t, f, rid)
	if pending.State != "pending" || len(pending.Decisions) != 0 {
		t.Errorf("approval = %+v, want still pending with no decisions after four refusals", pending)
	}

	// The request is still answerable: NextStep's "it can still be answered"
	// was true after all five refusals.
	final := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, final, &out)
	if out.Decision == nil || out.Decision.State != "approved" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != elicitResponderUsername {
		t.Errorf("final decision = %+v, want approved/in-band/%s", out.Decision, elicitResponderUsername)
	}
	if out.JobID == "" {
		t.Error("final answer did not mint a Job")
	}
}

// -----------------------------------------------------------------------
// Emission refusals
// -----------------------------------------------------------------------

// TestMCPElicitation_LegacyHeaderWithModernMetaDoesNotAsk proves the
// emission predicate's condition 2 (clientCanBeAsked, elicit.go): the
// SESSION's negotiated protocol version — synthesized from the
// MCP-Protocol-Version header, never the per-request _meta — governs whether
// a question can be asked at all.
//
// The two rows that would actually carry a mismatched header/_meta pair
// never reach Relay's handler: go-sdk v1.8.0's transport itself refuses them
// with HTTP 400 / JSON-RPC code -32020 before any Relay code runs
// (streamable.go). Those 400 rows ARE the proof this issue asks for — proven
// here with a hand-built JSON-RPC request, since no MCP client library
// constructs a mismatched pair: they are what keeps a modern-looking `_meta`
// on a legacy session from ever reaching condition 2.
//
// Neither 200 row below isolates condition 2 on its own. Both carry a legacy
// header, so condition 2 already refuses by itself (a legacy session); both
// ALSO fail condition 3 independently — one because its `_meta` omits the
// protocolVersion key outright, the other because its `_meta`'s own
// protocolVersion is itself legacy. The one pairing that WOULD isolate
// condition 2 — a modern `_meta` on a legacy header — is exactly the pairing
// the SDK transport refuses before either condition ever runs. So the two
// 200 rows are defence in depth for a combination no e2e request can
// exercise directly, never proof that condition 2 alone did the refusing.
func TestMCPElicitation_LegacyHeaderWithModernMetaDoesNotAsk(t *testing.T) {
	elicitCapsBody := map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}
	clientInfo := map[string]any{"name": "gleipnir", "version": "0.0.1"}

	metaWith := func(pv string) map[string]any {
		m := map[string]any{
			"io.modelcontextprotocol/clientInfo":         clientInfo,
			"io.modelcontextprotocol/clientCapabilities": elicitCapsBody,
		}
		if pv != "" {
			m["io.modelcontextprotocol/protocolVersion"] = pv
		}
		return m
	}

	const (
		modern = "2026-07-28"
		legacy = "2025-11-25"
	)

	cases := []struct {
		name       string
		header     string
		meta       map[string]any
		wantStatus int
		isControl  bool
	}{
		{"modern _meta, legacy header", legacy, metaWith(modern), http.StatusBadRequest, false},
		{"modern _meta, absent header", "", metaWith(modern), http.StatusBadRequest, false},
		{"elicitation caps with no protocolVersion key, legacy header", legacy, metaWith(""), http.StatusOK, false},
		{"legacy protocolVersion in _meta matching a legacy header", legacy, metaWith(legacy), http.StatusOK, false},
		{"control: modern _meta, modern header", modern, metaWith(modern), http.StatusOK, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, token, _ := startElicitingRelay(t)

			status, contentType, body := postRawToolCall(t, f, token, tc.header, tc.meta, "run_operation", restartNginxArgs())
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, tc.wantStatus, body)
			}
			if !strings.HasPrefix(contentType, "application/json") {
				t.Errorf("Content-Type = %q, want application/json*", contentType)
			}
			if strings.Contains(contentType, "text/event-stream") {
				t.Errorf("Content-Type = %q, must never be text/event-stream — the only channel a server-initiated request could travel on", contentType)
			}
			// The control row is exactly the one case that DOES carry a real
			// question (proving the builder can elicit at all); every other
			// row must carry no trace of one.
			if !tc.isControl && strings.Contains(string(body), "elicitation/create") {
				t.Errorf("body contains the literal elicitation/create: %s", body)
			}

			var decoded struct {
				Result *struct {
					ResultType        string          `json:"resultType"`
					InputRequests     json.RawMessage `json:"inputRequests"`
					RequestState      string          `json:"requestState"`
					StructuredContent struct {
						PendingApproval *struct {
							Status    string `json:"status"`
							RequestID string `json:"request_id"`
							PlanHash  string `json:"plan_hash"`
						} `json:"pending_approval"`
					} `json:"structuredContent"`
				} `json:"result"`
				Error *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("decode: %v; body = %s", err, body)
			}

			if tc.wantStatus == http.StatusBadRequest {
				if decoded.Result != nil {
					t.Errorf("a 400 row carries a result member: %s", body)
				}
				if decoded.Error == nil {
					t.Fatalf("no error member: %s", body)
				}
				if decoded.Error.Code != -32020 {
					t.Errorf("error code = %d, want -32020 (go-sdk CodeHeaderMismatch)", decoded.Error.Code)
				}

				list := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals", f.Credential, nil)
				defer list.Body.Close()
				var got approvalListBody
				if err := json.NewDecoder(list.Body).Decode(&got); err != nil {
					t.Fatalf("decode approvals: %v", err)
				}
				if len(got.Approvals) != 0 {
					t.Errorf("approvals = %+v, want none — the handler never ran", got.Approvals)
				}
				records, err := f.Deps.audit.List(context.Background())
				if err != nil {
					t.Fatalf("audit List: %v", err)
				}
				for _, r := range records {
					if r.Kind == audit.KindApprovalRequested {
						t.Errorf("found a KindApprovalRequested record — the handler must never have run: %+v", r)
					}
				}
				return
			}

			if decoded.Result == nil {
				t.Fatalf("no result member: %s", body)
			}
			if tc.isControl {
				if decoded.Result.ResultType != "input_required" {
					t.Fatalf("control row resultType = %q, want input_required — the builder must be able to elicit for the other rows to mean anything", decoded.Result.ResultType)
				}
				return
			}
			if decoded.Result.ResultType == "input_required" {
				t.Fatalf("resultType = input_required, want pending_approval rendering: %s", body)
			}
			if len(decoded.Result.InputRequests) != 0 {
				t.Errorf("inputRequests present: %s", body)
			}
			if decoded.Result.RequestState != "" {
				t.Errorf("requestState present: %s", body)
			}
			pending := decoded.Result.StructuredContent.PendingApproval
			if pending == nil || pending.Status != "pending_approval" {
				t.Fatalf("structuredContent.pending_approval = %+v, want the handler to have run: %s", pending, body)
			}
			parkRecordFor(t, f, pending.RequestID)
		})
	}
}

// TestMCPElicitation_RedriveOfAPendingRequestAsksNobody is AP-62's e2e proof:
// a re-drive that bounces off a request already pending — on the SAME
// session, and on a FRESH one for the same token — asks nobody: the park is
// OBSERVED, not created, so it is never askable, regardless of the client's
// own capabilities.
func TestMCPElicitation_RedriveOfAPendingRequestAsksNobody(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	_, _, rid, ph := askApproval(t, session, restartNginxArgs())

	assertObservedPark := func(t *testing.T, res *sdkmcp.CallToolResult) {
		t.Helper()
		if res.NeedsInput() {
			t.Fatal("NeedsInput() = true, want false — an OBSERVED park is never askable")
		}
		if len(res.InputRequests) != 0 {
			t.Errorf("InputRequests = %+v, want empty — an OBSERVED park asks nobody", res.InputRequests)
		}
		if res.RequestState != "" {
			t.Errorf("RequestState = %q, want empty", res.RequestState)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.PendingApproval == nil {
			t.Fatalf("did not park: %+v", out)
		}
		if out.PendingApproval.RequestID != rid || out.PendingApproval.PlanHash != ph {
			t.Errorf("pending approval = %+v, want the SAME request %s/%s", out.PendingApproval, rid, ph)
		}
		if out.PendingApproval.Status != "pending_approval" {
			t.Errorf("Status = %q, want pending_approval", out.PendingApproval.Status)
		}
	}

	res2 := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	assertObservedPark(t, res2)

	freshSession := connectEliciting(t, f, token)
	res3 := relaytest.CallTool(t, freshSession, "run_operation", restartNginxArgs())
	assertObservedPark(t, res3)

	records, err := f.Deps.audit.ByApproval(context.Background(), rid)
	if err != nil {
		t.Fatalf("ByApproval(%s): %v", rid, err)
	}
	var requested, observed int
	for _, r := range records {
		switch r.Kind {
		case audit.KindApprovalRequested:
			requested++
		case audit.KindApprovalPendingObserved:
			observed++
		}
	}
	if requested != 1 {
		t.Errorf("KindApprovalRequested records = %d, want exactly 1", requested)
	}
	if observed != 2 {
		t.Errorf("KindApprovalPendingObserved records = %d, want exactly 2", observed)
	}
	if len(decisionRecordsFor(t, f, rid)) != 0 {
		t.Error("a decision record exists, want none")
	}
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
}

// TestMCPElicitation_ElicitedParkEmitsNoTaskEnvelope is AP-85's e2e proof: a
// client capable of BOTH elicitation and Tasks gets the question and no task
// envelope, while the control — a Tasks-capable, elicitation-incapable client
// on the SAME fixture — bounces off the now-pending request into the ordinary
// pending_approval result: resultType complete, no task_id or
// task_expires_at, no taskId.
func TestMCPElicitation_ElicitedParkEmitsNoTaskEnvelope(t *testing.T) {
	f, token, _ := startElicitingRelay(t)

	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "gleipnir", "version": "0.0.1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{
			"elicitation": map[string]any{"form": map[string]any{}},
			"extensions":  map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}},
		},
	}
	status, _, body := postRawToolCall(t, f, token, "2026-07-28", meta, "run_operation", restartNginxArgs())
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}

	var decoded struct {
		Result struct {
			ResultType        string          `json:"resultType"`
			InputRequests     json.RawMessage `json:"inputRequests"`
			RequestState      string          `json:"requestState"`
			StructuredContent json.RawMessage `json:"structuredContent"`
			Meta              map[string]any  `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v; body = %s", err, body)
	}
	if decoded.Result.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", decoded.Result.ResultType)
	}
	if len(decoded.Result.StructuredContent) != 0 {
		t.Errorf("structuredContent present, want none: %s", body)
	}
	if decoded.Result.RequestState == "" {
		t.Error("requestState is empty, want the sealed state")
	}
	rid, _ := decoded.Result.Meta["relay/request_id"].(string)
	if rid == "" {
		t.Fatal("_meta[relay/request_id] is empty")
	}
	var reqs map[string]json.RawMessage
	if err := json.Unmarshal(decoded.Result.InputRequests, &reqs); err != nil {
		t.Fatalf("decode inputRequests: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("inputRequests has %d entries, want exactly 1", len(reqs))
	}
	if _, ok := reqs[rid]; !ok {
		t.Errorf("inputRequests is not keyed by the request ID %q: %+v", rid, reqs)
	}
	for _, forbidden := range []string{`"taskId"`, `"pollIntervalMs"`, `"ttlMs"`} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("body contains %s, want no task envelope: %s", forbidden, body)
		}
	}
	if strings.Contains(string(body), `"resultType":"task"`) {
		t.Error("resultType is task, want input_required")
	}

	// CONTROL: on the SAME fixture, a Tasks-capable client with no elicitation
	// capability bounces off the now-pending request into pending_approval.
	taskOnly := rawToolCall(t, f, token, true, restartNginxArgs())
	taskJSON, err := json.Marshal(taskOnly["result"])
	if err != nil {
		t.Fatalf("re-marshal result: %v", err)
	}
	var plain struct {
		ResultType        string `json:"resultType"`
		StructuredContent struct {
			PendingApproval map[string]any `json:"pending_approval"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(taskJSON, &plain); err != nil {
		t.Fatalf("decode result: %v; result = %s", err, taskJSON)
	}
	if plain.ResultType != "complete" || plain.StructuredContent.PendingApproval["status"] != "pending_approval" {
		t.Errorf("control result = %s, want a complete pending_approval result", taskJSON)
	}
	for _, key := range []string{"task_id", "task_expires_at"} {
		if _, present := plain.StructuredContent.PendingApproval[key]; present {
			t.Errorf("control pending_approval carries %q; a park has no task handle", key)
		}
	}
	if strings.Contains(string(taskJSON), `"taskId"`) {
		t.Errorf("control result carries a taskId: %s", taskJSON)
	}
}

// -----------------------------------------------------------------------
// Retry behaviour
// -----------------------------------------------------------------------

// TestMCPElicitation_FleetChangedRetryReParks is AP-66's e2e proof: an
// approving retry whose fleet changed since the question re-parks with a
// FRESH, created, askable question — a new request id and plan hash, an
// updated summary — dispatching nothing, while the FIRST request stays
// approved against the plan the human actually saw (mirrors
// TestAnsweredRetry_FleetChangedReParksAndAsksAfresh at the plain-retry
// seam, minus the question).
func TestMCPElicitation_FleetChangedRetryReParks(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	q1, qid1, rid1, ph1 := askApproval(t, session, restartNginxArgs())
	if !strings.Contains(q1.InputRequests[qid1].(*sdkmcp.ElicitParams).Message, "on 1 node(s)") {
		t.Fatalf("first question message = %q, want it to name 1 node", q1.InputRequests[qid1].(*sdkmcp.ElicitParams).Message)
	}

	if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: "node-e2e-2"}); err != nil {
		t.Fatalf("upsert second Node: %v", err)
	}

	res := answerAsResponder(t, session, restartNginxArgs(), q1, qid1, "accept")
	if !res.NeedsInput() {
		t.Fatalf("retry after a fleet change: NeedsInput() = false, want true (a fresh, created, askable park): IsError=%v content=%+v", res.IsError, res.Content)
	}
	if len(res.InputRequests) != 1 {
		t.Fatalf("InputRequests has %d entries, want exactly 1: %+v", len(res.InputRequests), res.InputRequests)
	}
	rid2, _ := res.Meta["relay/request_id"].(string)
	ph2, _ := res.Meta["relay/plan_hash"].(string)
	if rid2 == "" || rid2 == rid1 {
		t.Errorf("new request id = %q, want a fresh, non-empty id (had %q)", rid2, rid1)
	}
	if ph2 == "" || ph2 == ph1 {
		t.Errorf("new plan hash = %q, want a fresh, non-empty hash (had %q)", ph2, ph1)
	}
	if _, ok := res.InputRequests[rid2]; !ok {
		t.Errorf("InputRequests is not keyed by the new request id %q: %+v", rid2, res.InputRequests)
	}
	newParams := res.InputRequests[rid2].(*sdkmcp.ElicitParams)
	if !strings.Contains(newParams.Message, "on 2 node(s)") || !strings.Contains(newParams.Message, "node-e2e-2") {
		t.Errorf("new question message = %q, want it to name 2 nodes including node-e2e-2", newParams.Message)
	}
	if got := fetchApproval(t, f, rid2); newParams.Message != got.Summary {
		t.Errorf("new question message = %q, want the approval's own summary %q", newParams.Message, got.Summary)
	}

	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records = %d, want 0", dispatchCount)
	}

	first := fetchApproval(t, f, rid1)
	if first.State != "approved" || len(first.Decisions) != 1 {
		t.Errorf("first request = %+v, want approved with exactly 1 decision", first)
	}
	second := fetchApproval(t, f, rid2)
	if second.State != "pending" || len(second.Decisions) != 0 {
		t.Errorf("second request = %+v, want pending with no decisions", second)
	}
	parkRecordFor(t, f, rid2)

	final := answerAsResponder(t, session, restartNginxArgs(), res, rid2, "accept")
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, final, &out)
	if out.JobID == "" {
		t.Fatal("final answer did not mint a Job")
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %+v, want 2 (node-e2e-1 and node-e2e-2)", out.Results)
	}
	if out.Decision == nil || out.Decision.RequestID != rid2 {
		t.Errorf("Decision = %+v, want RequestID %q", out.Decision, rid2)
	}
	jobList := allJobs(t, f)
	if len(jobList) != 1 || jobList[0].ApprovalID != rid2 {
		t.Fatalf("Jobs = %+v, want exactly 1 bound to %q, never %q", jobList, rid2, rid1)
	}
}

// TestMCPElicitation_DuplicateRetryReAttaches is AP-67's e2e proof: a
// duplicate approving retry against an already-bound Job re-attaches — no
// second Job, no second Task — recording the audited re-attach and mint no
// second decision. The plain re-drive race this comment used to carve out as
// #713 is now closed too (AP-77, approval_release_once_e2e_test.go): the
// capability layer's claim backstops this adapter-level path as well.
func TestMCPElicitation_DuplicateRetryReAttaches(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectEliciting(t, f, token)
	q, qid, rid, _ := askApproval(t, session, restartNginxArgs())

	first := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	var out1 mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, first, &out1)
	if out1.JobID == "" {
		t.Fatal("first retry did not mint a Job")
	}
	if out1.Decision == nil || out1.Decision.NextStep != nextStepRanAndRecorded {
		t.Errorf("first Decision.NextStep = %+v, want %q", out1.Decision, nextStepRanAndRecorded)
	}

	second := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if second.IsError {
		t.Fatalf("second retry: IsError = true, content=%+v", second.Content)
	}
	var out2 mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, second, &out2)
	if out2.JobID != out1.JobID {
		t.Errorf("second retry's job_id = %q, want the SAME job %q", out2.JobID, out1.JobID)
	}
	if len(out2.Results) != len(out1.Results) {
		t.Fatalf("second retry's results = %+v, want the same shape as the first %+v", out2.Results, out1.Results)
	}
	for i := range out1.Results {
		if out2.Results[i].NodeID != out1.Results[i].NodeID || out2.Results[i].Outcome != out1.Results[i].Outcome {
			t.Errorf("second retry's result[%d] = %+v, want %+v", i, out2.Results[i], out1.Results[i])
		}
	}
	if out2.Decision == nil {
		t.Fatalf("second Decision is nil")
	}
	if out2.Decision.State != "approved" || out2.Decision.Channel != "" || out2.Decision.OnBehalfOf != "" || out2.Decision.RequestID != rid {
		t.Errorf("second Decision = %+v, want approved/''/''/%s", out2.Decision, rid)
	}
	if out2.Decision.NextStep != nextStepReattachedNotRecorded {
		t.Errorf("second Decision.NextStep = %q, want %q", out2.Decision.NextStep, nextStepReattachedNotRecorded)
	}
	if out2.AnswerRefused != nil {
		t.Errorf("second AnswerRefused = %+v, want nil", out2.AnswerRefused)
	}

	if got := len(allJobs(t, f)); got != 1 {
		t.Errorf("Jobs = %d, want exactly 1", got)
	}
	taskPage, err := f.Deps.store.JobQueries().QueryTasks(context.Background(), jobs.TaskQuery{JobID: out1.JobID}, 0, "")
	if err != nil {
		t.Fatalf("QueryTasks: %v", err)
	}
	if len(taskPage.Tasks) != 1 {
		t.Errorf("Tasks = %+v, want exactly 1", taskPage.Tasks)
	}
	dispatchCount, readCount := auditCounts(t, f)
	if dispatchCount != 1 {
		t.Errorf("KindDispatch records = %d, want exactly 1", dispatchCount)
	}
	if readCount != 1 {
		t.Errorf("KindRead records = %d, want exactly 1 (the audited re-attach)", readCount)
	}
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	for _, r := range records {
		if r.Kind != audit.KindRead {
			continue
		}
		if r.JobID != out1.JobID || r.OperationName != "run_operation" {
			t.Errorf("read record = %+v, want JobID %q OperationName run_operation", r, out1.JobID)
		}
	}
	if got := decisionRecordsFor(t, f, rid); len(got) != 1 {
		t.Errorf("decision records = %+v, want exactly 1 — the duplicate recorded nothing", got)
	}
}

// -----------------------------------------------------------------------
// The rescue (ADR-0040 as amended)
// -----------------------------------------------------------------------

// TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest is the ADR-0040-as-
// amended rescue for a request parked over MCP and never asked in-band (the
// client advertises no elicitation): a human Account still decides it on the
// Control API — nothing is dispatched by the decision itself, which is
// attributed to the deciding human, verified and out-of-band (AP-17) — and the
// requester's re-drive over the SAME MCP session then runs. No other e2e test
// parks over MCP and decides on the Control API for a client that cannot be
// asked.
func TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest(t *testing.T) {
	f, token, _ := startElicitingRelayWith(t, gateAllMutates)
	// An ordinary client: it advertises no elicitation, so it is never asked.
	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))

	res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	if res.NeedsInput() {
		t.Fatal("NeedsInput() = true, want false — this client cannot be asked")
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("did not park: %+v", out)
	}
	rid := out.PendingApproval.RequestID
	ph := out.PendingApproval.PlanHash

	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs before the decision = %d, want 0", got)
	}
	if dispatchCount, _ := auditCounts(t, f); dispatchCount != 0 {
		t.Errorf("KindDispatch records before the decision = %d, want 0 — a park dispatches nothing", dispatchCount)
	}

	dana := mintAccount(t, f, "dana", accounts.KindHuman, accounts.RoleOperator)
	decideResp := controlAPIRequest(t, f.ClientFor(dana), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+rid+"/decision", dana,
		map[string]any{"approve": true, "plan_hash": ph})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(decideResp.Body)
		t.Fatalf("decision status = %d, want 200; body = %s", decideResp.StatusCode, body)
	}

	if got := fetchApproval(t, f, rid); got.State != "approved" {
		t.Errorf("approval state = %q, want approved", got.State)
	}
	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+rid, f.Credential, nil)
	defer getResp.Body.Close()
	var view elicitDecisionView
	if err := json.NewDecoder(getResp.Body).Decode(&view); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if len(view.Decisions) != 1 {
		t.Fatalf("decisions = %+v, want exactly 1", view.Decisions)
	}
	cd := view.Decisions[0]
	if cd.Account != "dana" || !cd.Approve || cd.Channel != "out-of-band" || !cd.Human {
		t.Errorf("Control API decision = %+v, want dana's human out-of-band approval", cd)
	}

	decisions := decisionRecordsFor(t, f, rid)
	if len(decisions) != 1 {
		t.Fatalf("decision records = %+v, want exactly 1", decisions)
	}
	d := decisions[0]
	if d.DecisionChannel != "out-of-band" {
		t.Errorf("DecisionChannel = %q, want out-of-band", d.DecisionChannel)
	}
	if d.Attribution.Verified.AccountName != "dana" {
		t.Errorf("Attribution.Verified.AccountName = %q, want dana", d.Attribution.Verified.AccountName)
	}
	if d.Attribution.Asserted.OnBehalfOf != "" {
		t.Errorf("Attribution.Asserted.OnBehalfOf = %q, want empty — out of band, dana IS the approver, verified", d.Attribution.Asserted.OnBehalfOf)
	}

	assertRedriveRuns(t, f, session, rid)
}

// TestMCPElicitation_StrandedAnswerIsRescuedOnTheControlAPI is
// threat-model R27's rescue: a request that emitted a question, whose answer
// is then refused for a state sealed under another key — simulating a
// restart landing on a replica with a different seal key — stays pending and
// STRANDED (a further plain re-drive still asks nobody, since it is now an
// OBSERVED park), and is rescued on the Control API, which is the rescue's only
// decision surface (mirrors TestAnsweredRetry_RefusedStateStaysDecidableByTheRescue's plain-
// retry proof, minus the question).
func TestMCPElicitation_StrandedAnswerIsRescuedOnTheControlAPI(t *testing.T) {
	f, token, accountID := startElicitingRelayWith(t, gateAllMutates)
	session := connectEliciting(t, f, token)
	q, qid, rid, ph := askApproval(t, session, restartNginxArgs())

	foreign := sealUnderAnotherKey(t, accountID, rid, ph, restartNginxArgs())
	before := auditLen(t, f)
	qf := *q
	qf.RequestState = foreign
	res := answerAsResponder(t, session, restartNginxArgs(), &qf, qid, "accept")
	assertStateRefusedNothingRecorded(t, f, res, requeststate.ErrTampered.Error(), before, rid)

	// R27 stranding: a plain re-drive renders pending_approval with no
	// question — it is now an OBSERVED park.
	strandedRes := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	if strandedRes.NeedsInput() {
		t.Fatal("NeedsInput() = true, want false — the park is now OBSERVED, not created")
	}
	var strandedOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, strandedRes, &strandedOut)
	if strandedOut.PendingApproval == nil || strandedOut.PendingApproval.RequestID != rid {
		t.Fatalf("stranded re-drive = %+v, want it still pending on %q", strandedOut, rid)
	}

	// assertRescuerDecided checks the decision record AND, via
	// elicitDecisionView (as TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest
	// does), that the Control API's own view of the decision reports the
	// rescuer as Human — the rescue is only credible if a person decided
	// it, not merely if the recorded name matches rescuer.
	assertRescuerDecided := func(t *testing.T, rescuer string) {
		t.Helper()
		view := decisionRecordsFor(t, f, rid)
		if len(view) != 1 || view[0].Attribution.Verified.AccountName != rescuer || view[0].DecisionChannel != "out-of-band" {
			t.Errorf("decision records = %+v, want %s's out-of-band decision", view, rescuer)
		}
		getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+rid, f.Credential, nil)
		defer getResp.Body.Close()
		var dview elicitDecisionView
		if err := json.NewDecoder(getResp.Body).Decode(&dview); err != nil {
			t.Fatalf("decode approval: %v", err)
		}
		if len(dview.Decisions) != 1 {
			t.Fatalf("decisions = %+v, want exactly 1", dview.Decisions)
		}
		cd := dview.Decisions[0]
		if cd.Account != rescuer || !cd.Approve || cd.Channel != "out-of-band" || !cd.Human {
			t.Errorf("Control API decision = %+v, want %s's human out-of-band approval", cd, rescuer)
		}
	}

	bianca := mintAccount(t, f, "bianca", accounts.KindHuman, accounts.RoleOperator)
	decideResp := controlAPIRequest(t, f.ClientFor(bianca), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+rid+"/decision", bianca,
		map[string]any{"approve": true, "plan_hash": ph})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(decideResp.Body)
		t.Fatalf("decision status = %d, want 200; body = %s", decideResp.StatusCode, body)
	}
	var decided approvalBody
	if err := json.NewDecoder(decideResp.Body).Decode(&decided); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decided.State != "approved" {
		t.Errorf("state = %q, want approved", decided.State)
	}
	assertRescuerDecided(t, "bianca")

	assertRedriveRuns(t, f, session, rid)
}
