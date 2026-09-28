// Package main: mcp_elicitation_clientname_e2e_test.go is #743's e2e proof —
// through the REAL composition root — of AP-78 (Relay asks the approval
// question only when the caller's declared client name is recognised) and
// AP-79 (a Claude Code accept/decline with no responder assertion is
// recorded as an unnamed confirmation). Kept out of mcp_elicitation_e2e_test.go
// and mcp_elicitation_refusals_e2e_test.go, both of which #752 (issue #713,
// AP-77) is concurrently editing.
//
// Reuses this package's existing fixtures and helpers rather than building
// new ones: startElicitingRelay/startElicitingRelayWith, connectEliciting,
// askApproval, answerAsResponder, decisionRecordsFor, fetchApproval, allJobs,
// postRawToolCall, restartNginxArgs, askQuestionE2E.
package main

import (
	"encoding/json"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// unnamedClaudeCodeApprover mirrors tools_approval.go's own unexported
// unnamedConfirmationApprover — duplicated here for the same reason this
// package's other files duplicate elicit.go's unexported constants (see
// mcp_elicitation_e2e_test.go's mcpMetaKeyRequestID pattern, elicit_test.go):
// package main cannot reach an unexported identifier in package mcp, and a
// drift between the two literals would fail every test below that expects an
// unnamed confirmation.
const unnamedClaudeCodeApprover = "(unnamed: claude-code confirmation)"

// connectClaudeCode opens an MRTR-capable session declaring the recognised
// client name "claude-code" (AP-78), with Claude Code's own observed
// capability shape (roots listChanged, elicitation advertising both form and
// url — spec Known limits) and the SDK's automatic answer-fulfilment
// middleware disabled, so the test drives the retry itself exactly as
// connectEliciting does for "gleipnir".
func connectClaudeCode(t *testing.T, f *relayFixture, token string) *sdkmcp.ClientSession {
	t.Helper()
	opts := relaytest.ElicitingClientOptions()
	opts.Capabilities.Elicitation.URL = &sdkmcp.URLElicitationCapabilities{}
	return relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(token), relaytest.ConnectOptions{
		Client:     opts,
		ClientName: relaytest.ClaudeCodeClientName,
	})
}

// answerAsClaudeCode retries the parked call with action and NO responder
// assertion at all — Claude Code's own observed retry shape. The ONLY thing
// that makes this recorded rather than refused as a machine self-decision is
// the retry's own declared client name (AP-79), read by acceptElicitedAnswer
// from the retried call's `_meta` — never anything on this ElicitResult.
func answerAsClaudeCode(t *testing.T, session *sdkmcp.ClientSession, args map[string]any, q *sdkmcp.CallToolResult, questionID, action string) *sdkmcp.CallToolResult {
	t.Helper()
	return relaytest.RetryTool(t, session, "run_operation", args, q.RequestState,
		sdkmcp.InputResponseMap{questionID: &sdkmcp.ElicitResult{Action: action}})
}

// TestMCPElicitation_UnrecognisedMRTRClientGetsPendingApproval is AP-78's e2e
// proof: through the real composition root, an MRTR-capable,
// elicitation-advertising client declaring a name Relay does not recognise
// gets today's pending_approval — carrying a real request_id and plan_hash,
// no inputRequests, an empty requestState — and dispatches nothing. The armed
// control, a FRESH fixture whose client declares "gleipnir", really does get
// asked.
func TestMCPElicitation_UnrecognisedMRTRClientGetsPendingApproval(t *testing.T) {
	f, token, _ := startElicitingRelay(t)

	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "some-other-client", "version": "0.0.1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{
			"elicitation": map[string]any{"form": map[string]any{}},
		},
	}
	status, _, body := postRawToolCall(t, f, token, "2026-07-28", meta, "run_operation", restartNginxArgs())
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
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
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v; body = %s", err, body)
	}
	if decoded.Result == nil {
		t.Fatalf("no result member: %s", body)
	}
	if decoded.Result.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval (unrecognised client name): %s", body)
	}
	if len(decoded.Result.InputRequests) != 0 {
		t.Errorf("inputRequests present for an unrecognised client name: %s", body)
	}
	if decoded.Result.RequestState != "" {
		t.Errorf("requestState = %q, want empty", decoded.Result.RequestState)
	}
	pa := decoded.Result.StructuredContent.PendingApproval
	if pa == nil || pa.Status != "pending_approval" || pa.RequestID == "" || pa.PlanHash == "" {
		t.Fatalf("pending_approval = %+v, want a real request_id and plan_hash", pa)
	}
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}

	// Armed control: a FRESH fixture, so a distinct Plan cannot dedup onto the
	// SAME request the unrecognised call above already parked
	// (capability/approval.go's ByPlanHash) — the same fixture shape, only
	// the declared client name changed to a recognised one.
	controlF, controlToken, _ := startElicitingRelay(t)
	controlSession := connectEliciting(t, controlF, controlToken)
	askQuestionE2E(t, controlSession)
}

// TestMCPElicitation_ClaudeCodeAcceptIsRecordedUnnamed is AP-79's e2e proof:
// a Claude Code accept with no responder assertion is recorded as an unnamed
// confirmation, dispatches the Job exactly as a named answer would, and the
// unnamed value lands in both the tool response and the durable audit trail.
//
// This ALSO covers the "unnamed self-confirmation is admitted exactly like a
// named one" claim: startElicitingRelay's rule (gateAllMutatesInBandAskable)
// sets requester_allowed: true, and the requesting Account here (the
// machine token connectClaudeCode dials with) is the SAME Account that
// confirms its own request below — no separate fixture is needed for that
// row.
func TestMCPElicitation_ClaudeCodeAcceptIsRecordedUnnamed(t *testing.T) {
	f, token, accountID := startElicitingRelay(t)
	session := connectClaudeCode(t, f, token)

	q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())

	res := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID == "" {
		t.Fatal("job_id is empty, want a real Job — an unnamed confirmation dispatches exactly as a named answer would")
	}
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.State != "approved" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != unnamedClaudeCodeApprover {
		t.Errorf("Decision = %+v, want approved/in-band/%s", out.Decision, unnamedClaudeCodeApprover)
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
	if d.Attribution.Verified.AccountID != accountID {
		t.Errorf("Verified.AccountID = %q, want %q — the VERIFIED lane is the calling machine Account, unnamed or not", d.Attribution.Verified.AccountID, accountID)
	}
	if d.Attribution.Asserted.OnBehalfOf != unnamedClaudeCodeApprover {
		t.Errorf("Asserted.OnBehalfOf = %q, want %q", d.Attribution.Asserted.OnBehalfOf, unnamedClaudeCodeApprover)
	}

	if got := fetchApproval(t, f, requestID); got.State != "approved" {
		t.Errorf("approval state = %q, want approved", got.State)
	}
}

// TestMCPElicitation_ClaudeCodeDeclineIsADenial is AP-79's decline half:
// terminal, dispatches nothing, and the denial's asserted lane is the SAME
// unnamed-confirmation value an accept records.
func TestMCPElicitation_ClaudeCodeDeclineIsADenial(t *testing.T) {
	f, token, accountID := startElicitingRelay(t)
	session := connectClaudeCode(t, f, token)

	q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())

	res := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "decline")
	if res.IsError {
		t.Fatalf("decline: IsError = true, content=%+v", res.Content)
	}
	if res.NeedsInput() {
		t.Fatalf("decline: NeedsInput() = true, want false")
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.State != "denied" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != unnamedClaudeCodeApprover {
		t.Errorf("Decision = %+v, want denied/in-band/%s", out.Decision, unnamedClaudeCodeApprover)
	}
	if out.JobID != "" {
		t.Errorf("JobID = %q, want empty", out.JobID)
	}

	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
	}
	d := decisions[0]
	if d.ApprovalAnswer != audit.ApprovalAnswerDenied {
		t.Errorf("ApprovalAnswer = %q, want %q", d.ApprovalAnswer, audit.ApprovalAnswerDenied)
	}
	if d.Attribution.Verified.AccountID != accountID {
		t.Errorf("Verified.AccountID = %q, want %q", d.Attribution.Verified.AccountID, accountID)
	}
	if d.Attribution.Asserted.OnBehalfOf != unnamedClaudeCodeApprover {
		t.Errorf("Asserted.OnBehalfOf = %q, want %q", d.Attribution.Asserted.OnBehalfOf, unnamedClaudeCodeApprover)
	}

	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
	if got := fetchApproval(t, f, requestID); got.State != "denied" {
		t.Errorf("approval state = %q, want denied", got.State)
	}
}

// assertDuplicateDeciderNotRecorded asserts out is the classifyElicitedDecision
// shape a still-pending request's SECOND decision from the SAME Account
// gets (approval.ErrDuplicateDecider, tools_approval.go's classifyElicitedDecision):
// re-parked as an OBSERVED, non-askable pending_approval (AP-62) with a
// Decision block whose Channel and OnBehalfOf are BLANK — nothing was
// recorded — never an AnswerRefused block, because the request itself is
// still open to a DIFFERENT Account.
func assertDuplicateDeciderNotRecorded(t *testing.T, label string, out mcp.RunOrPlanOutput) {
	t.Helper()
	if out.AnswerRefused != nil {
		t.Errorf("%s: AnswerRefused = %+v, want nil (a duplicate decider on a still-pending request is not a refusal)", label, out.AnswerRefused)
	}
	if out.PendingApproval == nil {
		t.Fatalf("%s: PendingApproval is nil, want the still-pending, OBSERVED park", label)
	}
	if out.Decision == nil {
		t.Fatalf("%s: Decision is nil, want a decision block reporting nothing new was recorded", label)
	}
	if out.Decision.Channel != "" || out.Decision.OnBehalfOf != "" {
		t.Errorf("%s: Decision = %+v, want empty Channel/OnBehalfOf — this Account's answer was NOT recorded", label, out.Decision)
	}
	if out.JobID != "" {
		t.Errorf("%s: JobID = %q, want empty", label, out.JobID)
	}
}

// TestMCPElicitation_SpoofedClaudeCodeCountsNoMoreThanANamedAnswer is AP-79's
// anti-escalation proof: an unnamed confirmation is bound to the deciding
// ACCOUNT exactly as a named answer is — a second answer from the SAME
// Account, whether unnamed again or a named "gleipnir" client asserting a
// DIFFERENT responder, records nothing new (approval.ErrDuplicateDecider),
// and no Job is ever dispatched beyond the first (which never completes the
// count:2 quorum alone).
func TestMCPElicitation_SpoofedClaudeCodeCountsNoMoreThanANamedAnswer(t *testing.T) {
	f, token, _ := startElicitingRelayWith(t, gateCountTwoInBandAskable)
	session := connectClaudeCode(t, f, token)

	q, qid, _, _ := askApproval(t, session, restartNginxArgs())

	first := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
	if first.NeedsInput() {
		t.Fatalf("first answer: NeedsInput() = true, want false (a partial quorum's park is OBSERVED, not askable)")
	}
	if first.IsError {
		t.Fatalf("first answer: IsError = true, content=%+v", first.Content)
	}
	var firstOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, first, &firstOut)
	if firstOut.Decision == nil || firstOut.Decision.Progress != "1 of 2" {
		t.Fatalf("first answer decision = %+v, want progress 1 of 2", firstOut.Decision)
	}
	if firstOut.JobID != "" {
		t.Errorf("JobID after the first answer = %q, want empty (still pending)", firstOut.JobID)
	}

	// A second answer from the SAME Account — unnamed claude-code again —
	// records nothing new: this Account already decided.
	second := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
	var secondOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, second, &secondOut)
	assertDuplicateDeciderNotRecorded(t, "second (unnamed) answer", secondOut)

	// A third answer, same Account, this time a NAMED "gleipnir" client
	// asserting a DIFFERENT responder ("bob") — the SAME requestState the
	// first claude-code question sealed, retried over a plain gleipnir
	// session. This is the same result a named answer gets: nothing new
	// recorded, because it is the ACCOUNT that already decided, whatever form
	// or name its answer takes.
	gleipnirSession := connectEliciting(t, f, token)
	bobAnswer := &sdkmcp.ElicitResult{
		Action: "accept",
		Meta:   sdkmcp.Meta{"io.gleipnir/responder": map[string]any{"gate": "permission", "username": "bob"}},
	}
	third := relaytest.RetryTool(t, gleipnirSession, "run_operation", restartNginxArgs(), q.RequestState,
		sdkmcp.InputResponseMap{qid: bobAnswer})
	var thirdOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, third, &thirdOut)
	assertDuplicateDeciderNotRecorded(t, "third (named, different responder) answer", thirdOut)

	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0 — no answer beyond the first ever moved the quorum", got)
	}
}

// TestMCPElicitation_ClaudeCodeAnswerWithAResponderTakesTheNamedPath is
// AP-79's ordering rule at the e2e seam: a claude-code client that DOES
// carry a real io.gleipnir/responder assertion is recorded under that name,
// never the unnamed-confirmation value — a present responder always takes
// the named path first, whatever the declared client name.
func TestMCPElicitation_ClaudeCodeAnswerWithAResponderTakesTheNamedPath(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	session := connectClaudeCode(t, f, token)

	q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
	res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.Decision == nil || out.Decision.OnBehalfOf != elicitResponderUsername {
		t.Errorf("Decision = %+v, want OnBehalfOf %q — a present responder always takes the named path, even from claude-code",
			out.Decision, elicitResponderUsername)
	}

	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 || decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
		t.Errorf("decision records = %+v, want exactly one asserting %q", decisions, elicitResponderUsername)
	}
}
