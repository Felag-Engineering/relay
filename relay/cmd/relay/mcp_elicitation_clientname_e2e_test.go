// Package main: mcp_elicitation_clientname_e2e_test.go is #743's e2e proof —
// through the REAL composition root — of AP-78 (Relay asks the approval
// question only where the declared client name is recognised for the
// calling Principal's own session) and AP-79 (a Claude Code accept/decline
// with no responder assertion, on an OAuth session of a human Account, is
// that human's own verified in-band decision). AP-78 and AP-79 as rewritten
// 2026-09-28 (docs/specs/approval.md, PR #767): there is no unnamed form —
// "claude-code" earns nothing beyond gleipnir's own path unless the calling
// session itself authenticated by OAuth with a human Account.
//
// Kept out of mcp_elicitation_e2e_test.go and mcp_elicitation_refusals_e2e_test.go,
// both of which #752 (issue #713, AP-77) is concurrently editing.
//
// Reuses this package's existing fixtures and helpers rather than building
// new ones: startElicitingRelay/startElicitingRelayWith, startOAuthElicitingRelay
// (oauth_idp_e2e_test.go), connectEliciting, askApproval, answerAsResponder,
// decisionRecordsFor, fetchApproval, allJobs, postRawToolCall, restartNginxArgs,
// sshdRestartArgs, askQuestionE2E.
package main

import (
	"encoding/json"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// connectClaudeCode opens an MRTR-capable session declaring the recognised
// client name "claude-code" (AP-78), with Claude Code's own observed
// capability shape (roots listChanged, elicitation advertising both form and
// url — spec Known limits) and the SDK's automatic answer-fulfilment
// middleware disabled, so the test drives the retry itself exactly as
// connectEliciting does for "gleipnir". credential may be an API Token or an
// OAuth JWT — whichever the calling test needs.
func connectClaudeCode(t *testing.T, f *relayFixture, credential string) *sdkmcp.ClientSession {
	t.Helper()
	opts := relaytest.ElicitingClientOptions()
	opts.Capabilities.Elicitation.URL = &sdkmcp.URLElicitationCapabilities{}
	return relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(credential), relaytest.ConnectOptions{
		Client:     opts,
		ClientName: relaytest.ClaudeCodeClientName,
	})
}

// answerAsClaudeCode retries the parked call with action and NO responder
// assertion at all — Claude Code's own observed retry shape. Whether this
// counts as a decision at all depends on the RETRY's own session
// (claudeCodeAnswerCounts, tools_approval.go) — never on anything in this
// ElicitResult.
func answerAsClaudeCode(t *testing.T, session *sdkmcp.ClientSession, args map[string]any, q *sdkmcp.CallToolResult, questionID, action string) *sdkmcp.CallToolResult {
	t.Helper()
	return relaytest.RetryTool(t, session, "run_operation", args, q.RequestState,
		sdkmcp.InputResponseMap{questionID: &sdkmcp.ElicitResult{Action: action}})
}

// assertNotAskedPendingApproval asserts res is an ORDINARY pending_approval
// result — no question, no answered-retry block of any kind — the shape
// every call AP-78 does not ask gets, whatever produced the call (a fresh
// ask or a retry treated as an ordinary call because clientCanBeAsked is
// false for it).
func assertNotAskedPendingApproval(t *testing.T, res *sdkmcp.CallToolResult) {
	t.Helper()
	if res.IsError {
		t.Fatalf("IsError = true, content=%+v", res.Content)
	}
	if res.NeedsInput() {
		t.Fatalf("NeedsInput() = true, want an ordinary pending_approval result: %+v", res)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("PendingApproval is nil, want a real park: %+v", out)
	}
	if out.PendingApproval.RequestID == "" || out.PendingApproval.PlanHash == "" {
		t.Errorf("PendingApproval = %+v, want a real request_id and plan_hash", out.PendingApproval)
	}
	if out.Decision != nil {
		t.Errorf("Decision = %+v, want nil (an ordinary call, not an answered retry)", out.Decision)
	}
	if out.AnswerRefused != nil {
		t.Errorf("AnswerRefused = %+v, want nil (an ordinary call, not a refused answer)", out.AnswerRefused)
	}
	if out.JobID != "" {
		t.Errorf("JobID = %q, want empty", out.JobID)
	}
}

// onBehalfOfRoundTripper injects X-Relay-On-Behalf-Of on every request, so a
// test can prove a stray asserted-lane header is still cleared on an AP-79
// verified decision.
type onBehalfOfRoundTripper struct {
	base  http.RoundTripper
	value string
}

func (rt onBehalfOfRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(controlplane.HeaderOnBehalfOf, rt.value)
	return rt.base.RoundTrip(req)
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

// TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsNotAsked is AP-78's
// e2e proof that the declared name alone is not enough: a HUMAN Account on
// an API Token session, declaring "claude-code" with Claude Code's own
// observed capability shape, still gets today's pending_approval — AP-78
// asks claude-code only on an OAuth session of a human Account.
func TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsNotAsked(t *testing.T) {
	f, _, _ := startElicitingRelay(t)
	token := mintAccount(t, f, "hana-api", accounts.KindHuman, accounts.RoleAdmin)
	session := connectClaudeCode(t, f, token)

	res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	assertNotAskedPendingApproval(t, res)
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
	}
}

// TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted
// is AP-78/AP-79's machine-Account proof: an OAuth session authenticates the
// Account, but a machine Account's claude-code call is still not asked (a),
// and — proving the session really is askable for gleipnir, so (a) is about
// the declared name and Account kind rather than some other fixture defect —
// a gleipnir ask on the SAME token, retried by a claude-code session, is
// treated as an ordinary call rather than an accepted answer (b).
func TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted(t *testing.T) {
	f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
	createAccount(t, f, "bot", accounts.KindMachine, accounts.RoleAdmin)
	token := idp.token(t, "bot")

	t.Run("claude-code is not asked", func(t *testing.T) {
		session := connectClaudeCode(t, f, token)
		res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
		assertNotAskedPendingApproval(t, res)
	})

	t.Run("a claude-code retry of a real gleipnir ask is an ordinary call", func(t *testing.T) {
		gleipnirSession := connectEliciting(t, f, token)
		q, qid, requestID, _ := askApproval(t, gleipnirSession, sshdRestartArgs())

		ccSession := connectClaudeCode(t, f, token)
		retry := answerAsClaudeCode(t, ccSession, sshdRestartArgs(), q, qid, "accept")
		assertNotAskedPendingApproval(t, retry)

		if got := len(decisionRecordsFor(t, f, requestID)); got != 0 {
			t.Errorf("decision records = %d, want 0", got)
		}
		if got := fetchApproval(t, f, requestID); got.State != "pending" {
			t.Errorf("approval state = %q, want pending", got.State)
		}
		if got := len(allJobs(t, f)); got != 0 {
			t.Errorf("Jobs = %d, want 0", got)
		}
	})
}

// TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision
// is AP-79's headline e2e proof: a claude-code accept/decline with no
// responder assertion, on an OAuth session of a human Account, is recorded
// as that human's own verified in-band decision — approved dispatches, a
// denial is terminal, and nothing lands in the asserted lane either way,
// even when the caller sends a stray X-Relay-On-Behalf-Of header.
func TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision(t *testing.T) {
	t.Run("accept dispatches, verified as the human, nothing asserted", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
		session := connectClaudeCode(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
		}

		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.JobID == "" {
			t.Fatal("job_id is empty, want a real Job — a verified decision dispatches exactly as a named answer would")
		}
		if out.Decision == nil {
			t.Fatalf("Decision is nil: %+v", out)
		}
		if out.Decision.State != "approved" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != "" {
			t.Errorf("Decision = %+v, want approved/in-band/empty on_behalf_of", out.Decision)
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
			t.Errorf("Verified.AccountID = %q, want %q — the human's own verified Account", d.Attribution.Verified.AccountID, accountID)
		}
		if d.Attribution.Verified.TokenID != "" {
			t.Errorf("Verified.TokenID = %q, want empty — this session is OAuth, not an API Token", d.Attribution.Verified.TokenID)
		}
		if d.Attribution.Asserted.OnBehalfOf != "" {
			t.Errorf("Asserted.OnBehalfOf = %q, want empty — nothing is written to the asserted lane", d.Attribution.Asserted.OnBehalfOf)
		}

		if got := fetchApproval(t, f, requestID); got.State != "approved" {
			t.Errorf("approval state = %q, want approved", got.State)
		}
	})

	t.Run("decline is a terminal denial, nothing asserted", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
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
		if out.Decision.State != "denied" || out.Decision.Channel != "in-band" || out.Decision.OnBehalfOf != "" {
			t.Errorf("Decision = %+v, want denied/in-band/empty on_behalf_of", out.Decision)
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
		if d.Attribution.Asserted.OnBehalfOf != "" {
			t.Errorf("Asserted.OnBehalfOf = %q, want empty", d.Attribution.Asserted.OnBehalfOf)
		}

		if got := len(allJobs(t, f)); got != 0 {
			t.Errorf("Jobs = %d, want 0", got)
		}
		if got := fetchApproval(t, f, requestID); got.State != "denied" {
			t.Errorf("approval state = %q, want denied", got.State)
		}
	})

	t.Run("a stray X-Relay-On-Behalf-Of header still records nothing asserted", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")

		headerClient := f.ClientFor(token)
		headerClient.Transport = onBehalfOfRoundTripper{base: headerClient.Transport, value: "mallory"}
		opts := relaytest.ElicitingClientOptions()
		opts.Capabilities.Elicitation.URL = &sdkmcp.URLElicitationCapabilities{}
		session := relaytest.ConnectWithOptions(t, f.ControlBase, headerClient, relaytest.ConnectOptions{
			Client:     opts,
			ClientName: relaytest.ClaudeCodeClientName,
		})

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
		}

		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.Decision == nil || out.Decision.OnBehalfOf != "" {
			t.Errorf("Decision = %+v, want empty on_behalf_of despite the stray header", out.Decision)
		}

		decisions := decisionRecordsFor(t, f, requestID)
		if len(decisions) != 1 {
			t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
		}
		if decisions[0].Attribution.Asserted.OnBehalfOf != "" {
			t.Errorf("Asserted.OnBehalfOf = %q, want empty — the header must be cleared, not recorded", decisions[0].Attribution.Asserted.OnBehalfOf)
		}
		if decisions[0].Attribution.Verified.AccountID != accountID {
			t.Errorf("Verified.AccountID = %q, want %q", decisions[0].Attribution.Verified.AccountID, accountID)
		}
	})
}

// TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals is AP-79's
// "same refusals" claim, proven end to end wherever it is reachable through
// the real composition root.
//
// Requester exclusion is NOT reachable end to end and is not attempted here:
// AP-61 never emits a question where the rule excludes the requester (the
// gate is checked before Askable is ever set), and the seal binds an answer
// to the Account that was asked — so no Claude Code retry can ever arrive at
// a request its own Account was excluded from answering. That half of "the
// same refusals" is proven at the capability seam
// (TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified, subtest
// "requester_allowed false") and, for the adapter's classification of it,
// at the MCP acceptance seam (TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals).
func TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals(t *testing.T) {
	t.Run("duplicate decider: a second answer from the same human records nothing new", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateCountTwoInBandAskable)
		createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
		session := connectClaudeCode(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())

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

		second := answerAsClaudeCode(t, session, restartNginxArgs(), q, qid, "accept")
		var secondOut mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, second, &secondOut)
		assertDuplicateDeciderNotRecorded(t, "second (same human) answer", secondOut)

		if got := len(decisionRecordsFor(t, f, requestID)); got != 1 {
			t.Errorf("decision records = %d, want exactly 1 (the duplicate recorded nothing new)", got)
		}
		if got := len(allJobs(t, f)); got != 0 {
			t.Errorf("Jobs = %d, want 0 — count:2 never reached with only one distinct approver", got)
		}
	})

	t.Run("an out-of-band rule is not asked (AP-13/AP-69)", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesOutOfBandAskable)
		createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
		session := connectClaudeCode(t, f, token)

		res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
		assertNotAskedPendingApproval(t, res)
	})
}

// TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing is
// AP-78/AP-79's anti-escalation proof: a gleipnir ask (a real sealed state,
// on a machine Account's plain API Token session), retried by a claude-code
// session on the SAME non-OAuth token, is treated as an ordinary call —
// exactly what 77a497d's first-version "unnamed confirmation" would have
// accepted, and AP-79 as rewritten does not.
func TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing(t *testing.T) {
	f, token, _ := startElicitingRelay(t)
	gleipnirSession := connectEliciting(t, f, token)
	q, qid, requestID, _ := askApproval(t, gleipnirSession, restartNginxArgs())

	ccSession := connectClaudeCode(t, f, token)
	retry := answerAsClaudeCode(t, ccSession, restartNginxArgs(), q, qid, "accept")
	assertNotAskedPendingApproval(t, retry)

	if got := len(decisionRecordsFor(t, f, requestID)); got != 0 {
		t.Errorf("decision records = %d, want 0", got)
	}
	if got := fetchApproval(t, f, requestID); got.State != "pending" {
		t.Errorf("approval state = %q, want pending", got.State)
	}
	if got := len(allJobs(t, f)); got != 0 {
		t.Errorf("Jobs = %d, want 0", got)
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

// TestMCPElicitation_ClaudeCodeAnswerWithAResponderTakesTheNamedPath is
// AP-79's ordering rule at the e2e seam: a claude-code client that DOES
// carry a real io.gleipnir/responder assertion is recorded under that name,
// never the calling human's own identity — a present responder always takes
// the named path first, whatever the declared client name or session. Run
// on an OAuth human session, since claude-code on an API Token session is no
// longer asked at all.
func TestMCPElicitation_ClaudeCodeAnswerWithAResponderTakesTheNamedPath(t *testing.T) {
	f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
	accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
	token := idp.token(t, "hana")
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
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
	}
	if decisions[0].Attribution.Verified.AccountID != accountID {
		t.Errorf("Verified.AccountID = %q, want %q — the human's own verified Account, regardless of the named responder",
			decisions[0].Attribution.Verified.AccountID, accountID)
	}
	if decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
		t.Errorf("decision records = %+v, want exactly one asserting %q", decisions, elicitResponderUsername)
	}
}
