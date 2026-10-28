// Package main: mcp_elicitation_clientname_e2e_test.go is #743's e2e proof —
// through the REAL composition root — of AP-86 (Relay asks the approval
// question of any client that advertises elicitation, on any session, and the
// declared client name decides nothing), AP-87 (an answer on an API-token
// session counts as that session's Account, and any other session needs a
// responder) and AP-79 (on a signed-in human session — an OAuth session of a
// human Account — an answered retry is that human's own verified in-band
// decision, whatever the declared client name). The session decides, never the
// client's declared name (owner decision 2026-09-29): a claude-code retry and
// a gleipnir retry on the same qualifying session are accepted identically,
// and a present io.gleipnir/responder on an OAuth human session is ignored
// rather than taking the named path.
//
// Kept out of mcp_elicitation_e2e_test.go and mcp_elicitation_refusals_e2e_test.go,
// both of which #752 (issue #713, AP-77) is concurrently editing.
//
// Reuses this package's existing fixtures and helpers rather than building
// new ones: startElicitingRelay/startElicitingRelayWith, startOAuthElicitingRelay
// (oauth_idp_e2e_test.go), connectEliciting, askApproval, answerAsResponder,
// decisionRecordsFor, fetchApproval, allJobs, postRawToolCall, restartNginxArgs,
// sshdRestartArgs, askQuestionE2E, auditLen, assertMachineSelfDecisionRefused
// (mcp_elicitation_refusals_e2e_test.go), mintAccount (approval_e2e_test.go).
package main

import (
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// connectClaudeCode opens an MRTR-capable session declaring the client name
// "claude-code" (which decides nothing, AP-86), with Claude Code's own observed
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

// answerWithNoResponder retries the parked call with action and NO
// responder assertion at all — Claude Code's own observed retry shape, also
// used here for a gleipnir retry that carries no responder. Whether this
// counts as a decision at all depends on the RETRY's own session
// (capability.ElicitedResponderRule), never on the client name and never on
// anything else in this ElicitResult.
func answerWithNoResponder(t *testing.T, session *sdkmcp.ClientSession, args map[string]any, q *sdkmcp.CallToolResult, questionID, action string) *sdkmcp.CallToolResult {
	t.Helper()
	return relaytest.RetryTool(t, session, "run_operation", args, q.RequestState,
		sdkmcp.InputResponseMap{questionID: &sdkmcp.ElicitResult{Action: action}})
}

// assertNotAskedPendingApproval asserts res is an ORDINARY pending_approval
// result — no question, no answered-retry block of any kind — the shape
// every call that is not asked gets, whatever produced the call (a fresh ask
// or a retry treated as an ordinary call because clientCanBeAsked is false for
// it).
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

// connectNamed opens an MRTR-capable, eliciting session declaring name. An
// empty name is relaytest's neutral default.
func connectNamed(t *testing.T, f *relayFixture, credential, name string) *sdkmcp.ClientSession {
	t.Helper()
	return relaytest.ConnectWithOptions(t, f.ControlBase, f.ClientFor(credential), relaytest.ConnectOptions{
		Client:     relaytest.ElicitingClientOptions(),
		ClientName: name,
	})
}

// TestMCPElicitation_AnyElicitingClientIsAskedOnAnySession is AP-86's e2e
// proof: through the real composition root, a client declaring the neutral
// default name and advertising form elicitation is asked on a machine API
// token, a human API token and an OAuth session of a human Account. Each
// subtest uses a FRESH fixture, so a distinct park cannot dedup onto another's
// request (capability/approval.go's ByPlanHash).
//
// Proves AP-86.
func TestMCPElicitation_AnyElicitingClientIsAskedOnAnySession(t *testing.T) {
	t.Run("machine API token", func(t *testing.T) {
		f, token, _ := startElicitingRelay(t)
		askApproval(t, connectNamed(t, f, token, ""), restartNginxArgs())
	})

	t.Run("human API token", func(t *testing.T) {
		f, _, _ := startElicitingRelay(t)
		token := mintAccount(t, f, "hana-api", accounts.KindHuman, accounts.RoleOperator)
		askApproval(t, connectNamed(t, f, token, ""), restartNginxArgs())
	})

	t.Run("OAuth session of a human Account", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		askApproval(t, connectNamed(t, f, idp.token(t, "hana"), ""), restartNginxArgs())
	})

	t.Run("a client advertising no elicitation is not asked", func(t *testing.T) {
		f, token, _ := startElicitingRelay(t)
		session := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))
		res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
		assertNotAskedPendingApproval(t, res)
		if got := len(allJobs(t, f)); got != 0 {
			t.Errorf("Jobs = %d, want 0", got)
		}
	})
}

// TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsAskedAndItsAnswerCounts
// is AP-86/AP-87's e2e proof for Claude Code's own shape: a HUMAN Account on
// an API Token session, declaring "claude-code" with its observed capability
// shape, is asked, and an accept with no responder is that human's decision
// on a token session, which runs the Job.
//
// Proves AP-86, AP-87.
func TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsAskedAndItsAnswerCounts(t *testing.T) {
	f, _, _ := startElicitingRelay(t)
	token := mintAccount(t, f, "hana-api", accounts.KindHuman, accounts.RoleOperator)
	session := connectClaudeCode(t, f, token)

	q, qid, _, _ := askApproval(t, session, restartNginxArgs())
	res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID == "" {
		t.Fatal("job_id is empty, want a real Job: a token session's answer counts")
	}
	if len(allJobs(t, f)) != 1 {
		t.Errorf("Jobs = %d, want 1", len(allJobs(t, f)))
	}
}

// TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsAskedButNeedsAResponder
// is AP-86/AP-87/AP-79's machine-Account proof: an OAuth session of a machine
// Account is asked like any other, but never takes the AP-79 verified path, so
// an accept with no responder is a machine self-decision. A responder it sends
// is accepted, recorded as asserted.
//
// Proves AP-86, AP-87, AP-79.
func TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsAskedButNeedsAResponder(t *testing.T) {
	f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
	createAccount(t, f, "bot", accounts.KindMachine, accounts.RoleAdmin)
	token := idp.token(t, "bot")
	session := connectClaudeCode(t, f, token)

	q, qid, requestID, _ := askApproval(t, session, sshdRestartArgs())

	before := auditLen(t, f)
	refused := answerWithNoResponder(t, session, sshdRestartArgs(), q, qid, "accept")
	assertMachineSelfDecisionRefused(t, f, refused, requestID, before)
	if got := len(decisionRecordsFor(t, f, requestID)); got != 0 {
		t.Errorf("decision records = %d, want 0", got)
	}

	res := answerAsResponder(t, session, sshdRestartArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}
	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 || decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
		t.Fatalf("decision records = %+v, want one asserting %q", decisions, elicitResponderUsername)
	}
	if got := fetchApproval(t, f, requestID).Decisions; len(got) != 1 || got[0].IdentifiedBy != "responder_assertion" {
		t.Errorf("decisions = %+v, want identified_by responder_assertion", got)
	}
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
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
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

		got := fetchApproval(t, f, requestID)
		if got.State != "approved" {
			t.Errorf("approval state = %q, want approved", got.State)
		}
		if len(got.Decisions) != 1 || got.Decisions[0].IdentifiedBy != "oauth_session" {
			t.Errorf("decisions = %+v, want identified_by oauth_session (AP-88)", got.Decisions)
		}
	})

	t.Run("decline is a terminal denial, nothing asserted", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
		session := connectClaudeCode(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "decline")
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
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
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

		first := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
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

		second := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
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

// TestMCPElicitation_SpoofedClientNamesEarnNothingBeyondBeingAsked is
// AP-86/AP-87's anti-escalation proof: the declared name is self-reported, so
// it earns nothing beyond being asked. On a machine OAuth session each of
// claude-code, gleipnir and the default name is asked, and each answer
// without a responder is refused the same way. On a human API token, a client
// declaring gleipnir and one declaring some-client record identical decisions.
//
// Proves AP-86, AP-87.
func TestMCPElicitation_SpoofedClientNamesEarnNothingBeyondBeingAsked(t *testing.T) {
	for _, name := range []string{relaytest.ClaudeCodeClientName, relaytest.GleipnirClientName, ""} {
		t.Run("machine OAuth session, name "+name, func(t *testing.T) {
			f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
			createAccount(t, f, "bot", accounts.KindMachine, accounts.RoleAdmin)
			session := connectNamed(t, f, idp.token(t, "bot"), name)

			q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
			before := auditLen(t, f)
			res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
			assertMachineSelfDecisionRefused(t, f, res, requestID, before)
			if got := len(allJobs(t, f)); got != 0 {
				t.Errorf("Jobs = %d, want 0", got)
			}
		})
	}

	type recorded struct {
		Answer     string
		Channel    string
		OnBehalfOf string
		TokenUsed  bool
		Human      bool
		Identified string
	}
	var got []recorded
	for _, name := range []string{relaytest.GleipnirClientName, "some-client"} {
		f, _, _ := startElicitingRelay(t)
		token := mintAccount(t, f, "hana-api", accounts.KindHuman, accounts.RoleOperator)
		session := connectNamed(t, f, token, name)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("name %q: answered retry: NeedsInput=%v IsError=%v", name, res.NeedsInput(), res.IsError)
		}
		decisions := decisionRecordsFor(t, f, requestID)
		approved := fetchApproval(t, f, requestID)
		if len(decisions) != 1 || len(approved.Decisions) != 1 {
			t.Fatalf("name %q: decision records = %d, approval decisions = %d, want 1 each", name, len(decisions), len(approved.Decisions))
		}
		d := decisions[0]
		got = append(got, recorded{
			Answer: d.ApprovalAnswer, Channel: d.DecisionChannel, OnBehalfOf: d.Attribution.Asserted.OnBehalfOf,
			TokenUsed: d.Attribution.Verified.TokenID != "", Human: approved.Decisions[0].Human,
			Identified: approved.Decisions[0].IdentifiedBy,
		})
	}
	if got[0] != got[1] {
		t.Errorf("the declared name changed the recorded decision: gleipnir %+v vs some-client %+v", got[0], got[1])
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

// TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored is AP-79's e2e
// proof that a signed-in human session ignores a present
// io.gleipnir/responder completely: the answer is recorded as the human's
// own verified decision, never under the responder's name — whatever the
// declared client name. Run once per recognised client name, each on a
// FRESH fixture: a claude-code session (the one Gleipnir never sends a
// responder from) and a gleipnir session (which normally would take the
// named path off this session shape).
func TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored(t *testing.T) {
	connectors := []struct {
		name    string
		connect func(t *testing.T, f *relayFixture, token string) *sdkmcp.ClientSession
	}{
		{"claude-code session", func(t *testing.T, f *relayFixture, token string) *sdkmcp.ClientSession {
			return connectClaudeCode(t, f, token)
		}},
		{"gleipnir session", connectEliciting},
	}

	for _, c := range connectors {
		t.Run(c.name, func(t *testing.T) {
			f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
			accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
			token := idp.token(t, "hana")
			session := c.connect(t, f, token)

			q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
			res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
			if res.NeedsInput() || res.IsError {
				t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
			}

			var out mcp.RunOrPlanOutput
			relaytest.DecodeToolJSON(t, res, &out)
			if out.JobID == "" {
				t.Fatal("job_id is empty, want a real Job — the human's verified accept dispatches")
			}
			if out.Decision == nil || out.Decision.OnBehalfOf != "" {
				t.Errorf("Decision = %+v, want empty on_behalf_of — the responder is ignored on this session (AP-79)", out.Decision)
			}

			decisions := decisionRecordsFor(t, f, requestID)
			if len(decisions) != 1 {
				t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
			}
			if decisions[0].Attribution.Verified.AccountID != accountID {
				t.Errorf("Verified.AccountID = %q, want %q — the human's own verified Account, never the responder's",
					decisions[0].Attribution.Verified.AccountID, accountID)
			}
			if decisions[0].Attribution.Verified.TokenID != "" {
				t.Errorf("Verified.TokenID = %q, want empty — this session is OAuth, not an API Token", decisions[0].Attribution.Verified.TokenID)
			}
			if decisions[0].Attribution.Asserted.OnBehalfOf != "" {
				t.Errorf("Asserted.OnBehalfOf = %q, want empty — never %q, the ignored responder's identity",
					decisions[0].Attribution.Asserted.OnBehalfOf, elicitResponderUsername)
			}
		})
	}
}

// TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision
// is the e2e proof that a client name other than claude-code counts as
// verified too (AP-86/AP-79: the session decides, never the name) — and it
// is FEASIBLE end to end: connectEliciting declares "gleipnir" and accepts
// any credential, and any eliciting client is asked on any session, so an
// OAuth human token gets a real question. Mirrors
// TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision's
// assertions, with connectEliciting in place of connectClaudeCode and
// answerWithNoResponder for the retry.
//
// Arbitrary names such as "some-other-client" are proven at the acceptance
// seam (TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName) and, for what
// a name earns on a token session, in
// TestMCPElicitation_SpoofedClientNamesEarnNothingBeyondBeingAsked.
func TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision(t *testing.T) {
	t.Run("accept dispatches, verified as the human, nothing asserted", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
		token := idp.token(t, "hana")
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
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
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "decline")
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
}

// TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath is
// AP-79's negative e2e proof: an OAuth session of a MACHINE Account never
// takes the verified path, whatever the declared client name — proving the
// check is on the Account's kind, not merely on the auth method. The
// session is asked (any eliciting client is, AP-86), so both subtests reach
// acceptElicitedAnswer for real.
func TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath(t *testing.T) {
	t.Run("no responder is a machine self-decision", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		createAccount(t, f, "bot", accounts.KindMachine, accounts.RoleAdmin)
		token := idp.token(t, "bot")
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		before := auditLen(t, f)
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
		assertMachineSelfDecisionRefused(t, f, res, requestID, before)

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

	t.Run("a valid responder still takes the named path (AP-87)", func(t *testing.T) {
		f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
		accountID := createAccount(t, f, "bot", accounts.KindMachine, accounts.RoleAdmin)
		token := idp.token(t, "bot")
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
		}

		decisions := decisionRecordsFor(t, f, requestID)
		if len(decisions) != 1 {
			t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
		}
		if decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
			t.Errorf("Asserted.OnBehalfOf = %q, want %q — the named path", decisions[0].Attribution.Asserted.OnBehalfOf, elicitResponderUsername)
		}
		if decisions[0].Attribution.Verified.AccountID != accountID {
			t.Errorf("Verified.AccountID = %q, want %q", decisions[0].Attribution.Verified.AccountID, accountID)
		}
	})
}

// TestMCPElicitation_HumanAPITokenSessionAnswerIsTheHumansTokenSessionDecision
// is AP-87/AP-88's headline e2e proof: an accept with no responder on the API
// token session of a HUMAN Account runs the Job, recorded as that human's
// decision (human, in-band), identified by the API-token session, with nothing
// in the asserted lane. It is distinct from the AP-79 OAuth verified decision
// in how it was identified.
//
// Proves AP-87, AP-88.
func TestMCPElicitation_HumanAPITokenSessionAnswerIsTheHumansTokenSessionDecision(t *testing.T) {
	f, _, _ := startElicitingRelay(t)
	// RoleOperator, not RoleViewer: the least role that may run a structured
	// Operation (accounts.go), so the mutate run_operation reaches the
	// approval gate instead of being refused by role first.
	token := mintAccount(t, f, "hana-api", accounts.KindHuman, accounts.RoleOperator)
	session := connectEliciting(t, f, token)

	// gateAllMutatesInBandAskable has requester_allowed true, so hana-api is
	// asked about its own request.
	q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
	res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
	if res.NeedsInput() || res.IsError {
		t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
	}

	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID == "" {
		t.Fatal("job_id is empty, want a real Job: a human's token-session answer counts")
	}
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.State != "approved" || out.Decision.Channel != "in-band" ||
		out.Decision.OnBehalfOf != "" || out.Decision.IdentifiedBy != "api_token_session" {
		t.Errorf("Decision = %+v, want approved/in-band/no on_behalf_of/api_token_session", out.Decision)
	}

	decisions := decisionRecordsFor(t, f, requestID)
	if len(decisions) != 1 {
		t.Fatalf("decision records = %d, want exactly 1", len(decisions))
	}
	if decisions[0].Attribution.Verified.TokenID == "" {
		t.Error("Verified.TokenID is empty, want the API Token the session used")
	}
	if decisions[0].Attribution.Asserted.OnBehalfOf != "" {
		t.Errorf("Asserted.OnBehalfOf = %q, want empty", decisions[0].Attribution.Asserted.OnBehalfOf)
	}
	got := fetchApproval(t, f, requestID)
	if len(got.Decisions) != 1 || !got.Decisions[0].Human || got.Decisions[0].IdentifiedBy != "api_token_session" {
		t.Errorf("decisions = %+v, want one human decision identified by api_token_session", got.Decisions)
	}
}
