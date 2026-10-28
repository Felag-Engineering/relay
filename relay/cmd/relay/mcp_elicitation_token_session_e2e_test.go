// Package main: mcp_elicitation_token_session_e2e_test.go is the e2e proof,
// through the REAL composition root, that a machine Account's elicited answer
// on its own API Token session is machine self-confirmation (AP-87), and that
// how its decider was identified is recorded (AP-88).
package main

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestMCPElicitation_MachineAPITokenAnswerIsMachineSelfConfirmation: a machine
// API Token with no responder runs the Job, recorded as a machine decision
// identified by the API-token session; a second request carrying a responder
// records it in the asserted lane, still identified by the API-token session.
//
// Proves AP-87, AP-88.
func TestMCPElicitation_MachineAPITokenAnswerIsMachineSelfConfirmation(t *testing.T) {
	t.Run("no responder", func(t *testing.T) {
		f, token, _ := startElicitingRelay(t)
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerWithNoResponder(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.JobID == "" {
			t.Fatal("job_id is empty, want a real Job: a machine's token-session answer is accepted")
		}
		if out.Decision == nil || out.Decision.IdentifiedBy != "api_token_session" || out.Decision.OnBehalfOf != "" {
			t.Errorf("Decision = %+v, want identified_by api_token_session and no on_behalf_of", out.Decision)
		}

		got := fetchApproval(t, f, requestID)
		if len(got.Decisions) != 1 || got.Decisions[0].Human || got.Decisions[0].IdentifiedBy != "api_token_session" {
			t.Errorf("decisions = %+v, want one machine decision identified by api_token_session", got.Decisions)
		}
	})

	t.Run("with a responder", func(t *testing.T) {
		f, token, _ := startElicitingRelay(t)
		session := connectEliciting(t, f, token)

		q, qid, requestID, _ := askApproval(t, session, restartNginxArgs())
		res := answerAsResponder(t, session, restartNginxArgs(), q, qid, "accept")
		if res.NeedsInput() || res.IsError {
			t.Fatalf("answered retry: NeedsInput=%v IsError=%v content=%+v", res.NeedsInput(), res.IsError, res.Content)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.Decision == nil || out.Decision.IdentifiedBy != "api_token_session" || out.Decision.OnBehalfOf != elicitResponderUsername {
			t.Errorf("Decision = %+v, want api_token_session with on_behalf_of %q", out.Decision, elicitResponderUsername)
		}

		decisions := decisionRecordsFor(t, f, requestID)
		if len(decisions) != 1 || decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
			t.Errorf("decision records = %+v, want one asserting %q", decisions, elicitResponderUsername)
		}
	})
}
