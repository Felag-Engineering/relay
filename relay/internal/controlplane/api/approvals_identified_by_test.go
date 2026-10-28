package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestApprovals_DecisionRendersHowTheDeciderWasIdentified: an in-band decision
// carries how its decider was identified; an out-of-band one has no such key.
//
// Proves AP-88.
func TestApprovals_DecisionRendersHowTheDeciderWasIdentified(t *testing.T) {
	req := testApprovalRequest("req-1", jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate,
	})
	req.Decisions = []approval.Decision{
		{Account: "hana", AccountID: "acct-h", Approve: true, Channel: approval.ChannelInBand, DeciderHuman: true,
			IdentifiedBy: approval.IdentifiedByAPITokenSession, At: apiNow},
		{Account: "mike", AccountID: "acct-m", Approve: true, Channel: approval.ChannelOutOfBand, DeciderHuman: true, At: apiNow},
	}
	ap := &fakeApprovals{pending: []approval.Request{req}, byID: map[string]approval.Request{"req-1": req}}
	h := newApprovalFixture(t, accounts.RoleViewer, ap)

	rec := do(t, h, http.MethodGet, "/api/v1/approvals/req-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	var raw struct {
		Decisions []map[string]any `json:"decisions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.Decisions) != 2 {
		t.Fatalf("decisions = %d, want 2", len(raw.Decisions))
	}
	if got := raw.Decisions[0]["identified_by"]; got != "api_token_session" {
		t.Errorf("in-band identified_by = %v, want api_token_session", got)
	}
	if _, present := raw.Decisions[1]["identified_by"]; present {
		t.Error("an out-of-band decision carries identified_by")
	}
}
