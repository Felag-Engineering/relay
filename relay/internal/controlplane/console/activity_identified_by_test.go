package console

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// TestActivity_ApprovalDecisionShowsHowTheDeciderWasIdentified: an approval
// decision's audit Reason carries how the Relay identified the decider, and
// Activity renders the Reason.
//
// Proves AP-88.
func TestActivity_ApprovalDecisionShowsHowTheDeciderWasIdentified(t *testing.T) {
	const reason = "approval request ap-9 approved by hana over in-band, decider identified by api_token_session (1 of 1, request now approved): restart nginx"
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalDecided, ApprovalID: "ap-9", Reason: reason, Timestamp: testNow, Verified: consoleActor},
	}}
	body := contentOf(activityAs(t, q, "/console/activity"))

	if !strings.Contains(body, "decider identified by api_token_session") {
		t.Errorf("the decision row does not say how its decider was identified:\n%s", body)
	}
}
