package console

// activity_fixtures_test.go holds the row and identity builders the Activity
// tests share.

import (
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// apiIdentity is a verified identity authenticated with an API Token, so none
// of its calls is a read made from a Console session.
func apiIdentity(id, name, role string) capability.VerifiedIdentity {
	return capability.VerifiedIdentity{
		AccountID: id, AccountName: name, Role: role, Method: string(capability.AuthMethodAPIToken),
	}
}

// refusalBy is one refusal row. The reason is what tells two refusals apart on
// screen, so two refusals with the same reason render identically.
func refusalBy(v capability.VerifiedIdentity, age time.Duration, reason string) capability.AuditRow {
	return capability.AuditRow{
		Kind: audit.KindRefusal, ActionKind: "operation", OperationName: "service.restart",
		Reason: reason, Timestamp: testNow.Add(-age), Verified: v,
	}
}

// finishedJob is a resolved Job: nothing unresolved, so not running.
func finishedJob(id, requester, accountID string) capability.JobSummary {
	sum := runningJob(id, requester, accountID)
	sum.Unresolved = 0
	sum.Selector = "role=web"
	sum.Counts = map[jobs.Outcome]int{jobs.OutcomeSuccess: 3}
	return sum
}
