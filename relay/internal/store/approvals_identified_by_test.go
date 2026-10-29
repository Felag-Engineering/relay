package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// TestApprovals_DecisionIdentifiedByRoundTrips: each identification is stored
// and read back, and an out-of-band decision reads back as unrecorded.
//
// Proves AP-88.
func TestApprovals_DecisionIdentifiedByRoundTrips(t *testing.T) {
	ctx := context.Background()
	for _, id := range []approval.IdentifiedBy{
		approval.IdentifiedByUnrecorded, approval.IdentifiedByOAuthSession,
		approval.IdentifiedByAPITokenSession, approval.IdentifiedByResponderAssertion,
	} {
		t.Run(id.String(), func(t *testing.T) {
			repo := approvalStore(t)
			if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
				t.Fatalf("Create: %v", err)
			}
			at := storeNow.Add(time.Minute)
			if _, err := repo.RecordDecision(ctx, "req-1", approval.Decision{
				AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand,
				PlanHash: "hash-a", DeciderHuman: true, IdentifiedBy: id, At: at,
			}, at); err != nil {
				t.Fatalf("RecordDecision: %v", err)
			}
			got, err := repo.Get(ctx, "req-1")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(got.Decisions) != 1 || got.Decisions[0].IdentifiedBy != id {
				t.Errorf("decisions = %+v, want IdentifiedBy %v", got.Decisions, id)
			}
		})
	}
}

// TestApprovals_UnknownIdentifiedByIsAnError: a stored value the Relay does
// not know is a read error, never silently rendered as unrecorded.
//
// Proves AP-88.
func TestApprovals_UnknownIdentifiedByIsAnError(t *testing.T) {
	ctx := context.Background()
	st, db := openStore(t)
	repo := st.Approvals()
	if err := repo.Create(ctx, pendingRequest("req-1", "hash-a", time.Hour)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	at := storeNow.Add(time.Minute)
	if _, err := repo.RecordDecision(ctx, "req-1", approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand,
		PlanHash: "hash-a", DeciderHuman: true, At: at,
	}, at); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE approval_decisions SET identified_by = 'telepathy'`); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	if _, err := repo.Get(ctx, "req-1"); !errors.Is(err, approval.ErrUnknownIdentifiedBy) {
		t.Fatalf("Get err = %v, want ErrUnknownIdentifiedBy", err)
	}
}
