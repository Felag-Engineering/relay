package auditsink

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// Proves EN-36.
func TestRecordEnrollmentTokenMint_WritesTheControlAPIsTokenMintRecord(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	at := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(func() time.Time { return at }))
	p := capability.Principal{
		AccountID: "acct-7", Account: "olive", Role: "admin", Kind: capability.PrincipalKindHuman,
		AuthMethod: capability.AuthMethodConsoleSession, Source: "10.0.0.9",
	}
	asserted := capability.Assertions{OnBehalfOf: "carol", ChangeRef: "CHG-1"}

	err := sink.RecordEnrollmentTokenMint(context.Background(), capability.EnrollmentMintEvent{
		Principal: p, TokenID: "tok-abc", Asserted: asserted,
	})
	if err != nil {
		t.Fatalf("RecordEnrollmentTokenMint: %v", err)
	}

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("records = %d, want 1", len(all))
	}
	r := all[0]
	if r.Kind != audit.KindTokenMint || r.Reason != "token_id=tok-abc" || r.Principal != p.Attribution() || !r.Timestamp.Equal(at) {
		t.Errorf("record = kind %q, reason %q, principal %q, at %v", r.Kind, r.Reason, r.Principal, r.Timestamp)
	}
	if r.Attribution.Verified.AccountID != "acct-7" || r.Attribution.Verified.Role != "admin" {
		t.Errorf("verified lane = %+v", r.Attribution.Verified)
	}
	if r.Attribution.Asserted.OnBehalfOf != "carol" || r.Attribution.Asserted.ChangeRef != "CHG-1" {
		t.Errorf("asserted lane = %+v, want the event's, kept apart from the verified one", r.Attribution.Asserted)
	}
}
