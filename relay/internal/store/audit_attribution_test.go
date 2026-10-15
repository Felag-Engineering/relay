package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

func attributedRecord(id, accountID, onBehalfOf string) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		Kind:      audit.KindDispatch,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   accountID,
				AccountName: "gleipnir",
				Role:        "operator",
				TokenID:     "tok-" + id,
			},
			Asserted: audit.Asserted{
				OnBehalfOf:  onBehalfOf,
				Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
				SessionRef:  "conv_" + id,
				ChangeRef:   "CHG-4821",
			},
		},
		Selector:   "relay:env=prod",
		JobID:      "job-" + id,
		NodeID:     "node-1",
		ActionKind: "operation",
	}
}

// Acceptance: "A dispatch with on_behalf_of + traceparent shows both in its
// audit record, marked asserted; the same record's Account/token fields are
// marked verified." Both lanes survive a write and a read, intact and separate.
func TestAudit_AttributionRoundTrips(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	want := attributedRecord("a1", "acct-gleipnir", "ops-team")
	if err := repo.Append(ctx, want); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := repo.List(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v (%d records)", err, len(got))
	}
	if got[0].Attribution != want.Attribution {
		t.Errorf("attribution round-trip mismatch:\n got %+v\nwant %+v", got[0].Attribution, want.Attribution)
	}
}

// A record written with no attribution at all reads back as empty, not as an
// empty *assertion*: a NULL column and a caller who asserted "" must not be
// distinguishable in a way that invents a claim nobody made.
func TestAudit_UnattributedRecordRoundTripsEmpty(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	bare := audit.Record{
		ID:        "a0",
		Timestamp: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		Kind:      audit.KindFreezeEngage,
		Principal: "founding-admin:admin",
	}
	if err := st.Audit().Append(ctx, bare); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, _ := st.Audit().List(ctx)
	if !got[0].Attribution.Asserted.IsZero() {
		t.Errorf("asserted lane = %+v, want zero", got[0].Attribution.Asserted)
	}
	if (got[0].Attribution.Verified != audit.Verified{}) {
		t.Errorf("verified lane = %+v, want zero", got[0].Attribution.Verified)
	}
}

// Acceptance: "Audit queries filter by Account and by on_behalf_of."
func TestAudit_QueryByAccountAndByOnBehalfOf(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	records := []audit.Record{
		attributedRecord("a1", "acct-gleipnir", "ops-team"),
		attributedRecord("a2", "acct-gleipnir", "platform-team"),
		attributedRecord("a3", "acct-ci", "ops-team"),
	}
	for _, r := range records {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	byAccount, err := repo.ByAccount(ctx, "acct-gleipnir")
	if err != nil {
		t.Fatalf("ByAccount: %v", err)
	}
	if len(byAccount) != 2 {
		t.Errorf("ByAccount returned %d records, want 2 (a1, a2)", len(byAccount))
	}
	for _, r := range byAccount {
		if r.Attribution.Verified.AccountID != "acct-gleipnir" {
			t.Errorf("ByAccount returned a record for %q", r.Attribution.Verified.AccountID)
		}
	}

	byTeam, err := repo.ByOnBehalfOf(ctx, "ops-team")
	if err != nil {
		t.Fatalf("ByOnBehalfOf: %v", err)
	}
	if len(byTeam) != 2 {
		t.Errorf("ByOnBehalfOf returned %d records, want 2 (a1, a3)", len(byTeam))
	}

	// The two queries answer genuinely different questions — the same trail,
	// sliced by "who did the Relay authenticate" versus "who did someone say
	// this was for". a2 and a3 prove they are not the same slice.
	if len(byAccount) == len(byTeam) && byAccount[0].ID == byTeam[0].ID && byAccount[1].ID == byTeam[1].ID {
		t.Error("the verified and asserted queries returned identical slices; the fixture no longer distinguishes the lanes")
	}

	// Exact match, never a prefix: the value is caller-controlled.
	partial, err := repo.ByOnBehalfOf(ctx, "ops")
	if err != nil {
		t.Fatalf("ByOnBehalfOf(partial): %v", err)
	}
	if len(partial) != 0 {
		t.Errorf("a partial on_behalf_of matched %d records; matching must be exact", len(partial))
	}

	if got, _ := repo.ByAccount(ctx, "acct-nobody"); len(got) != 0 {
		t.Errorf("ByAccount for an unknown Account returned %d records", len(got))
	}
}
