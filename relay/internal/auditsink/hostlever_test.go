package auditsink

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

var hostLeverNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestHostPasswordRecord_AttributesToLocalHostNotAnAccount(t *testing.T) {
	rec, err := HostPasswordSetRecord("id-1", hostLeverNow, "acct-1", "admin")
	if err != nil {
		t.Fatalf("HostPasswordSetRecord: %v", err)
	}
	if rec.Principal != "local-host" {
		t.Errorf("Principal = %q, want local-host", rec.Principal)
	}
	if want := (audit.Verified{AccountName: "local-host"}); rec.Attribution.Verified != want {
		t.Errorf("Verified = %+v, want %+v", rec.Attribution.Verified, want)
	}
	if rec.Attribution.Asserted != (audit.Asserted{}) {
		t.Errorf("Asserted = %+v, want zero", rec.Attribution.Asserted)
	}
	if rec.Kind != audit.KindPasswordSet || rec.Reason != "account_id=acct-1 name=admin" {
		t.Errorf("Kind = %q, Reason = %q", rec.Kind, rec.Reason)
	}

	clr, err := HostPasswordClearRecord("id-2", hostLeverNow, "acct-1", "admin", false)
	if err != nil {
		t.Fatalf("HostPasswordClearRecord: %v", err)
	}
	if clr.Kind != audit.KindPasswordClear || clr.Reason != "account_id=acct-1 name=admin removed=false" {
		t.Errorf("Kind = %q, Reason = %q", clr.Kind, clr.Reason)
	}
}

func TestHostLeverAttribution_MatchesTheFreezeSignal(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(fixedClock(hostLeverNow)))
	ev := capability.FreezeEvent{Principal: capability.Principal{Account: "local-host"}, Engage: true}
	if err := sink.RecordFreeze(context.Background(), ev); err != nil {
		t.Fatalf("RecordFreeze: %v", err)
	}
	freeze, err := repo.List(context.Background())
	if err != nil || len(freeze) != 1 {
		t.Fatalf("List = %v (err %v)", freeze, err)
	}

	set, _ := HostPasswordSetRecord("a", hostLeverNow, "acct", "admin")
	mint, _ := HostAPITokenMintRecord("b", hostLeverNow, "acct", "tok")
	for _, rec := range []audit.Record{set, mint} {
		if rec.Principal != freeze[0].Principal || !reflect.DeepEqual(rec.Attribution, freeze[0].Attribution) {
			t.Errorf("%s attributes as %q %+v, the freeze signal as %q %+v",
				rec.Kind, rec.Principal, rec.Attribution, freeze[0].Principal, freeze[0].Attribution)
		}
	}
}

func TestHostAPITokenMintRecord_ReasonMatchesTheAPIMint(t *testing.T) {
	rec, err := HostAPITokenMintRecord("id-1", hostLeverNow, "acct-1", "tok-1")
	if err != nil {
		t.Fatalf("HostAPITokenMintRecord: %v", err)
	}
	want := accountAdminReason(capability.AccountAdminEvent{
		Kind: capability.AccountAdminTokenMint, AccountID: "acct-1", TokenID: "tok-1",
	})
	if rec.Kind != audit.KindAPITokenMint || rec.Reason != want {
		t.Errorf("Kind = %q, Reason = %q, want %q / %q", rec.Kind, rec.Reason, audit.KindAPITokenMint, want)
	}
}

func TestHostLeverRecords_RefuseMissingIdentifiers(t *testing.T) {
	if _, err := HostPasswordSetRecord("", hostLeverNow, "acct", "admin"); err == nil {
		t.Error("an empty audit id was accepted")
	}
	if _, err := HostPasswordSetRecord("id", hostLeverNow, "", "admin"); err == nil {
		t.Error("an empty account id was accepted")
	}
	if _, err := HostPasswordClearRecord("", hostLeverNow, "acct", "admin", true); err == nil {
		t.Error("an empty audit id was accepted for a clear")
	}
	if _, err := HostAPITokenMintRecord("id", hostLeverNow, "acct", ""); err == nil {
		t.Error("an empty token id was accepted")
	}
}
