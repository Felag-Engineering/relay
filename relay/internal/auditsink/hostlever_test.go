package auditsink

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
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

func TestHostConfigReloadRecord_KeysOnlyAndHostAttributed(t *testing.T) {
	rec, err := HostConfigReloadRecord("id-1", hostLeverNow, []string{"log.format", "approval.webhook_secret"})
	if err != nil {
		t.Fatalf("HostConfigReloadRecord: %v", err)
	}
	if rec.Kind != audit.KindConfigReload || rec.Principal != "local-host" {
		t.Errorf("Kind = %q, Principal = %q", rec.Kind, rec.Principal)
	}
	if want := "configuration reloaded on the Relay host; changed: log.format, approval.webhook_secret"; rec.Reason != want {
		t.Errorf("Reason = %q, want %q", rec.Reason, want)
	}
	// The same attribution as the host credential levers, which match the freeze signal's.
	set, _ := HostPasswordSetRecord("a", hostLeverNow, "acct", "admin")
	if rec.Principal != set.Principal || !reflect.DeepEqual(rec.Attribution, set.Attribution) {
		t.Errorf("attribution differs from the host lever's: %+v vs %+v", rec.Attribution, set.Attribution)
	}

	none, err := HostConfigReloadRecord("id-2", hostLeverNow, nil)
	if err != nil || none.Reason != "configuration reloaded on the Relay host; no setting changed" {
		t.Errorf("no change: Reason = %q, err = %v", none.Reason, err)
	}
	if _, err := HostConfigReloadRecord("", hostLeverNow, nil); err == nil {
		t.Error("an empty id was accepted")
	}
	for _, k := range []string{"relay.example", "http://127.0.0.1:1/hook-token", ""} {
		if _, err := HostConfigReloadRecord("id", hostLeverNow, []string{"log.format", k}); err == nil {
			t.Errorf("non-member key %q was accepted", k)
		}
	}
}

func TestHostConfigReloadRefusedRecord_StagePhraseOnly(t *testing.T) {
	const prefix = "configuration reload refused on the Relay host; "
	for _, tc := range []struct {
		stage ReloadStage
		keys  []string
		want  string
	}{
		{ReloadRefusedFile, nil, "the configuration file was refused (file check, decode or validation)"},
		{ReloadRefusedRestart, []string{"ca.dir", "tls.hostname"}, "restart required: ca.dir, tls.hostname"},
		{ReloadRefusedNamedFiles, nil, "a file the configuration names, or the store or CA directory, was refused"},
		{ReloadRefusedCA, nil, "restart required: the CA on disk is not the CA this Relay is running"},
		{ReloadRefusedSettings, nil, "an operator setting was refused"},
		{ReloadRefusedAudit, nil, "the reload's audit record could not be written"},
		{ReloadRefusedInternal, nil, "the reload failed unexpectedly"},
	} {
		rec, err := HostConfigReloadRefusedRecord("id", hostLeverNow, tc.stage, tc.keys)
		if err != nil {
			t.Fatalf("stage %d: %v", tc.stage, err)
		}
		if rec.Kind != audit.KindConfigReloadRefused || rec.Principal != "local-host" || rec.Reason != prefix+tc.want {
			t.Errorf("stage %d: Kind = %q, Principal = %q, Reason = %q", tc.stage, rec.Kind, rec.Principal, rec.Reason)
		}
	}
	for name, call := range map[string]func() error{
		"restart stage without keys": func() error {
			_, err := HostConfigReloadRefusedRecord("id", hostLeverNow, ReloadRefusedRestart, nil)
			return err
		},
		"keys on another stage": func() error {
			_, err := HostConfigReloadRefusedRecord("id", hostLeverNow, ReloadRefusedFile, []string{"ca.dir"})
			return err
		},
		"non-member key": func() error {
			_, err := HostConfigReloadRefusedRecord("id", hostLeverNow, ReloadRefusedRestart, []string{"relay.example"})
			return err
		},
		"unknown stage": func() error {
			_, err := HostConfigReloadRefusedRecord("id", hostLeverNow, ReloadStage(99), nil)
			return err
		},
		"empty id": func() error {
			_, err := HostConfigReloadRefusedRecord("", hostLeverNow, ReloadRefusedFile, nil)
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
