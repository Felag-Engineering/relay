package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func TestIdentityAPI_MintWithoutTTLDefaultsAHumanTokenToSevenDays(t *testing.T) {
	f := newIdentityFixture(t)
	human, err := f.store.Accounts().Create(context.Background(), accounts.Account{
		Name: "hana", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create human account: %v", err)
	}

	before := time.Now()
	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+human.ID+"/tokens", map[string]any{"name": "laptop"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	var out mintAPITokenResponse
	decodeInto(t, rec, &out)
	expires, err := time.Parse(time.RFC3339, out.APIToken.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q: %v", out.APIToken.ExpiresAt, err)
	}
	want := before.Add(7 * 24 * time.Hour)
	if d := expires.Sub(want); d < -time.Minute || d > time.Minute {
		t.Errorf("expires_at = %v, want about %v", expires, want)
	}
}

func TestIdentityAPI_MintWithoutTTLForAMachineIsRefused(t *testing.T) {
	f := newIdentityFixture(t)
	machine, _ := f.mintFor(t, "ci", accounts.RoleViewer)

	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+machine.ID+"/tokens", map[string]any{"name": "no-ttl"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	list, err := f.tokens.List(context.Background(), machine.ID)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("machine has %d tokens, want 1 (only mintFor's own)", len(list))
	}
}
