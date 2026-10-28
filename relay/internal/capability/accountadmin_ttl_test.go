package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func mintFixture(t *testing.T, kind accounts.Kind) (*testSvc, *fakeAPITokenStore, *spyAuditSink) {
	accountStore := &fakeAccountStore{accountsByID: map[string]accounts.Account{
		"acct-1": {ID: "acct-1", Name: "one", Kind: kind, Role: accounts.RoleViewer},
	}}
	tokenStore := &fakeAPITokenStore{mintOut: accounts.APIToken{ID: "tok-1", AccountID: "acct-1"}}
	svc, audit := newAccountAdminFixture(t, &permissiveControlAuthorizer{}, accountStore, tokenStore)
	return svc, tokenStore, audit
}

func TestMintAPIToken_HumanAccountDefaultsToSevenDays(t *testing.T) {
	svc, tokens, _ := mintFixture(t, accounts.KindHuman)
	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin", Kind: PrincipalKindHuman}

	if _, _, err := svc.MintAPIToken(context.Background(), p, "acct-1", "ci", DefaultAPITokenLifetime()); err != nil {
		t.Fatalf("MintAPIToken: %v", err)
	}
	if len(tokens.mintCalls) != 1 || tokens.mintCalls[0].ttl != 7*24*time.Hour {
		t.Errorf("mint calls = %+v, want one with ttl 168h", tokens.mintCalls)
	}
}

func TestMintAPIToken_MachineAccountNeedsAnExplicitLifetime(t *testing.T) {
	svc, tokens, audit := mintFixture(t, accounts.KindMachine)
	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin", Kind: PrincipalKindHuman}

	_, _, err := svc.MintAPIToken(context.Background(), p, "acct-1", "ci", DefaultAPITokenLifetime())
	if !errors.Is(err, ErrAPITokenTTLRequired) {
		t.Fatalf("err = %v, want ErrAPITokenTTLRequired", err)
	}
	if len(tokens.mintCalls) != 0 {
		t.Errorf("mint calls = %d, want 0", len(tokens.mintCalls))
	}
	if len(audit.accountAdminCalls) != 0 {
		t.Errorf("account-admin events = %d, want 0", len(audit.accountAdminCalls))
	}

	if _, _, err := svc.MintAPIToken(context.Background(), p, "acct-1", "ci", ExplicitAPITokenLifetime(0)); err != nil {
		t.Fatalf("an explicit 0 is a deliberate choice: %v", err)
	}
}
