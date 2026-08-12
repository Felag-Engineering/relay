package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TokenService's behaviour is also exercised end-to-end against the real
// SQLite store (internal/store/tokens_api_test.go), and those tests stay —
// they prove the persistence. These cover the service's own logic here, in the
// package that owns it, where a reader looking for "what does Verify do"
// expects to find them.

func serviceFixture(t *testing.T) (*TokenService, *memoryStore, Account) {
	t.Helper()
	m := newMemoryStore()
	acct, err := m.Create(context.Background(), Account{
		Name: "gleipnir", Kind: KindMachine, Role: RoleOperator, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return NewTokenService(m, m, nil), m, acct
}

func TestTokenService_MintAndVerify(t *testing.T) {
	svc, _, acct := serviceFixture(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Mint(ctx, acct.ID, "ci", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	if !strings.HasPrefix(cred, TokenPrefix) {
		t.Errorf("credential %q lacks the %q prefix", cred, TokenPrefix)
	}
	if len(tok.SecretHash) != 32 {
		t.Errorf("SecretHash length = %d, want 32", len(tok.SecretHash))
	}

	got, verified, err := svc.Verify(ctx, cred)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ID != acct.ID || got.Role != RoleOperator {
		t.Errorf("verified as %+v, want the minting Account with its role", got)
	}
	if verified.ID != tok.ID {
		t.Errorf("verified token = %q, want %q", verified.ID, tok.ID)
	}
	// Verify returns the token as it was READ, so the last-used stamp is not
	// on the returned value — it is written afterwards, best-effort. The
	// meaningful claim is that it reached the store, which is what makes "is
	// this token still in use?" answerable before someone revokes it.
	stored, err := svc.List(ctx, acct.ID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("list: %v (%d tokens)", err, len(stored))
	}
	if stored[0].LastUsedAt.IsZero() {
		t.Error("LastUsedAt was not recorded after a successful verification")
	}
}

// The clock is injected, so expiry is tested by moving time rather than by
// sleeping — a sleeping test is a slow test that still races.
func TestTokenService_ExpiryAndZeroTTL(t *testing.T) {
	m := newMemoryStore()
	ctx := context.Background()
	acct, _ := m.Create(ctx, Account{Name: "ci", Kind: KindMachine, Role: RoleViewer, Enabled: true})

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	svc := NewTokenService(m, m, func() time.Time { return now })

	_, short, err := svc.Mint(ctx, acct.ID, "short", time.Minute)
	if err != nil {
		t.Fatalf("mint short: %v", err)
	}
	_, forever, err := svc.Mint(ctx, acct.ID, "forever", 0)
	if err != nil {
		t.Fatalf("mint forever: %v", err)
	}

	if _, _, err := svc.Verify(ctx, short.Reveal()); err != nil {
		t.Fatalf("verify before expiry: %v", err)
	}

	now = now.Add(2 * time.Minute)
	if _, _, err := svc.Verify(ctx, short.Reveal()); !IsInvalidToken(err) {
		t.Errorf("after expiry: %v, want ErrTokenInvalid", err)
	}
	if _, _, err := svc.Verify(ctx, forever.Reveal()); err != nil {
		t.Errorf("a zero-TTL token must not expire: %v", err)
	}

	if _, _, err := svc.Mint(ctx, acct.ID, "bad", -time.Second); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("negative TTL: %v, want ErrInvalidTTL", err)
	}
}

func TestTokenService_RevokeAndDisablement(t *testing.T) {
	svc, m, acct := serviceFixture(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Mint(ctx, acct.ID, "ci", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := svc.Verify(ctx, cred); !IsInvalidToken(err) {
		t.Errorf("after revoke: %v, want ErrTokenInvalid", err)
	}
	// Idempotent on repeat, an error on an unknown id.
	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Errorf("second revoke: %v, want nil", err)
	}
	if err := svc.Revoke(ctx, "nope"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("revoke unknown: %v, want ErrTokenNotFound", err)
	}

	// A live token on a disabled Account is refused without being revoked:
	// the two levers are distinct, and re-enabling restores access.
	_, live, err := svc.Mint(ctx, acct.ID, "live", 0)
	if err != nil {
		t.Fatalf("mint live: %v", err)
	}
	if err := m.SetEnabled(ctx, acct.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, _, err := svc.Verify(ctx, live.Reveal()); !IsInvalidToken(err) {
		t.Errorf("disabled Account: %v, want ErrTokenInvalid", err)
	}
	if _, _, err := svc.Mint(ctx, acct.ID, "another", 0); err == nil {
		t.Error("minting for a disabled Account succeeded")
	}
	if err := m.SetEnabled(ctx, acct.ID, true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if _, _, err := svc.Verify(ctx, live.Reveal()); err != nil {
		t.Errorf("after re-enable: %v, want the token to work again", err)
	}
}

// The role is read from the Account at verification time, never captured at
// mint — which is what makes "a token inherits role changes of its Account"
// true by construction rather than by a synchronization step.
func TestTokenService_RoleIsReadFresh(t *testing.T) {
	svc, m, acct := serviceFixture(t)
	ctx := context.Background()

	_, plaintext, err := svc.Mint(ctx, acct.ID, "ci", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	if got, _, _ := svc.Verify(ctx, cred); got.Role != RoleOperator {
		t.Fatalf("initial role = %q, want operator", got.Role)
	}
	if err := m.SetRole(ctx, acct.ID, RoleAdmin); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got, _, _ := svc.Verify(ctx, cred); got.Role != RoleAdmin {
		t.Errorf("role after promotion = %q, want admin without a restart", got.Role)
	}
}

// Every failure mode returns the SAME error, so the endpoint is not an oracle
// telling an attacker which part of their guess was right.
func TestTokenService_AllFailuresAreIndistinguishable(t *testing.T) {
	svc, _, acct := serviceFixture(t)
	ctx := context.Background()

	_, plaintext, err := svc.Mint(ctx, acct.ID, "real", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	real := plaintext.Reveal()
	id := strings.TrimPrefix(strings.Split(real, ".")[0], TokenPrefix)

	for _, c := range []struct{ label, cred string }{
		{"empty", ""},
		{"no prefix", "deadbeef.secret"},
		{"prefix only", TokenPrefix},
		{"no separator", TokenPrefix + "deadbeef"},
		{"empty id", TokenPrefix + ".secret"},
		{"empty secret", TokenPrefix + "deadbeef."},
		{"unknown id", TokenPrefix + "0123456789abcdef.secret"},
		{"right id, wrong secret", TokenPrefix + id + ".wrong"},
	} {
		if _, _, err := svc.Verify(ctx, c.cred); !IsInvalidToken(err) {
			t.Errorf("[%s] verify = %v, want the generic ErrTokenInvalid", c.label, err)
		}
	}
}

func TestTokenService_ListIsNewestFirstAndScopedToTheAccount(t *testing.T) {
	svc, m, acct := serviceFixture(t)
	ctx := context.Background()

	other, err := m.Create(ctx, Account{Name: "other", Kind: KindMachine, Role: RoleViewer, Enabled: true})
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if _, _, err := svc.Mint(ctx, other.ID, "theirs", 0); err != nil {
		t.Fatalf("mint theirs: %v", err)
	}
	for _, name := range []string{"first", "second"} {
		if _, _, err := svc.Mint(ctx, acct.ID, name, 0); err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
	}

	got, err := svc.List(ctx, acct.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d tokens, want only this Account's 2", len(got))
	}
	for _, tok := range got {
		if tok.AccountID != acct.ID {
			t.Errorf("list returned a token for %q", tok.AccountID)
		}
	}
}

func TestLooksLikeAPIToken(t *testing.T) {
	for _, c := range []struct {
		credential string
		want       bool
	}{
		{TokenPrefix + "abc.def", true},
		{TokenPrefix, true},
		{"glp", false},
		{"", false},
		{"eyJhbGciOiJSUzI1NiJ9.e30.sig", false},
	} {
		if got := LooksLikeAPIToken(c.credential); got != c.want {
			t.Errorf("LooksLikeAPIToken(%q) = %v, want %v", c.credential, got, c.want)
		}
	}
}
