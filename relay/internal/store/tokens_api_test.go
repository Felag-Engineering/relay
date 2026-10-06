package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// tokenFixture opens a store, seeds an enabled machine Account, and returns a
// TokenService over both.
func tokenFixture(t *testing.T) (*accounts.TokenService, accounts.Repository, accounts.Account) {
	t.Helper()
	st, _ := openTestStore(t)
	ctx := context.Background()

	acctRepo := st.Accounts()
	acct, err := acctRepo.Create(ctx, accounts.Account{
		Name: "gleipnir", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return accounts.NewTokenService(st.APITokens(), acctRepo, nil), acctRepo, acct
}

// Acceptance: "A minted token authenticates until revoked/expired."
func TestAPIToken_MintAndVerify(t *testing.T) {
	svc, _, acct := tokenFixture(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Mint(ctx, acct.ID, "ci-deploy", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	if !strings.HasPrefix(cred, accounts.TokenPrefix) {
		t.Errorf("credential %q lacks the %q prefix that makes a leak greppable", cred, accounts.TokenPrefix)
	}
	if !accounts.LooksLikeAPIToken(cred) {
		t.Error("LooksLikeAPIToken() = false for a freshly minted credential")
	}
	if len(tok.SecretHash) != 32 {
		t.Errorf("SecretHash length = %d, want 32 (sha256)", len(tok.SecretHash))
	}
	if strings.Contains(cred, string(tok.SecretHash)) {
		t.Error("the stored hash appears inside the credential")
	}

	got, verified, err := svc.Verify(ctx, cred)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ID != acct.ID || got.Role != accounts.RoleOperator {
		t.Errorf("verified account = %+v, want the minting Account with its role", got)
	}
	if verified.ID != tok.ID {
		t.Errorf("verified token ID = %q, want %q", verified.ID, tok.ID)
	}

	// last-used is recorded, so "is this token still in use?" is answerable.
	stored, err := svc.List(ctx, acct.ID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("list: %v (%d tokens)", err, len(stored))
	}
	if stored[0].LastUsedAt.IsZero() {
		t.Error("LastUsedAt is zero after a successful verification")
	}
}

// Acceptance: "revocation cuts access on the next request."
func TestAPIToken_RevokeCutsAccessImmediately(t *testing.T) {
	svc, _, acct := tokenFixture(t)
	ctx := context.Background()

	_, plaintext, err := svc.Mint(ctx, acct.ID, "laptop", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	tok, _, err := svc.Verify(ctx, cred)
	if err != nil {
		t.Fatalf("verify before revoke: %v", err)
	}
	_ = tok

	list, _ := svc.List(ctx, acct.ID)
	if err := svc.Revoke(ctx, list[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, _, err := svc.Verify(ctx, cred); !accounts.IsInvalidToken(err) {
		t.Errorf("verify after revoke: %v, want ErrTokenInvalid", err)
	}

	// Revoking twice is a no-op, not an error: an operator racing themselves
	// mid-incident should not see a failure.
	if err := svc.Revoke(ctx, list[0].ID); err != nil {
		t.Errorf("second revoke: %v, want nil (idempotent)", err)
	}
	// ...but an unknown id IS an error — that is a typo they need to hear about
	// while they still believe they revoked something.
	if err := svc.Revoke(ctx, "no-such-token"); !errors.Is(err, accounts.ErrTokenNotFound) {
		t.Errorf("revoke unknown: %v, want ErrTokenNotFound", err)
	}
}

func TestAPIToken_ExpiryAndZeroTTL(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	acct, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "ci", Kind: accounts.KindMachine, Role: accounts.RoleViewer, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	clock := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), func() time.Time { return clock })

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

	clock = clock.Add(2 * time.Minute)
	if _, _, err := svc.Verify(ctx, short.Reveal()); !accounts.IsInvalidToken(err) {
		t.Errorf("verify after expiry: %v, want ErrTokenInvalid", err)
	}
	if _, _, err := svc.Verify(ctx, forever.Reveal()); err != nil {
		t.Errorf("a zero-TTL token must not expire; got %v", err)
	}

	if _, _, err := svc.Mint(ctx, acct.ID, "bad", -time.Second); !errors.Is(err, accounts.ErrInvalidTTL) {
		t.Errorf("mint with negative TTL: %v, want ErrInvalidTTL", err)
	}
}

// Acceptance: "A token inherits role changes of its Account" — and a disabled
// Account cuts every one of its tokens off at once.
func TestAPIToken_InheritsAccountRoleAndDisablement(t *testing.T) {
	svc, acctRepo, acct := tokenFixture(t)
	ctx := context.Background()

	_, plaintext, err := svc.Mint(ctx, acct.ID, "ci", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cred := plaintext.Reveal()

	got, _, _ := svc.Verify(ctx, cred)
	if got.Role != accounts.RoleOperator {
		t.Fatalf("initial role = %q, want operator", got.Role)
	}

	if err := acctRepo.SetRole(ctx, acct.ID, accounts.RoleOperator, accounts.RoleAdmin); err != nil {
		t.Fatalf("promote: %v", err)
	}
	got, _, err = svc.Verify(ctx, cred)
	if err != nil {
		t.Fatalf("verify after role change: %v", err)
	}
	if got.Role != accounts.RoleAdmin {
		t.Errorf("role after promotion = %q, want admin — a token must not cache its role", got.Role)
	}

	// A second enabled admin, so disabling acct below (now an admin, since
	// this test's subject is token inheritance, not the last-admin guard)
	// does not trip ErrLastAdmin (#653) — without this, the assertions below
	// would silently start exercising that refusal instead of the disabled-
	// Account path this test is actually named for.
	if _, err := acctRepo.Create(ctx, accounts.Account{
		Name: "other-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatalf("create other admin: %v", err)
	}

	if err := acctRepo.SetEnabled(ctx, acct.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, _, err := svc.Verify(ctx, cred); !accounts.IsInvalidToken(err) {
		t.Errorf("verify with a disabled Account: %v, want ErrTokenInvalid", err)
	}

	// Minting for a disabled Account is refused: a credential for an identity
	// that cannot authenticate is a trap that looks like access.
	if _, _, err := svc.Mint(ctx, acct.ID, "another", 0); err == nil {
		t.Error("mint for a disabled Account succeeded, want a refusal")
	}
}

// Every failure mode returns the SAME error, so the endpoint is not an oracle
// telling an attacker which part of their guess was right.
func TestAPIToken_AllFailuresAreIndistinguishable(t *testing.T) {
	svc, _, acct := tokenFixture(t)
	ctx := context.Background()

	_, plaintext, err := svc.Mint(ctx, acct.ID, "real", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	real := plaintext.Reveal()
	id := strings.TrimPrefix(strings.Split(real, ".")[0], accounts.TokenPrefix)

	for _, c := range []struct{ label, cred string }{
		{"empty", ""},
		{"no prefix", "deadbeef.secret"},
		{"prefix only", accounts.TokenPrefix},
		{"no separator", accounts.TokenPrefix + "deadbeef"},
		{"empty id", accounts.TokenPrefix + ".secret"},
		{"empty secret", accounts.TokenPrefix + "deadbeef."},
		{"unknown id", accounts.TokenPrefix + "0123456789abcdef.secret"},
		{"right id, wrong secret", accounts.TokenPrefix + id + ".wrong-secret"},
	} {
		_, _, err := svc.Verify(ctx, c.cred)
		if !accounts.IsInvalidToken(err) {
			t.Errorf("[%s] verify = %v, want the generic ErrTokenInvalid", c.label, err)
		}
	}
}

// Acceptance: "The token plaintext appears exactly once in any output, ever
// (mint response); grep-proven for logs/audit."
//
// The Go counterpart of the Rust no-Debug guarantee: every incidental
// rendering path is redacted, so a leak requires an explicit Reveal() call
// that a reviewer can grep for.
func TestAPIToken_PlaintextIsUnloggable(t *testing.T) {
	svc, _, acct := tokenFixture(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Mint(ctx, acct.ID, "ci", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	secret := plaintext.Reveal()

	// Every formatting verb, JSON, and slog must redact. The %s case is the
	// literal thing under test — that the verb itself is safe — so the
	// "just call String()" simplification is exactly what must not be applied.
	renders := map[string]string{
		"%s": fmt.Sprintf("%s", plaintext), //nolint:staticcheck // testing the verb, not the method

		"%v":           fmt.Sprintf("%v", plaintext),
		"%#v":          fmt.Sprintf("%#v", plaintext),
		"%+v":          fmt.Sprintf("%+v", plaintext),
		"String()":     plaintext.String(),
		"struct embed": fmt.Sprintf("%v", struct{ T accounts.Plaintext }{plaintext}),
		"slice":        fmt.Sprintf("%v", []accounts.Plaintext{plaintext}),
	}
	for label, out := range renders {
		if strings.Contains(out, secret) {
			t.Errorf("[%s] rendered the plaintext: %q", label, out)
		}
	}

	blob, err := json.Marshal(struct {
		Token accounts.Plaintext `json:"token"`
	}{plaintext})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Errorf("json.Marshal leaked the plaintext: %s", blob)
	}

	// slog, through a real handler, for both the Plaintext and the stored token.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("minted", "token", plaintext, "stored", &tok)
	if strings.Contains(buf.String(), secret) {
		t.Errorf("slog leaked the plaintext: %s", buf.String())
	}
	if bytes.Contains(buf.Bytes(), tok.SecretHash) {
		t.Errorf("slog leaked the secret hash: %s", buf.String())
	}

	// And the stored record itself never holds the plaintext.
	stored, _ := svc.List(ctx, acct.ID)
	if strings.Contains(fmt.Sprintf("%+v", stored), secret) {
		t.Error("the stored token record contains the plaintext")
	}
}
