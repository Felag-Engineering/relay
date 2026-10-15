package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

func credentialRecord(id, kind string) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		Kind:      kind,
		Principal: audit.PrincipalLocalHost,
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountName: audit.PrincipalLocalHost},
		},
		Reason: "account_id=x",
	}
}

func credentialFixture(t *testing.T) (*Store, accounts.Account) {
	t.Helper()
	st, _ := openTestStore(t)
	admin, err := st.Accounts().EnsureFoundingAdmin(context.Background())
	if err != nil {
		t.Fatalf("EnsureFoundingAdmin: %v", err)
	}
	return st, admin
}

func hashOf(t *testing.T, pw string) accounts.PasswordHash {
	t.Helper()
	h, err := accounts.HashPassword(accounts.NewPassword(pw))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

func TestSetPasswordRecorded_WritesTheCredentialAndTheRecordTogether(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	rec := credentialRecord("rec-1", audit.KindPasswordSet)

	if err := st.SetPasswordRecorded(ctx, admin.ID, hashOf(t, "a strong console passphrase"), rec); err != nil {
		t.Fatalf("SetPasswordRecorded: %v", err)
	}

	h, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil || !h.Verify(accounts.NewPassword("a strong console passphrase")) {
		t.Fatalf("the password was not stored (err %v)", err)
	}
	got, err := st.Audit().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].ID != "rec-1" || got[0].Kind != audit.KindPasswordSet ||
		got[0].Principal != audit.PrincipalLocalHost || got[0].Attribution.Verified.AccountName != audit.PrincipalLocalHost {
		t.Fatalf("audit trail = %+v, want exactly the one password_set record", got)
	}
}

func TestSetPasswordRecorded_AnUnwritableRecordLeavesThePasswordUnchanged(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "passphrase number one")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindPasswordSet)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	err := st.SetPasswordRecorded(ctx, admin.ID, hashOf(t, "passphrase number two"), credentialRecord("dup", audit.KindPasswordSet))
	if err == nil {
		t.Fatal("SetPasswordRecorded with a colliding record id returned nil")
	}

	h, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if !h.Verify(accounts.NewPassword("passphrase number one")) || h.Verify(accounts.NewPassword("passphrase number two")) {
		t.Error("a password change whose record could not be written was not rolled back")
	}
	if got, _ := st.Audit().List(ctx); len(got) != 1 {
		t.Errorf("audit trail has %d records, want only the pre-existing one", len(got))
	}
}

func TestClearPasswordRecorded_AnUnwritableRecordKeepsThePassword(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "passphrase number one")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindPasswordClear)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	err := st.ClearPasswordRecorded(ctx, admin.ID, func(bool) (audit.Record, error) {
		return credentialRecord("dup", audit.KindPasswordClear), nil
	})
	if err == nil {
		t.Fatal("ClearPasswordRecorded with a colliding record id returned nil")
	}
	h, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil || !h.Verify(accounts.NewPassword("passphrase number one")) {
		t.Errorf("the password did not survive an unrecordable clear (err %v)", err)
	}
}

func TestClearPasswordRecorded_ReportsWhetherAPasswordWasRemoved(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()

	var seen []bool
	clear := func(id string) error {
		return st.ClearPasswordRecorded(ctx, admin.ID, func(removed bool) (audit.Record, error) {
			seen = append(seen, removed)
			return credentialRecord(id, audit.KindPasswordClear), nil
		})
	}
	if err := clear("c1"); err != nil {
		t.Fatalf("clear with no password: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "passphrase number one")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := clear("c2"); err != nil {
		t.Fatalf("clear with a password: %v", err)
	}
	if len(seen) != 2 || seen[0] || !seen[1] {
		t.Errorf("removed flags = %v, want [false true]", seen)
	}
}

func TestCreateAPITokenRecorded_WritesTheTokenAndTheRecordTogether(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	tok := accounts.APIToken{ID: "tok-1", AccountID: admin.ID, Name: "bootstrap", SecretHash: []byte("hash"), CreatedAt: time.Now()}

	if err := st.CreateAPITokenRecorded(ctx, tok, credentialRecord("rec-1", audit.KindAPITokenMint)); err != nil {
		t.Fatalf("CreateAPITokenRecorded: %v", err)
	}
	if _, err := st.APITokens().TokenByID(ctx, "tok-1"); err != nil {
		t.Errorf("the token was not stored: %v", err)
	}
	if got, _ := st.Audit().List(ctx); len(got) != 1 || got[0].Kind != audit.KindAPITokenMint {
		t.Errorf("audit trail = %+v, want the one api_token_mint record", got)
	}
}

func TestCreateAPITokenRecorded_AnUnwritableRecordCreatesNoToken(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindAPITokenMint)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	tok := accounts.APIToken{ID: "tok-1", AccountID: admin.ID, Name: "bootstrap", SecretHash: []byte("hash"), CreatedAt: time.Now()}

	if err := st.CreateAPITokenRecorded(ctx, tok, credentialRecord("dup", audit.KindAPITokenMint)); err == nil {
		t.Fatal("CreateAPITokenRecorded with a colliding record id returned nil")
	}
	toks, err := st.APITokens().TokensByAccount(ctx, admin.ID)
	if err != nil || len(toks) != 0 {
		t.Errorf("tokens = %v (err %v), want none: a credential whose record could not be written was issued", toks, err)
	}
}

func TestSetPasswordRecorded_UnknownAccountWritesNoRecord(t *testing.T) {
	st, _ := credentialFixture(t)
	ctx := context.Background()

	err := st.SetPasswordRecorded(ctx, "no-such-account", hashOf(t, "a strong console passphrase"),
		credentialRecord("rec-1", audit.KindPasswordSet))
	if !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("err = %v, want accounts.ErrNotFound", err)
	}
	if got, _ := st.Audit().List(ctx); len(got) != 0 {
		t.Errorf("audit trail has %d records for a change that did not happen", len(got))
	}
}

func TestRecordWith_RefusesARecordWithNoID(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()

	err := st.SetPasswordRecorded(ctx, admin.ID, hashOf(t, "a strong console passphrase"),
		credentialRecord("", audit.KindPasswordSet))
	if err == nil {
		t.Fatal("a credential change with an id-less record was accepted")
	}
	if _, err := st.Passwords().GetPassword(ctx, admin.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Errorf("GetPassword err = %v, want ErrNoPassword: the change was not rolled back", err)
	}
	if got, _ := st.Audit().List(ctx); len(got) != 0 {
		t.Errorf("audit trail has %d records, want none", len(got))
	}
}
