package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func human(name string, role accounts.Role) accounts.Account {
	return accounts.Account{Name: name, Kind: accounts.KindHuman, Role: role, Enabled: true}
}

func TestPasswords_SetGetClear(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	acct, err := st.Accounts().Create(ctx, human("mike", accounts.RoleAdmin))
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	repo := st.Passwords()

	if _, err := repo.GetPassword(ctx, acct.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Fatalf("GetPassword on a fresh Account = %v, want ErrNoPassword", err)
	}

	hash, err := accounts.HashPassword(accounts.NewPassword("a first console password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := repo.SetPassword(ctx, acct.ID, hash); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	got, err := repo.GetPassword(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if !got.Hash.Verify(accounts.NewPassword("a first console password")) {
		t.Error("the stored hash does not verify the password it was set from")
	}

	// Replacing a password must leave exactly one credential behind, not two.
	replacement, err := accounts.HashPassword(accounts.NewPassword("a second console password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := repo.SetPassword(ctx, acct.ID, replacement); err != nil {
		t.Fatalf("SetPassword (replace): %v", err)
	}
	got, err = repo.GetPassword(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetPassword after replace: %v", err)
	}
	if got.Hash.Verify(accounts.NewPassword("a first console password")) {
		t.Error("the replaced password still verifies")
	}
	if !got.Hash.Verify(accounts.NewPassword("a second console password")) {
		t.Error("the replacement password does not verify")
	}

	if err := repo.ClearPassword(ctx, acct.ID); err != nil {
		t.Fatalf("ClearPassword: %v", err)
	}
	if _, err := repo.GetPassword(ctx, acct.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Fatalf("GetPassword after clear = %v, want ErrNoPassword", err)
	}
	// Clearing twice is not an error: the postcondition holds either way.
	if err := repo.ClearPassword(ctx, acct.ID); err != nil {
		t.Errorf("ClearPassword on an Account with none: %v", err)
	}
}

func TestPasswords_SetForAnUnknownAccountIsRefused(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	hash, err := accounts.HashPassword(accounts.NewPassword("a console password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// The foreign key is the guard, so a caller that forgets to check the
	// Account exists cannot leave an orphaned credential behind.
	if err := st.Passwords().SetPassword(ctx, "no-such-account", hash); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("SetPassword for an unknown Account = %v, want ErrNotFound", err)
	}
}

func TestPasswords_DeletingAnAccountRemovesItsPassword(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	acct, err := st.Accounts().Create(ctx, human("departing", accounts.RoleViewer))
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword("a console password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, acct.ID, hash); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// ON DELETE CASCADE: a deleted Account can never leave behind a
	// credential that still verifies.
	if _, err := st.db.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, acct.ID); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if _, err := st.Passwords().GetPassword(ctx, acct.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Fatalf("GetPassword after the Account was deleted = %v, want ErrNoPassword", err)
	}
}

func TestPasswords_ACorruptRowFailsClosed(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	acct, err := st.Accounts().Create(ctx, human("corrupted", accounts.RoleOperator))
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword("a console password"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, acct.ID, hash); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, err := st.db.ExecContext(ctx,
		`UPDATE account_passwords SET password_hash = ? WHERE account_id = ?`,
		"$argon2id$v=19$m=8,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA", acct.ID); err != nil {
		t.Fatalf("corrupt the row: %v", err)
	}

	// A damaged credential must be distinguishable from an absent one.
	// Collapsing the two would make database tampering an authentication
	// bypass rather than an outage.
	_, err = st.Passwords().GetPassword(ctx, acct.ID)
	if errors.Is(err, accounts.ErrNoPassword) {
		t.Fatal("a corrupt hash was reported as 'no password set'")
	}
	if !errors.Is(err, accounts.ErrPasswordHashMalformed) {
		t.Fatalf("GetPassword on a corrupt row = %v, want ErrPasswordHashMalformed", err)
	}
}

func TestPasswords_RefusesToStoreAnEmptyHash(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	acct, err := st.Accounts().Create(ctx, human("empty", accounts.RoleViewer))
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, acct.ID, accounts.PasswordHash{}); err == nil {
		t.Fatal("SetPassword stored the zero PasswordHash")
	}
}
