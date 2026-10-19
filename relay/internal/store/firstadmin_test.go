package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

func firstAdmin(name string) accounts.Account {
	return accounts.Account{Name: name, Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true}
}

// issueWith returns an Issue that mints a token for the created Account and the
// records named by ids, one per id, in order.
func issueWith(t *testing.T, ids ...string) func(accounts.Account) (accounts.APIToken, []audit.Record, error) {
	t.Helper()
	return func(acct accounts.Account) (accounts.APIToken, []audit.Record, error) {
		tok := accounts.APIToken{ID: "tok-" + acct.ID, AccountID: acct.ID, Name: "init", SecretHash: []byte("hash"), CreatedAt: time.Now()}
		recs := make([]audit.Record, 0, len(ids))
		for _, id := range ids {
			recs = append(recs, credentialRecord(id, audit.KindAccountCreate))
		}
		return tok, recs, nil
	}
}

func TestCreateFirstAdminRecorded_CreatesTheAccountPasswordTokenAndRecordsTogether(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	created, err := st.CreateFirstAdminRecorded(ctx, firstAdmin("alice"), FirstAdminCredentials{
		Password: hashOf(t, "a strong console passphrase"),
		Issue:    issueWith(t, "r1", "r2", "r3"),
	})
	if err != nil {
		t.Fatalf("CreateFirstAdminRecorded: %v", err)
	}
	got, err := st.Accounts().GetByName(ctx, "alice")
	if err != nil || got.ID != created.ID || got.Kind != accounts.KindHuman || got.Role != accounts.RoleAdmin || !got.Enabled {
		t.Fatalf("stored = %+v (err %v), want the enabled human admin %s", got, err, created.ID)
	}
	if _, err := st.Passwords().GetPassword(ctx, created.ID); err != nil {
		t.Errorf("the password was not stored: %v", err)
	}
	if toks, err := st.APITokens().TokensByAccount(ctx, created.ID); err != nil || len(toks) != 1 {
		t.Errorf("tokens = %v (err %v), want the one first token", toks, err)
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 3 {
		t.Errorf("audit trail holds %d records, want the 3 the act returned", len(recs))
	}
}

// A human Account of any role or state means the first admin exists: nothing is
// written, not even the records.
func TestCreateFirstAdminRecorded_RefusesWhenAHumanAccountExists(t *testing.T) {
	for _, existing := range []accounts.Account{
		firstAdmin("bob"),
		{Name: "carol", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: false},
	} {
		st, _ := openTestStore(t)
		ctx := context.Background()
		if _, err := st.Accounts().Create(ctx, existing); err != nil {
			t.Fatalf("create %s: %v", existing.Name, err)
		}
		_, err := st.CreateFirstAdminRecorded(ctx, firstAdmin("alice"), FirstAdminCredentials{
			Password: hashOf(t, "a strong console passphrase"),
			Issue:    issueWith(t, "r1"),
		})
		if !errors.Is(err, accounts.ErrHumanAccountExists) {
			t.Errorf("with %s present: err = %v, want ErrHumanAccountExists", existing.Name, err)
		}
		if _, err := st.Accounts().GetByName(ctx, "alice"); !errors.Is(err, accounts.ErrNotFound) {
			t.Errorf("with %s present: alice was created (err %v)", existing.Name, err)
		}
		if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
			t.Errorf("with %s present: %d audit records written, want none", existing.Name, len(recs))
		}
	}
}

// Machine Accounts are not the first admin: a store holding only machines still
// gets one.
func TestCreateFirstAdminRecorded_MachineAccountsDoNotCount(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := st.Accounts().Create(ctx, machine("gleipnir", accounts.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFirstAdminRecorded(ctx, firstAdmin("alice"), FirstAdminCredentials{
		Password: hashOf(t, "a strong console passphrase"),
		Issue:    issueWith(t, "r1"),
	}); err != nil {
		t.Fatalf("CreateFirstAdminRecorded with only a machine Account: %v", err)
	}
}

// A record that cannot be written leaves no Account, password or token behind.
func TestCreateFirstAdminRecorded_AnUnwritableRecordCreatesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindAPITokenMint)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_, err := st.CreateFirstAdminRecorded(ctx, firstAdmin("alice"), FirstAdminCredentials{
		Password: hashOf(t, "a strong console passphrase"),
		Issue:    issueWith(t, "r1", "dup"),
	})
	if err == nil {
		t.Fatal("CreateFirstAdminRecorded with a colliding record id returned nil")
	}
	if _, err := st.Accounts().GetByName(ctx, "alice"); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("alice exists (err %v): an act whose record could not be written was made", err)
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 1 {
		t.Errorf("audit trail holds %d records, want only the pre-existing one", len(recs))
	}
}

func TestCreateFirstAdminRecorded_RefusesAnythingButAnEnabledHumanAdmin(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	for _, a := range []accounts.Account{
		{Name: "m", Kind: accounts.KindMachine, Role: accounts.RoleAdmin, Enabled: true},
		{Name: "v", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true},
		{Name: "d", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: false},
	} {
		if _, err := st.CreateFirstAdminRecorded(ctx, a, FirstAdminCredentials{
			Password: hashOf(t, "a strong console passphrase"),
			Issue:    issueWith(t, "r-"+a.Name),
		}); err == nil {
			t.Errorf("%+v was created as the first admin", a)
		}
	}
	if _, err := st.CreateFirstAdminRecorded(ctx, firstAdmin("alice"), FirstAdminCredentials{
		Password: hashOf(t, "a strong console passphrase"),
		Issue: func(acct accounts.Account) (accounts.APIToken, []audit.Record, error) {
			return accounts.APIToken{ID: "t", AccountID: "someone-else", SecretHash: []byte("h"), CreatedAt: time.Now()},
				[]audit.Record{credentialRecord("r", audit.KindAccountCreate)}, nil
		},
	}); err == nil {
		t.Error("a first token naming another Account was stored")
	}
	if all, _ := st.Accounts().List(ctx); len(all) != 0 {
		t.Errorf("accounts = %+v, want none", all)
	}
}
