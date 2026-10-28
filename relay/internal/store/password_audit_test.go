package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

var passwordNow = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

func passwordAppender(t *testing.T, st *Store) audit.PasswordAppender {
	t.Helper()
	app, ok := st.Audit().(audit.PasswordAppender)
	if !ok {
		t.Fatal("the store's audit Repository is not a PasswordAppender")
	}
	return app
}

func passwordRecord(id, kind, reason string) audit.Record {
	r := credentialRecord(id, kind)
	r.Reason = reason
	return r
}

func newHumanAccount(name string) accounts.Account {
	return accounts.Account{Name: name, Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true}
}

func twoRecords(createID, issueID string) func(accounts.Account) ([]audit.Record, error) {
	return func(created accounts.Account) ([]audit.Record, error) {
		return []audit.Record{
			passwordRecord(createID, audit.KindAccountCreate, "account_id="+created.ID+" name="+created.Name),
			passwordRecord(issueID, audit.KindPasswordTemporarySet, "account_id="+created.ID+" name="+created.Name),
		}, nil
	}
}

func TestAppendWithTemporaryAccount_IsAtomic(t *testing.T) {
	st, _ := credentialFixture(t)
	ctx := context.Background()
	until := passwordNow.Add(accounts.TemporaryPasswordLifetime)

	created, err := passwordAppender(t, st).AppendWithTemporaryAccount(ctx, newHumanAccount("newbie"), hashOf(t, "a temporary password"), until, twoRecords("rec-c", "rec-t"))
	if err != nil {
		t.Fatalf("AppendWithTemporaryAccount: %v", err)
	}

	got, err := st.Passwords().GetPassword(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if !got.Temporary() || !got.TemporaryUntil.Equal(until) {
		t.Errorf("TemporaryUntil = %v, want %v", got.TemporaryUntil, until)
	}
	if !got.Hash.Verify(accounts.NewPassword("a temporary password")) {
		t.Error("the stored hash does not verify the temporary password")
	}
	status, err := st.PasswordStatuses().Status(ctx, created.ID)
	if err != nil || status.Own || !status.TemporaryUntil.Equal(until) {
		t.Errorf("Status = %+v, %v; want not Own, expiring at %v", status, err, until)
	}

	recs, err := st.Audit().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range recs {
		kinds = append(kinds, r.Kind)
	}
	if len(kinds) != 2 || kinds[0] != audit.KindAccountCreate || kinds[1] != audit.KindPasswordTemporarySet {
		t.Errorf("the trail holds %v, want exactly account_create then password_temporary_set", kinds)
	}
}

func TestAppendWithTemporaryAccount_RollsBackOnABadRecord(t *testing.T) {
	st, _ := credentialFixture(t)
	ctx := context.Background()
	until := passwordNow.Add(accounts.TemporaryPasswordLifetime)
	app := passwordAppender(t, st)

	for name, recs := range map[string]func(accounts.Account) ([]audit.Record, error){
		"a recorder error": func(accounts.Account) ([]audit.Record, error) { return nil, errors.New("boom") },
		"one record": func(c accounts.Account) ([]audit.Record, error) {
			return []audit.Record{passwordRecord("r1", audit.KindAccountCreate, "account_id="+c.ID)}, nil
		},
		"the wrong kind order": func(c accounts.Account) ([]audit.Record, error) {
			return []audit.Record{
				passwordRecord("r1", audit.KindPasswordTemporarySet, "account_id="+c.ID),
				passwordRecord("r2", audit.KindAccountCreate, "account_id="+c.ID),
			}, nil
		},
		"a record naming another Account": func(accounts.Account) ([]audit.Record, error) {
			return []audit.Record{
				passwordRecord("r1", audit.KindAccountCreate, "account_id=someone-else"),
				passwordRecord("r2", audit.KindPasswordTemporarySet, "account_id=someone-else"),
			}, nil
		},
		"no record id": func(c accounts.Account) ([]audit.Record, error) {
			return []audit.Record{
				passwordRecord("", audit.KindAccountCreate, "account_id="+c.ID),
				passwordRecord("r2", audit.KindPasswordTemporarySet, "account_id="+c.ID),
			}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := app.AppendWithTemporaryAccount(ctx, newHumanAccount("ghost"), hashOf(t, "a temporary password"), until, recs); err == nil {
				t.Fatal("AppendWithTemporaryAccount succeeded")
			}
			if _, err := st.Accounts().GetByName(ctx, "ghost"); !errors.Is(err, accounts.ErrNotFound) {
				t.Errorf("the Account survived a failed create: %v", err)
			}
			if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
				t.Errorf("the trail holds %d records after a failed create", len(recs))
			}
		})
	}

	// A colliding record id fails at the insert, after the Account and the
	// password are written: all of it rolls back.
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindPasswordSet)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AppendWithTemporaryAccount(ctx, newHumanAccount("ghost"), hashOf(t, "a temporary password"), until, twoRecords("dup", "rec-t")); err == nil {
		t.Fatal("a colliding record id was accepted")
	}
	if _, err := st.Accounts().GetByName(ctx, "ghost"); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("the Account survived an unrecordable create: %v", err)
	}
}

func TestAppendWithTemporaryAccount_RefusesAMachineAndAnInvalidAccount(t *testing.T) {
	st, _ := credentialFixture(t)
	ctx := context.Background()
	app := passwordAppender(t, st)
	until := passwordNow.Add(time.Hour)

	machine := accounts.Account{Name: "bot", Kind: accounts.KindMachine, Role: accounts.RoleViewer, Enabled: true}
	if _, err := app.AppendWithTemporaryAccount(ctx, machine, hashOf(t, "a temporary password"), until, twoRecords("a", "b")); !errors.Is(err, accounts.ErrMachinePassword) {
		t.Errorf("a machine create = %v, want ErrMachinePassword", err)
	}
	if _, err := app.AppendWithTemporaryAccount(ctx, newHumanAccount("admin"), hashOf(t, "a temporary password"), until, twoRecords("a", "b")); !errors.Is(err, accounts.ErrNameTaken) {
		t.Errorf("a name in use = %v, want ErrNameTaken", err)
	}
}

func TestAppendWithTemporaryPassword_RefusesOnceOwned(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	app := passwordAppender(t, st)
	until := passwordNow.Add(time.Hour)

	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "the humans own password")); err != nil {
		t.Fatal(err)
	}
	err := app.AppendWithTemporaryPassword(ctx, admin.ID, hashOf(t, "a temporary password"), until,
		passwordRecord("rec-1", audit.KindPasswordTemporarySet, "account_id="+admin.ID))
	if !errors.Is(err, accounts.ErrPasswordOwned) {
		t.Fatalf("err = %v, want ErrPasswordOwned", err)
	}
	got, _ := st.Passwords().GetPassword(ctx, admin.ID)
	if !got.Hash.Verify(accounts.NewPassword("the humans own password")) || got.Temporary() {
		t.Error("a refused issue changed the human's own password")
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
		t.Errorf("a refused issue wrote %d records", len(recs))
	}
}

func TestAppendWithTemporaryPassword_IssuesToAnAccountWithNoPasswordAndReplacesThePrevious(t *testing.T) {
	st, admin := credentialFixture(t) // no row: a human created with no password
	ctx := context.Background()
	app := passwordAppender(t, st)

	first := passwordNow.Add(time.Hour)
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, hashOf(t, "first temporary one"), first,
		passwordRecord("rec-1", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	second := passwordNow.Add(2 * time.Hour)
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, hashOf(t, "second temporary one"), second,
		passwordRecord("rec-2", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err != nil {
		t.Fatalf("re-issue: %v", err)
	}

	got, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash.Verify(accounts.NewPassword("first temporary one")) {
		t.Error("the replaced temporary password still verifies")
	}
	if !got.Hash.Verify(accounts.NewPassword("second temporary one")) || !got.TemporaryUntil.Equal(second) {
		t.Errorf("the re-issue is not stored: until %v, want %v", got.TemporaryUntil, second)
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 2 {
		t.Errorf("the trail holds %d records, want one per issue", len(recs))
	}
}

func TestAppendWithTemporaryPassword_RefusesAMachineAnUnknownAccountAndABadRecord(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	app := passwordAppender(t, st)
	until := passwordNow.Add(time.Hour)
	h := hashOf(t, "a temporary password")

	bot, err := st.Accounts().Create(ctx, accounts.Account{Name: "bot", Kind: accounts.KindMachine, Role: accounts.RoleViewer, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.AppendWithTemporaryPassword(ctx, bot.ID, h, until, passwordRecord("r1", audit.KindPasswordTemporarySet, "account_id="+bot.ID)); !errors.Is(err, accounts.ErrMachinePassword) {
		t.Errorf("a machine = %v, want ErrMachinePassword", err)
	}
	if err := app.AppendWithTemporaryPassword(ctx, "no-such", h, until, passwordRecord("r2", audit.KindPasswordTemporarySet, "account_id=no-such")); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("an unknown Account = %v, want ErrNotFound", err)
	}
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, h, until, passwordRecord("r3", audit.KindPasswordChange, "account_id="+admin.ID)); err == nil {
		t.Error("a password_temporary_set write accepted a password_change record")
	}
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, h, time.Time{}, passwordRecord("r4", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err == nil {
		t.Error("a temporary password with no expiry was accepted")
	}

	// An unrecordable issue leaves no password behind.
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindPasswordSet)); err != nil {
		t.Fatal(err)
	}
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, h, until, passwordRecord("dup", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err == nil {
		t.Fatal("a colliding record id was accepted")
	}
	if _, err := st.Passwords().GetPassword(ctx, admin.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Errorf("GetPassword after an unrecordable issue = %v, want ErrNoPassword", err)
	}
}

func TestAppendWithPasswordChange_ComparesAndSetsAndClearsTemporary(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	app := passwordAppender(t, st)

	temp := hashOf(t, "a temporary password")
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, temp, passwordNow.Add(time.Hour),
		passwordRecord("rec-1", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err != nil {
		t.Fatal(err)
	}

	mine := hashOf(t, "the humans own password")
	if err := app.AppendWithPasswordChange(ctx, admin.ID, temp, mine,
		passwordRecord("rec-2", audit.KindPasswordChange, "account_id="+admin.ID+" forced=true")); err != nil {
		t.Fatalf("change: %v", err)
	}
	got, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Temporary() || !got.Hash.Verify(accounts.NewPassword("the humans own password")) || got.Hash.Verify(accounts.NewPassword("a temporary password")) {
		t.Errorf("after the change: temporary=%v, hash verifies the new password only = %v", got.Temporary(), got.Hash.Verify(accounts.NewPassword("the humans own password")))
	}
	status, err := st.PasswordStatuses().Status(ctx, admin.ID)
	if err != nil || !status.Own || !status.TemporaryUntil.IsZero() {
		t.Errorf("Status = %+v, %v; want Own with no temporary expiry", status, err)
	}

	// Once the human owns it, no issue is accepted (the change is the lock).
	if err := app.AppendWithTemporaryPassword(ctx, admin.ID, temp, passwordNow.Add(time.Hour),
		passwordRecord("rec-3", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); !errors.Is(err, accounts.ErrPasswordOwned) {
		t.Errorf("an issue after the change = %v, want ErrPasswordOwned", err)
	}
}

func TestAppendWithPasswordChange_StaleExpectIsRefused(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	app := passwordAppender(t, st)

	verified := hashOf(t, "the verified password")
	if err := st.Passwords().SetPassword(ctx, admin.ID, verified); err != nil {
		t.Fatal(err)
	}
	// Another writer changes the password between the verification and the write.
	other := hashOf(t, "someone elses password")
	if err := st.Passwords().SetPassword(ctx, admin.ID, other); err != nil {
		t.Fatal(err)
	}

	err := app.AppendWithPasswordChange(ctx, admin.ID, verified, hashOf(t, "the new password"),
		passwordRecord("rec-1", audit.KindPasswordChange, "account_id="+admin.ID))
	if !errors.Is(err, accounts.ErrPasswordChanged) {
		t.Fatalf("err = %v, want ErrPasswordChanged", err)
	}
	got, _ := st.Passwords().GetPassword(ctx, admin.ID)
	if !got.Hash.Verify(accounts.NewPassword("someone elses password")) {
		t.Error("a stale change overwrote the password")
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
		t.Errorf("a refused change wrote %d records", len(recs))
	}

	// An unrecordable change is not made either.
	if err := st.Audit().Append(ctx, credentialRecord("dup", audit.KindPasswordSet)); err != nil {
		t.Fatal(err)
	}
	if err := app.AppendWithPasswordChange(ctx, admin.ID, other, hashOf(t, "the new password"),
		passwordRecord("dup", audit.KindPasswordChange, "account_id="+admin.ID)); err == nil {
		t.Fatal("a colliding record id was accepted")
	}
	got, _ = st.Passwords().GetPassword(ctx, admin.ID)
	if !got.Hash.Verify(accounts.NewPassword("someone elses password")) {
		t.Error("a change whose record could not be written was not rolled back")
	}
}

func TestSetPassword_ClearsTemporaryState(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()

	if err := passwordAppender(t, st).AppendWithTemporaryPassword(ctx, admin.ID, hashOf(t, "a temporary password"), passwordNow.Add(time.Hour),
		passwordRecord("rec-1", audit.KindPasswordTemporarySet, "account_id="+admin.ID)); err != nil {
		t.Fatal(err)
	}
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "a host lever password")); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Passwords().GetPassword(ctx, admin.ID)
	if got.Temporary() {
		t.Error("a host-lever set left the password temporary")
	}
}

func TestPasswordStatuses_ReportsUnknownNoRowAndNeverAHash(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	reader := st.PasswordStatuses()

	if _, err := reader.Status(ctx, "no-such"); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("an unknown Account = %v, want ErrNotFound", err)
	}
	status, err := reader.Status(ctx, admin.ID)
	if err != nil || status.Own || !status.TemporaryUntil.IsZero() {
		t.Errorf("an Account with no row = %+v, %v; want not Own and no expiry", status, err)
	}
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "the humans own password")); err != nil {
		t.Fatal(err)
	}
	if status, err = reader.Status(ctx, admin.ID); err != nil || !status.Own {
		t.Errorf("an Account with its own password = %+v, %v; want Own", status, err)
	}
}

func TestGetPassword_AnUnparseableTemporaryUntilIsMalformedNeverOwn(t *testing.T) {
	st, admin := credentialFixture(t)
	ctx := context.Background()
	if err := st.Passwords().SetPassword(ctx, admin.ID, hashOf(t, "the humans own password")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE account_passwords SET temporary_until = 'not a time' WHERE account_id = ?`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Passwords().GetPassword(ctx, admin.ID); !errors.Is(err, accounts.ErrPasswordHashMalformed) {
		t.Errorf("GetPassword = %v, want ErrPasswordHashMalformed: damage must not read as the human's own password", err)
	}
	if _, err := st.PasswordStatuses().Status(ctx, admin.ID); !errors.Is(err, accounts.ErrPasswordHashMalformed) {
		t.Errorf("Status = %v, want ErrPasswordHashMalformed", err)
	}
}

// Every password row written before migration 34 was set by relay init, so the
// column's default reads as the human's own password.
func TestMigration0034_ExistingRowsReadAsOwn(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema33.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	migrations, _ := seedMigrations(t, db, 34)

	if _, err := db.ExecContext(ctx, `INSERT INTO accounts (id, name, name_normalized, kind, role, created_at) VALUES ('acct-1', 'old', 'old', 'human', 'admin', ?)`, formatTime(passwordNow)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO account_passwords (account_id, password_hash, updated_at) VALUES ('acct-1', ?, ?)`, hashOf(t, "an init time password").Encoded(), formatTime(passwordNow)); err != nil {
		t.Fatal(err)
	}

	var applied bool
	for _, m := range migrations {
		if m.version == 34 {
			if !strings.Contains(m.name, "temporary") {
				t.Fatalf("migration 34 is %q, want the temporary password column", m.name)
			}
			if err := applyMigration(ctx, db, m, discardLogger()); err != nil {
				t.Fatalf("apply 34: %v", err)
			}
			applied = true
		}
	}
	if !applied {
		t.Fatal("no migration 34")
	}

	var until string
	if err := db.QueryRowContext(ctx, `SELECT temporary_until FROM account_passwords WHERE account_id = 'acct-1'`).Scan(&until); err != nil {
		t.Fatal(err)
	}
	if until != "" {
		t.Errorf("an existing row's temporary_until = %q, want '' (the human's own password)", until)
	}
}
