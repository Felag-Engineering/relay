package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

var _ audit.PasswordAppender = (*sqliteAudit)(nil)

// Each method below validates before BeginTx and then runs ONE transaction,
// which takes the write lock at BEGIN (sqliteDSN), so the check inside it and
// the write after it cannot interleave with another writer. A record that
// cannot be written rolls the password change back (ADR-0045 decisions 2, 10).
// No error here carries a hash.

// AppendWithTemporaryAccount creates the human Account a with its temporary
// password and chains the two records recs returns for it.
func (a *sqliteAudit) AppendWithTemporaryAccount(ctx context.Context, acct accounts.Account, h accounts.PasswordHash, until time.Time, recs func(created accounts.Account) ([]audit.Record, error)) (accounts.Account, error) {
	if acct.Kind != accounts.KindHuman {
		return accounts.Account{}, accounts.ErrMachinePassword
	}
	if err := validateForCreate(acct); err != nil {
		return accounts.Account{}, err
	}
	if h.IsZero() || until.IsZero() {
		return accounts.Account{}, errors.New("store: refusing a temporary password with no hash or expiry")
	}

	var created accounts.Account
	err := inTx(ctx, a.db, "account create with temporary password", "account create with temporary password", func(tx *sql.Tx) error {
		var err error
		created, err = insertAccountExec(ctx, tx, acct)
		if err != nil {
			return err
		}
		if err := setTemporaryPasswordExec(ctx, tx, created.ID, h, until, time.Now()); err != nil {
			return err
		}
		rs, err := recs(created)
		if err != nil {
			return err
		}
		prepared, err := prepareTemporaryAccountRecords(rs, created.ID)
		if err != nil {
			return err
		}
		return insertChained(ctx, tx, prepared)
	})
	if err != nil {
		return accounts.Account{}, err
	}
	return created, nil
}

func prepareTemporaryAccountRecords(rs []audit.Record, accountID string) ([]preparedAudit, error) {
	want := []string{audit.KindAccountCreate, audit.KindPasswordTemporarySet}
	if len(rs) != len(want) {
		return nil, errors.New("store: an account create with a temporary password records exactly an account_create and a password_temporary_set")
	}
	prepared := make([]preparedAudit, len(rs))
	for i, r := range rs {
		switch {
		case r.Kind != want[i]:
			return nil, fmt.Errorf("store: record %d of an account create with a temporary password must be %s", i+1, want[i])
		case r.ID == "":
			return nil, errors.New("store: refusing to record a credential change with no audit record id")
		case !strings.HasPrefix(r.Reason, "account_id="+accountID):
			return nil, errors.New("store: a record of an account create must name the Account it created")
		}
		p, err := prepareAudit(r)
		if err != nil {
			return nil, err
		}
		prepared[i] = p
	}
	return prepared, nil
}

// AppendWithTemporaryPassword issues accountID a temporary password while its
// human has never set their own, and chains r.
func (a *sqliteAudit) AppendWithTemporaryPassword(ctx context.Context, accountID string, h accounts.PasswordHash, until time.Time, r audit.Record) error {
	if h.IsZero() || until.IsZero() {
		return errors.New("store: refusing a temporary password with no hash or expiry")
	}
	p, err := preparePasswordRecord(r, audit.KindPasswordTemporarySet)
	if err != nil {
		return err
	}

	return inTx(ctx, a.db, "temporary password", "temporary password and record", func(tx *sql.Tx) error {
		var kind string
		err := tx.QueryRowContext(ctx, `SELECT kind FROM accounts WHERE id = ?`, accountID).Scan(&kind)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return accounts.ErrNotFound
		case err != nil:
			return fmt.Errorf("read account kind: %w", err)
		case accounts.Kind(kind) != accounts.KindHuman:
			return accounts.ErrMachinePassword
		}

		var temporaryUntil string
		err = tx.QueryRowContext(ctx,
			`SELECT temporary_until FROM account_passwords WHERE account_id = ?`, accountID).Scan(&temporaryUntil)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("read account password state: %w", err)
		case temporaryUntil == "":
			return accounts.ErrPasswordOwned
		}

		if err := setTemporaryPasswordExec(ctx, tx, accountID, h, until, time.Now()); err != nil {
			return err
		}
		return insertChained(ctx, tx, []preparedAudit{p})
	})
}

// AppendWithPasswordChange replaces accountID's hash with h if it still is
// expect, clearing any temporary state, and chains r.
func (a *sqliteAudit) AppendWithPasswordChange(ctx context.Context, accountID string, expect, h accounts.PasswordHash, r audit.Record) error {
	if h.IsZero() || expect.IsZero() {
		return errors.New("store: refusing a password change with no hash")
	}
	p, err := preparePasswordRecord(r, audit.KindPasswordChange)
	if err != nil {
		return err
	}

	return inTx(ctx, a.db, "password change", "password change and record", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE account_passwords
			SET password_hash = ?, updated_at = ?, temporary_until = ''
			WHERE account_id = ? AND password_hash = ?`,
			h.Encoded(), time.Now().UTC().Format(time.RFC3339Nano), accountID, expect.Encoded())
		if err != nil {
			return fmt.Errorf("store: change account password: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("store: change account password: %w", err)
		}
		if n == 0 {
			return accounts.ErrPasswordChanged
		}
		return insertChained(ctx, tx, []preparedAudit{p})
	})
}

func preparePasswordRecord(r audit.Record, kind string) (preparedAudit, error) {
	switch {
	case r.Kind != kind:
		return preparedAudit{}, fmt.Errorf("store: this password act is recorded only as a %s record", kind)
	case r.ID == "":
		return preparedAudit{}, errors.New("store: refusing to record a credential change with no audit record id")
	}
	return prepareAudit(r)
}
