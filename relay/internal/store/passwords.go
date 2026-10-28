package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// sqlitePasswords implements accounts.PasswordRepository against the
// account_passwords table (migration 0018).
//
// It never renders a hash into an error message or a log line — the values it
// handles are accounts.PasswordHash, which redacts under every stringifying
// interface, so an added `%v` cannot spill one.
type sqlitePasswords struct {
	db  *sql.DB
	now func() time.Time
}

var _ accounts.PasswordRepository = (*sqlitePasswords)(nil)

// SetPassword stores h as accountID's local password, replacing any existing
// one.
//
// The foreign key to accounts(id) is what turns "set a password for an Account
// that does not exist" into accounts.ErrNotFound rather than an orphaned row;
// it is enforced by the schema, so this cannot be bypassed by a caller that
// forgets to check first. (Store.Open enables foreign_keys — see store.go.)
func (r *sqlitePasswords) SetPassword(ctx context.Context, accountID string, h accounts.PasswordHash) error {
	return setPasswordExec(ctx, r.db, accountID, h, r.now())
}

func setPasswordExec(ctx context.Context, ex execer, accountID string, h accounts.PasswordHash, now time.Time) error {
	return upsertPasswordExec(ctx, ex, accountID, h, "", now)
}

// setTemporaryPasswordExec stores h as accountID's temporary password, refused
// at and after until (ADR-0045), replacing any existing one.
func setTemporaryPasswordExec(ctx context.Context, ex execer, accountID string, h accounts.PasswordHash, until, now time.Time) error {
	if until.IsZero() {
		return fmt.Errorf("store: refusing a temporary password with no expiry for account %q", accountID)
	}
	return upsertPasswordExec(ctx, ex, accountID, h, until.UTC().Format(time.RFC3339Nano), now)
}

// upsertPasswordExec is the one write of account_passwords' hash. A host-lever
// set writes an empty temporary_until and so clears temporary state: only a
// temporary issue writes an instant.
func upsertPasswordExec(ctx context.Context, ex execer, accountID string, h accounts.PasswordHash, temporaryUntil string, now time.Time) error {
	if h.IsZero() {
		return fmt.Errorf("store: refusing to store an empty password hash for account %q", accountID)
	}
	_, err := ex.ExecContext(ctx, `
		INSERT INTO account_passwords (account_id, password_hash, updated_at, temporary_until)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(account_id) DO UPDATE SET
			password_hash   = excluded.password_hash,
			updated_at      = excluded.updated_at,
			temporary_until = excluded.temporary_until`,
		accountID, h.Encoded(), now.UTC().Format(time.RFC3339Nano), temporaryUntil)
	if err != nil {
		if isForeignKeyViolation(err) {
			return accounts.ErrNotFound
		}
		return fmt.Errorf("store: set account password: %w", err)
	}
	return nil
}

// GetPassword returns accountID's stored password, or accounts.ErrNoPassword.
//
// A stored value that will not parse is returned as
// accounts.ErrPasswordHashMalformed, NOT as ErrNoPassword. The distinction is
// the whole point of parsing here: "no credential" and "a damaged credential"
// must not be the same answer, or corrupting a row would be an authentication
// bypass rather than an outage. An unparseable temporary_until is the same
// failure, never read as "the human's own password".
func (r *sqlitePasswords) GetPassword(ctx context.Context, accountID string) (accounts.StoredPassword, error) {
	var encoded, until string
	err := r.db.QueryRowContext(ctx,
		`SELECT password_hash, temporary_until FROM account_passwords WHERE account_id = ?`, accountID).Scan(&encoded, &until)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return accounts.StoredPassword{}, accounts.ErrNoPassword
	case err != nil:
		return accounts.StoredPassword{}, fmt.Errorf("store: get account password: %w", err)
	}
	h, err := accounts.ParsePasswordHash(encoded)
	if err != nil {
		return accounts.StoredPassword{}, err
	}
	sp := accounts.StoredPassword{Hash: h}
	if until != "" {
		sp.TemporaryUntil, err = time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return accounts.StoredPassword{}, accounts.ErrPasswordHashMalformed
		}
	}
	return sp, nil
}

// sqlitePasswordStatus implements accounts.PasswordStatusReader. It never
// selects password_hash, so a status read cannot return one.
type sqlitePasswordStatus struct{ db *sql.DB }

var _ accounts.PasswordStatusReader = (*sqlitePasswordStatus)(nil)

// Status derives eligibility from the row alone: an Account with no row, or a
// row with a temporary_until, has not set its own password. A future lever
// that deletes a row would make an Account eligible for a temporary password
// again, and must decide that deliberately.
func (r *sqlitePasswordStatus) Status(ctx context.Context, accountID string) (accounts.PasswordStatus, error) {
	var hasRow bool
	var until string
	err := r.db.QueryRowContext(ctx, `
		SELECT p.account_id IS NOT NULL, COALESCE(p.temporary_until, '')
		FROM accounts a LEFT JOIN account_passwords p ON p.account_id = a.id
		WHERE a.id = ?`, accountID).Scan(&hasRow, &until)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return accounts.PasswordStatus{}, accounts.ErrNotFound
	case err != nil:
		return accounts.PasswordStatus{}, fmt.Errorf("store: get account password status: %w", err)
	}
	st := accounts.PasswordStatus{Own: hasRow && until == ""}
	if until != "" {
		st.TemporaryUntil, err = time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return accounts.PasswordStatus{}, accounts.ErrPasswordHashMalformed
		}
	}
	return st, nil
}

// ClearPassword removes accountID's local password. Removing a row that is not
// there is not an error: the postcondition ("this Account has no local
// password") holds either way.
func (r *sqlitePasswords) ClearPassword(ctx context.Context, accountID string) error {
	_, err := clearPasswordExec(ctx, r.db, accountID)
	return err
}

// clearPasswordExec reports whether a row was actually removed.
func clearPasswordExec(ctx context.Context, ex execer, accountID string) (bool, error) {
	res, err := ex.ExecContext(ctx,
		`DELETE FROM account_passwords WHERE account_id = ?`, accountID)
	if err != nil {
		return false, fmt.Errorf("store: clear account password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: clear account password: %w", err)
	}
	return n > 0, nil
}
