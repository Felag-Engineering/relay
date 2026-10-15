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
	if h.IsZero() {
		return fmt.Errorf("store: refusing to store an empty password hash for account %q", accountID)
	}
	_, err := ex.ExecContext(ctx, `
		INSERT INTO account_passwords (account_id, password_hash, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(account_id) DO UPDATE SET
			password_hash = excluded.password_hash,
			updated_at    = excluded.updated_at`,
		accountID, h.Encoded(), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		if isForeignKeyViolation(err) {
			return accounts.ErrNotFound
		}
		return fmt.Errorf("store: set account password: %w", err)
	}
	return nil
}

// GetPassword returns accountID's stored hash, or accounts.ErrNoPassword.
//
// A stored value that will not parse is returned as
// accounts.ErrPasswordHashMalformed, NOT as ErrNoPassword. The distinction is
// the whole point of parsing here: "no credential" and "a damaged credential"
// must not be the same answer, or corrupting a row would be an authentication
// bypass rather than an outage.
func (r *sqlitePasswords) GetPassword(ctx context.Context, accountID string) (accounts.PasswordHash, error) {
	var encoded string
	err := r.db.QueryRowContext(ctx,
		`SELECT password_hash FROM account_passwords WHERE account_id = ?`, accountID).Scan(&encoded)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return accounts.PasswordHash{}, accounts.ErrNoPassword
	case err != nil:
		return accounts.PasswordHash{}, fmt.Errorf("store: get account password: %w", err)
	}
	return accounts.ParsePasswordHash(encoded)
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
