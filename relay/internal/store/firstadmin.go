package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// FirstAdminCredentials is what the first admin is created with: the hash of
// its Console password, and a function that makes its first API Token and the
// audit records for the whole act once the Account's ID exists. Neither carries
// a plaintext the store could write.
type FirstAdminCredentials struct {
	Password accounts.PasswordHash
	// Issue returns the token to store for acct and the records to append, in
	// order, in the same transaction.
	Issue func(acct accounts.Account) (accounts.APIToken, []audit.Record, error)
}

// CreateFirstAdminRecorded creates the first admin (RC-28): on a store holding
// no human Account, one human Account a, its Console password, its first API
// Token, and the audit records Issue returns, in ONE transaction. Any failure
// leaves the store as it was. A store already holding a human Account returns
// accounts.ErrHumanAccountExists and writes nothing; the check runs inside the
// transaction, which takes the write lock at BEGIN (sqliteDSN), so two callers
// cannot both find the store empty.
func (s *Store) CreateFirstAdminRecorded(ctx context.Context, a accounts.Account, c FirstAdminCredentials) (accounts.Account, error) {
	if a.Kind != accounts.KindHuman || a.Role != accounts.RoleAdmin || !a.Enabled {
		return accounts.Account{}, errors.New("store: the first admin is an enabled human admin")
	}
	if err := validateForCreate(a); err != nil {
		return accounts.Account{}, err
	}
	if c.Issue == nil {
		return accounts.Account{}, errors.New("store: the first admin needs its first API Token")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("begin first admin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var humans int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM accounts WHERE kind = ?`, string(accounts.KindHuman)).Scan(&humans); err != nil {
		return accounts.Account{}, fmt.Errorf("count human accounts: %w", err)
	}
	if humans > 0 {
		return accounts.Account{}, accounts.ErrHumanAccountExists
	}

	created, err := insertAccountExec(ctx, tx, a)
	if err != nil {
		return accounts.Account{}, err
	}
	if err := setPasswordExec(ctx, tx, created.ID, c.Password, time.Now()); err != nil {
		return accounts.Account{}, err
	}
	tok, recs, err := c.Issue(created)
	if err != nil {
		return accounts.Account{}, err
	}
	if tok.AccountID != created.ID {
		return accounts.Account{}, errors.New("store: the first admin's token names another account")
	}
	if err := createTokenExec(ctx, tx, tok); err != nil {
		return accounts.Account{}, err
	}
	if len(recs) == 0 {
		return accounts.Account{}, errors.New("store: refusing to create the first admin with no audit record")
	}
	prepared := make([]preparedAudit, 0, len(recs))
	for _, rec := range recs {
		if rec.ID == "" {
			return accounts.Account{}, errors.New("store: refusing to record the first admin with no audit record id")
		}
		p, err := prepareAudit(rec)
		if err != nil {
			return accounts.Account{}, err
		}
		prepared = append(prepared, p)
	}
	if err := insertChained(ctx, tx, prepared); err != nil {
		return accounts.Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return accounts.Account{}, fmt.Errorf("commit first admin and audit records: %w", err)
	}
	return created, nil
}
