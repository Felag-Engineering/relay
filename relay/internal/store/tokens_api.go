package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// sqliteAPITokens implements accounts.TokenRepository against the api_tokens
// table (migration 0009). Pure persistence: expiry, revocation, and Account
// state are decided by accounts.TokenService, never here.
type sqliteAPITokens struct {
	db *sql.DB
}

var _ accounts.TokenRepository = (*sqliteAPITokens)(nil)

// CreateToken stores a newly minted token.
func (r *sqliteAPITokens) CreateToken(ctx context.Context, t accounts.APIToken) error {
	return createTokenExec(ctx, r.db, t)
}

func createTokenExec(ctx context.Context, ex execer, t accounts.APIToken) error {
	_, err := ex.ExecContext(ctx, `
		INSERT INTO api_tokens (id, account_id, name, secret_hash, created_at, expires_at, last_used_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
		t.ID, t.AccountID, t.Name, t.SecretHash,
		formatTime(roundTripTime(t.CreatedAt)), nullTime(t.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("insert api token: %w", err)
	}
	return nil
}

// TokenByID returns the stored token, or accounts.ErrTokenNotFound.
func (r *sqliteAPITokens) TokenByID(ctx context.Context, id string) (accounts.APIToken, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, account_id, name, secret_hash, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens WHERE id = ?`, id)
	tok, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return accounts.APIToken{}, accounts.ErrTokenNotFound
	}
	return tok, err
}

// TokensByAccount lists an Account's tokens, newest first.
func (r *sqliteAPITokens) TokensByAccount(ctx context.Context, accountID string) ([]accounts.APIToken, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, account_id, name, secret_hash, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens WHERE account_id = ? ORDER BY created_at DESC, id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	var out []accounts.APIToken
	for rows.Next() {
		tok, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api tokens: %w", err)
	}
	return out, nil
}

// RevokeToken marks a token revoked. Revoking an already-revoked token is a
// no-op: revocation asserts an end state, and an operator racing themselves
// mid-incident should not see a failure. An unknown id IS an error — that is a
// typo the operator needs to hear about while they still believe they revoked
// something.
func (r *sqliteAPITokens) RevokeToken(ctx context.Context, id string, at time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`,
		formatTime(roundTripTime(at)), id)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	return rowsAffectedOr(res, accounts.ErrTokenNotFound, "revoke api token rows affected")
}

// TouchTokenLastUsed records a successful verification.
func (r *sqliteAPITokens) TouchTokenLastUsed(ctx context.Context, id string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`,
		formatTime(roundTripTime(at)), id)
	if err != nil {
		return fmt.Errorf("touch api token: %w", err)
	}
	return nil
}

func scanToken(s rowScanner) (accounts.APIToken, error) {
	var (
		id, accountID, name              string
		secretHash                       []byte
		createdAt                        string
		expiresAt, lastUsedAt, revokedAt sql.NullString
	)
	if err := s.Scan(&id, &accountID, &name, &secretHash, &createdAt, &expiresAt, &lastUsedAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return accounts.APIToken{}, err
		}
		return accounts.APIToken{}, fmt.Errorf("scan api token: %w", err)
	}

	created, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return accounts.APIToken{}, fmt.Errorf("parse created_at for token %q: %w", id, err)
	}
	expires, err := parseTime(expiresAt)
	if err != nil {
		return accounts.APIToken{}, fmt.Errorf("parse expires_at for token %q: %w", id, err)
	}
	lastUsed, err := parseTime(lastUsedAt)
	if err != nil {
		return accounts.APIToken{}, fmt.Errorf("parse last_used_at for token %q: %w", id, err)
	}
	revoked, err := parseTime(revokedAt)
	if err != nil {
		return accounts.APIToken{}, fmt.Errorf("parse revoked_at for token %q: %w", id, err)
	}

	return accounts.APIToken{
		ID:         id,
		AccountID:  accountID,
		Name:       name,
		SecretHash: secretHash,
		CreatedAt:  created,
		ExpiresAt:  expires,
		LastUsedAt: lastUsed,
		RevokedAt:  revoked,
	}, nil
}
