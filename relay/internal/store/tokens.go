package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
)

// sqliteTokens implements enroll.Repository against the tokens table. Making the
// store the authority for Enrollment Tokens is what lets a revoked (or partly
// used) token survive a Relay restart (issue #133, ADR-0006): the memory
// repository lost that state at every restart.
type sqliteTokens struct {
	db *sql.DB
}

var _ enroll.Repository = (*sqliteTokens)(nil)

// Create inserts t. Returns enroll.ErrDuplicateID if a token with the same ID
// already exists. The existence check runs inside the transaction (mirroring
// sqliteRegistry.Upsert) rather than matching a driver-specific UNIQUE error.
func (r *sqliteTokens) Create(ctx context.Context, t *enroll.Token) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM tokens WHERE token_id = ?`, t.ID).Scan(&one)
	if err == nil {
		return enroll.ErrDuplicateID
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check token exists: %w", err)
	}

	scopeJSON, err := encodeStringSlice(t.Scope)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tokens (token_id, secret_hash, scope, expires_at, revoked,
			max_uses, uses, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SecretHash, scopeJSON, formatTime(roundTripTime(t.ExpiresAt)), boolToInt(t.Revoked),
		t.MaxUses, t.Uses, formatTime(roundTripTime(t.CreatedAt)), t.CreatedBy,
	); err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	return tx.Commit()
}

// ByID returns the stored token or enroll.ErrNotFound. Each read builds a fresh
// *enroll.Token (new SecretHash and Scope slices), so the result is inherently a
// defensive copy.
func (r *sqliteTokens) ByID(ctx context.Context, id string) (*enroll.Token, error) {
	var (
		secretHash    []byte
		scope         sql.NullString
		expiresAt     string
		revoked       int
		maxUses, uses int
		createdAt     string
		createdBy     string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT secret_hash, scope, expires_at, revoked, max_uses, uses, created_at, created_by
		FROM tokens WHERE token_id = ?`, id,
	).Scan(&secretHash, &scope, &expiresAt, &revoked, &maxUses, &uses, &createdAt, &createdBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, enroll.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query token %q: %w", id, err)
	}

	scopeSlice, err := decodeStringSlice(scope)
	if err != nil {
		return nil, err
	}
	expiresAtTime, err := parseTime(sql.NullString{String: expiresAt, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("parse expires_at for token %q: %w", id, err)
	}
	createdAtTime, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("parse created_at for token %q: %w", id, err)
	}

	return &enroll.Token{
		ID:         id,
		SecretHash: secretHash,
		Scope:      scopeSlice,
		ExpiresAt:  expiresAtTime,
		Revoked:    revoked != 0,
		MaxUses:    maxUses,
		Uses:       uses,
		CreatedAt:  createdAtTime,
		CreatedBy:  createdBy,
	}, nil
}

// Save persists the only mutable fields of an existing token (Revoked, Uses),
// matching the enroll.Repository contract. Returns enroll.ErrNotFound if no
// token with that ID exists.
func (r *sqliteTokens) Save(ctx context.Context, t *enroll.Token) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked = ?, uses = ? WHERE token_id = ?`,
		boolToInt(t.Revoked), t.Uses, t.ID)
	if err != nil {
		return fmt.Errorf("update token: %w", err)
	}
	return rowsAffectedOr(res, enroll.ErrNotFound, "rows affected")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
