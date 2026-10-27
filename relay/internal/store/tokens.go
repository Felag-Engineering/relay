package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// sqliteTokens implements enroll.Repository against the tokens table. Making the
// store the authority for Enrollment Tokens is what lets a revoked (or partly
// used) token survive a Relay restart (ADR-0006): the memory
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

	scopeJSON, err := encodeTokenList(t.LegacyScope)
	if err != nil {
		return err
	}
	tagsJSON, err := encodeTokenList(t.InitialTags)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tokens (token_id, secret_hash, scope, initial_tags, expires_at, revoked,
			max_uses, uses, created_at, created_by, created_by_account_id, created_by_human)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SecretHash, scopeJSON, tagsJSON, formatTime(roundTripTime(t.ExpiresAt)), boolToInt(t.Revoked),
		t.MaxUses, t.Uses, formatTime(roundTripTime(t.CreatedAt)), t.CreatedBy,
		t.CreatedByAccountID, boolToInt(t.CreatedByHuman),
	); err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	return tx.Commit()
}

// encodeTokenList renders a token's list column. Both columns are NOT NULL, so a
// nil list is stored as an empty array.
func encodeTokenList(list []string) (string, error) {
	if list == nil {
		return "[]", nil
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("encode token list: %w", err)
	}
	return string(b), nil
}

// ByID returns the stored token or enroll.ErrNotFound. Each read builds a fresh
// *enroll.Token (new SecretHash, LegacyScope and InitialTags slices), so the
// result is inherently a defensive copy.
func (r *sqliteTokens) ByID(ctx context.Context, id string) (*enroll.Token, error) {
	var (
		secretHash    []byte
		scope         sql.NullString
		initialTags   sql.NullString
		expiresAt     string
		revoked       int
		maxUses, uses int
		createdAt     string
		createdBy     string
		byAccountID   string
		byHuman       int
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT secret_hash, scope, initial_tags, expires_at, revoked, max_uses, uses, created_at,
			created_by, created_by_account_id, created_by_human
		FROM tokens WHERE token_id = ?`, id,
	).Scan(&secretHash, &scope, &initialTags, &expiresAt, &revoked, &maxUses, &uses, &createdAt,
		&createdBy, &byAccountID, &byHuman)
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
	tagsSlice, err := decodeStringSlice(initialTags)
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
		ID:                 id,
		SecretHash:         secretHash,
		LegacyScope:        scopeSlice,
		InitialTags:        tagsSlice,
		ExpiresAt:          expiresAtTime,
		Revoked:            revoked != 0,
		MaxUses:            maxUses,
		Uses:               uses,
		CreatedAt:          createdAtTime,
		CreatedBy:          createdBy,
		CreatedByAccountID: byAccountID,
		CreatedByHuman:     byHuman != 0,
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
