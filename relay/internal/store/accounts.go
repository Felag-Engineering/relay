package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// sqliteAccounts implements accounts.Repository against the accounts table
// (migration 0008). Validation lives here as well as in the domain package
// because this is the single write path every surface funnels through: the
// CHECK constraints in the schema are defense-in-depth, not the primary guard.
type sqliteAccounts struct {
	db *sql.DB
}

var _ accounts.Repository = (*sqliteAccounts)(nil)

// newAccountID returns a random, opaque Account identifier.
//
// Random rather than sequential: an Account ID appears in audit records and
// (later) API paths, and a guessable/enumerable identifier leaks how many
// Accounts exist and in what order they were created. Mirrors the node-/
// token-ID convention in internal/enroll.
func newAccountID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate account id: %w", err)
	}
	return "acct-" + hex.EncodeToString(b), nil
}

// validateForCreate applies the domain rules Create promises, before touching
// the database.
func validateForCreate(a accounts.Account) error {
	if err := accounts.ValidateName(a.Name); err != nil {
		return err
	}
	if !a.Kind.Valid() {
		return accounts.ErrInvalidKind
	}
	if !a.Role.Valid() {
		return accounts.ErrInvalidRole
	}
	if accounts.NormalizeName(a.Name) == accounts.FoundingAdminName {
		return accounts.ErrReservedName
	}
	return nil
}

// Create stores a new Account. See accounts.Repository.Create.
func (r *sqliteAccounts) Create(ctx context.Context, a accounts.Account) (accounts.Account, error) {
	if err := validateForCreate(a); err != nil {
		return accounts.Account{}, err
	}
	return r.insert(ctx, a)
}

// insert is Create without the reserved-name check, so seeding can create the
// founding admin that Create deliberately refuses.
func (r *sqliteAccounts) insert(ctx context.Context, a accounts.Account) (accounts.Account, error) {
	id, err := newAccountID()
	if err != nil {
		return accounts.Account{}, err
	}
	now := roundTripTime(time.Now())
	normalized := accounts.NormalizeName(a.Name)

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO accounts (id, name, name_normalized, kind, role, enabled, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		id, a.Name, normalized, string(a.Kind), string(a.Role), boolToInt(a.Enabled), formatTime(now),
	)
	if err != nil {
		// The UNIQUE index on name_normalized is the authority on collisions —
		// a pre-check would race another writer between SELECT and INSERT.
		if isUniqueViolation(err) {
			return accounts.Account{}, accounts.ErrNameTaken
		}
		return accounts.Account{}, fmt.Errorf("insert account: %w", err)
	}

	return accounts.Account{
		ID:        id,
		Name:      a.Name,
		Kind:      a.Kind,
		Role:      a.Role,
		Enabled:   a.Enabled,
		CreatedAt: now,
	}, nil
}

// Get returns the Account with the given ID, or accounts.ErrNotFound.
func (r *sqliteAccounts) Get(ctx context.Context, id string) (accounts.Account, error) {
	return r.scanOne(ctx, `SELECT id, name, kind, role, enabled, created_at, last_seen_at
		FROM accounts WHERE id = ?`, id)
}

// GetByName returns the Account with the given (normalized) name.
func (r *sqliteAccounts) GetByName(ctx context.Context, name string) (accounts.Account, error) {
	return r.scanOne(ctx, `SELECT id, name, kind, role, enabled, created_at, last_seen_at
		FROM accounts WHERE name_normalized = ?`, accounts.NormalizeName(name))
}

func (r *sqliteAccounts) scanOne(ctx context.Context, query string, arg any) (accounts.Account, error) {
	var (
		id, name, kind, role string
		enabled              int
		createdAt            string
		lastSeenAt           sql.NullString
	)
	err := r.db.QueryRowContext(ctx, query, arg).
		Scan(&id, &name, &kind, &role, &enabled, &createdAt, &lastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return accounts.Account{}, accounts.ErrNotFound
	}
	if err != nil {
		return accounts.Account{}, fmt.Errorf("query account: %w", err)
	}

	created, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return accounts.Account{}, fmt.Errorf("parse created_at for account %q: %w", id, err)
	}
	lastSeen, err := parseTime(lastSeenAt)
	if err != nil {
		return accounts.Account{}, fmt.Errorf("parse last_seen_at for account %q: %w", id, err)
	}

	return accounts.Account{
		ID:         id,
		Name:       name,
		Kind:       accounts.Kind(kind),
		Role:       accounts.Role(role),
		Enabled:    enabled != 0,
		CreatedAt:  created,
		LastSeenAt: lastSeen,
	}, nil
}

// List returns every Account, ordered by name.
func (r *sqliteAccounts) List(ctx context.Context) ([]accounts.Account, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM accounts ORDER BY name_normalized`)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan account id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}

	out := make([]accounts.Account, 0, len(ids))
	for _, id := range ids {
		a, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// SetRole changes an Account's role, effective immediately.
func (r *sqliteAccounts) SetRole(ctx context.Context, id string, role accounts.Role) error {
	if !role.Valid() {
		return accounts.ErrInvalidRole
	}
	return r.update(ctx, `UPDATE accounts SET role = ? WHERE id = ?`, string(role), id)
}

// SetEnabled enables or disables an Account, effective immediately.
func (r *sqliteAccounts) SetEnabled(ctx context.Context, id string, enabled bool) error {
	return r.update(ctx, `UPDATE accounts SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
}

func (r *sqliteAccounts) update(ctx context.Context, query string, value any, id string) error {
	res, err := r.db.ExecContext(ctx, query, value, id)
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update account rows affected: %w", err)
	}
	if n == 0 {
		return accounts.ErrNotFound
	}
	return nil
}

// TouchLastSeen records a successful authentication.
func (r *sqliteAccounts) TouchLastSeen(ctx context.Context, id string, at time.Time) error {
	return r.update(ctx, `UPDATE accounts SET last_seen_at = ? WHERE id = ?`,
		formatTime(roundTripTime(at)), id)
}

// EnsureFoundingAdmin creates the founding admin Account if absent and returns
// it either way — idempotent and deterministic across restarts.
//
// It never modifies an existing founding admin. If an operator has disabled it
// or changed its role (both legitimate: that is how you retire the seeded
// credential's authority once real Accounts exist), that decision survives
// every subsequent start. A seeding routine that "repaired" the row on boot
// would silently undo a deliberate security action.
func (r *sqliteAccounts) EnsureFoundingAdmin(ctx context.Context) (accounts.Account, error) {
	existing, err := r.GetByName(ctx, accounts.FoundingAdminName)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, accounts.ErrNotFound) {
		return accounts.Account{}, err
	}

	created, err := r.insert(ctx, accounts.Account{
		Name:    accounts.FoundingAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	})
	if errors.Is(err, accounts.ErrNameTaken) {
		// Lost a race with another writer that seeded it first; the row now
		// exists, which is exactly the desired end state.
		return r.GetByName(ctx, accounts.FoundingAdminName)
	}
	if err != nil {
		return accounts.Account{}, err
	}
	return created, nil
}

// isUniqueViolation reports whether err is a UNIQUE-constraint failure.
//
// Matched on the driver's message rather than a typed error: modernc.org/sqlite
// does not export a stable sentinel for this, and the alternative — a
// SELECT-then-INSERT pre-check — is racy by construction. The match is narrow
// enough that any other error still surfaces as itself.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
