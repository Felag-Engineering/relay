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

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
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
	defer rows.Close()

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

// setRoleGuardSQL is SetRole's single UPDATE: it changes role IFF
// the stored role is still :from AND doing so does not leave zero enabled
// admin rows. The WHERE clause is a conjunction of
//
//   - role = :from                        — the compare of the compare-and-set: a
//     caller that decided something from the role it read (the Console's step-up
//     classification) writes only if that role is still the stored one.
//
// and a disjunction of "this change cannot possibly be the one that empties the
// enabled-admin set":
//
//   - :role = 'admin'                     — this is a promotion, never a problem.
//   - role <> 'admin'                     — the row being changed is not an admin at all.
//   - enabled = 0                         — the row is a disabled admin; it was never
//     counted as an enabled admin, so changing its role removes nothing.
//   - EXISTS (... o.id <> :id)            — another enabled admin exists, so this row
//     is not the last one.
//
// This is the same rule ErrNameTaken's guard already applies in this file
// (insert, above): "The UNIQUE index on name_normalized is the authority on
// collisions — a pre-check would race another writer between SELECT and
// INSERT." The last-admin guard is that argument applied to a second
// invariant, over a COUNT rather than a UNIQUE index, which is why it has to
// be expressed as a WHERE clause rather than a constraint.
//
// SetMaxOpenConns(1) (store.go:171) serialises STATEMENTS, not the
// read-then-write SEQUENCE a layer-level check would need: two goroutines can
// each complete a read and then each issue a write. Putting the guard inside
// this one statement is what makes it atomic; a check-then-write above the
// store would not be (TestSQLiteAccounts_LastAdminGuardIsASingleStatement
// pins this as a source-level fact, since a goroutine race would pass against
// either shape under a single-connection pool).
//
// sql.Named binds :id (and :role) by name rather than position: this
// statement uses :id twice and :role twice, and a positional rewrite that
// silently transposed one pair would fail OPEN in at least one direction.
const setRoleGuardSQL = `UPDATE accounts SET role = :role
	WHERE id = :id
	  AND role = :from
	  AND (:role = 'admin' OR role <> 'admin' OR enabled = 0
	       OR EXISTS (SELECT 1 FROM accounts o
	                   WHERE o.role = 'admin' AND o.enabled = 1 AND o.id <> :id))`

// setDisabledGuardSQL is SetEnabled(false)'s single UPDATE: the same
// shape as setRoleGuardSQL, minus the ":role = 'admin'" promotion disjunct,
// since disabling is never a promotion. Enabling is never guarded at all —
// see SetEnabled below.
const setDisabledGuardSQL = `UPDATE accounts SET enabled = 0
	WHERE id = :id
	  AND (role <> 'admin' OR enabled = 0
	       OR EXISTS (SELECT 1 FROM accounts o
	                   WHERE o.role = 'admin' AND o.enabled = 1 AND o.id <> :id))`

// SetRole changes an Account's role from `from` to `to`, effective
// immediately. Returns accounts.ErrRoleChanged if the stored role is not
// `from`, and accounts.ErrLastAdmin if the change would demote the last
// enabled admin — see setRoleGuardSQL and updateGuarded.
func (r *sqliteAccounts) SetRole(ctx context.Context, id string, from, to accounts.Role) error {
	if !from.Valid() || !to.Valid() {
		return accounts.ErrInvalidRole
	}
	return r.updateGuarded(ctx, setRoleGuardSQL, id, roleRefusal(from),
		sql.Named("role", string(to)), sql.Named("from", string(from)))
}

// SetEnabled enables or disables an Account, effective immediately. Enabling
// is unguarded — it can never empty the enabled-admin set. Disabling returns
// accounts.ErrLastAdmin if it would leave zero enabled admin rows — see
// setDisabledGuardSQL and updateGuarded.
func (r *sqliteAccounts) SetEnabled(ctx context.Context, id string, enabled bool) error {
	if enabled {
		return r.update(ctx, `UPDATE accounts SET enabled = ? WHERE id = ?`, boolToInt(true), id)
	}
	return r.updateGuarded(ctx, setDisabledGuardSQL, id, lastAdminRefusal)
}

func (r *sqliteAccounts) update(ctx context.Context, query string, value any, id string) error {
	res, err := r.db.ExecContext(ctx, query, value, id)
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}
	return rowsAffectedOr(res, accounts.ErrNotFound, "update account rows affected")
}

// updateGuarded runs a single guarded UPDATE (query, built from extraArgs
// plus a `:id` binding this function builds ITSELF from id) and, when it
// affects zero rows, disambiguates WHY: accounts.ErrNotFound if id does not
// exist, otherwise whatever refused(current) names (ErrLastAdmin, or for
// SetRole ErrRoleChanged when the stored role is no longer the one expected).
//
// The `:id` binding is built here, once, rather than passed in by each
// caller alongside the OTHER copy of id used for the Get disambiguation
// below — a caller passing its own sql.Named("id", id) is a second place the
// same value could be spelled differently by a future edit and silently
// diverge from the id the disambiguation actually checks. Building it here
// from the same id parameter both uses makes that divergence impossible
// rather than merely unlikely.
//
// The not-found disambiguation is EXACT, for two reasons specific to this
// schema: accounts.Repository has no Delete, so a row can never vanish
// between the UPDATE and the Get below — an id that existed a moment ago
// still exists now, or it never did. And SQLite counts a no-op UPDATE (new
// value equals the old one) as one changed row, not zero, so a redundant
// write can never be mistaken for a refused one.
//
// Between a role mismatch and the last-admin guard the explanation is
// best-effort: a second writer landing between the UPDATE and the Get can
// change which reason is reported, in either direction (a mismatch that was
// restored in the gap reads as ErrLastAdmin; a last-admin refusal followed by
// a role change reads as ErrRoleChanged). Every outcome is still a refusal
// with nothing written, and n > 0 is the only nil return, so this can never
// fail open. Mismatch is checked first so a stale caller is told to re-read.
// There is deliberately no transaction around UPDATE+Get: r.Get uses r.db,
// and under SetMaxOpenConns(1) a transaction holding the only connection
// would deadlock against it; an exact message would need a tx-scoped scan, which
// is churn for a wording-only gain.
func (r *sqliteAccounts) updateGuarded(ctx context.Context, query string, id string, refused func(current accounts.Account) error, extraArgs ...any) error {
	args := append(append([]any{}, extraArgs...), sql.Named("id", id))
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update account rows affected: %w", err)
	}
	if n > 0 {
		return nil
	}
	cur, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	return refused(cur)
}

// lastAdminRefusal names why a zero-row SetEnabled was refused: the last-admin
// guard is the only condition its UPDATE adds.
func lastAdminRefusal(accounts.Account) error { return accounts.ErrLastAdmin }

// roleRefusal names why a zero-row SetRole was refused: a stored role that is
// no longer `from` is ErrRoleChanged, otherwise the last-admin guard.
func roleRefusal(from accounts.Role) func(accounts.Account) error {
	return func(cur accounts.Account) error {
		if cur.Role != from {
			return accounts.ErrRoleChanged
		}
		return accounts.ErrLastAdmin
	}
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

// isForeignKeyViolation reports whether err is a FOREIGN KEY constraint
// failure. Matched on the driver's message for the same reason
// isUniqueViolation is, and narrow enough that any other error surfaces as
// itself.
func isForeignKeyViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "foreign key constraint failed")
}
