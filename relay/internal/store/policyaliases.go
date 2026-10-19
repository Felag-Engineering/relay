package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/policyalias"
)

// sqlitePolicyAliases implements policyalias.Reader against the
// policy_aliases table.
type sqlitePolicyAliases struct {
	db *sql.DB
}

var (
	_ policyalias.Reader        = (*sqlitePolicyAliases)(nil)
	_ audit.PolicyAliasAppender = (*sqliteAudit)(nil)
)

// List returns every alias held, fingerprint to alias. The map is fresh and
// never nil.
func (p *sqlitePolicyAliases) List(ctx context.Context) (map[string]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT fingerprint, alias FROM policy_aliases`)
	if err != nil {
		return nil, fmt.Errorf("query policy aliases: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp, alias string
		if err := rows.Scan(&fp, &alias); err != nil {
			return nil, fmt.Errorf("scan policy alias: %w", err)
		}
		out[fp] = alias
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy aliases: %w", err)
	}
	return out, nil
}

// AppendWithPolicyAlias applies c and chains r onto the trail in one
// transaction: on a nil error both landed, on a non-nil error neither did.
//
// The alias is written before the record, so a record that cannot be written
// rolls the alias back. The stored alias is re-checked against c.From inside
// the transaction (policyalias.ErrChanged), and the new alias against every
// other fingerprint (policyalias.ErrTaken). Every malformed call is refused
// before BeginTx.
func (a *sqliteAudit) AppendWithPolicyAlias(ctx context.Context, r audit.Record, c policyalias.Change) error {
	switch {
	case r.ID == "":
		return errors.New("store: refusing to record a Policy alias change with no audit record id")
	case r.Kind != audit.KindPolicyAlias:
		return errors.New("store: a Policy alias change is recorded only as a policy_alias record")
	case !wellFormedFingerprint(c.Fingerprint):
		return errors.New("store: refusing a Policy alias change for a fingerprint that is not 64 lowercase hexadecimal characters")
	case c.From == c.To:
		return errors.New("store: refusing a Policy alias change that changes nothing")
	}
	p, err := prepareAudit(r)
	if err != nil {
		return err
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy alias change: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var current string
	err = tx.QueryRowContext(ctx, `SELECT alias FROM policy_aliases WHERE fingerprint = ?`, c.Fingerprint).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read policy alias: %w", err)
	}
	if current != c.From {
		return policyalias.ErrChanged
	}

	if c.To != "" {
		var other string
		err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM policy_aliases WHERE alias = ? AND fingerprint <> ?`, c.To, c.Fingerprint).Scan(&other)
		if err == nil {
			return policyalias.ErrTaken
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check policy alias uniqueness: %w", err)
		}
	}

	if c.To == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM policy_aliases WHERE fingerprint = ?`, c.Fingerprint)
	} else {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO policy_aliases (fingerprint, alias, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT(fingerprint) DO UPDATE SET
				alias = excluded.alias,
				updated_at = excluded.updated_at`,
			c.Fingerprint, c.To, formatTime(roundTripTime(time.Now().UTC())))
	}
	if err != nil {
		return fmt.Errorf("write policy alias: %w", err)
	}

	if err := insertChained(ctx, tx, []preparedAudit{p}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy alias change and record: %w", err)
	}
	return nil
}

// wellFormedFingerprint reports whether fp is 64 lowercase hexadecimal
// characters, the daemon's Policy fingerprint. The capability layer checks the
// same shape; the store does not trust its caller to have.
func wellFormedFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		if c := fp[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
