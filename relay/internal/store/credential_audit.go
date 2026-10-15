package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// execer is what *sql.DB and *sql.Tx share, so one SQL body serves both the
// plain repository method and its transactional "Recorded" twin.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// recordWith runs change and appends the audit record it returns in ONE
// transaction: on a nil error both landed, on any error neither did. That is
// the fail-closed property the host credential levers require — a
// credential change that cannot be recorded is not made.
//
// change returns the record so a change can report what it found (whether a
// password was there to clear) into the record it is written with.
func (s *Store) recordWith(ctx context.Context, change func(context.Context, execer) (audit.Record, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin credential change: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	rec, err := change(ctx, tx)
	if err != nil {
		return err
	}
	if rec.ID == "" {
		return errors.New("store: refusing to record a credential change with no audit record id")
	}
	p, err := prepareAudit(rec)
	if err != nil {
		return err
	}
	if err := insertChained(ctx, tx, []preparedAudit{p}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit credential change and audit record: %w", err)
	}
	return nil
}

// SetPasswordRecorded sets accountID's password and appends rec atomically.
func (s *Store) SetPasswordRecorded(ctx context.Context, accountID string, h accounts.PasswordHash, rec audit.Record) error {
	return s.recordWith(ctx, func(ctx context.Context, ex execer) (audit.Record, error) {
		return rec, setPasswordExec(ctx, ex, accountID, h, time.Now())
	})
}

// ClearPasswordRecorded removes accountID's password and appends the record
// built by recFor atomically. recFor is told whether a password was actually
// removed (the DELETE's rows affected).
func (s *Store) ClearPasswordRecorded(ctx context.Context, accountID string, recFor func(removed bool) (audit.Record, error)) error {
	return s.recordWith(ctx, func(ctx context.Context, ex execer) (audit.Record, error) {
		removed, err := clearPasswordExec(ctx, ex, accountID)
		if err != nil {
			return audit.Record{}, err
		}
		return recFor(removed)
	})
}

// CreateAPITokenRecorded stores t and appends rec atomically.
func (s *Store) CreateAPITokenRecorded(ctx context.Context, t accounts.APIToken, rec audit.Record) error {
	return s.recordWith(ctx, func(ctx context.Context, ex execer) (audit.Record, error) {
		return rec, createTokenExec(ctx, ex, t)
	})
}
