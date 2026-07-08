package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// sqliteAudit implements audit.Repository against the audit table.
type sqliteAudit struct {
	db *sql.DB
}

var _ audit.Repository = (*sqliteAudit)(nil)

// Append persists a new Record.
func (a *sqliteAudit) Append(ctx context.Context, r audit.Record) error {
	argsJSON, err := encodeStringMap(r.Args)
	if err != nil {
		return err
	}
	argvJSON, err := encodeStringSlice(r.RawExecArgv)
	if err != nil {
		return err
	}

	_, err = a.db.ExecContext(ctx, `
		INSERT INTO audit (audit_id, ts, principal, selector, job_id, action_kind, operation_name, args, raw_exec_argv, outcome)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, formatTime(roundTripTime(r.Timestamp)), r.Principal, r.Selector, r.JobID, r.ActionKind,
		nullIfEmpty(r.OperationName), argsJSON, argvJSON, int(r.Outcome),
	)
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

// List returns all Records, ordered by Timestamp.
func (a *sqliteAudit) List(ctx context.Context) ([]audit.Record, error) {
	return a.query(ctx, `ORDER BY ts`)
}

// ByJob returns all Records for jobID, ordered by Timestamp.
func (a *sqliteAudit) ByJob(ctx context.Context, jobID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE job_id = ? ORDER BY ts`, jobID)
}

func (a *sqliteAudit) query(ctx context.Context, whereClause string, args ...any) ([]audit.Record, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT audit_id, ts, principal, selector, job_id, action_kind, operation_name, args, raw_exec_argv, outcome
		FROM audit `+whereClause, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer rows.Close()

	var out []audit.Record
	for rows.Next() {
		var (
			id, ts, principal, selector, jobID, actionKind string
			operationName                                  sql.NullString
			argsJSON, argvJSON                             sql.NullString
			outcome                                        int
		)
		if err := rows.Scan(&id, &ts, &principal, &selector, &jobID, &actionKind,
			&operationName, &argsJSON, &argvJSON, &outcome); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		tsTime, err := parseTime(sql.NullString{String: ts, Valid: true})
		if err != nil {
			return nil, fmt.Errorf("parse ts for audit record %q: %w", id, err)
		}
		args, err := decodeStringMap(argsJSON)
		if err != nil {
			return nil, err
		}
		argv, err := decodeStringSlice(argvJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, audit.Record{
			ID:            id,
			Timestamp:     tsTime,
			Principal:     principal,
			Selector:      selector,
			JobID:         jobID,
			ActionKind:    actionKind,
			OperationName: operationName.String,
			Args:          args,
			RawExecArgv:   argv,
			Outcome:       jobs.Outcome(outcome),
		})
	}
	return out, rows.Err()
}
