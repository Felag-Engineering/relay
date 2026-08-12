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

	// Stdout/Stderr are stored raw, exactly as delivered — no redaction or
	// scrubbing (secrets in command output are retained by design; Policy is
	// the place to prevent secret-emitting commands, ADR-0002). This mirrors
	// how tasks.go persists Task output.
	v, as := r.Attribution.Verified, r.Attribution.Asserted
	_, err = a.db.ExecContext(ctx, `
		INSERT INTO audit (audit_id, ts, kind, principal, selector, job_id, node_id, action_kind, operation_name, args, raw_exec_argv, outcome, reason, stdout, stderr, truncated,
		                   account_id, account_name, account_role, token_id, auth_method,
		                   asserted_on_behalf_of, asserted_traceparent, asserted_session_ref, asserted_change_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, formatTime(roundTripTime(r.Timestamp)), r.Kind, r.Principal, r.Selector, r.JobID, nullIfEmpty(r.NodeID), r.ActionKind,
		nullIfEmpty(r.OperationName), argsJSON, argvJSON, int(r.Outcome), nullIfEmpty(r.Reason), r.Stdout, r.Stderr, boolToInt(r.Truncated),
		nullIfEmpty(v.AccountID), nullIfEmpty(v.AccountName), nullIfEmpty(v.Role), nullIfEmpty(v.TokenID), nullIfEmpty(v.Method),
		nullIfEmpty(as.OnBehalfOf), nullIfEmpty(as.Traceparent), nullIfEmpty(as.SessionRef), nullIfEmpty(as.ChangeRef),
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

// ByNode returns all Records for nodeID, ordered by Timestamp.
func (a *sqliteAudit) ByNode(ctx context.Context, nodeID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE node_id = ? ORDER BY ts`, nodeID)
}

// ByAccount returns all Records for an Account ID (verified lane), ordered by
// Timestamp.
func (a *sqliteAudit) ByAccount(ctx context.Context, accountID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE account_id = ? ORDER BY ts`, accountID)
}

// ByOnBehalfOf returns all Records with an exact asserted OnBehalfOf value,
// ordered by Timestamp. Exact match, never a prefix or LIKE: the value is
// caller-controlled, and a pattern match over untrusted strings invites both
// accidental over-matching and a query the caller can shape.
func (a *sqliteAudit) ByOnBehalfOf(ctx context.Context, onBehalfOf string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE asserted_on_behalf_of = ? ORDER BY ts`, onBehalfOf)
}

func (a *sqliteAudit) query(ctx context.Context, whereClause string, args ...any) ([]audit.Record, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT audit_id, ts, kind, principal, selector, job_id, node_id, action_kind, operation_name, args, raw_exec_argv, outcome, reason, stdout, stderr, truncated,
		       account_id, account_name, account_role, token_id, auth_method,
		       asserted_on_behalf_of, asserted_traceparent, asserted_session_ref, asserted_change_ref
		FROM audit `+whereClause, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer rows.Close()

	var out []audit.Record
	for rows.Next() {
		var (
			id, ts, kind, principal, selector, jobID, actionKind string
			nodeID                                               sql.NullString
			operationName                                        sql.NullString
			argsJSON, argvJSON                                   sql.NullString
			outcome                                              int
			reason                                               sql.NullString
			stdout, stderr                                       []byte
			truncated                                            int
			accountID, accountName, accountRole, tokenID         sql.NullString
			authMethod                                           sql.NullString
			onBehalfOf, traceparent, sessionRef, changeRef       sql.NullString
		)
		if err := rows.Scan(&id, &ts, &kind, &principal, &selector, &jobID, &nodeID, &actionKind,
			&operationName, &argsJSON, &argvJSON, &outcome, &reason, &stdout, &stderr, &truncated,
			&accountID, &accountName, &accountRole, &tokenID, &authMethod,
			&onBehalfOf, &traceparent, &sessionRef, &changeRef); err != nil {
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
			ID:        id,
			Timestamp: tsTime,
			Kind:      kind,
			Principal: principal,
			Attribution: audit.Attribution{
				Verified: audit.Verified{
					AccountID:   accountID.String,
					AccountName: accountName.String,
					Role:        accountRole.String,
					TokenID:     tokenID.String,
					Method:      authMethod.String,
				},
				Asserted: audit.Asserted{
					OnBehalfOf:  onBehalfOf.String,
					Traceparent: traceparent.String,
					SessionRef:  sessionRef.String,
					ChangeRef:   changeRef.String,
				},
			},
			Selector:      selector,
			JobID:         jobID,
			NodeID:        nodeID.String,
			ActionKind:    actionKind,
			OperationName: operationName.String,
			Args:          args,
			RawExecArgv:   argv,
			Outcome:       jobs.Outcome(outcome),
			Reason:        reason.String,
			Stdout:        stdout,
			Stderr:        stderr,
			Truncated:     truncated != 0,
		})
	}
	return out, rows.Err()
}
