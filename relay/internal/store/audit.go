package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// sqliteAudit implements audit.Repository against the audit table.
type sqliteAudit struct {
	db *sql.DB
}

var _ audit.Repository = (*sqliteAudit)(nil)

// insertAuditSQL is the one INSERT text shared by every audit writer, so their
// column list cannot drift apart. The last three placeholders are the chain
// position. Only insertChained may reference it: a raw insert would
// write a row with no chain position, and
// TestInsertAuditSQL_OnlyReferencedByInsertChained fails the build if one
// appears.
const insertAuditSQL = `
	INSERT INTO audit (audit_id, ts, kind, principal, selector, job_id, node_id, action_kind, operation_name, args, raw_exec_argv, outcome, reason, stdout, stderr, truncated,
	                   account_id, account_name, account_role, token_id, auth_method, verified_source,
	                   asserted_on_behalf_of, asserted_traceparent, asserted_session_ref, asserted_change_ref,
	                   approval_id, grant_id, approval_answer, decision_channel, plan_hash,
	                   seq, prev_hash, hash)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// auditInsertArgs builds the ordered argument list for insertAuditSQL from r.
//
// ts is written through formatAuditTime, not the store-wide formatTime: the
// audit table's ts is fixed-width so that ORDER BY on it is chronological
// (migration 0024). Record.Timestamp is unaffected by that choice — the
// driver re-renders the column on read and parseTime accepts either width —
// so nothing above the store sees a representation change. The roundTripTime
// call this replaced was doing nothing: an RFC3339Nano format/parse round
// trip is lossless at nanosecond precision, and its stated purpose
// ("byte-identical to what will be read back") is now the formatter's.
//
// Stdout/Stderr are stored raw, exactly as delivered — no redaction or
// scrubbing (secrets in command output are retained by design; Policy is the
// place to prevent secret-emitting commands, ADR-0002). This mirrors how
// tasks.go persists Task output.
func auditInsertArgs(r audit.Record) ([]any, error) {
	argsJSON, err := encodeStringMap(r.Args)
	if err != nil {
		return nil, err
	}
	argvJSON, err := encodeStringSlice(r.RawExecArgv)
	if err != nil {
		return nil, err
	}

	v, as := r.Attribution.Verified, r.Attribution.Asserted
	return []any{
		r.ID, formatAuditTime(r.Timestamp), r.Kind, r.Principal, r.Selector, r.JobID, nullIfEmpty(r.NodeID), r.ActionKind,
		nullIfEmpty(r.OperationName), argsJSON, argvJSON, int(r.Outcome), nullIfEmpty(r.Reason), r.Stdout, r.Stderr, boolToInt(r.Truncated),
		nullIfEmpty(v.AccountID), nullIfEmpty(v.AccountName), nullIfEmpty(v.Role), nullIfEmpty(v.TokenID), nullIfEmpty(v.Method), nullIfEmpty(v.Source),
		nullIfEmpty(as.OnBehalfOf), nullIfEmpty(as.Traceparent), nullIfEmpty(as.SessionRef), nullIfEmpty(as.ChangeRef),
		nullIfEmpty(r.ApprovalID), nullIfEmpty(r.GrantID), nullIfEmpty(r.ApprovalAnswer), nullIfEmpty(r.DecisionChannel), nullIfEmpty(r.PlanHash),
	}, nil
}

// auditOrderAsc is the ONE ascending order every Repository reader uses:
// Timestamp, ties broken by ID.
//
// Both halves matter. Without ", audit_id" two rows sharing a ts come back
// in whatever order the index yields — and a dispatch fan-out guarantees
// rows share a ts, since every per-Node Record copies one clock reading.
// Without migration 0024's fixed-width ts, "ORDER BY ts" on a TEXT column
// puts a whole-second row AFTER the .5 row in the same second, because
// RFC3339Nano trims trailing zeros.
//
// auditquery.go's read lane holds the mirror of this, auditOrderDesc.
// TestAuditSQL_EveryOrderByTsCarriesTheTieBreak is what keeps a clause added
// later from spelling either one differently.
const auditOrderAsc = `ORDER BY ts, audit_id`

// Append persists a new Record, chained onto the trail's head in its own
// write transaction.
func (a *sqliteAudit) Append(ctx context.Context, r audit.Record) error {
	p, err := prepareAudit(r)
	if err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit append: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := insertChained(ctx, tx, []preparedAudit{p}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit record: %w", err)
	}
	return nil
}

// AppendAll persists every Record in rs in one transaction: on a nil error
// all of them were written, on a non-nil error none were (see
// audit.Repository.AppendAll).
//
// Every record is prepared up front, before BeginTx, so an encode error
// returns before anything touches the store. A context that is done before or
// during the call makes database/sql roll the transaction back and return a
// non-nil error, writing nothing — which is what lets the cascade count the
// whole chunk as unrecorded. A Commit error that races a commit which
// actually landed can only OVER-report the shortfall, never under-report it.
func (a *sqliteAudit) AppendAll(ctx context.Context, rs []audit.Record) error {
	if len(rs) == 0 {
		return nil
	}

	prepared := make([]preparedAudit, len(rs))
	for i, r := range rs {
		p, err := prepareAudit(r)
		if err != nil {
			return err
		}
		prepared[i] = p
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit append: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := insertChained(ctx, tx, prepared); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit records: %w", err)
	}
	return nil
}

// AppendWithTasks inserts every task as Pending and chains r onto the trail,
// in one transaction: on a nil error all of it landed, on a non-nil error none
// of it did (see audit.Repository.AppendWithTasks). The Tasks and the audit
// row share this one *sql.DB, so a crash cannot leave either without the
// other.
//
// Every refusal happens before BeginTx, so a malformed call writes nothing.
func (a *sqliteAudit) AppendWithTasks(ctx context.Context, r audit.Record, tasks []jobs.Task) error {
	if r.ID == "" {
		return errors.New("store: refusing to record a dispatch intent with no audit record id")
	}
	if r.JobID == "" {
		return errors.New("store: refusing to record a dispatch intent with no job id")
	}
	if len(tasks) == 0 {
		return errors.New("store: refusing to record a dispatch intent with no tasks")
	}
	for _, t := range tasks {
		if t.JobID != r.JobID {
			return fmt.Errorf("store: task %q belongs to job %q, not the intent's job %q", t.ID, t.JobID, r.JobID)
		}
	}
	p, err := prepareAudit(r)
	if err != nil {
		return err
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin dispatch intent: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	for _, t := range tasks {
		if err := createTaskExec(ctx, tx, t); err != nil {
			return err
		}
	}
	if err := insertChained(ctx, tx, []preparedAudit{p}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dispatch intent and tasks: %w", err)
	}
	return nil
}

// List returns all Records, ordered by Timestamp, ties broken by ID.
func (a *sqliteAudit) List(ctx context.Context) ([]audit.Record, error) {
	return a.query(ctx, "")
}

// ByJob returns all Records for jobID, ordered by Timestamp, ties broken
// by ID.
func (a *sqliteAudit) ByJob(ctx context.Context, jobID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE job_id = ?`, jobID)
}

// ByNode returns all Records for nodeID, ordered by Timestamp, ties broken
// by ID.
func (a *sqliteAudit) ByNode(ctx context.Context, nodeID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE node_id = ?`, nodeID)
}

// ByAccount returns all Records for an Account ID (verified lane), ordered by
// Timestamp, ties broken by ID.
func (a *sqliteAudit) ByAccount(ctx context.Context, accountID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE account_id = ?`, accountID)
}

// ByApproval returns all Records authorized by an approval Request, ordered by
// Timestamp, ties broken by ID — the park, the decision, and everything that
// ran under it.
func (a *sqliteAudit) ByApproval(ctx context.Context, approvalID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE approval_id = ?`, approvalID)
}

// ByGrant returns all Records released by a batch/window Grant, ordered by
// Timestamp, ties broken by ID.
func (a *sqliteAudit) ByGrant(ctx context.Context, grantID string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE grant_id = ?`, grantID)
}

// ByOnBehalfOf returns all Records with an exact asserted OnBehalfOf value,
// ordered by Timestamp, ties broken by ID. Exact match, never a prefix or
// LIKE: the value is caller-controlled, and a pattern match over untrusted strings invites both
// accidental over-matching and a query the caller can shape.
func (a *sqliteAudit) ByOnBehalfOf(ctx context.Context, onBehalfOf string) ([]audit.Record, error) {
	return a.query(ctx, `WHERE asserted_on_behalf_of = ?`, onBehalfOf)
}

// query runs one by-key read: the caller supplies only its WHERE (empty for
// List), and query appends auditOrderAsc itself, so the seven readers cannot
// spell the order seven ways.
//
// What it covers, exactly, and no more: every reader ON THIS PATH. A caller
// that passed its own ORDER BY would get a RUNTIME SQL syntax error, not a
// compile error, and a new reader that called a.db.QueryContext directly
// bypasses this function entirely — visible to
// TestAuditSQL_EveryOrderByTsCarriesTheTieBreak only if its clause is a
// string literal in a non-test file of this package.
func (a *sqliteAudit) query(ctx context.Context, whereClause string, args ...any) ([]audit.Record, error) {
	//nolint:gosec // G202: every caller passes a constant WHERE clause with ? placeholders
	rows, err := a.db.QueryContext(ctx, `SELECT `+auditRecordColumns+` FROM audit `+whereClause+` `+auditOrderAsc, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer rows.Close()

	var out []audit.Record
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// auditRecordColumns is the column list scanAuditRecord reads, in its order.
// The readers, the migration 28 back-fill and the verifier all select it, so a
// Record is decoded one way everywhere — which is what lets the verifier
// re-derive exactly the bytes the writer hashed.
const auditRecordColumns = `audit_id, ts, kind, principal, selector, job_id, node_id, action_kind, operation_name, args, raw_exec_argv, outcome, reason, stdout, stderr, truncated,
	       account_id, account_name, account_role, token_id, auth_method, verified_source,
	       asserted_on_behalf_of, asserted_traceparent, asserted_session_ref, asserted_change_ref,
	       approval_id, grant_id, approval_answer, decision_channel, plan_hash`

// scanAuditRecord decodes one row selected with auditRecordColumns. lead are
// extra scan destinations for columns the caller selected BEFORE the record
// columns. A row that scanned but did not decode still returns its ID, so the
// caller can name it.
func scanAuditRecord(sc interface{ Scan(...any) error }, lead ...any) (audit.Record, error) {
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
		authMethod, verifiedSource                           sql.NullString
		onBehalfOf, traceparent, sessionRef, changeRef       sql.NullString
		approvalID, grantID                                  sql.NullString
		approvalAnswer, decisionChannel, planHash            sql.NullString
	)
	dest := append(lead, &id, &ts, &kind, &principal, &selector, &jobID, &nodeID, &actionKind,
		&operationName, &argsJSON, &argvJSON, &outcome, &reason, &stdout, &stderr, &truncated,
		&accountID, &accountName, &accountRole, &tokenID, &authMethod, &verifiedSource,
		&onBehalfOf, &traceparent, &sessionRef, &changeRef,
		&approvalID, &grantID, &approvalAnswer, &decisionChannel, &planHash)
	if err := sc.Scan(dest...); err != nil {
		return audit.Record{}, fmt.Errorf("scan audit row: %w", err)
	}
	tsTime, err := parseTime(sql.NullString{String: ts, Valid: true})
	if err != nil {
		return audit.Record{ID: id}, fmt.Errorf("parse ts for audit record %q: %w", id, err)
	}
	args, err := decodeStringMap(argsJSON)
	if err != nil {
		return audit.Record{ID: id}, fmt.Errorf("audit record %q: %w", id, err)
	}
	argv, err := decodeStringSlice(argvJSON)
	if err != nil {
		return audit.Record{ID: id}, fmt.Errorf("audit record %q: %w", id, err)
	}
	return audit.Record{
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
				Source:      verifiedSource.String,
			},
			Asserted: audit.Asserted{
				OnBehalfOf:  onBehalfOf.String,
				Traceparent: traceparent.String,
				SessionRef:  sessionRef.String,
				ChangeRef:   changeRef.String,
			},
		},
		Selector:        selector,
		JobID:           jobID,
		NodeID:          nodeID.String,
		ActionKind:      actionKind,
		OperationName:   operationName.String,
		Args:            args,
		RawExecArgv:     argv,
		Outcome:         jobs.Outcome(outcome),
		Reason:          reason.String,
		Stdout:          stdout,
		Stderr:          stderr,
		Truncated:       truncated != 0,
		ApprovalID:      approvalID.String,
		GrantID:         grantID.String,
		ApprovalAnswer:  approvalAnswer.String,
		DecisionChannel: decisionChannel.String,
		PlanHash:        planHash.String,
	}, nil
}
