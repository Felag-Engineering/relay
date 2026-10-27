package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// sqliteTasks implements jobs.TaskRepository against the tasks table.
type sqliteTasks struct {
	db *sql.DB
}

var _ jobs.TaskRepository = (*sqliteTasks)(nil)

// CreateTask persists a new Task with State = jobs.DispatchStatePending.
func (t *sqliteTasks) CreateTask(ctx context.Context, task jobs.Task) error {
	return createTaskExec(ctx, t.db, task)
}

// createTaskExec is CreateTask's body over an execer, so AppendWithTasks can
// insert a Job's Tasks inside its own transaction.
func createTaskExec(ctx context.Context, ex execer, task jobs.Task) error {
	kindStr, err := actionKindToString(task.Action.Kind)
	if err != nil {
		return err
	}
	argsJSON, err := encodeStringMap(task.Action.OperationArgs)
	if err != nil {
		return err
	}
	argvJSON, err := encodeStringSlice(task.Action.RawExecArgv)
	if err != nil {
		return err
	}

	_, err = ex.ExecContext(ctx, `
		INSERT INTO tasks (task_id, job_id, stage_id, node_id, action_kind, operation_name,
			operation_args, raw_exec_argv, risk_class, timeout_seconds, state,
			outcome, exit_code, stdout, stderr, created_at, dispatched_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, NULL, ?, NULL, NULL)`,
		task.ID, task.JobID, task.StageID, task.NodeID, kindStr, nullIfEmpty(task.Action.OperationName),
		argsJSON, argvJSON, jobs.RiskClassName(task.Action.RiskClass), task.TimeoutSeconds,
		formatTime(roundTripTime(task.CreatedAt)),
	)
	if err != nil {
		return fmt.Errorf("insert task: %w", err)
	}
	return nil
}

// MarkDispatched transitions a Task from Pending to Dispatched. Returns
// jobs.ErrTaskNotFound if the Task does not exist, or jobs.ErrInvalidTaskState
// if it is not currently Pending.
func (t *sqliteTasks) MarkDispatched(ctx context.Context, taskID string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventDispatch, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE tasks SET state = 'dispatched', dispatched_at = ? WHERE task_id = ?`,
			formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// Resolve transitions a Task from Dispatched to Resolved, recording r.
// Returns jobs.ErrTaskNotFound if the Task does not exist, or
// jobs.ErrInvalidTaskState if it is not currently Dispatched.
//
// Stdout/Stderr are persisted exactly as delivered, size-capped upstream by
// the daemon per /proto. This is where Task output lives for the Task store;
// the audit trail ALSO retains full per-Task output for a mutate-class Task
// (full-output-always as ADR-0025 amends it, internal/audit,
// internal/store/audit.go) — a deliberate
// retention posture, not a desired-state spec, documented in
// docs/operations/audit-output-retention.md.
func (t *sqliteTasks) Resolve(ctx context.Context, taskID string, r jobs.Result) error {
	return t.transition(ctx, taskID, jobs.TaskEventResolve, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, exit_code = ?, stdout = ?, stderr = ?, resolved_at = ?
			WHERE task_id = ?`,
			int(r.Outcome), r.ExitCode, r.Stdout, r.Stderr, formatTime(roundTripTime(time.Now().UTC())), taskID)
		return err
	})
}

// MarkUnreachable transitions a Task from Pending directly to Resolved with
// jobs.OutcomeUnreachable, leaving dispatched_at NULL — the Task was never
// sent. Returns jobs.ErrTaskNotFound if the Task does not exist, or
// jobs.ErrInvalidTaskState if it is not currently Pending.
func (t *sqliteTasks) MarkUnreachable(ctx context.Context, taskID string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventUnreachable, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeUnreachable), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkVersionRefused transitions a Task from Pending directly to Resolved
// with jobs.OutcomeVersionRefused and Stderr = jobs.VersionRefusedMessage,
// leaving dispatched_at NULL — the Task was never sent because its Node's
// relay-daemon is below the Relay's configured minimum version (ADR-0014).
// Returns jobs.ErrTaskNotFound if the Task does not exist, or
// jobs.ErrInvalidTaskState if it is not currently Pending.
func (t *sqliteTasks) MarkVersionRefused(ctx context.Context, taskID string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventVersionRefused, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, stderr = ?, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeVersionRefused), []byte(jobs.VersionRefusedMessage), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkUnsupported transitions a Task from Pending directly to Resolved with
// jobs.OutcomeUnsupported and Stderr = reason, leaving dispatched_at NULL —
// the Relay excluded its Node from a Template dispatch (ADR-0042), so the
// Task was never sent. Returns jobs.ErrTaskNotFound if the Task does not
// exist, or jobs.ErrInvalidTaskState if it is not currently Pending.
func (t *sqliteTasks) MarkUnsupported(ctx context.Context, taskID, reason string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventUnsupported, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, stderr = ?, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeUnsupported), []byte(reason), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkHalted transitions a Task from Pending directly to Resolved with
// jobs.OutcomeCancelled and Stderr = reason, leaving dispatched_at NULL — its
// mutate Job halted before the Task was sent (execution.md, Halting a failing
// mutation), so InFlight never returns it. Returns jobs.ErrTaskNotFound if the
// Task does not exist, or jobs.ErrInvalidTaskState if it is not currently
// Pending.
func (t *sqliteTasks) MarkHalted(ctx context.Context, taskID, reason string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventHalt, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, stderr = ?, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeCancelled), []byte(reason), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkCancelled transitions a Task from Pending directly to Resolved with
// jobs.OutcomeCancelled, leaving dispatched_at NULL — the Task was cancelled
// before it was ever sent (ADR-0013). Returns jobs.ErrTaskNotFound if the
// Task does not exist, or jobs.ErrInvalidTaskState if it is not currently
// Pending.
func (t *sqliteTasks) MarkCancelled(ctx context.Context, taskID string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventCancel, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeCancelled), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkCancelledBeforeSend transitions a Task from Dispatched to Resolved with
// jobs.OutcomeCancelled and sets dispatched_at back to NULL — the engine marked
// the Task Dispatched but its Job's cancel was seen before the send began, so
// the Task never left the Relay. The row is identical to MarkCancelled's,
// so the Console reads it as never sent and InFlight never returns it. Returns
// jobs.ErrTaskNotFound if the Task does not exist, or jobs.ErrInvalidTaskState
// if it is not currently Dispatched.
func (t *sqliteTasks) MarkCancelledBeforeSend(ctx context.Context, taskID string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventCancelBeforeSend, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, dispatched_at = NULL, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeCancelled), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// MarkHaltedBeforeSend transitions a Task from Dispatched to Resolved with
// jobs.OutcomeCancelled and Stderr = reason, and sets dispatched_at back to NULL
// — the engine marked the Task Dispatched but its mutate Job halted before the
// send began, so the Task never left the Relay. The row is MarkHalted's, so
// InFlight never returns it. Returns jobs.ErrTaskNotFound if the Task does not
// exist, or jobs.ErrInvalidTaskState if it is not currently Dispatched.
func (t *sqliteTasks) MarkHaltedBeforeSend(ctx context.Context, taskID, reason string, at time.Time) error {
	return t.transition(ctx, taskID, jobs.TaskEventHaltBeforeSend, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET state = 'resolved', outcome = ?, stderr = ?, dispatched_at = NULL, resolved_at = ? WHERE task_id = ?`,
			int(jobs.OutcomeCancelled), []byte(reason), formatTime(roundTripTime(at)), taskID)
		return err
	})
}

// transition runs fn inside a tx after verifying taskID is in the state ev
// requires, translating "not found" / "wrong state" into the sentinel errors
// jobs.ErrTaskNotFound / jobs.ErrInvalidTaskState.
//
// This is the optimistic-concurrency guard against another writer (CancelJob,
// a Reconciler, another process) moving the row first; whether the transition
// is legal is decided by jobs.Task.Transition, and the required state is read
// from the same table (jobs.TaskEventKind.From).
func (t *sqliteTasks) transition(ctx context.Context, taskID string, ev jobs.TaskEventKind, fn func(tx *sql.Tx) error) error {
	from, ok := ev.From()
	if !ok {
		return jobs.ErrUnknownTaskEvent
	}
	requiredState, ok := dispatchStateToString(from)
	if !ok {
		return jobs.ErrUnknownTaskEvent
	}
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM tasks WHERE task_id = ?`, taskID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.ErrTaskNotFound
	}
	if err != nil {
		return fmt.Errorf("query task %q state: %w", taskID, err)
	}
	if state != requiredState {
		return jobs.ErrInvalidTaskState
	}

	if err := fn(tx); err != nil {
		return fmt.Errorf("update task %q: %w", taskID, err)
	}
	return tx.Commit()
}

// Get returns the Task with the given ID, or jobs.ErrTaskNotFound.
func (t *sqliteTasks) Get(ctx context.Context, taskID string) (jobs.Task, error) {
	task, ok, err := getTask(ctx, t.db, taskID)
	if err != nil {
		return jobs.Task{}, err
	}
	if !ok {
		return jobs.Task{}, jobs.ErrTaskNotFound
	}
	return task, nil
}

// InFlight returns every Task in DispatchStateDispatched with no result yet.
func (t *sqliteTasks) InFlight(ctx context.Context) ([]jobs.Task, error) {
	return queryTasks(ctx, t.db, `WHERE state = 'dispatched' ORDER BY task_id`)
}

// ByJob returns all Tasks belonging to jobID.
func (t *sqliteTasks) ByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	return queryTasks(ctx, t.db, `WHERE job_id = ? ORDER BY task_id`, jobID)
}

func queryTasks(ctx context.Context, db *sql.DB, whereClause string, args ...any) ([]jobs.Task, error) {
	rows, err := db.QueryContext(ctx, taskSelectColumns+" FROM tasks "+whereClause, args...)
	if err != nil {
		return nil, fmt.Errorf("query tasks: %w", err)
	}
	defer rows.Close()

	var out []jobs.Task
	for rows.Next() {
		task, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, rows.Err()
}

func getTask(ctx context.Context, db *sql.DB, taskID string) (jobs.Task, bool, error) {
	row := db.QueryRowContext(ctx, taskSelectColumns+` FROM tasks WHERE task_id = ?`, taskID)
	task, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.Task{}, false, nil
	}
	if err != nil {
		return jobs.Task{}, false, err
	}
	return task, true, nil
}

const taskSelectColumns = `SELECT task_id, job_id, stage_id, node_id, action_kind, operation_name,
	operation_args, raw_exec_argv, risk_class, timeout_seconds, state,
	outcome, exit_code, stdout, stderr, created_at, dispatched_at, resolved_at`

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTask(row rowScanner) (jobs.Task, error) {
	var (
		id, jobID, stageID, nodeID, actionKind string
		operationName                          sql.NullString
		operationArgs, rawExecArgv             sql.NullString
		riskClass, state                       string
		timeoutSeconds                         int32
		outcome                                sql.NullInt64
		exitCode                               sql.NullInt64
		stdout, stderr                         []byte
		createdAt                              string
		dispatchedAt, resolvedAt               sql.NullString
	)
	if err := row.Scan(&id, &jobID, &stageID, &nodeID, &actionKind, &operationName,
		&operationArgs, &rawExecArgv, &riskClass, &timeoutSeconds, &state,
		&outcome, &exitCode, &stdout, &stderr, &createdAt, &dispatchedAt, &resolvedAt); err != nil {
		return jobs.Task{}, fmt.Errorf("scan task row: %w", err)
	}

	kind, err := actionKindFromString(actionKind)
	if err != nil {
		return jobs.Task{}, err
	}
	args, err := decodeStringMap(operationArgs)
	if err != nil {
		return jobs.Task{}, err
	}
	argv, err := decodeStringSlice(rawExecArgv)
	if err != nil {
		return jobs.Task{}, err
	}
	createdAtTime, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return jobs.Task{}, fmt.Errorf("parse created_at for task %q: %w", id, err)
	}
	dispatchedAtTime, err := parseTime(dispatchedAt)
	if err != nil {
		return jobs.Task{}, fmt.Errorf("parse dispatched_at for task %q: %w", id, err)
	}
	resolvedAtTime, err := parseTime(resolvedAt)
	if err != nil {
		return jobs.Task{}, fmt.Errorf("parse resolved_at for task %q: %w", id, err)
	}

	return jobs.Task{
		ID:      id,
		JobID:   jobID,
		StageID: stageID,
		NodeID:  nodeID,
		Action: jobs.Action{
			Kind:          kind,
			OperationName: operationName.String,
			OperationArgs: args,
			RawExecArgv:   argv,
			RiskClass:     riskClassFromString(riskClass),
		},
		State:          dispatchStateFromString(state),
		Outcome:        outcomeFromNullInt64(outcome),
		ExitCode:       int32(exitCode.Int64), //nolint:gosec // G115: stored from an int32 exit code, so it round-trips
		Stdout:         stdout,
		Stderr:         stderr,
		TimeoutSeconds: timeoutSeconds,
		CreatedAt:      createdAtTime,
		DispatchedAt:   dispatchedAtTime,
		ResolvedAt:     resolvedAtTime,
	}, nil
}

func actionKindToString(k jobs.ActionKind) (string, error) {
	switch k {
	case jobs.ActionOperation:
		return "operation", nil
	case jobs.ActionRawExec:
		return "raw_exec", nil
	default:
		return "", fmt.Errorf("store: unsupported action kind %d", k)
	}
}

func actionKindFromString(s string) (jobs.ActionKind, error) {
	switch s {
	case "operation":
		return jobs.ActionOperation, nil
	case "raw_exec":
		return jobs.ActionRawExec, nil
	default:
		return jobs.ActionUnspecified, fmt.Errorf("store: unrecognized action_kind %q", s)
	}
}

func riskClassFromString(s string) jobs.RiskClass {
	switch s {
	case "read":
		return jobs.RiskClassRead
	case "mutate":
		return jobs.RiskClassMutate
	default:
		return jobs.RiskClassUnspecified
	}
}

func dispatchStateFromString(s string) jobs.DispatchState {
	switch s {
	case "dispatched":
		return jobs.DispatchStateDispatched
	case "resolved":
		return jobs.DispatchStateResolved
	default:
		return jobs.DispatchStatePending
	}
}

// dispatchStateToString is the inverse of dispatchStateFromString for the
// states a transition can start from. Resolved is terminal and never a source
// state, and an unknown state is refused rather than defaulted, so a future
// event cannot quietly guard on the wrong state.
func dispatchStateToString(s jobs.DispatchState) (string, bool) {
	switch s {
	case jobs.DispatchStatePending:
		return "pending", true
	case jobs.DispatchStateDispatched:
		return "dispatched", true
	default:
		return "", false
	}
}

func outcomeFromNullInt64(n sql.NullInt64) jobs.Outcome {
	if !n.Valid {
		return jobs.OutcomeUnspecified
	}
	return jobs.Outcome(n.Int64)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func encodeStringMap(m map[string]string) (any, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode string map: %w", err)
	}
	return string(b), nil
}

func decodeStringMap(s sql.NullString) (map[string]string, error) {
	if !s.Valid {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s.String), &m); err != nil {
		return nil, fmt.Errorf("decode string map: %w", err)
	}
	return m, nil
}

func encodeStringSlice(s []string) (any, error) {
	if s == nil {
		return nil, nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode string slice: %w", err)
	}
	return string(b), nil
}

func decodeStringSlice(s sql.NullString) ([]string, error) {
	if !s.Valid {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s.String), &out); err != nil {
		return nil, fmt.Errorf("decode string slice: %w", err)
	}
	return out, nil
}
