// Package jobs holds the Relay's domain model for Jobs, Stages, and Tasks —
// the unit of dispatch, at-most-once execution, and blast-radius control
// (ADR-0004). A Job comprises one Task per matched Node, grouped into Stages;
// v1 permits exactly one Stage per Job so a post-1.0 staged rollout lands
// without a data migration (ROADMAP).
//
// These are domain mirrors of the gleipnirv1 wire vocabulary (Outcome,
// RiskClass, Operation/RawExec), following the registry.Facts precedent: this
// package carries no proto dependency and, critically, no database/sql
// dependency either — that boundary is what makes a later Postgres swap a
// single-package (internal/store) change.
package jobs

import (
	"context"
	"errors"
	"time"
)

// ErrSingleStageOnly is returned by AddStage when the Job already has a
// Stage. v1 enforces exactly one Stage per Job in code, not by convention;
// the schema (internal/store) backs this with a CHECK/UNIQUE constraint.
var ErrSingleStageOnly = errors.New("jobs: a Job may have exactly one stage in v1")

// ErrJobNotFound is returned when an operation targets a Job that does not exist.
var ErrJobNotFound = errors.New("jobs: job not found")

// ErrTaskNotFound is returned when an operation targets a Task that does not exist.
var ErrTaskNotFound = errors.New("jobs: task not found")

// ErrInvalidTaskState is returned when a Task state transition is attempted
// out of order: MarkDispatched on a Task that is not Pending, or Resolve on a
// Task that is not Dispatched. This is the at-most-once reconciliation guard —
// a Relay restart must never re-dispatch a Task it already resolved, and must
// never resolve a Task it never dispatched.
var ErrInvalidTaskState = errors.New("jobs: invalid task state transition")

// Outcome mirrors gleipnirv1.Outcome. The zero value, OutcomeUnspecified,
// means "not yet resolved" (a Pending or Dispatched Task has no Outcome).
type Outcome int

const (
	OutcomeUnspecified Outcome = iota
	OutcomeSuccess
	OutcomeFailure
	OutcomeTimeout
	OutcomeDeniedByPolicy
	OutcomeCancelled
	OutcomeUnreachable
)

// RiskClass mirrors gleipnirv1.RiskClass. The zero value, RiskClassUnspecified,
// keeps the enum's zero value defined, matching how Outcome mirrors Unspecified.
type RiskClass int

const (
	RiskClassUnspecified RiskClass = iota
	RiskClassRead
	RiskClassMutate
)

// DispatchState is a Task's position in the at-most-once execution lifecycle:
// Pending (created, not yet sent) -> Dispatched (sent to the daemon, no
// result yet) -> Resolved (result recorded). In-flight dispatch state —
// Dispatched with no result — is what a Relay restart must recover to decide
// whether re-dispatch is safe (ADR-0004).
type DispatchState int

const (
	DispatchStatePending DispatchState = iota
	DispatchStateDispatched
	DispatchStateResolved
)

// ActionKind distinguishes a structured Operation from Raw Exec.
type ActionKind int

const (
	ActionUnspecified ActionKind = iota
	ActionOperation
	ActionRawExec
)

// Action is the work a Task performs on its Node: either a structured,
// typed Operation (name + validated args, never a shell) or Raw Exec
// (arbitrary argv, gated by Policy regex). Mirrors the TaskRequest oneof.
type Action struct {
	Kind          ActionKind
	OperationName string
	OperationArgs map[string]string
	RawExecArgv   []string
	RiskClass     RiskClass
}

// Job is the unit of audit and blast-radius control: one Job comprises one
// Task per matched Node, grouped into Stages. Selector and principal
// provenance live in audit for now; a later issue may extend Job itself.
type Job struct {
	ID        string
	CreatedAt time.Time
}

// Stage is a batch of Tasks within a Job. v1 permits exactly one Stage per
// Job (Index is always 0); AddStage enforces this.
type Stage struct {
	ID    string
	JobID string
	Index int
}

// Task is the execution of one Action on a single Node, as part of a Job's
// Stage. TaskID is unique and is the at-most-once execution key (ADR-0004).
type Task struct {
	ID      string
	JobID   string
	StageID string
	NodeID  string
	Action  Action

	State          DispatchState
	Outcome        Outcome
	ExitCode       int32
	Stdout         []byte
	Stderr         []byte
	TimeoutSeconds int32

	CreatedAt    time.Time
	DispatchedAt time.Time
	ResolvedAt   time.Time
}

// Result is the outcome of a resolved Task, as reported by the relay-daemon
// (or synthesized by the Relay, e.g. OutcomeUnreachable).
type Result struct {
	Outcome  Outcome
	ExitCode int32
	Stdout   []byte
	Stderr   []byte
}

// JobRepository persists Jobs and their Stages.
type JobRepository interface {
	// CreateJob persists a new Job.
	CreateJob(ctx context.Context, job Job) error

	// AddStage adds a Stage to a Job. Returns ErrSingleStageOnly if the Job
	// already has a Stage — v1's one-stage-per-Job constraint, enforced in
	// code (the schema's CHECK/UNIQUE is defense-in-depth, not the primary guard).
	AddStage(ctx context.Context, stage Stage) error

	// GetJob returns the Job with the given ID, or ErrJobNotFound.
	GetJob(ctx context.Context, id string) (Job, error)

	// Stages returns all Stages for jobID (at most one, in v1), ordered by Index.
	Stages(ctx context.Context, jobID string) ([]Stage, error)
}

// TaskRepository persists Tasks and their dispatch state.
type TaskRepository interface {
	// CreateTask persists a new Task with State = DispatchStatePending.
	CreateTask(ctx context.Context, task Task) error

	// MarkDispatched transitions a Task from Pending to Dispatched, recording
	// the dispatch time. Returns ErrTaskNotFound if the Task does not exist,
	// or ErrInvalidTaskState if the Task is not currently Pending.
	MarkDispatched(ctx context.Context, taskID string, at time.Time) error

	// Resolve transitions a Task from Dispatched to Resolved, recording the
	// Result and resolve time. Returns ErrTaskNotFound if the Task does not
	// exist, or ErrInvalidTaskState if the Task is not currently Dispatched.
	Resolve(ctx context.Context, taskID string, r Result) error

	// MarkUnreachable transitions a Task from Pending directly to Resolved
	// with OutcomeUnreachable, recording the resolve time but no
	// DispatchedAt — the Task was never sent (ADR-0004's offline fail-fast:
	// a matched-but-disconnected Node's Task must reach a terminal, truthful
	// outcome without ever claiming to have been dispatched). Returns
	// ErrTaskNotFound if the Task does not exist, or ErrInvalidTaskState if
	// the Task is not currently Pending.
	MarkUnreachable(ctx context.Context, taskID string, at time.Time) error

	// Get returns the Task with the given ID, or ErrTaskNotFound.
	Get(ctx context.Context, taskID string) (Task, error)

	// InFlight returns every Task in DispatchStateDispatched with no result
	// yet — the set a Relay restart must reconcile to preserve at-most-once
	// execution (ADR-0004).
	InFlight(ctx context.Context) ([]Task, error)

	// ByJob returns all Tasks belonging to jobID.
	ByJob(ctx context.Context, jobID string) ([]Task, error)
}
