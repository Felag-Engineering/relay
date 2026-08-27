package jobs

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidCursor is returned when a caller-supplied QueryJobs/QueryTasks
// cursor cannot be parsed. Never a silent reset to page one, on the same
// reasoning audit.ErrInvalidCursor states.
var ErrInvalidCursor = errors.New("jobs: invalid pagination cursor")

// query.go is the Job/Task read lane (#441): filtered, paginated summaries
// over Jobs and Tasks, distinct from JobRepository/TaskRepository's
// create/transition/by-key surface. Kept SQL-free like the rest of this
// package (nosql_test.go); the SQLite implementation is
// internal/store/jobquery.go.

// JobState is a Job's derived lifecycle state, distinct from a single Task's
// DispatchState: a Job is JobStateRunning while at least one of its Tasks is
// still Pending or Dispatched, and JobStateComplete once every Task is
// Resolved. A zero-Task Job (the fan-out matched nothing) is Complete —
// nothing is left to happen, so there is nothing to wait for.
type JobState int

const (
	JobStateRunning JobState = iota
	JobStateComplete
)

// JobQuery is the Job list's filter. Every non-zero field ANDs; the zero
// value matches every Job.
type JobQuery struct {
	// State restricts to JobStateRunning or JobStateComplete. nil means
	// either.
	State *JobState

	// RequesterAccountID restricts to Jobs whose dispatch was attributed to
	// this verified Account. Jobs carry no requester of their own (Job's doc
	// comment: "Selector and principal provenance live in audit for now") —
	// the store implementation joins this from the audit trail.
	RequesterAccountID string

	// Operation restricts to this operation_name. Every Task of a v1 Job
	// shares one Action (jobs.go's Stage/Task model), so this is a Job-level
	// filter, not a per-Task one.
	Operation string

	// RiskClass restricts to this RiskClass. nil means either.
	RiskClass *RiskClass

	// Since and Until bound CreatedAt, half-open [Since, Until). The zero
	// value on either side is unbounded.
	Since, Until time.Time
}

// JobSummary is one row of a Job list: everything a list screen needs
// without fetching every Task.
type JobSummary struct {
	JobID     string
	CreatedAt time.Time
	State     JobState

	ActionKind    ActionKind
	OperationName string
	RiskClass     RiskClass

	// Selector, Requester, and RequesterAccountID are joined from the audit
	// trail (the dispatch record the Job engine wrote when it ran), exactly
	// as RequesterAccountID above is. A Job whose audit row has not been
	// written yet — an in-flight Job the Job engine is still inside disp.run
	// for — still appears, with these three fields empty: the store's
	// implementation LEFT JOINs so a Job is never hidden by a race with its
	// own audit write.
	Selector           string
	Requester          string
	RequesterAccountID string

	// Total is the Job's Task count. Counts is a per-Outcome tally over
	// resolved Tasks (jobs.OutcomeUnspecified excluded — that is "not yet
	// resolved", not a result). Unresolved is the count of Tasks still
	// Pending or Dispatched — what makes State Running.
	Total      int
	Counts     map[Outcome]int
	Unresolved int
}

// JobPage is one page of JobSummary rows, cursor-paginated newest first.
type JobPage struct {
	Jobs  []JobSummary
	Next  string
	Limit int
}

// TaskQuery is a single Job's Task list filter.
type TaskQuery struct {
	JobID string
	// Outcome restricts to Tasks resolved with this Outcome. nil means any
	// Task regardless of outcome (including unresolved ones).
	Outcome *Outcome
}

// TaskSummary is one row of a Job's Task list.
//
// Stdout, Stderr, and RiskClass ARE present here, unlike audit.Row: #423
// (job detail) clusters Tasks by identical output and renders the deny rule
// verbatim, which needs the captured bytes for mutate-class Tasks, and the
// tasks table already stores them (store/tasks.go). RiskClass is what lets a
// caller one layer up (capability.QueryTasks) strip output for read-class
// Tasks exactly as auditsink.go:219 already does for the audit trail — see
// that method's doc comment for the decision this makes deliberately
// reversible.
//
// Truncated is deliberately ABSENT. The tasks table has no truncated column
// and jobs.Task carries none either — only audit.Record and jobs.Result do,
// and neither is available to a plain SELECT over tasks. Backfilling it here
// would mean either a write-path migration (out of scope for an index-only
// change) or a LEFT JOIN to the audit table for one flag, which would
// contradict this query's own reason for reading tasks instead of audit in
// the first place: an in-flight Job has no audit row yet (see JobSummary's
// Selector/Requester doc comment), and Task state must never depend on
// whether the trail has caught up. #423 keeps today's audit-trail fallback
// for this one signal until a follow-up gives Tasks a real truncated column.
type TaskSummary struct {
	TaskID   string
	NodeID   string
	State    DispatchState
	Outcome  Outcome
	ExitCode int32

	RiskClass RiskClass
	Stdout    []byte
	Stderr    []byte

	CreatedAt    time.Time
	DispatchedAt time.Time
	ResolvedAt   time.Time
}

// TaskPage is one page of TaskSummary rows, cursor-paginated by ascending
// task_id. Task IDs are random (capability.defaultID), not time-ordered, so
// this is NOT creation order — it is a fixed, total, gap-free order over a
// set that is written once and never reordered, which is all keyset
// pagination needs for stability under concurrent reads.
type TaskPage struct {
	Tasks []TaskSummary
	Next  string
	Limit int
}

// QueryRepository is the Job/Task read lane: filtered, paginated summaries.
//
// Deliberately separate from JobRepository/TaskRepository, on the same
// append-vs-query reasoning audit.QueryRepository states: this interface can
// only read.
type QueryRepository interface {
	// QueryJobs returns one page of JobSummary rows matching q, newest
	// (CreatedAt) first. limit <= 0 defaults; cursor is opaque, and a
	// malformed or foreign one is an error rather than a silent reset.
	QueryJobs(ctx context.Context, q JobQuery, limit int, cursor string) (JobPage, error)

	// QueryTasks returns one page of TaskSummary rows for q.JobID, optionally
	// filtered by q.Outcome, ordered by ascending task_id (see TaskPage).
	QueryTasks(ctx context.Context, q TaskQuery, limit int, cursor string) (TaskPage, error)
}
