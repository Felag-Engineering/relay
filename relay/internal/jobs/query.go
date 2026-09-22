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
// Resolved. A zero-Task Job is Complete — nothing is left to happen, so
// there is nothing to wait for. No new dispatch creates one: a zero-match
// dispatch has been refused before any Job exists since #571, but rows
// written before that still exist in older stores, so this derivation must
// keep handling them.
type JobState int

const (
	JobStateRunning JobState = iota
	JobStateComplete
)

// JobQuery is the Job list's filter. Every non-zero field ANDs; the zero
// value matches every Job.
type JobQuery struct {
	// JobID restricts to one Job. It is what lets a Job-detail screen read
	// the whole per-outcome tally as ONE aggregate row without
	// materialising a single Task — the property that makes that screen
	// bounded at 10,000 Nodes rather than merely paginated.
	JobID string

	// State restricts to JobStateRunning or JobStateComplete. nil means
	// either.
	State *JobState

	// RequesterAccountID restricts to Jobs whose recorded requester (Job's
	// Requester field) is this verified Account. A Job with no recorded
	// requester never matches any value here.
	RequesterAccountID string

	// Operation restricts to this operation_name. Every Task of a v1 Job
	// shares one Action (jobs.go's Stage/Task model), so this is a Job-level
	// filter, not a per-Task one.
	Operation string

	// RiskClass restricts to this RiskClass. nil means either.
	RiskClass *RiskClass

	// OnBehalfOf restricts to Jobs whose dispatch carried this ASSERTED
	// on-behalf-of value. Joined from the audit trail, and matched EXACTLY —
	// never a prefix and never a LIKE, mirroring audit.Query.OnBehalfOf. The
	// asserted lane is caller-claimed and nothing checked it; a fuzzy match
	// over it would let one agent's claim answer a question asked about
	// another's.
	OnBehalfOf string

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

	// Requester, RequesterAccountID and RequesterKind come from the Job row.
	// They are present from the moment the Job exists (in-flight Jobs
	// included), empty for a Job with no recorded requester (legacy), and
	// never filled from the trail.
	//
	// Selector is still audit-joined (the dispatch record the Job engine
	// wrote when it ran): a Job whose audit row has not been written yet —
	// an in-flight Job the Job engine is still inside disp.run for — still
	// appears, with Selector empty: the store's implementation LEFT JOINs so
	// a Job is never hidden by a race with its own audit write.
	Selector           string
	Requester          string
	RequesterAccountID string
	RequesterKind      string

	// OnBehalfOf, ApprovalID, GrantID, Args and RawExecArgv join from the
	// SAME per-Job audit aggregate Selector above joins from, and are empty
	// for an in-flight Job for the same LEFT-JOIN reason.
	//
	// They are exact, not a sample. Every dispatch record within one Job is
	// written from ONE base record — the fan-out loop that writes a record
	// per Node result mutates only the Node, the outcome and the captured
	// output (internal/auditsink) — so MIN() over the Job's dispatch rows
	// returns the single value they all carry. That rests on the same
	// assumption the three fields above already make: one dispatch Record
	// call per Job ID.
	//
	// There is NO Stdout, Stderr or Truncated field here, and there never
	// will be. A Job list must not become a path to captured output
	// (ADR-0025); the SELECT behind this struct names no BLOB column, so
	// there is nothing here to redact.
	OnBehalfOf  string
	ApprovalID  string
	GrantID     string
	Args        map[string]string
	RawExecArgv []string

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
