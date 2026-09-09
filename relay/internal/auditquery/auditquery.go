// Package auditquery is the read-lane adapter (#441): it maps
// capability.AuditFilter/AuditRow/... onto internal/audit.QueryRepository and
// capability.JobFilter/JobSummary/... onto internal/jobs.QueryRepository.
//
// It lives in its own package, not package capability or package audit/jobs,
// for auditsink's stated reason (auditsink.go:1-10, restated on
// capability/query.go's package doc comment): it must reference both
// capability and audit/jobs, and capability's import allowlist bars
// internal/audit specifically so a caller-controlled value never gets a path
// to the store through that package. internal/jobs IS allowed in capability,
// but its query types are mirrored there anyway (capability/query.go's doc
// comment explains why), so this package owns that mapping too, on the same
// terms as the audit half.
//
// Pure, total mapping in both directions. No filtering, no defaulting, no
// policy: every decision (validation, pagination clamping, output stripping)
// is made in capability/readlane.go, and every row shape is owned by
// internal/audit and internal/jobs.
package auditquery

import (
	"context"
	"errors"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Queries adapts an audit.QueryRepository and a jobs.QueryRepository to
// capability.AuditQuery and capability.JobQuery.
type Queries struct {
	audit audit.QueryRepository
	jobs  jobs.QueryRepository
}

// New returns a Queries backed by a and j.
func New(a audit.QueryRepository, j jobs.QueryRepository) *Queries {
	return &Queries{audit: a, jobs: j}
}

var (
	_ capability.AuditQuery = (*Queries)(nil)
	_ capability.JobQuery   = (*Queries)(nil)
)

// QueryAudit implements capability.AuditQuery.
func (q *Queries) QueryAudit(ctx context.Context, f capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	p, err := q.audit.Query(ctx, toAuditQuery(f), page.Limit, page.Cursor)
	if err != nil {
		return capability.AuditPage{}, mapCursorErr(err)
	}
	return fromAuditPage(p), nil
}

// AuditCounts implements capability.AuditQuery.
func (q *Queries) AuditCounts(ctx context.Context, f capability.AuditFilter, bucket time.Duration) ([]capability.PrincipalBucket, error) {
	buckets, err := q.audit.CountsByPrincipal(ctx, toAuditQuery(f), bucket)
	if err != nil {
		return nil, err
	}
	out := make([]capability.PrincipalBucket, len(buckets))
	for i, b := range buckets {
		out[i] = fromBucket(b)
	}
	return out, nil
}

// AuditReach implements capability.AuditQuery.
func (q *Queries) AuditReach(ctx context.Context, f capability.AuditFilter) (capability.Reach, error) {
	r, err := q.audit.ReachCounts(ctx, toAuditQuery(f))
	if err != nil {
		return capability.Reach{}, err
	}
	return fromReach(r), nil
}

// QueryJobs implements capability.JobQuery.
func (q *Queries) QueryJobs(ctx context.Context, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	p, err := q.jobs.QueryJobs(ctx, toJobQuery(f), page.Limit, page.Cursor)
	if err != nil {
		return capability.JobPage{}, mapCursorErr(err)
	}
	return fromJobPage(p), nil
}

// QueryTasks implements capability.JobQuery.
func (q *Queries) QueryTasks(ctx context.Context, f capability.TaskFilter, page capability.PageRequest) (capability.TaskPage, error) {
	p, err := q.jobs.QueryTasks(ctx, toTaskQuery(f), page.Limit, page.Cursor)
	if err != nil {
		return capability.TaskPage{}, mapCursorErr(err)
	}
	return fromTaskPage(p), nil
}

// mapCursorErr translates the store-layer cursor sentinels
// (audit.ErrInvalidCursor, jobs.ErrInvalidCursor) onto capability's own
// (capability.ErrInvalidCursor), so a caller of the capability layer never
// has to know which store-layer package produced the error — mirroring how
// this whole package hides internal/audit and internal/jobs behind
// capability's vocabulary.
func mapCursorErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrInvalidCursor), errors.Is(err, jobs.ErrInvalidCursor):
		return capability.ErrInvalidCursor
	default:
		return err
	}
}

func toAuditQuery(f capability.AuditFilter) audit.Query {
	var outcome *jobs.Outcome
	if f.Outcome != nil {
		v := *f.Outcome
		outcome = &v
	}
	return audit.Query{
		Kinds:          f.Kinds,
		AccountID:      f.AccountID,
		OnBehalfOf:     f.OnBehalfOf,
		Operations:     f.Operations,
		NodeID:         f.NodeID,
		JobID:          f.JobID,
		ApprovalID:     f.ApprovalID,
		GrantID:        f.GrantID,
		Outcome:        outcome,
		Since:          f.Since,
		Until:          f.Until,
		ArgKey:         f.ArgKey,
		ArgValuePrefix: f.ArgValuePrefix,
	}
}

func fromAuditRow(r audit.Row) capability.AuditRow {
	return capability.AuditRow{
		ID:        r.ID,
		Timestamp: r.Timestamp,
		Kind:      r.Kind,
		Principal: r.Principal,
		Verified: capability.VerifiedIdentity{
			AccountID:   r.Attribution.Verified.AccountID,
			AccountName: r.Attribution.Verified.AccountName,
			Role:        r.Attribution.Verified.Role,
			TokenID:     r.Attribution.Verified.TokenID,
			Method:      r.Attribution.Verified.Method,
			Source:      r.Attribution.Verified.Source,
		},
		Asserted: capability.Assertions{
			OnBehalfOf:  r.Attribution.Asserted.OnBehalfOf,
			Traceparent: r.Attribution.Asserted.Traceparent,
			SessionRef:  r.Attribution.Asserted.SessionRef,
			ChangeRef:   r.Attribution.Asserted.ChangeRef,
		},
		Selector:        r.Selector,
		JobID:           r.JobID,
		NodeID:          r.NodeID,
		ActionKind:      r.ActionKind,
		OperationName:   r.OperationName,
		Args:            copyStringMap(r.Args),
		RawExecArgv:     copyStringSlice(r.RawExecArgv),
		Outcome:         r.Outcome,
		Reason:          r.Reason,
		ApprovalID:      r.ApprovalID,
		GrantID:         r.GrantID,
		ApprovalAnswer:  capability.ApprovalAnswer(r.ApprovalAnswer),
		DecisionChannel: r.DecisionChannel,
		PlanHash:        r.PlanHash,
	}
}

func fromAuditPage(p audit.Page) capability.AuditPage {
	rows := make([]capability.AuditRow, len(p.Rows))
	for i, r := range p.Rows {
		rows[i] = fromAuditRow(r)
	}
	return capability.AuditPage{Rows: rows, Next: p.Next, Limit: p.Limit}
}

func fromBucket(b audit.Bucket) capability.PrincipalBucket {
	return capability.PrincipalBucket{
		AccountID:   b.AccountID,
		AccountName: b.AccountName,
		Start:       b.Start,
		Count:       b.Count,
	}
}

func fromReach(r audit.Reach) capability.Reach {
	return capability.Reach{
		Calls:           r.Calls,
		DistinctTargets: r.DistinctTargets,
		DistinctNodes:   r.DistinctNodes,
	}
}

func toJobQuery(f capability.JobFilter) jobs.JobQuery {
	return jobs.JobQuery{
		JobID:              f.JobID,
		State:              f.State,
		RequesterAccountID: f.RequesterAccountID,
		Operation:          f.Operation,
		RiskClass:          f.RiskClass,
		OnBehalfOf:         f.OnBehalfOf,
		Since:              f.Since,
		Until:              f.Until,
	}
}

func fromJobSummary(s jobs.JobSummary) capability.JobSummary {
	return capability.JobSummary{
		JobID:              s.JobID,
		CreatedAt:          s.CreatedAt,
		State:              s.State,
		ActionKind:         s.ActionKind,
		OperationName:      s.OperationName,
		RiskClass:          s.RiskClass,
		Selector:           s.Selector,
		Requester:          s.Requester,
		RequesterAccountID: s.RequesterAccountID,
		OnBehalfOf:         s.OnBehalfOf,
		ApprovalID:         s.ApprovalID,
		GrantID:            s.GrantID,
		Args:               copyStringMap(s.Args),
		RawExecArgv:        copyStringSlice(s.RawExecArgv),
		Total:              s.Total,
		Counts:             copyOutcomeCounts(s.Counts),
		Unresolved:         s.Unresolved,
	}
}

// copyStringMap, copyStringSlice and copyOutcomeCounts are what make this
// package's mapping TOTAL in the sense that matters at a seam boundary: the
// capability-layer value shares no backing store with the internal one it was
// built from. Handing the same map across the boundary is an alias, and an
// alias is a caller one layer up quietly mutating the layer below's value —
// which is exactly the kind of coupling mirroring these types was meant to
// prevent. Applied to every reference-typed field this package maps EXCEPT
// TaskRow's Stdout/Stderr, which are deliberately handed over as they are:
// they are up to a megabyte per Task and the page above may hold a hundred of
// them, so copying them would double the largest allocation on the read lane
// to guard a value nothing else retains. That exception is stated here rather
// than left to be inferred from the code.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}

func copyOutcomeCounts(m map[jobs.Outcome]int) map[jobs.Outcome]int {
	if m == nil {
		return nil
	}
	out := make(map[jobs.Outcome]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func fromJobPage(p jobs.JobPage) capability.JobPage {
	out := make([]capability.JobSummary, len(p.Jobs))
	for i, j := range p.Jobs {
		out[i] = fromJobSummary(j)
	}
	return capability.JobPage{Jobs: out, Next: p.Next, Limit: p.Limit}
}

func toTaskQuery(f capability.TaskFilter) jobs.TaskQuery {
	return jobs.TaskQuery{JobID: f.JobID, Outcome: f.Outcome}
}

func fromTaskSummary(s jobs.TaskSummary) capability.TaskRow {
	return capability.TaskRow{
		TaskID:       s.TaskID,
		NodeID:       s.NodeID,
		State:        s.State,
		Outcome:      s.Outcome,
		ExitCode:     s.ExitCode,
		RiskClass:    s.RiskClass,
		Stdout:       s.Stdout,
		Stderr:       s.Stderr,
		CreatedAt:    s.CreatedAt,
		DispatchedAt: s.DispatchedAt,
		ResolvedAt:   s.ResolvedAt,
	}
}

func fromTaskPage(p jobs.TaskPage) capability.TaskPage {
	out := make([]capability.TaskRow, len(p.Tasks))
	for i, task := range p.Tasks {
		out[i] = fromTaskSummary(task)
	}
	return capability.TaskPage{Tasks: out, Next: p.Next, Limit: p.Limit}
}
