package capability

import (
	"context"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// readlane.go is the TRAIL AND JOB half of the read lane on *Service (#441):
// the capability layer's seam over the audit trail's and Jobs/Tasks'
// filtered, paginated queries. Its registry half — the fleet enumeration and
// the single-Node read — is readlane_registry.go (#450); both obey the order
// below without exception.
//
// Every method follows the same order: validate the filter -> record the
// read, FAIL CLOSED -> delegate to the seam. Recording first mirrors
// mcp/readaudit.go's auditRead and ADR-0025: an unauditable read of the
// trail must not silently happen. That is a real cost, stated plainly on the
// same precedent readaudit.go states it on: a Relay that cannot write its
// audit trail stops answering these queries rather than answering them
// invisibly.

// Read-lane tool names. Low-cardinality and stable — they land in the audit
// trail via RecordRead, so they must read the same way a year from now as
// they do today.
const (
	toolQueryAudit  = "query_audit"
	toolQueryJobs   = "query_jobs"
	toolQueryTasks  = "query_tasks"
	toolAuditCounts = "audit_counts"
	toolAuditReach  = "audit_reach"
)

// clampPage applies DefaultPageSize/MaxPageSize to a caller's PageRequest,
// returning the effective limit. Limit <= 0 becomes the default; anything
// above the max is clamped, never refused, and the effective value is
// reported back on the resulting Page (Page.Limit) so a caller can see it
// was clamped.
func clampPage(p PageRequest) int {
	switch {
	case p.Limit <= 0:
		return DefaultPageSize
	case p.Limit > MaxPageSize:
		return MaxPageSize
	default:
		return p.Limit
	}
}

// QueryAudit returns one page of AuditRow matching f, newest first.
func (s *Service) QueryAudit(ctx context.Context, p Principal, f AuditFilter, page PageRequest) (AuditPage, error) {
	if s.auditQ == nil {
		return AuditPage{}, ErrQueriesUnavailable
	}
	if err := f.validate(); err != nil {
		return AuditPage{}, err
	}
	if err := s.recordQueryRead(ctx, p, toolQueryAudit, f.summary(), f.NodeID, f.JobID); err != nil {
		return AuditPage{}, err
	}
	return s.auditQ.QueryAudit(ctx, f, PageRequest{Limit: clampPage(page), Cursor: page.Cursor})
}

// AuditCounts returns f's matching Records grouped by verified Account and
// by time bucket — read egress's per-principal trend.
//
// f must carry a bounded Since/Until window (validateWindow) and bucket is
// floored to MinAuditBucket (clampBucket) — F1, #441 cycle-2 security
// review: unlike QueryAudit, this path has no LIMIT, so AuditFilter{} with a
// caller-chosen sub-second bucket would otherwise be an unbounded,
// repeatable multi-GB allocation on a large trail.
func (s *Service) AuditCounts(ctx context.Context, p Principal, f AuditFilter, bucket time.Duration) ([]PrincipalBucket, error) {
	if s.auditQ == nil {
		return nil, ErrQueriesUnavailable
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	if err := f.validateWindow(); err != nil {
		return nil, err
	}
	bucket = clampBucket(bucket)
	if err := s.recordQueryRead(ctx, p, toolAuditCounts, f.summary(), f.NodeID, f.JobID); err != nil {
		return nil, err
	}
	return s.auditQ.AuditCounts(ctx, f, bucket)
}

// AuditReach returns f's call count, distinct-target count, and
// distinct-Node count — read egress's "how far did this reach" summary.
//
// f must carry a bounded Since/Until window (validateWindow) — F1, #441
// cycle-2 security review: AuditReach has no LIMIT either, and its
// distinct-target expression evaluates a json_extract COALESCE per matching
// row (F6), so an unbounded filter is a full scan of the largest table.
func (s *Service) AuditReach(ctx context.Context, p Principal, f AuditFilter) (Reach, error) {
	if s.auditQ == nil {
		return Reach{}, ErrQueriesUnavailable
	}
	if err := f.validate(); err != nil {
		return Reach{}, err
	}
	if err := f.validateWindow(); err != nil {
		return Reach{}, err
	}
	if err := s.recordQueryRead(ctx, p, toolAuditReach, f.summary(), f.NodeID, f.JobID); err != nil {
		return Reach{}, err
	}
	return s.auditQ.AuditReach(ctx, f)
}

// QueryJobs returns one page of JobSummary matching f, newest (CreatedAt)
// first.
func (s *Service) QueryJobs(ctx context.Context, p Principal, f JobFilter, page PageRequest) (JobPage, error) {
	if s.jobQ == nil {
		return JobPage{}, ErrQueriesUnavailable
	}
	if err := f.validate(); err != nil {
		return JobPage{}, err
	}
	// The Job ID is recorded on the read record itself, not only inside the
	// summary, so the trail can answer "who looked at this Job" by the same
	// indexed column every other lookup uses.
	if err := s.recordQueryRead(ctx, p, toolQueryJobs, f.summary(), "", f.JobID); err != nil {
		return JobPage{}, err
	}
	return s.jobQ.QueryJobs(ctx, f, PageRequest{Limit: clampPage(page), Cursor: page.Cursor})
}

// QueryTasks returns one page of TaskRow for f.JobID, optionally filtered by
// f.Outcome.
//
// **D3** (flagged for human review in the #441 plan, TaskRow's doc comment
// carries the full reasoning): output is stripped here, on the returned
// TaskRow, for every Task EXCEPT one whose RiskClass is explicitly
// jobs.RiskClassMutate — keyed on the class, so the Console (or any future
// caller) is not the layer that has to remember the rule. Mutate-class Tasks
// keep their captured Stdout/Stderr, which #423 (job detail) needs to
// cluster identical output.
//
// The strip condition is "!= Mutate", not "== Read" (F3, #441 cycle-2
// security review): everywhere else in this codebase RiskClassUnspecified is
// deliberately treated as mutate ("a guardrail must fail safe"), but for
// OUTPUT RETENTION that direction is inverted — an unrecognised or
// unspecified class must default to STRIPPING the bytes, not keeping them.
// tasks.risk_class is NOT NULL and written from the Operation catalog today,
// so RiskClassUnspecified is not reachable through this path yet, but a
// future schema or catalog change must not silently turn a permissive
// default into a read-output leak. This deliberately diverges from
// auditsink.go:219's `!= RiskClassRead` (retain-unless-Read): that call site
// is unchanged by this issue.
func (s *Service) QueryTasks(ctx context.Context, p Principal, f TaskFilter, page PageRequest) (TaskPage, error) {
	if s.jobQ == nil {
		return TaskPage{}, ErrQueriesUnavailable
	}
	if err := f.validate(); err != nil {
		return TaskPage{}, err
	}
	if err := s.recordQueryRead(ctx, p, toolQueryTasks, f.summary(), "", f.JobID); err != nil {
		return TaskPage{}, err
	}
	tp, err := s.jobQ.QueryTasks(ctx, f, PageRequest{Limit: clampPage(page), Cursor: page.Cursor})
	if err != nil {
		return TaskPage{}, err
	}
	for i := range tp.Tasks {
		if tp.Tasks[i].RiskClass != jobs.RiskClassMutate {
			tp.Tasks[i].Stdout = nil
			tp.Tasks[i].Stderr = nil
		}
	}
	return tp, nil
}

// recordQueryRead writes the read-lane's own access record and fails closed:
// an unauditable read of the trail must not silently happen (ADR-0025,
// mirroring mcp/readaudit.go's auditRead). Called BEFORE the seam runs, on
// the same precedent — readlane_test.go's spy proves the seam is never
// reached when this write fails.
//
// The returned error wraps BOTH ErrReadUnaudited (readlane_registry.go) and
// the sink's own error. The sentinel is what lets a surface distinguish "this
// Relay could not record your read, so it did not serve it" from "the thing
// you asked to read could not be read" — two failures that send an operator
// to opposite components, and one of which is the audit trail itself. The
// underlying error is still wrapped, so a log or a test can say why.
func (s *Service) recordQueryRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	if err := s.audit.RecordRead(ctx, p, tool, selector, nodeID, jobID); err != nil {
		return fmt.Errorf("%w: recording %s: %w", ErrReadUnaudited, tool, err)
	}
	return nil
}

// validate checks f before it reaches any seam — the same reasoning
// AuditFilter.validate states.
func (f JobFilter) validate() error {
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Until.After(f.Since) {
		return fmt.Errorf("%w: until must be after since", ErrInvalidFilter)
	}
	if err := validateJobID(f.JobID); err != nil {
		return err
	}
	return validateOnBehalfOf(f.OnBehalfOf)
}

// maxJobIDBytes bounds a caller-supplied Job ID on the read lane. A Job ID
// the Relay issued is 32 hex characters (execution.go), so this is four
// times the real thing and still a bound — the value is caller-controlled
// and lands in the append-only trail as the read record's own selector, the
// same reason AuditFilter.validate bounds Kinds and Operations (F2, #441
// cycle-2 security review).
const maxJobIDBytes = 128

func validateJobID(id string) error {
	if len(id) > maxJobIDBytes {
		return fmt.Errorf("%w: job id exceeds %d bytes", ErrInvalidFilter, maxJobIDBytes)
	}
	return nil
}

// maxOnBehalfOfBytes bounds a caller-supplied asserted on-behalf-of on the
// read lane, mirroring maxJobIDBytes above and audit's own
// MaxAssertedFieldBytes (256) — a value that could never have been RECORDED
// longer than that is not one worth accepting as a filter for.
//
// The recorded read record is already safe without this: filterSummary.String
// control-strips and truncates to maxFilterSummaryBytes. The bound is here
// because the value crosses the capability boundary INTACT on its way to the
// store, and net/http's roughly 1 MB header limit is not a bound this layer
// should be relying on. Bounded here means bounded for every surface, not
// only for the one whose transport happens to bound it.
const maxOnBehalfOfBytes = 256

func validateOnBehalfOf(v string) error {
	if len(v) > maxOnBehalfOfBytes {
		return fmt.Errorf("%w: on_behalf_of exceeds %d bytes", ErrInvalidFilter, maxOnBehalfOfBytes)
	}
	return nil
}

// summary renders f as a compact, control-character-stripped string,
// recorded as the read record's selector — the Job-list analogue of
// AuditFilter.summary.
func (f JobFilter) summary() string {
	var s filterSummary
	field := s.field
	field("job", f.JobID)
	if f.State != nil {
		field("state", jobStateLabel(*f.State))
	}
	field("requester", f.RequesterAccountID)
	// The asserted lane is recorded too, so the trail can answer "who searched
	// for whose work". No extra validation is needed for it: the value lands
	// only in the read record's selector, and filterSummary.String already
	// strips control characters and truncates to maxFilterSummaryBytes, which
	// is the whole bound this field needs.
	field("on_behalf_of", f.OnBehalfOf)
	field("op", f.Operation)
	if f.RiskClass != nil {
		field("risk_class", riskClassLabel(*f.RiskClass))
	}
	if !f.Since.IsZero() {
		field("since", f.Since.UTC().Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		field("until", f.Until.UTC().Format(time.RFC3339))
	}
	return s.String()
}

// validate checks f before it reaches any seam. JobID is required: an empty
// one is not "every Job's Tasks", it is a query that matches nothing —
// silently, since job_id is never empty in the tasks table — so it is
// refused rather than returned as a truthful-looking empty page.
func (f TaskFilter) validate() error {
	if f.JobID == "" {
		return fmt.Errorf("%w: job id is required", ErrInvalidFilter)
	}
	return validateJobID(f.JobID)
}

// summary renders f as a compact string, recorded as the read record's
// selector.
func (f TaskFilter) summary() string {
	var s filterSummary
	s.field("job", f.JobID)
	if f.Outcome != nil {
		s.field("outcome", outcomeLabel(*f.Outcome))
	}
	return s.String()
}

// jobStateLabel and riskClassLabel render their jobs.* enums as the fixed,
// low-cardinality strings JobFilter.summary uses — mirroring auditsink.go's
// outcomeLabel, which is why outcomeLabel below follows the same shape for
// jobs.Outcome.
func jobStateLabel(st jobs.JobState) string {
	if st == jobs.JobStateRunning {
		return "running"
	}
	return "complete"
}

func riskClassLabel(rc jobs.RiskClass) string {
	switch rc {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// outcomeLabel renders a jobs.Outcome as a fixed-vocabulary string, for
// TaskFilter.summary. A local copy of auditsink.go's outcomeLabel: capability
// may not import internal/auditsink (it would be a cycle — auditsink already
// imports capability), and the mapping is small enough that duplicating it
// here is cheaper than a third package to share it from.
func outcomeLabel(o jobs.Outcome) string {
	switch o {
	case jobs.OutcomeSuccess:
		return "success"
	case jobs.OutcomeFailure:
		return "failure"
	case jobs.OutcomeTimeout:
		return "timeout"
	case jobs.OutcomeDeniedByPolicy:
		return "denied_by_policy"
	case jobs.OutcomeCancelled:
		return "cancelled"
	case jobs.OutcomeUnreachable:
		return "unreachable"
	case jobs.OutcomeVersionRefused:
		return "version_refused"
	case jobs.OutcomeUnsupported:
		return "unsupported"
	default:
		return "unspecified"
	}
}
