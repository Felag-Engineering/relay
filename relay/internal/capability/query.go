package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// query.go is the capability layer's read-lane vocabulary: the
// filtered, paginated, aggregating query surface over the audit trail and
// over Jobs/Tasks, so the Console's Activity, Job detail, and AI-agent history
// screens — and any future /api/v1 audit route — share ONE
// seam (invariant 10) instead of each materialising the whole trail.
//
// Every type here MIRRORS internal/audit's and internal/jobs' read-lane
// types rather than reusing them directly. That is deliberate for the
// audit half: capability's import allowlist bars internal/audit
// (assertions.go's doc comment, and .golangci.yml's capability-imports rule)
// specifically so a caller-controlled value never gets a path to the store
// through this package, and internal/auditquery — auditsink's twin — owns
// the total mapping in both directions. The Job/Task half is mirrored too,
// even though internal/jobs IS an allowed import here, so the capability
// layer's own public contract (Filter/Row naming) does not simply re-export
// whatever internal/jobs.QueryRepository happens to look like today.

// AuditFilter is the trail's read filter — capability's mirror of
// audit.Query. Every non-zero field ANDs; the zero value matches every Row.
type AuditFilter struct {
	Kinds      []string
	AccountID  string
	OnBehalfOf string
	Operations []string
	NodeID     string
	JobID      string
	ApprovalID string
	GrantID    string
	// Outcome is a pointer because jobs.OutcomeUnspecified is itself a real,
	// meaningful value (refusals, plans, and Freeze rows all carry it) — see
	// audit.Query.Outcome's doc comment.
	Outcome      *jobs.Outcome
	Since, Until time.Time
	// ArgKey and ArgValuePrefix filter on one key of a Record's Args map. See
	// audit.Query's doc comment for the exact matching semantics.
	ArgKey, ArgValuePrefix string
}

// VerifiedIdentity is AuditRow's verified-lane mirror of audit.Verified —
// capability's own vocabulary for the attribution the Relay itself
// established, kept separate from the caller-claimed Assertions type the
// dispatch pipeline already carries (assertions.go).
type VerifiedIdentity struct {
	AccountID   string
	AccountName string
	Role        string
	TokenID     string
	Method      string
	Source      string
}

// AuditRow is the projection QueryAudit returns — capability's mirror of
// audit.Row.
//
// **AuditRow has NO Stdout/Stderr/Truncated field.** That absence is
// deliberate (ADR-0025: a read-class query never returns read output — the
// seam has no field for it), not an oversight: the SELECT
// behind audit.Row does not name those columns either (internal/store/
// auditquery.go), so no output ever crosses this seam to redact — there is
// nothing here for a caller of this package to accidentally forward.
type AuditRow struct {
	ID        string
	Timestamp time.Time
	Kind      string
	Principal string

	// Verified and Asserted are the two attribution lanes. Verified is
	// this file's own VerifiedIdentity; Asserted reuses the existing
	// capability.Assertions type, since that is already this package's
	// vocabulary for the caller-claimed lane.
	Verified VerifiedIdentity
	Asserted Assertions

	Selector      string
	JobID         string
	NodeID        string
	ActionKind    string
	OperationName string
	Args          map[string]string
	RawExecArgv   []string
	Outcome       jobs.Outcome
	Reason        string

	ApprovalID string
	GrantID    string

	// ApprovalAnswer, DecisionChannel, and PlanHash are the structured
	// counterpart to a decision's prose Reason. This does NOT widen
	// the seam toward output: the excluded fields are Stdout/Stderr/Truncated,
	// and these are the same class of field as ApprovalID/GrantID above.
	// DecisionChannel is a plain string here — a
	// rendered projection, not a domain value a surface may act on.
	ApprovalAnswer  ApprovalAnswer
	DecisionChannel string
	PlanHash        string
}

// AuditPage is one page of AuditRow, cursor-paginated newest first.
type AuditPage struct {
	Rows  []AuditRow
	Next  string
	Limit int
}

// PrincipalBucket is one principal's Record count within one time bucket —
// capability's mirror of audit.Bucket. No Console screen has consumed
// these aggregates since the Read-egress screen was retired (2026-10-01).
type PrincipalBucket struct {
	AccountID   string
	AccountName string
	Start       time.Time
	Count       int
}

// Reach is AuditReach's aggregate over an AuditFilter — capability's mirror
// of audit.Reach: how many calls, how many distinct targets, and how many
// distinct Nodes.
type Reach struct {
	Calls           int
	DistinctTargets int
	DistinctNodes   int
}

// JobFilter is the Job list's filter — capability's mirror of jobs.JobQuery.
// jobs.JobState and jobs.RiskClass are reused directly rather than mirrored:
// internal/jobs is already an allowed import here (unlike internal/audit),
// so mirroring its enums would only add a conversion with nothing to guard.
type JobFilter struct {
	// JobID restricts to one Job — the Job-detail screen's whole header:
	// exact per-outcome counts as ONE aggregate row, with no Task
	// materialised. Mirrors AuditFilter.JobID above.
	JobID              string
	State              *jobs.JobState
	RequesterAccountID string
	Operation          string
	RiskClass          *jobs.RiskClass
	// OnBehalfOf is the ASSERTED lane's exact match — never a prefix and
	// never a LIKE, mirroring AuditFilter.OnBehalfOf and jobs.JobQuery's.
	OnBehalfOf   string
	Since, Until time.Time

	// Order is the list's direction and the one the page cursor walks. The
	// zero value is newest first; oldest first over running Jobs is
	// longest-running first. A cursor minted in one direction is refused in
	// the other.
	Order jobs.JobOrder

	// CountMatching asks for JobPage.Matching, computed inside the same
	// audited read. It narrows nothing. The zero value asks for no count.
	CountMatching bool
}

// JobSummary is one row of a Job list — capability's mirror of
// jobs.JobSummary.
type JobSummary struct {
	JobID     string
	CreatedAt time.Time
	State     jobs.JobState

	ActionKind    jobs.ActionKind
	OperationName string
	RiskClass     jobs.RiskClass

	// Requester, RequesterAccountID and RequesterKind come from the Job row:
	// present from the moment the Job exists (in-flight Jobs included), and
	// empty for a Job with no recorded requester — never filled
	// from the trail. Selector is still audit-joined, and is empty for a Job
	// whose audit row has not been written yet (in-flight) — see
	// jobs.JobSummary's doc comment.
	Selector           string
	Requester          string
	RequesterAccountID string
	RequesterKind      string

	// OnBehalfOf, ApprovalID, GrantID, Args and RawExecArgv join from the
	// same per-Job dispatch aggregate as the three fields above, and are
	// empty for the same in-flight reason — see jobs.JobSummary's doc
	// comment for why MIN over a Job's dispatch rows is exact rather than a
	// sample. They are here so that "who asked, FOR WHOM, WHO APPROVED, what
	// happened" is ONE query rather than one query plus a per-row lookup:
	// every read-lane call appends a record to the append-only trail
	// (readlane.go), so a 25-row page enriched row by row would append 25
	// read records to render one screen.
	//
	// Nothing added here is output. As with AuditRow above (see its doc
	// comment), **JobSummary has NO Stdout/Stderr/Truncated field** and must
	// never grow one: the SELECT behind it names no BLOB column either, so
	// there is nothing on this seam to redact.
	OnBehalfOf  string
	ApprovalID  string
	GrantID     string
	Args        map[string]string
	RawExecArgv []string

	Total      int
	Counts     map[jobs.Outcome]int
	Unresolved int

	// Recording is how much of the Job's dispatch audit record the trail holds;
	// see jobs.JobSummary.Recording. Read it through OutcomeUnrecorded.
	Recording jobs.JobRecording
}

// OutcomeUnrecorded reports "intent recorded, outcome unknown": the Job is
// finished, yet the trail holds its dispatch intent with none, or only some,
// of its per-Node outcome rows. This is the single definition (invariant 10):
// adapters render it and never decide it.
//
// A Job still Running is never reported, because Running already says the
// outcome is pending. That leaves one case it cannot see: a crash before
// dispatch reached every Task leaves Pending survivors, which ADR-0004 says
// are never run, so the Job stays Running with Recording == IntentOnly and
// this is false. The read lane still reports Recording; the store has no
// restart epoch, so a surface cannot tell that Job from a live run.
func (s JobSummary) OutcomeUnrecorded() bool {
	return s.State == jobs.JobStateComplete &&
		(s.Recording == jobs.JobRecordingIntentOnly || s.Recording == jobs.JobRecordingOutcomePartial)
}

// JobPage is one page of JobSummary, cursor-paginated in JobFilter.Order's
// direction.
type JobPage struct {
	Jobs  []JobSummary
	Next  string
	Limit int

	// Matching is the number of Jobs matching the filter, ignoring paging.
	// It is zero unless JobFilter.CountMatching was set.
	Matching int
}

// TaskFilter is a single Job's Task list filter — capability's mirror of
// jobs.TaskQuery.
type TaskFilter struct {
	JobID   string
	Outcome *jobs.Outcome
}

// TaskRow is one row of a Job's Task list — capability's mirror of
// jobs.TaskSummary.
//
// Stdout, Stderr, and RiskClass ARE present here — unlike AuditRow. D3 (a
// decision deliberately flagged for human review): job detail clusters Tasks by
// identical output and renders the deny rule verbatim, which needs the captured
// bytes for mutate-class Tasks, and the tasks table already stores them.
// RiskClass is what lets readlane.go strip output before a TaskRow ever leaves
// this package for every Task EXCEPT one whose RiskClass is explicitly
// RiskClassMutate — see QueryTasks in readlane.go for exactly where and why the
// condition is "!= Mutate" and not "== Read" (F3, cycle-2 security review:
// output retention must fail safe toward STRIPPING, the opposite of this
// codebase's usual Unspecified-means-mutate guardrail default). If a reviewer
// reads "a read-class query never returns read output" as covering the Task
// lane too, the alternative is an output-free TaskRow with job detail kept on
// the existing JobReader for output instead — that reversal touches only this
// struct and readlane.go's QueryTasks.
// Truncated is deliberately ABSENT — see jobs.TaskSummary's doc comment: the
// tasks table has no truncated column, and this seam does not invent one.
type TaskRow struct {
	TaskID   string
	NodeID   string
	State    jobs.DispatchState
	Outcome  jobs.Outcome
	ExitCode int32

	RiskClass jobs.RiskClass
	Stdout    []byte
	Stderr    []byte

	CreatedAt    time.Time
	DispatchedAt time.Time
	ResolvedAt   time.Time
}

// TaskPage is one page of TaskRow.
type TaskPage struct {
	Tasks []TaskRow
	Next  string
	Limit int
}

// PageRequest is a query lane caller's pagination ask. Limit <= 0 means
// DefaultPageSize; a Limit above MaxPageSize is clamped, never refused, and
// the effective value is reported back on the resulting Page.
type PageRequest struct {
	Limit  int
	Cursor string
}

// DefaultPageSize and MaxPageSize bound every query-lane page. Code
// constants, not settings — invariant 11: nothing here reads or exposes
// Relay configuration, and no API can raise them.
const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// ErrInvalidFilter is returned when a Filter fails validation before it ever
// reaches a seam.
var ErrInvalidFilter = errors.New("capability: invalid query filter")

// ErrInvalidCursor is returned when a caller-supplied pagination cursor
// cannot be parsed. Never a silent reset to page one — see readlane.go.
var ErrInvalidCursor = errors.New("capability: invalid pagination cursor")

// ErrQueriesUnavailable is returned by the read-lane methods on a ReadLane
// assembled with no query seams (unreachable through NewReadLane). A wiring
// fault, surfaced as a legible error rather than a nil-seam panic — mirrors
// ErrApprovalUnavailable.
var ErrQueriesUnavailable = errors.New("capability: audit/Job queries are not configured on this Relay")

// validate checks f before it reaches any seam. Caller-controlled inputs are
// bounded HERE, not just at the store: a query filter reaches an append-only
// table by way of the read-audit record readlane.go writes for every call
// (the unbounded-field lesson audit/attribution.go's
// MaxAssertedFieldBytes states — the same reasoning applies to a filter that
// gets recorded as the search itself).
func (f AuditFilter) validate() error {
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Until.After(f.Since) {
		return fmt.Errorf("%w: until must be after since", ErrInvalidFilter)
	}
	// The same bound JobFilter and TaskFilter carry (readlane.go's
	// validateJobID). All three land in the read record — this one in its
	// job_id COLUMN, not merely in the summary — so bounding two of the three
	// would leave the bound in place only where it was cheapest to add.
	if err := validateJobID(f.JobID); err != nil {
		return err
	}
	// The asserted lane is caller-controlled and reaches the store intact —
	// see validateOnBehalfOf in readlane.go for why the recorded summary's own
	// truncation is not enough.
	if err := validateOnBehalfOf(f.OnBehalfOf); err != nil {
		return err
	}
	if len(f.Kinds) > 32 {
		return fmt.Errorf("%w: %d kinds requested, max 32", ErrInvalidFilter, len(f.Kinds))
	}
	for _, k := range f.Kinds {
		if len(k) > 64 {
			return fmt.Errorf("%w: kind %q exceeds 64 bytes", ErrInvalidFilter, k)
		}
	}
	// Operations is capped exactly as Kinds is (F2, cycle-2 security
	// review): buildAuditWhere emits one bound placeholder per entry, and an
	// uncapped list is an asymmetric caller-driven allocation on a request
	// path — confirmed empirically to fail SQLite's "too many SQL variables"
	// limit at 60,000 entries. It fails closed rather than injecting, but
	// refusing it here means the caller gets a legible error instead of a
	// driver error from three layers down.
	if len(f.Operations) > 32 {
		return fmt.Errorf("%w: %d operations requested, max 32", ErrInvalidFilter, len(f.Operations))
	}
	for _, op := range f.Operations {
		if len(op) > 64 {
			return fmt.Errorf("%w: operation %q exceeds 64 bytes", ErrInvalidFilter, op)
		}
	}
	if f.ArgValuePrefix != "" {
		if !validArgKey(f.ArgKey) {
			return fmt.Errorf("%w: arg key %q is not a valid identifier (^[a-z][a-z0-9_]*$)", ErrInvalidFilter, f.ArgKey)
		}
		if len(f.ArgValuePrefix) > 256 {
			return fmt.Errorf("%w: arg value prefix exceeds 256 bytes", ErrInvalidFilter)
		}
	}
	return nil
}

// MaxAggregateWindow bounds Since..Until on the AGGREGATE paths — AuditCounts
// and AuditReach — validated by validateWindow (F1, cycle-2 security
// review). Unlike QueryAudit, neither aggregate paginates: AuditCounts has
// no LIMIT and AuditReach returns one row computed over every matching
// Record, so an unbounded window is an unbounded scan/allocation reachable
// from any authenticated caller with AuditFilter{}. 90 days covers a
// quarterly trend view with room to spare.
const MaxAggregateWindow = 90 * 24 * time.Hour

// MinAuditBucket floors AuditCounts' caller-supplied bucket width (F1): with
// no floor, a caller-chosen 1-second bucket over the maximum window
// materialises one PrincipalBucket per (account, second) — on a large trail,
// tens of millions of rows and gigabytes of heap, in one request, repeatable.
// A bucket below the floor is clamped up to it, never refused — the same
// "clamp, don't reject" convention clampPage uses for Limit.
const MinAuditBucket = 60 * time.Second

// validateWindow checks f is safe to hand to an aggregate path (AuditCounts,
// AuditReach): both require a bounded Since/Until window before the filter
// ever reaches SQL, because neither aggregate has a page size to clamp
// against. AuditFilter{} — otherwise a perfectly legal match-everything
// filter for QueryAudit — is exactly the hostile case this refuses for the
// aggregate paths.
func (f AuditFilter) validateWindow() error {
	if f.Since.IsZero() || f.Until.IsZero() {
		return fmt.Errorf("%w: aggregate queries require both since and until", ErrInvalidFilter)
	}
	if f.Until.Sub(f.Since) > MaxAggregateWindow {
		return fmt.Errorf("%w: window exceeds the maximum of %s", ErrInvalidFilter, MaxAggregateWindow)
	}
	return nil
}

// clampBucket floors a caller-supplied bucket width to MinAuditBucket — a
// caller asking for finer granularity than allowed gets the coarsest safe
// granularity instead of a refusal, mirroring clampPage.
func clampBucket(d time.Duration) time.Duration {
	if d < MinAuditBucket {
		return MinAuditBucket
	}
	return d
}

// validArgKey reports whether s matches ^[a-z][a-z0-9_]*$, hand-written
// because capability's import allowlist admits no regexp package.
func validArgKey(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && c >= '0' && c <= '9':
		case i > 0 && c == '_':
		default:
			return false
		}
	}
	return true
}

// maxFilterSummaryBytes bounds summary()'s rendering — recorded as the read
// record's selector, so it is subject to the same storage-exhaustion
// reasoning as every other caller-controlled audit field.
const maxFilterSummaryBytes = 256

// filterSummary accumulates a filter's "name=value" pairs, joined by ';',
// for the read record's selector.
//
// One builder for both filters, and it ESCAPES ';' and '=' inside a value.
// stripControl removes control characters and nothing else, so without this a
// caller-controlled field could forge the summary's own structure: a Job ID
// of `x;requester=admin;op=raw_exec` would be recorded as a selector no human
// reading the trail could tell from a genuine multi-field filter. The trail is
// evidence, and evidence whose structure the subject can write is not.
type filterSummary struct{ b strings.Builder }

func (s *filterSummary) field(name, value string) {
	if value == "" {
		return
	}
	if s.b.Len() > 0 {
		s.b.WriteByte(';')
	}
	s.b.WriteString(name)
	s.b.WriteByte('=')
	s.b.WriteString(escapeFilterValue(value))
}

// String renders the accumulated fields, stripped of control characters and
// bounded, exactly as it is recorded.
func (s *filterSummary) String() string {
	return truncateBytes(stripControl(s.b.String()), maxFilterSummaryBytes)
}

// wouldTruncate reports whether String() would shorten the accumulated
// summary — that is, whether the caller needs to ask the question BEFORE
// writing, rather than discover it only after a record already understates
// the filter. String() itself cannot answer this after the fact: a
// pre-truncation length of exactly maxFilterSummaryBytes and one well over
// it both render as a maxFilterSummaryBytes-byte string, so the check has to
// run on the untruncated length. canonicalEventKinds (readlane.go) is the
// first caller that needs to REFUSE rather than silently accept a
// truncation.
func (s *filterSummary) wouldTruncate() bool {
	return len(stripControl(s.b.String())) > maxFilterSummaryBytes
}

// escapeFilterValue backslash-escapes the two characters that carry structure
// in a summary, and the backslash itself so the escaping is reversible.
func escapeFilterValue(v string) string {
	if !strings.ContainsAny(v, `;=\`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for _, r := range v {
		if r == ';' || r == '=' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// summary renders f as a compact, control-character-stripped string —
// "kinds=...;account=...;node=...;op=...;since=...;until=...;arg=..." —
// recorded as the read record's selector (readlane.go), so the trail can
// answer "who searched the trail for what".
func (f AuditFilter) summary() string {
	var s filterSummary
	field := s.field
	field("kinds", strings.Join(f.Kinds, ","))
	field("account", f.AccountID)
	field("on_behalf_of", f.OnBehalfOf)
	field("node", f.NodeID)
	field("job", f.JobID)
	field("op", strings.Join(f.Operations, ","))
	field("approval", f.ApprovalID)
	field("grant", f.GrantID)
	if !f.Since.IsZero() {
		field("since", f.Since.UTC().Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		field("until", f.Until.UTC().Format(time.RFC3339))
	}
	if f.ArgKey != "" {
		// ArgKey is validated as an identifier and the '=' between the two is
		// this field's own structure, so only the caller-controlled prefix is
		// escaped.
		field("arg", f.ArgKey+"="+escapeFilterValue(f.ArgValuePrefix))
	}
	return s.String()
}

// stripControl removes C0/C1 control characters and DEL — the same rule
// audit.isControl applies, hand-copied because capability may not import
// internal/audit: a newline in a recorded search is a log-forging vector
// exactly as it is in an asserted attribution field.
func stripControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateBytes bounds s to n bytes, cutting on a UTF-8 rune boundary (a
// continuation byte has its top two bits "10", hand-checked because
// capability's import allowlist admits no unicode/utf8 package) so a
// truncated summary never holds an invalid fragment.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// AuditQuery is the trail's read-lane seam: filtered, paginated queries and
// aggregations. Satisfied by internal/auditquery.Queries, the adapter to
// internal/audit.QueryRepository — see this file's package doc comment for
// why the adapter lives in its own package.
type AuditQuery interface {
	// QueryAudit returns one page of AuditRow matching f, newest first.
	QueryAudit(ctx context.Context, f AuditFilter, page PageRequest) (AuditPage, error)

	// AuditCounts returns f's matching Records grouped by verified Account
	// and by time bucket. No Console screen has consumed it since the
	// Read-egress screen was retired (2026-10-01).
	AuditCounts(ctx context.Context, f AuditFilter, bucket time.Duration) ([]PrincipalBucket, error)

	// AuditReach returns f's call count, distinct-target count, and
	// distinct-Node count: how far a query's matching Records reached. No
	// Console screen has consumed it since the Read-egress screen was
	// retired (2026-10-01).
	AuditReach(ctx context.Context, f AuditFilter) (Reach, error)
}

// JobQuery is the Job/Task read-lane seam: filtered, paginated summaries.
// Satisfied by internal/auditquery.Queries, the adapter to
// internal/jobs.QueryRepository.
type JobQuery interface {
	// QueryJobs returns one page of JobSummary matching f, in f.Order's
	// direction (newest CreatedAt first by default).
	QueryJobs(ctx context.Context, f JobFilter, page PageRequest) (JobPage, error)

	// QueryTasks returns one page of TaskRow for f.JobID, optionally
	// filtered by f.Outcome.
	QueryTasks(ctx context.Context, f TaskFilter, page PageRequest) (TaskPage, error)
}
