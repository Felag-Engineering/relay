package audit

import (
	"context"
	"errors"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// query.go is the trail's READ LANE: a filtered, paginated,
// aggregating query over the append-only table, distinct from Repository's
// append+by-key surface. It exists as its own interface — QueryRepository,
// not an extension of Repository — because a reader that also holds Append
// is exactly the "not append-only" shape this package's doc comment (and
// auditsink's) warns against: Query is read-only by construction, and a
// caller that only imports this file cannot reach Append at all.
//
// Kept SQL-free like the rest of this package (.golangci.yml's domain-no-sql rule): the SQLite
// implementation is internal/store/auditquery.go.

// Query is the trail's read filter. Every non-zero field ANDs; the zero
// value means "no constraint" — Query{} matches every Record.
type Query struct {
	// Kinds restricts to these audit.Kind* values. Empty means any kind.
	Kinds []string

	// AccountID is the verified-lane exact match — the same lane
	// Repository.ByAccount queries.
	AccountID string

	// OnBehalfOf is the asserted-lane exact match. Never a prefix or LIKE:
	// the value is caller-controlled, and Repository.ByOnBehalfOf's doc
	// comment states why a pattern match over it is refused. Mirrored here
	// for the same reason.
	OnBehalfOf string

	// Operations restricts to these operation_name values. Read-class
	// dispatch selection (e.g. a screen's own catalog) is a caller-
	// supplied list rather than a stored risk class — the audit table has no
	// risk_class column.
	Operations []string

	NodeID     string
	JobID      string
	ApprovalID string
	GrantID    string

	// Outcome restricts to one jobs.Outcome. nil means any outcome — a
	// pointer because jobs.OutcomeUnspecified is itself a real, meaningful
	// value (Record's doc comment: refusals, plans, and Freeze rows all carry
	// it), so a zero value cannot double as "unset".
	Outcome *jobs.Outcome

	// Since and Until bound Timestamp, half-open [Since, Until). Both the
	// zero value means unbounded on that side. Comparison is second-granular
	// and WIDENING — see internal/store/auditquery.go's doc comment for why:
	// ts is RFC3339Nano text that trims trailing zeros, so sub-second text
	// order is not chronological order, and a range bound has to widen to the
	// enclosing second to stay correct.
	Since, Until time.Time

	// ArgKey and ArgValuePrefix filter on one key of the Args map, matching
	// records whose Args[ArgKey] starts with ArgValuePrefix. ArgKey is
	// validated against ^[a-z][a-z0-9_]*$ wherever ArgValuePrefix is set — see
	// capability.AuditFilter.validate and the store implementation, both of
	// which check it independently (defense in depth: the store trusts no
	// caller).
	ArgKey, ArgValuePrefix string
}

// Row is the projection QueryRepository.Query returns: audit.Record,
// field-for-field, MINUS Stdout, Stderr, and Truncated.
//
// That absence is deliberate, not an oversight:
// "a read-class query never returns read output — the seam has no field for
// it." The SELECT in internal/store/auditquery.go does not name those columns
// either, so the read lane never pulls a BLOB off disk — which is what makes
// paginating the trail cheap, and what makes a reflect test on this struct a
// meaningful guarantee rather than a convention someone could quietly drop.
type Row struct {
	ID          string
	Timestamp   time.Time
	Kind        string
	Principal   string
	Attribution Attribution

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

	ApprovalAnswer  string
	DecisionChannel string
	PlanHash        string
}

// Page is one page of Rows, cursor-paginated newest first.
type Page struct {
	Rows []Row
	// Next is the cursor for the following page; empty means "no more".
	Next  string
	Limit int
}

// Bucket is one principal's Record count within one time bucket —
// CountsByPrincipal's aggregate.
type Bucket struct {
	AccountID   string
	AccountName string
	Start       time.Time
	Count       int
}

// Reach is ReachCounts' aggregate over a Query: how many calls, how many
// distinct targets, and how many distinct Nodes it touched.
type Reach struct {
	Calls           int
	DistinctTargets int
	DistinctNodes   int
}

// TargetArgKeys is the precedence order that names WHAT a read touched: the
// first of these Args keys present on a Record is the read's target.
// This is the one definition: console/vocab.go's readTargetName iterates this slice, and
// internal/store/auditquery.go's reachTargetExpr builds its COALESCE from
// it. A divergence would make the Console name a read target differently
// from how the reach aggregate counts it.
var TargetArgKeys = []string{"path", "file", "unit", "service"}

// ErrInvalidCursor is returned when a caller-supplied cursor cannot be
// parsed. Never a silent reset to page one — see internal/store/auditquery.go.
var ErrInvalidCursor = errors.New("audit: invalid pagination cursor")

// ErrInvalidFilter is returned when a Query fails validation before it ever
// reaches SQL.
var ErrInvalidFilter = errors.New("audit: invalid query filter")

// DefaultPageSize is used when a caller asks for a page with limit <= 0.
const DefaultPageSize = 50

// MaxPageSize bounds the largest page a caller may request; a larger request
// is clamped, never refused.
const MaxPageSize = 500

// MaxCountBuckets bounds how many (account, bucket) groups
// QueryRepository.CountsByPrincipal may materialise into Go structs in one
// call. Independent of any caller-side
// window/bucket bound: this is the store's own defense-in-depth, the same
// "trust no caller, including one inside the same binary" reasoning
// internal/store/auditquery.go states for re-validating ArgKey. Exceeding it
// is ErrInvalidFilter, never a silent truncation — a caller that hits this
// needs a coarser bucket or a narrower window, not a report that quietly
// stopped partway through.
const MaxCountBuckets = 200_000

// QueryRepository is the trail's read lane: filtered, paginated queries and
// aggregations over the audit table.
//
// Deliberately separate from Repository (append+by-key): Repository is what
// the dispatch/refusal/Freeze/read-record writers use, and a type that held
// both Append and Query would be the "not append-only" shape auditsink's
// package doc warns a reader-that-can-also-write becomes. Only
// internal/store's implementation ever holds both, as two interfaces backed
// by the same *sqliteAudit — never as one interface a caller could hold and
// mistake for the whole trail.
type QueryRepository interface {
	// Query returns one page of Rows matching q, newest first (ORDER BY
	// Timestamp DESC), each field of q ANDed together. limit <= 0 means
	// DefaultPageSize; a limit above MaxPageSize is clamped. cursor is opaque
	// and, if non-empty, must be the Next value from a previous Page; a
	// malformed or foreign cursor is ErrInvalidCursor.
	Query(ctx context.Context, q Query, limit int, cursor string) (Page, error)

	// CountsByPrincipal returns q's matching Records grouped by verified
	// Account and by time bucket (bucket width in wall-clock time), ordered
	// bucket-ascending.
	CountsByPrincipal(ctx context.Context, q Query, bucket time.Duration) ([]Bucket, error)

	// ReachCounts returns the call count, distinct-target count, and
	// distinct-Node count for q's matching Records: how far they reached.
	ReachCounts(ctx context.Context, q Query) (Reach, error)
}
