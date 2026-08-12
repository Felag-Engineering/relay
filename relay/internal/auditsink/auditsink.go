// Package auditsink is the real capability.AuditSink: an adapter that maps
// capability.AuditEntry/capability.FreezeEvent onto the append-only
// audit.Repository (internal/store's SQLite implementation, #97).
//
// It lives in its own package, not package capability or package audit,
// because it must reference both: capability's non-test files are locked to
// a small import allowlist (TestCapabilityImportsOnlyRegistryAndJobs) that
// bars database/sql and internal/audit, and audit is deliberately a thin,
// SQL-free domain package that must not depend on capability. auditsink is
// the only place both meet.
//
// Redaction: Record/RecordFreeze copy ONLY the domain fields named below —
// Principal's attribution string, the Selector as written, the Action's
// kind/name/args/argv, per-Node Outcome, and (since #122's full-output-always
// posture) each NodeResult's captured Stdout/Stderr and the daemon-side
// Truncated flag, copied verbatim — the sink never scrubs or redacts them
// (Policy, ADR-0002, is where secret-emitting commands are prevented, not
// here). Nothing else is added: no enrichment from tokens, keys, or other
// in-memory secrets the sink never even sees.
//
// Logging (#181): Record additionally emits exactly one structured slog Info
// "audit decision" line per call, for each of the three Kinds it persists
// (dispatch, refusal, plan) — the store and the log are written from the
// same call so they cannot drift. That line carries ONLY the kind,
// Principal's attribution string, the Selector as written, the Action's
// kind and (for a typed Operation) name, the job_id (dispatch, omitted when
// empty), the aggregate matched count and per-outcome counts (dispatch), and
// the refusal reason (refusal) — a decision's routing/attribution metadata,
// never its content. It never logs an Action's OperationArgs or
// RawExecArgv, any NodeResult's Stdout/Stderr/Truncated, or any token/key
// material; the log is supplementary and never influences a decision.
// RecordFreeze and RecordCancel are unchanged and remain unlogged. Errors
// from Record/RecordFreeze/RecordCancel propagate up to Service.Run, which
// wraps but does not dump the entry's contents.
package auditsink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// idGen mints a new unique audit Record ID. A seam so tests can inject
// deterministic IDs; the production default is defaultID.
type idGen func() (string, error)

// defaultID generates a random 16-byte ID, hex-encoded with an "audit-"
// prefix, mirroring capability.defaultID's shape.
func defaultID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auditsink: generate id: %w", err)
	}
	return "audit-" + hex.EncodeToString(b), nil
}

// Sink is the real capability.AuditSink, backed by an audit.Repository.
type Sink struct {
	repo  audit.Repository
	newID idGen
	now   func() time.Time
	log   *slog.Logger
}

var _ capability.AuditSink = (*Sink)(nil)

// Option configures a Sink built by New.
type Option func(*Sink)

// WithNewID overrides the Sink's idGen seam (production default: defaultID).
func WithNewID(f idGen) Option {
	return func(s *Sink) { s.newID = f }
}

// WithClock overrides the Sink's clock seam (production default: time.Now,
// UTC).
func WithClock(f func() time.Time) Option {
	return func(s *Sink) { s.now = f }
}

// WithLogger overrides the Sink's logger seam (production default:
// slog.Default()), so tests can assert on the decision lines Record emits
// with a buffer-backed handler. A nil l falls back to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Sink) {
		if l == nil {
			l = slog.Default()
		}
		s.log = l
	}
}

// New returns a Sink backed by repo.
func New(repo audit.Repository, opts ...Option) *Sink {
	s := &Sink{
		repo:  repo,
		newID: defaultID,
		now:   func() time.Time { return time.Now().UTC() },
		log:   slog.Default(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Record implements capability.AuditSink. A Dispatch entry with Results
// fans out to one audit.Record PER NodeResult (ADR-0004: Tasks are the audit
// unit) so each is independently queryable by NodeID; a zero-match dispatch
// (no Results) still gets exactly one job-level Record, with an empty
// NodeID, so the attempt remains queryable by JobID. A Refusal entry (authz-
// deny or cap-reject: the dispatcher was never reached) gets exactly one
// Record with the refusal's Reason, jobs.OutcomeUnspecified, and no JobID/
// NodeID. A Plan entry (#119, ADR-0011: a no-execution PolicyQuery probe)
// gets exactly one Record, Principal+Selector+Action only — no JobID/NodeID/
// Outcome, since a Plan never creates a Job or Task. Per-Record Append
// failures are joined, not short-circuited, so one failing write does not
// silently drop the rest.
//
// Record also emits exactly one structured "audit decision" log line per
// call (see the package doc's Logging section), regardless of whether the
// store Append below succeeds — the decision remains visible in logs even
// if the SQLite write fails.
func (s *Sink) Record(ctx context.Context, e capability.AuditEntry) error {
	base := s.baseRecord(e.Principal, e.Asserted, e.Selector, e.Action)

	if e.Kind == capability.AuditKindRefusal {
		base.Kind = audit.KindRefusal
		base.Reason = e.Reason
		err := s.append(ctx, base)
		s.logDecision(audit.KindRefusal, e, 0, "")
		return err
	}

	if e.Kind == capability.AuditKindPlan {
		base.Kind = audit.KindPlan
		err := s.append(ctx, base)
		s.logDecision(audit.KindPlan, e, 0, "")
		return err
	}

	base.JobID = e.JobID
	if len(e.Results) == 0 {
		base.Kind = audit.KindDispatch
		err := s.append(ctx, base)
		s.logDecision(audit.KindDispatch, e, 0, "")
		return err
	}

	var errs []error
	for _, r := range e.Results {
		rec := base
		rec.Kind = audit.KindDispatch
		rec.NodeID = r.NodeID
		rec.Outcome = r.Outcome
		rec.Stdout = r.Stdout
		rec.Stderr = r.Stderr
		rec.Truncated = r.Truncated
		if err := s.append(ctx, rec); err != nil {
			errs = append(errs, err)
		}
	}
	s.logDecision(audit.KindDispatch, e, len(e.Results), outcomeCounts(e.Results))
	return errors.Join(errs...)
}

// RecordFreeze implements capability.AuditSink. It records exactly one
// Record per Freeze engage/release (ADR-0013): Kind is KindFreezeEngage or
// KindFreezeRelease depending on e.Engage, with Principal and Reason set and
// no Selector/NodeID/JobID/Action — Freeze is Relay-wide.
func (s *Sink) RecordFreeze(ctx context.Context, e capability.FreezeEvent) error {
	rec := audit.Record{
		Timestamp:   s.now(),
		Principal:   e.Principal.Attribution(),
		Attribution: attribution(e.Principal, e.Asserted),
		Reason:      e.Reason,
	}
	if e.Engage {
		rec.Kind = audit.KindFreezeEngage
	} else {
		rec.Kind = audit.KindFreezeRelease
	}
	return s.append(ctx, rec)
}

// RecordCancel implements capability.AuditSink (v0.0.6 [5/8], owner DECISION
// 2). It records exactly one audit.Record per cancel action: Kind is
// KindJobCancel, Principal is p's attribution, JobID is jobID — no Selector/
// NodeID/Action, since a cancel targets an existing Job by ID, not a fresh
// dispatch (mirrors RecordFreeze's Relay-wide shape, minus the Reason field).
func (s *Sink) RecordCancel(ctx context.Context, p capability.Principal, jobID string) error {
	rec := audit.Record{
		Timestamp:   s.now(),
		Kind:        audit.KindJobCancel,
		Principal:   p.Attribution(),
		Attribution: attribution(p, capability.AssertionsFromContext(ctx)),
		JobID:       jobID,
	}
	return s.append(ctx, rec)
}

// baseRecord builds the audit.Record fields common to every Kind: attributed
// Principal, the Selector as written, and the Action's shape. Kind, JobID,
// NodeID, Outcome, and Reason are filled in by the caller per Kind.
func (s *Sink) baseRecord(p capability.Principal, a capability.Assertions, sel capability.Selector, act jobs.Action) audit.Record {
	return audit.Record{
		Timestamp:     s.now(),
		Principal:     p.Attribution(),
		Attribution:   attribution(p, a),
		Selector:      sel.String(),
		ActionKind:    actionKindString(act.Kind),
		OperationName: act.OperationName,
		Args:          act.OperationArgs,
		RawExecArgv:   act.RawExecArgv,
	}
}

// actionKindString renders a jobs.ActionKind as the string audit.Record
// stores, mirroring internal/store's tasks.go action_kind mapping.
func actionKindString(k jobs.ActionKind) string {
	switch k {
	case jobs.ActionOperation:
		return "operation"
	case jobs.ActionRawExec:
		return "raw_exec"
	default:
		return "unspecified"
	}
}

// logDecision emits exactly one structured slog Info "audit decision" line
// for the Kind of decision e describes. It carries ONLY attribution/routing
// metadata — never e.Action.OperationArgs, e.Action.RawExecArgv, or any
// NodeResult's Stdout/Stderr/Truncated — so a decision line can never leak
// request content or captured output, even though the store retains both.
// matched and counts are dispatch-only (zero value/empty otherwise, and
// zero-match dispatch itself passes matched=0 and an empty counts string).
func (s *Sink) logDecision(kind string, e capability.AuditEntry, matched int, counts string) {
	attrs := []any{
		"kind", kind,
		"principal", e.Principal.Attribution(),
		"selector", e.Selector.String(),
		"action_kind", actionKindString(e.Action.Kind),
	}
	if e.Action.Kind == jobs.ActionOperation {
		attrs = append(attrs, "operation", e.Action.OperationName)
	}
	switch kind {
	case audit.KindDispatch:
		if e.JobID != "" {
			attrs = append(attrs, "job_id", e.JobID)
		}
		attrs = append(attrs, "matched", matched, "outcome_counts", counts)
	case audit.KindRefusal:
		attrs = append(attrs, "reason", e.Reason)
	}
	s.log.Info("audit decision", attrs...)
}

// outcomeOrder is outcomeCounts' fixed rendering order, so a decision line
// is deterministic across runs. It is self-contained to this package (not a
// reuse of internal/metrics's unexported outcomeLabel): OutcomeVersionRefused
// gets its own bucket here rather than folding into "unspecified".
var outcomeOrder = []jobs.Outcome{
	jobs.OutcomeSuccess,
	jobs.OutcomeFailure,
	jobs.OutcomeTimeout,
	jobs.OutcomeDeniedByPolicy,
	jobs.OutcomeCancelled,
	jobs.OutcomeUnreachable,
	jobs.OutcomeVersionRefused,
	jobs.OutcomeUnsupported,
	jobs.OutcomeUnspecified,
}

// outcomeLabel renders a jobs.Outcome as the fixed-vocabulary string
// outcomeCounts uses. Every named Outcome gets its own value; anything else
// (including any future/out-of-range Outcome) is "unspecified".
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

// outcomeCounts renders the aggregate per-Outcome tally across results as a
// compact string, e.g. "success=2,denied_by_policy=1", in outcomeOrder,
// omitting outcomes with a zero count. A nil/empty results yields "".
func outcomeCounts(results []capability.NodeResult) string {
	counts := make(map[jobs.Outcome]int, len(outcomeOrder))
	for _, r := range results {
		counts[r.Outcome]++
	}
	var b strings.Builder
	for _, o := range outcomeOrder {
		n := counts[o]
		if n == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%d", outcomeLabel(o), n)
	}
	return b.String()
}

// attribution maps the capability layer's verified Principal and
// caller-asserted metadata onto the audit record's two lanes (#300).
//
// This mapping is the only place the two representations meet, and it is
// deliberately total: the verified fields come exclusively from the Principal
// the authentication boundary produced, and the asserted fields exclusively
// from what the caller supplied. There is no path by which a value can cross
// from one lane to the other.
func attribution(p capability.Principal, a capability.Assertions) audit.Attribution {
	return audit.Attribution{
		Verified: audit.Verified{
			AccountID:   p.AccountID,
			AccountName: p.Account,
			Role:        p.Role,
			TokenID:     p.TokenID,
		},
		Asserted: audit.Asserted{
			OnBehalfOf:  a.OnBehalfOf,
			Traceparent: a.Traceparent,
			SessionRef:  a.SessionRef,
			ChangeRef:   a.ChangeRef,
		},
	}
}

func (s *Sink) append(ctx context.Context, rec audit.Record) error {
	id, err := s.newID()
	if err != nil {
		return fmt.Errorf("auditsink: generate audit record id: %w", err)
	}
	rec.ID = id
	if err := s.repo.Append(ctx, rec); err != nil {
		return fmt.Errorf("auditsink: append audit record: %w", err)
	}
	return nil
}
