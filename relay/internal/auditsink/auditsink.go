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
// in-memory secrets the sink never even sees. Record/RecordFreeze never log
// an AuditEntry's or FreezeEvent's field values (including output); errors
// propagate up to Service.Run, which wraps but does not dump the entry's
// contents.
package auditsink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// New returns a Sink backed by repo.
func New(repo audit.Repository, opts ...Option) *Sink {
	s := &Sink{
		repo:  repo,
		newID: defaultID,
		now:   func() time.Time { return time.Now().UTC() },
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
func (s *Sink) Record(ctx context.Context, e capability.AuditEntry) error {
	base := s.baseRecord(e.Principal, e.Selector, e.Action)

	if e.Kind == capability.AuditKindRefusal {
		base.Kind = audit.KindRefusal
		base.Reason = e.Reason
		return s.append(ctx, base)
	}

	if e.Kind == capability.AuditKindPlan {
		base.Kind = audit.KindPlan
		return s.append(ctx, base)
	}

	base.JobID = e.JobID
	if len(e.Results) == 0 {
		base.Kind = audit.KindDispatch
		return s.append(ctx, base)
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
	return errors.Join(errs...)
}

// RecordFreeze implements capability.AuditSink. It records exactly one
// Record per Freeze engage/release (ADR-0013): Kind is KindFreezeEngage or
// KindFreezeRelease depending on e.Engage, with Principal and Reason set and
// no Selector/NodeID/JobID/Action — Freeze is Relay-wide.
func (s *Sink) RecordFreeze(ctx context.Context, e capability.FreezeEvent) error {
	rec := audit.Record{
		Timestamp: s.now(),
		Principal: e.Principal.Attribution(),
		Reason:    e.Reason,
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
		Timestamp: s.now(),
		Kind:      audit.KindJobCancel,
		Principal: p.Attribution(),
		JobID:     jobID,
	}
	return s.append(ctx, rec)
}

// baseRecord builds the audit.Record fields common to every Kind: attributed
// Principal, the Selector as written, and the Action's shape. Kind, JobID,
// NodeID, Outcome, and Reason are filled in by the caller per Kind.
func (s *Sink) baseRecord(p capability.Principal, sel capability.Selector, act jobs.Action) audit.Record {
	return audit.Record{
		Timestamp:     s.now(),
		Principal:     p.Attribution(),
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
