package capability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
)

// Recorder is the capability layer's audit trail, metrics and operational log,
// held in one place so every service built over it records to the same trail.
// Construct it with NewRecorder; the composition root owns the one instance and
// hands it to NewControl and NewReadLane. It has no exported methods: the
// services record through it, and no adapter can reach it.
type Recorder struct {
	audit AuditSink

	// metrics is best-effort observability only (MetricsSink, seams.go); it
	// never affects a dispatch, authz, cap, or Freeze decision.
	metrics MetricsSink

	// log is where this layer's operational errors go; nil means
	// slog.Default() (logger). Propagated onto the Job engine at the end of
	// newExecution, like jobEvents.
	log *slog.Logger
}

// NewRecorder returns a Recorder over audit. audit is required: a layer that
// can act and cannot record is the state ADR-0025 forbids, so a nil sink is a
// composition-root bug and panics. A nil metrics becomes the no-op sink and a
// nil log means slog.Default(); both are observational only.
//
// NewRecorder does not refuse the no-op AuditSink itself: the services built
// over it decide whether they can run without a real trail.
func NewRecorder(audit AuditSink, metrics MetricsSink, log *slog.Logger) *Recorder {
	if audit == nil {
		panic("capability: NewRecorder: auditSink must not be nil")
	}
	if metrics == nil {
		metrics = noopMetricsSink{}
	}
	return &Recorder{audit: audit, metrics: metrics, log: log}
}

func (r *Recorder) logger() *slog.Logger { return logctx.Or(r.log) }

// recordRefusal audits a Freeze-engaged, authz-deny, no-Nodes-matched, or
// cap-reject short-circuit — the dispatcher was never reached, so there is
// no JobID or Results, only the refusal's Reason. It also increments the
// MetricsSink for kind. It returns refusalErr, joined with a wrapped
// audit-write error if the audit write itself failed, so a failed audit
// write is never silently swallowed.
func (r *Recorder) recordRefusal(ctx context.Context, p Principal, sel Selector, act jobs.Action, kind RefusalKind, refusalErr error) error {
	r.metrics.IncRefusal(kind)
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, Selector: sel, Action: act, Reason: refusalErr.Error(), Asserted: AssertionsFromContext(ctx)}
	var auditErr error
	if err := r.audit.Record(ctx, entry); err != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", err)
	}
	return errors.Join(refusalErr, auditErr)
}

// refuseControl audits a refused ControlAction and returns the refusal.
//
// It is recordRefusal's sibling for the acts that carry no Selector and no
// Action: nothing was resolved, nothing was dispatched, and there is no
// fan-out to describe — only who was refused and why. It goes to the SAME
// AuditKindRefusal the dispatch path uses, so "show me everything this
// Account was refused" stays one query rather than two (invariant 10 applied
// to the trail, not only to the code path).
func (r *Recorder) refuseControl(ctx context.Context, p Principal, refusalErr error) error {
	return r.recordRefusal(ctx, p, Selector{}, jobs.Action{}, RefusalUnauthorized, refusalErr)
}
