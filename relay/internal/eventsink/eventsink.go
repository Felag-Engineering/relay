// Package eventsink is the ONLY place the producing packages
// (capability, enroll, controlplane/mcp, registry) and internal/events meet.
//
// It exists for exactly the reason internal/auditsink exists (see that
// package's opening paragraph): internal/events is locked to the standard
// library — its own structural guard, no_read_output_test.go — and the
// producing packages must not depend on it either (capability's import
// allowlist stays jobs+registry; mcp's no_dispatch partition stays intact;
// enroll stays free of the bus's own dependencies). Each producer owns its
// own seam type (capability.JobEvent, enroll.AttemptEvent, mcp.ToolCallEvent)
// and this package is where they are mapped onto events.Event and published.
package eventsink

import (
	"context"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// jobEventSink adapts capability.JobEventSink onto events.Bus.
type jobEventSink struct {
	bus *events.Bus
}

// Jobs returns the real capability.JobEventSink, publishing capability's
// Job-grained transitions onto b.
func Jobs(b *events.Bus) capability.JobEventSink {
	return jobEventSink{bus: b}
}

// RecordJob maps e onto events.JobEvent and publishes it. Operation is
// act.OperationName, or the literal "raw_exec" when the Action is Raw Exec
// (jobs.Action has no name for that path — Raw Exec is not an Operation).
// Nothing else crosses: Outcomes is copied field-for-field from e.Outcomes,
// never touching anything output-shaped, because capability.JobEvent itself
// never holds any (seams.go's doc comment).
func (s jobEventSink) RecordJob(e capability.JobEvent) {
	ev := events.JobEvent{
		Transition: jobTransition(e.Transition),
		JobID:      e.JobID,
		Account:    e.Principal.Account,
		AccountID:  e.Principal.AccountID,
		Selector:   e.Selector.String(),
		Operation:  operationName(e.Action),
		RiskClass:  jobs.RiskClassName(e.Action.RiskClass),
		Nodes:      e.Nodes,
	}
	applyOutcomes(&ev, e.Outcomes)
	s.bus.PublishJob(ev)
}

// operationName is the Operation a published event names: the Action's own
// name, or "raw_exec" for Raw Exec, which has none.
func operationName(act jobs.Action) string {
	if act.Kind == jobs.ActionRawExec {
		return "raw_exec"
	}
	return act.OperationName
}

// jobTransition maps capability's Job transition onto the event vocabulary.
// An unrecognized transition maps to the empty value rather than a guess.
func jobTransition(t capability.JobTransition) events.JobTransition {
	switch t {
	case capability.JobCreated:
		return events.JobCreated
	case capability.JobCompleted:
		return events.JobCompleted
	case capability.JobCancelled:
		return events.JobCancelled
	default:
		return ""
	}
}

// applyOutcomes copies per-outcome Node counts onto ev, field for field.
// An outcome with no event field is dropped.
func applyOutcomes(ev *events.JobEvent, outcomes map[jobs.Outcome]int) {
	for outcome, count := range outcomes {
		switch outcome {
		case jobs.OutcomeSuccess:
			ev.Succeeded = count
		case jobs.OutcomeFailure:
			ev.Failed = count
		case jobs.OutcomeTimeout:
			ev.Timeout = count
		case jobs.OutcomeDeniedByPolicy:
			ev.Denied = count
		case jobs.OutcomeCancelled:
			ev.Cancelled = count
		case jobs.OutcomeUnreachable:
			ev.Unreachable = count
		case jobs.OutcomeVersionRefused:
			ev.VersionRefused = count
		case jobs.OutcomeUnsupported:
			ev.Unsupported = count
		}
	}
}

// enrollmentObserver adapts enroll.AttemptObserver onto events.Bus.
type enrollmentObserver struct {
	bus *events.Bus
}

// Enrollment returns the real enroll.AttemptObserver, publishing every
// Enroll attempt onto b.
func Enrollment(b *events.Bus) enroll.AttemptObserver {
	return enrollmentObserver{bus: b}
}

// Attempt maps e onto events.EnrollmentEvent and publishes it; see
// enrollmentReason for how the reason is mapped.
func (o enrollmentObserver) Attempt(_ context.Context, e enroll.AttemptEvent) {
	outcome := events.EnrollmentRejected
	if e.Accepted {
		outcome = events.EnrollmentAccepted
	}

	o.bus.PublishEnrollment(events.EnrollmentEvent{
		Outcome: outcome,
		Reason:  enrollmentReason(e.Reason),
		TokenID: e.TokenID,
		NodeID:  e.NodeID,
		Source:  e.Source,
	})
}

// ToolCall publishes one MCP tools/call invocation onto b. account/accountID
// are the already-resolved Principal — the composition-root adapter
// (cmd/relay/control_surfaces.go's toolCallObserver) resolves it from the
// request context, exactly as readAuditor does for the read-audit seam,
// because the mcp package itself must never name a capability type on this
// path (no_dispatch_test.go).
func ToolCall(b *events.Bus, account, accountID string, e mcp.ToolCallEvent) {
	b.PublishToolCall(events.ToolCallEvent{
		Tool:               e.Tool,
		Account:            account,
		AccountID:          accountID,
		Arguments:          e.Arguments,
		ArgumentsTruncated: e.ArgumentsTruncated,
	})
}

// registryObserver decorates a registry.Repository, publishing exactly
// three transitions and delegating every other method untouched.
//
// Deliberately NOT an embedded registry.Repository: every method below is
// written out and delegates explicitly, so a future method ADDED to
// registry.Repository fails THIS package to compile — fail-closed, forcing
// whoever adds it to decide whether it is a transition, rather than it
// silently promoting through an embedded interface and reaching every
// caller unobserved.
type registryObserver struct {
	r   registry.Repository
	bus *events.Bus
}

// ObserveRegistry wraps r, publishing onto b on exactly three methods:
// SetConnected(id, true) -> TransitionConnected, SetConnected(id, false) ->
// TransitionDisconnected, and a successful SetRelayLabels ->
// TransitionLabelsChanged. Every other method — Upsert, UpdateLastSeen,
// SetRevoked, SetRevokedAll, RecordEnrollment, RecordRenewal, Get, List,
// RevokedNodeIDs, Count — delegates and publishes NOTHING.
//
// UpdateLastSeen is the load-bearing omission: it is the heartbeat, called
// on every message from every connected Node. Publishing it would let a
// 100k-Node fleet evict the connect/disconnect history the Console actually
// needs from the ring buffer thirty times a second (acceptance criterion).
func ObserveRegistry(r registry.Repository, b *events.Bus) registry.Repository {
	return registryObserver{r: r, bus: b}
}

func (o registryObserver) Upsert(rep registry.Report) (registry.Node, error) {
	return o.r.Upsert(rep)
}

// UpdateLastSeen is the heartbeat — the load-bearing omission this whole
// decorator exists to enforce (see ObserveRegistry's doc comment). It
// delegates and publishes nothing.
func (o registryObserver) UpdateLastSeen(nodeID string, at time.Time) error {
	return o.r.UpdateLastSeen(nodeID, at)
}

func (o registryObserver) SetRelayLabels(nodeID string, labels map[string]string) error {
	err := o.r.SetRelayLabels(nodeID, labels)
	if err == nil {
		o.bus.PublishRegistry(events.RegistryEvent{
			Transition:  events.TransitionLabelsChanged,
			NodeID:      nodeID,
			RelayLabels: copyLabels(labels),
		})
	}
	return err
}

func (o registryObserver) Get(nodeID string) (registry.Node, bool) {
	return o.r.Get(nodeID)
}

func (o registryObserver) List() []registry.Node {
	return o.r.List()
}

func (o registryObserver) ListChecked() ([]registry.Node, error) {
	return o.r.ListChecked()
}

func (o registryObserver) RecordEnrollment(nodeID string, cert registry.Certificate, at time.Time) error {
	return o.r.RecordEnrollment(nodeID, cert, at)
}

func (o registryObserver) RecordRenewal(nodeID string, cert registry.Certificate, at time.Time) error {
	return o.r.RecordRenewal(nodeID, cert, at)
}

func (o registryObserver) SetConnected(nodeID string, connected bool) {
	o.r.SetConnected(nodeID, connected)
	transition := events.TransitionDisconnected
	if connected {
		transition = events.TransitionConnected
	}
	o.bus.PublishRegistry(events.RegistryEvent{Transition: transition, NodeID: nodeID})
}

func (o registryObserver) SetRevoked(nodeID string, at time.Time) error {
	return o.r.SetRevoked(nodeID, at)
}

func (o registryObserver) SetRevokedAll(nodeIDs []string, at time.Time) ([]string, error) {
	return o.r.SetRevokedAll(nodeIDs, at)
}

func (o registryObserver) RevokedNodeIDs() ([]string, error) {
	return o.r.RevokedNodeIDs()
}

func (o registryObserver) Count() (total int, revoked int, err error) {
	return o.r.Count()
}

// enrollmentReason maps an enroll.AttemptReason onto the event vocabulary. The
// mapping is an explicit switch whose default is ReasonInternal, never a
// passthrough of an unknown string, so a future AttemptReason this package
// hasn't been taught about degrades to the safe, generic reason.
func enrollmentReason(r enroll.AttemptReason) events.EnrollmentReason {
	switch r {
	case enroll.AttemptExpired:
		return events.ReasonExpired
	case enroll.AttemptRevoked:
		return events.ReasonRevoked
	case enroll.AttemptUnknown:
		return events.ReasonUnknown
	case enroll.AttemptExhausted:
		return events.ReasonExhausted
	case enroll.AttemptMalformed:
		return events.ReasonMalformed
	case enroll.AttemptRateLimited:
		return events.ReasonRateLimited
	case enroll.AttemptAtCapacity:
		return events.ReasonAtCapacity
	case enroll.AttemptRevokedMidEnrollment:
		return events.ReasonRevokedMidEnrollment
	case enroll.AttemptInvalidScope:
		return events.ReasonInvalidScope
	default:
		return events.ReasonInternal
	}
}

// copyLabels returns a shallow copy of labels, so the published event never
// aliases the map the caller (or the underlying registry) may go on to
// mutate.
func copyLabels(labels map[string]string) map[string]string {
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}
