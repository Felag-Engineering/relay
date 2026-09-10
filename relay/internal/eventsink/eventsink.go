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

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// riskClassString renders a jobs.RiskClass as the "read"/"mutate" string,
// mirroring controlplane/mcp/tools_operations.go's identically-named
// unexported helper (jobs.RiskClass has no String()/JSON helper of its own —
// see that file's doc comment for why this small local mapping exists
// rather than an ad hoc improvisation per caller).
func riskClassString(r jobs.RiskClass) string {
	switch r {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// jobEventSink adapts capability.JobEventSink onto events.Bus.
type jobEventSink struct {
	bus *events.Bus
}

// Jobs returns the real capability.JobEventSink, publishing capability's
// Job-grained transitions (#416) onto b.
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
	operation := e.Action.OperationName
	if e.Action.Kind == jobs.ActionRawExec {
		operation = "raw_exec"
	}

	transition := events.JobTransition("")
	switch e.Transition {
	case capability.JobCreated:
		transition = events.JobCreated
	case capability.JobCompleted:
		transition = events.JobCompleted
	case capability.JobCancelled:
		transition = events.JobCancelled
	}

	ev := events.JobEvent{
		Transition: transition,
		JobID:      e.JobID,
		Account:    e.Principal.Account,
		AccountID:  e.Principal.AccountID,
		Selector:   e.Selector.String(),
		Operation:  operation,
		RiskClass:  riskClassString(e.Action.RiskClass),
		Nodes:      e.Nodes,
	}
	for outcome, count := range e.Outcomes {
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
	s.bus.PublishJob(ev)
}

// enrollmentObserver adapts enroll.AttemptObserver onto events.Bus.
type enrollmentObserver struct {
	bus *events.Bus
}

// Enrollment returns the real enroll.AttemptObserver, publishing every
// Enroll attempt (#416) onto b.
func Enrollment(b *events.Bus) enroll.AttemptObserver {
	return enrollmentObserver{bus: b}
}

// Attempt maps e onto events.EnrollmentEvent and publishes it. The reason
// mapping is an explicit, exhaustive switch — a default that maps to
// ReasonInternal, never a passthrough of an unknown string, so a future
// AttemptReason this package hasn't been taught about degrades to the safe,
// generic reason rather than silently forwarding an unrecognized value.
func (o enrollmentObserver) Attempt(_ context.Context, e enroll.AttemptEvent) {
	outcome := events.EnrollmentRejected
	if e.Accepted {
		outcome = events.EnrollmentAccepted
	}

	var reason events.EnrollmentReason
	switch e.Reason {
	case enroll.AttemptExpired:
		reason = events.ReasonExpired
	case enroll.AttemptRevoked:
		reason = events.ReasonRevoked
	case enroll.AttemptUnknown:
		reason = events.ReasonUnknown
	case enroll.AttemptExhausted:
		reason = events.ReasonExhausted
	case enroll.AttemptMalformed:
		reason = events.ReasonMalformed
	case enroll.AttemptRateLimited:
		reason = events.ReasonRateLimited
	case enroll.AttemptAtCapacity:
		reason = events.ReasonAtCapacity
	case enroll.AttemptRevokedMidEnrollment:
		reason = events.ReasonRevokedMidEnrollment
	case enroll.AttemptInternal:
		reason = events.ReasonInternal
	case enroll.AttemptInvalidScope:
		reason = events.ReasonInvalidScope
	default:
		reason = events.ReasonInternal
	}

	o.bus.PublishEnrollment(events.EnrollmentEvent{
		Outcome: outcome,
		Reason:  reason,
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
// SetRevoked, RecordEnrollment, RecordRenewal, Get, List, RevokedNodeIDs,
// Count — delegates and publishes NOTHING.
//
// UpdateLastSeen is the load-bearing omission: it is the heartbeat, called
// on every message from every connected Node. Publishing it would let a
// 100k-Node fleet evict the connect/disconnect history the Console actually
// needs from the ring buffer thirty times a second (ROADMAP acceptance).
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

func (o registryObserver) RevokedNodeIDs() ([]string, error) {
	return o.r.RevokedNodeIDs()
}

func (o registryObserver) Count() (total int, revoked int, err error) {
	return o.r.Count()
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
