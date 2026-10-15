package main

import (
	"context"
	"log/slog"

	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/logctx"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// dispatch_wiring.go is the v0.0.5 dispatch transport's composition-root
// wiring: it is production-ready code, built by every build (no build tag).
// newServer (main.go) calls newDispatchStack and sets tunnel.sink whenever
// Config.ControlEnabled — the production execution flip — over the
// real mTLS Tunnel, paired with the real staged Authorizer
// (internal/authz.NewStaged, ADR-0010) capability.NewExecution's fail-open guard
// requires alongside a real dispatcher (pipeline.go). The dev harness
// (devharness.go, installDevHarness) uses this SAME assembly — the only
// difference is its own allow-all devHarnessAuthorizer, never
// authz.NewRoleGate — see TestTunnelSink_GatedByControlEnabled for the
// disabled-vs-enabled assertion this file's callers must keep true.

var _ dispatch.ViolationRecorder = (*auditsink.Sink)(nil)

// violationRecorder composes the one place a protocol violation's records
// are written: the durable audit row, the aggregate by-rule counter, and the
// counter that says the row is missing. It lives here rather than on
// *auditsink.Sink so the audit adapter gains no dependency on the transport
// package, and rather than on *metrics.Metrics for the symmetric reason.
//
// The by-rule counter is incremented BEFORE the write and unconditionally
// because it cannot fail and must not be skipped when the store cannot be
// written, which is exactly the moment an operator most needs the burst to
// be visible; the unrecorded counter is what makes the fail-open residual
// (internal/dispatch's recordViolation, and audit.KindProtocolViolation's
// doc) an alertable series rather than a log line.
//
// audit is REQUIRED: nil is a programming error, not a supported mode.
// RecordProtocolViolation does not nil-check it (unlike metrics, which is
// genuinely optional) because a nil *auditsink.Sink here would mean this
// composer was built wrong, and silently dropping the row it exists to
// write is worse than the panic s.append gives on the dispatching
// goroutine.
type violationRecorder struct {
	audit   *auditsink.Sink
	metrics *metrics.Metrics
}

func (v violationRecorder) RecordProtocolViolation(ctx context.Context, ev jobs.ProtocolViolationEvent) error {
	if v.metrics != nil {
		v.metrics.IncProtocolViolation(ev.Violation.Rule)
	}
	if err := v.audit.RecordProtocolViolation(ctx, ev); err != nil {
		if v.metrics != nil {
			v.metrics.IncProtocolViolationUnrecorded()
		}
		return err
	}
	return nil
}

// routerSink adapts *dispatch.Router to the unexported taskSink interface
// (tunnel.go): tunnelServer can only be handed a taskSink, and a type
// declared inside internal/dispatch cannot implement an unexported
// interface's methods (register/deliver/deliverVerdict) from outside package
// main. routerSink is a thin forwarding shim, nothing more.
type routerSink struct {
	r *dispatch.Router
}

func (s routerSink) register(nodeID string, send func(*relayv1.RelayMessage) error) (unregister func()) {
	return s.r.Register(nodeID, send)
}

func (s routerSink) deliver(nodeID string, result *relayv1.TaskResult) {
	s.r.Deliver(nodeID, result)
}

func (s routerSink) deliverVerdict(nodeID string, verdict *relayv1.PolicyVerdict) {
	s.r.DeliverVerdict(nodeID, verdict)
}

// newDispatchStack builds the Router + Reconciler + taskSink triple: a Node
// (re)connecting fires the Reconciler's restart-recovery (ADR-0004) via
// Router's onConnect hook.
//
// violations is passed straight through to NewRouter, which requires it
// positionally; see that doc comment for why nil is a supported mode.
func newDispatchStack(tasks jobs.TaskRepository, violations dispatch.ViolationRecorder, logger *slog.Logger) (*dispatch.Router, *dispatch.Reconciler, taskSink) {
	// reconciler is filled in after router exists (it needs router as its
	// Conduit); the onConnect closure captures the *dispatch.Reconciler
	// variable itself, not a snapshot, so it always sees the fully-built
	// value by the time a Node actually connects (Register only invokes
	// onConnect after Router itself has been constructed and returned).
	var reconciler *dispatch.Reconciler
	router := dispatch.NewRouter(func(nodeID string) {
		if err := reconciler.ReconcileNode(context.Background(), nodeID); err != nil {
			logctx.Or(logger).Error("reconcile on connect failed", "node_id", nodeID, "err", err)
		}
	}, violations, dispatch.WithLogger(logger))
	reconciler = dispatch.NewReconciler(tasks, router)

	return router, reconciler, routerSink{r: router}
}
