package main

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/dispatch"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// dispatch_wiring.go is the v0.0.5 dispatch transport's composition-root
// wiring: it is production-ready code, built by every build (no build tag).
// newServer (main.go) calls newDispatchStack and sets tunnel.sink whenever
// Config.ControlEnabled — the production execution flip (#154) — over the
// real mTLS Tunnel, paired with the real staged Authorizer
// (internal/authz.NewStaged, ADR-0010) capability.New's fail-open guard
// requires alongside a real dispatcher (service.go). The dev harness
// (devharness.go, installDevHarness) uses this SAME assembly — the only
// difference is its own allow-all devHarnessAuthorizer, never
// authz.NewStaged — see TestTunnelSink_GatedByControlEnabled for the
// disabled-vs-enabled assertion this file's callers must keep true.

// routerSink adapts *dispatch.Router to the unexported taskSink interface
// (tunnel.go): tunnelServer can only be handed a taskSink, and a type
// declared inside internal/dispatch cannot implement an unexported
// interface's methods (register/deliver/deliverVerdict) from outside package
// main. routerSink is a thin forwarding shim, nothing more.
type routerSink struct {
	r *dispatch.Router
}

func (s routerSink) register(nodeID string, send func(*gleipnirv1.RelayMessage) error) (unregister func()) {
	return s.r.Register(nodeID, send)
}

func (s routerSink) deliver(nodeID string, result *gleipnirv1.TaskResult) {
	s.r.Deliver(nodeID, result)
}

func (s routerSink) deliverVerdict(nodeID string, verdict *gleipnirv1.PolicyVerdict) {
	s.r.DeliverVerdict(nodeID, verdict)
}

// newDispatchStack builds the Router + Reconciler + taskSink triple: a Node
// (re)connecting fires the Reconciler's restart-recovery (ADR-0004) via
// Router's onConnect hook.
func newDispatchStack(tasks jobs.TaskRepository) (*dispatch.Router, *dispatch.Reconciler, taskSink) {
	// reconciler is filled in after router exists (it needs router as its
	// Conduit); the onConnect closure captures the *dispatch.Reconciler
	// variable itself, not a snapshot, so it always sees the fully-built
	// value by the time a Node actually connects (Register only invokes
	// onConnect after Router itself has been constructed and returned).
	var reconciler *dispatch.Reconciler
	router := dispatch.NewRouter(func(nodeID string) {
		if err := reconciler.ReconcileNode(context.Background(), nodeID); err != nil {
			// Reconciliation errors are per-Task-joined and already surfaced
			// to the caller of ReconcileNode in tests; a bare drop here
			// matches the existing "best-effort background hook" idiom
			// (freeze_signal.go) rather than introducing a new logging
			// dependency to this file.
			_ = err
		}
	})
	reconciler = dispatch.NewReconciler(tasks, router)

	return router, reconciler, routerSink{r: router}
}
