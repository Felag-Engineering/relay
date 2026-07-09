package main

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/dispatch"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// dispatch_wiring.go is the v0.0.5 dispatch transport's composition-root
// wiring: it is production-ready code, built by every build (no build tag),
// but newServer does not call newDispatchStack and never sets tunnel.sink —
// see TestTunnelSink_NilInProduction. Wiring the real Job engine
// (capability.WithExecution) into newServer is deferred to v0.0.6, when a
// real Authorizer exists: capability.New's fail-open guard panics if a real
// dispatcher rides the default allow-all Authorizer (service.go), and no
// real Authorizer is in scope this milestone. Until then this stack is
// exercised by tests and the #103 integration harness, which supply their
// own test Authorizer.
//
// This mirrors how execution.go's WithExecution exists, fully wired and
// unit-tested, without main ever calling it.

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
