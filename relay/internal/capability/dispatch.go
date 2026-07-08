package capability

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// dispatch is the authorized, resolved, cap-checked unit ready to execute:
// the Selector has been resolved to concrete Nodes, the Principal has
// cleared the Authorizer, and the blast-radius cap has cleared the
// CapChecker. It is unexported, and so is newDispatch, its only
// constructor — this is the compile-enforced half of "one capability
// layer" (ADR-0009/0010, ROADMAP invariant 10): no package outside
// capability can construct a dispatch, so a surface reaching around
// Service.Run to dispatch directly fails to compile rather than relying on
// review discipline. See dispatch_construction_test.go.
type dispatch struct {
	principal Principal
	selector  Selector
	nodes     []registry.Node
	action    jobs.Action
}

// newDispatch builds a dispatch from an already-authorized, already-resolved
// unit of work. It is unexported for the same reason dispatch itself is:
// only Service.Run may call it.
func newDispatch(p Principal, sel Selector, nodes []registry.Node, act jobs.Action) dispatch {
	return dispatch{principal: p, selector: sel, nodes: nodes, action: act}
}

// NodeResult is one Node's outcome from executing a dispatch.
type NodeResult struct {
	NodeID  string
	Outcome jobs.Outcome
}

// dispatcher executes an already-built dispatch. Both the interface and its
// run method are unexported, and run's parameter type (dispatch) is itself
// unexported — a foreign package can neither implement dispatcher nor call
// run, and even if it could, it has no way to fabricate a dispatch value to
// pass. The real Job engine (#99) must therefore be added as new files
// inside package capability (not internal/jobs), injecting its external
// collaborators (revocation.Connections, jobs.TaskRepository) through their
// own exported Option, e.g. WithExecution(...) — see service.go.
//
// Sealing the constructor and this seam only guarantees that dispatch is
// unreachable except through Service.Run; it does not by itself guarantee
// that dispatch is safe. New's allow-all/no-op Authorizer/CapChecker/
// AuditSink defaults are safe today only because the default dispatcher is
// noopDispatcher, which performs no execution. Any option that swaps in a
// real dispatcher (e.g. #99's WithExecution) MUST require real Authorizer,
// CapChecker, and AuditSink implementations rather than letting a real
// dispatcher ride these defaults — see the contract note on New in
// service.go.
type dispatcher interface {
	run(ctx context.Context, d dispatch) ([]NodeResult, error)
}

// noopDispatcher is the v0.0.5 default. It performs no execution and says
// so honestly: every matched Node gets OutcomeUnspecified, never a
// fabricated success. #99 replaces this with the real Job engine.
type noopDispatcher struct{}

func (noopDispatcher) run(_ context.Context, d dispatch) ([]NodeResult, error) {
	results := make([]NodeResult, 0, len(d.nodes))
	for _, n := range d.nodes {
		results = append(results, NodeResult{NodeID: n.NodeID, Outcome: jobs.OutcomeUnspecified})
	}
	return results, nil
}
