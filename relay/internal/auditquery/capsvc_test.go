package auditquery

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied". audit, auditQ and jobQ are required, as
// capability.NewReadLane requires them; authz builds the Control and the
// Service over it, and a test that sets none reads through the lane alone.
type capSeams struct {
	reg    registry.Repository
	authz  capability.Authorizer
	cap    capability.CapChecker
	audit  capability.AuditSink
	freeze capability.FreezeStore

	auditQ capability.AuditQuery
	jobQ   capability.JobQuery

	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
	conduit   capability.Conduit
	newID     func() (string, error)
}

// capLayer is what a test holds a built capability layer as: the leaf services
// embedded, so a test calls any of their methods unqualified. Service and
// Control are nil when the test supplied no authorizer.
type capLayer struct {
	*capability.Service
	*capability.ReadLane
	*capability.Control
}

// neverFrozen is a FreezeStore that is never frozen, standing in for
// capability's unexported no-op store: NewControl requires a store.
type neverFrozen struct{}

func (neverFrozen) Frozen(context.Context) (bool, error)          { return false, nil }
func (neverFrozen) Engage(context.Context, string) error          { return nil }
func (neverFrozen) Release(context.Context, string, string) error { return nil }

// newCapService builds the capability layer for a test: a thin wrapper over the
// capability constructors, so the layer's shape changes in one place.
func newCapService(t *testing.T, s capSeams) *capLayer {
	t.Helper()
	if s.audit == nil || s.auditQ == nil || s.jobQ == nil {
		t.Fatalf("newCapService: audit, auditQ and jobQ are required")
	}
	hasExec := s.jobsRepo != nil || s.tasksRepo != nil || s.conduit != nil
	if hasExec && (s.freeze == nil || s.authz == nil) {
		t.Fatalf("newCapService: execution seams need a freeze store and an authorizer")
	}
	rec := capability.NewRecorder(s.audit, nil, nil)
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, nil, nil, 0, nil)
	layer := &capLayer{ReadLane: read}
	if s.authz == nil {
		return layer
	}
	freeze := s.freeze
	if freeze == nil {
		freeze = neverFrozen{}
	}
	layer.Control = capability.NewControl(rec, s.authz, freeze)

	var opts []capability.Option
	if s.cap != nil {
		opts = append(opts, capability.WithCapChecker(s.cap))
	}
	if hasExec {
		var eo []capability.ExecOption
		if s.newID != nil {
			eo = append(eo, capability.WithExecNewID(s.newID))
		}
		opts = append(opts, capability.WithExecution(s.jobsRepo, s.tasksRepo, s.conduit, eo...))
	}
	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil, nil, nil)
	layer.Service = capability.New(layer.Control, read, appr, opts...)
	return layer
}

// unreachableApprovalStore is the approval store behind an empty gate: nothing
// ungated reaches it; a call panics on the nil embed, so a test that did would
// fail loudly.
type unreachableApprovalStore struct{ capability.ApprovalStore }

// denyApprovalDecisions is the decision floor behind an empty gate.
type denyApprovalDecisions struct{}

func (denyApprovalDecisions) AuthorizeApprovalDecision(context.Context, capability.Principal, jobs.ActionKind) error {
	return errors.New("test: approval decisions are not wired")
}
