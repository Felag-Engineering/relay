package auditquery

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied". audit, auditQ and jobQ are required, as
// capability.NewReadLane requires them; authz builds the Control over it, the
// execution seams build the Execution, and a test that sets none reads through the lane alone.
type capSeams struct {
	reg   registry.Repository
	authz capability.Authorizer
	// settings carries the blast caps; nil means the defaults.
	settings *capability.StaticOperatorSettings
	audit    capability.AuditSink
	freeze   capability.FreezeStore

	auditQ capability.AuditQuery
	jobQ   capability.JobQuery

	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
	conduit   capability.Conduit
	newID     func() (string, error)
}

// capLayer is what a test holds a built capability layer as: the leaf services
// embedded, so a test calls any of their methods unqualified. Control is nil
// when the test supplied no authorizer, and Execution unless it also supplied
// the execution seams.
type capLayer struct {
	*capability.Execution
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
	// One source for the read lane, the BlastCap and the Execution, as the
	// composition root wires them.
	settings := &capability.StaticOperatorSettings{}
	if s.settings != nil {
		settings.S = s.settings.S
	}
	settings.S.DispatchConcurrency = capability.DefaultDispatchConcurrency
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, nil, nil, settings, nil)
	layer := &capLayer{ReadLane: read}
	if s.authz == nil {
		return layer
	}
	freeze := s.freeze
	if freeze == nil {
		freeze = neverFrozen{}
	}
	layer.Control = capability.NewControl(rec, s.authz, freeze)

	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil)
	if hasExec {
		layer.Execution = capability.NewExecution(layer.Control, read, appr, capability.NewBlastCap(settings), nil, s.jobsRepo, s.tasksRepo, s.conduit, settings, s.newID, nil)
	}
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

// blastCaps is the settings a fixture hands newCapService to give the layer
// these blast caps; zero takes the package default, as BlastCap clamps it.
func blastCaps(readCap, mutateCap int) *capability.StaticOperatorSettings {
	return &capability.StaticOperatorSettings{S: capability.OperatorSettings{ReadBlastCap: readCap, MutateBlastCap: mutateCap}}
}
