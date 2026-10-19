package mcp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. idem,
// newID and concurrency may be zero (NewExecution's safe absences; a zero
// concurrency takes the default). audit, authz, freeze, both query seams, cap
// and the execution seams are required, as the capability constructors
// require them.
type capSeams struct {
	reg    registry.Repository
	authz  capability.Authorizer
	cap    capability.CapChecker
	audit  capability.AuditSink
	freeze capability.FreezeStore

	auditQ     capability.AuditQuery
	jobQ       capability.JobQuery
	policyView capability.PolicyViewSource
	nodeVocab  capability.TemplateVocabularySource
	aliases    capability.PolicyAliasSource
	idem       jobs.IdempotencyRepository

	jobsRepo    jobs.JobRepository
	tasksRepo   jobs.TaskRepository
	conduit     capability.Conduit
	newID       func() (string, error)
	concurrency int
}

// capLayer is what a test holds a built capability layer as: the Execution and
// the leaf services it is composed with, embedded so a test calls any of their
// methods unqualified, and a call site that hands one to the MCP server names
// the narrow embedded field, as the composition root does.
type capLayer struct {
	*capability.Execution
	*capability.ReadLane
	*capability.Control
}

// newCapService builds the capability layer for a test: a thin wrapper over the
// capability constructors, so the layer's shape changes in one place.
func newCapService(t *testing.T, s capSeams) *capLayer {
	t.Helper()
	if s.audit == nil || s.authz == nil || s.freeze == nil || s.auditQ == nil || s.jobQ == nil {
		t.Fatalf("newCapService: audit, authz, freeze, auditQ and jobQ are required")
	}
	rec := capability.NewRecorder(s.audit, nil, nil)
	ctl := capability.NewControl(rec, s.authz, s.freeze)
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, s.policyView, s.nodeVocab, 0, nil, capability.WithPolicyAliasSource(s.aliases))

	if s.cap == nil || s.jobsRepo == nil || s.tasksRepo == nil || s.conduit == nil {
		t.Fatalf("newCapService: cap, jobsRepo, tasksRepo and conduit are required")
	}
	conc := s.concurrency
	if conc == 0 {
		conc = capability.DefaultDispatchConcurrency
	}
	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil, nil, nil)
	exec := capability.NewExecution(ctl, read, appr, s.cap, s.idem, s.jobsRepo, s.tasksRepo, s.conduit, conc, s.newID, nil)
	return &capLayer{Execution: exec, ReadLane: read, Control: ctl}
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
