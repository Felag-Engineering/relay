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
// concurrency takes the default). audit, authz, freeze, both query seams
// and the execution seams are required, as the capability constructors
// require them.
type capSeams struct {
	reg    registry.Repository
	authz  capability.Authorizer
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
	// settings carries the blast caps (and, with concurrency, the dispatch
	// bound); nil means the defaults.
	settings *capability.StaticOperatorSettings
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
	// One source for the read lane, the BlastCap and the Execution, as the
	// composition root wires them.
	settings := &capability.StaticOperatorSettings{}
	if s.settings != nil {
		settings.S = s.settings.S
	}
	if s.concurrency != 0 {
		settings.S.DispatchConcurrency = s.concurrency
	}
	if settings.S.DispatchConcurrency == 0 {
		settings.S.DispatchConcurrency = capability.DefaultDispatchConcurrency
	}
	ctl := capability.NewControl(rec, s.authz, s.freeze)
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, s.policyView, s.nodeVocab, settings, nil, capability.WithPolicyAliasSource(s.aliases))

	if s.jobsRepo == nil || s.tasksRepo == nil || s.conduit == nil {
		t.Fatalf("newCapService: jobsRepo, tasksRepo and conduit are required")
	}
	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil, nil, nil)
	exec := capability.NewExecution(ctl, read, appr, capability.NewBlastCap(settings), s.idem, s.jobsRepo, s.tasksRepo, s.conduit, settings, s.newID, nil)
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

// blastCaps is the settings a fixture hands newCapService to give the layer
// these blast caps; zero takes the package default, as BlastCap clamps it.
func blastCaps(readCap, mutateCap int) *capability.StaticOperatorSettings {
	return &capability.StaticOperatorSettings{S: capability.OperatorSettings{ReadBlastCap: readCap, MutateBlastCap: mutateCap}}
}
