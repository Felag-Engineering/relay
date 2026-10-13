package mcp_test

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// execution field means "not supplied": the option is not emitted and
// capability.New keeps its default. audit, authz, freeze and both query seams
// are required, as the capability constructors require them.
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
	idem       jobs.IdempotencyRepository

	jobsRepo    jobs.JobRepository
	tasksRepo   jobs.TaskRepository
	conduit     capability.Conduit
	newID       func() (string, error)
	concurrency int
}

// capLayer is what a test holds a built capability layer as: the Service and
// the leaf services it is composed with, embedded so a test calls any of their
// methods unqualified, and a call site that hands one to the MCP server names
// the narrow embedded field, as the composition root does.
type capLayer struct {
	*capability.Service
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
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, s.policyView, s.nodeVocab, 0, nil)

	var opts []capability.Option
	if s.cap != nil {
		opts = append(opts, capability.WithCapChecker(s.cap))
	}
	if s.idem != nil {
		opts = append(opts, capability.WithIdempotency(s.idem))
	}
	if s.jobsRepo != nil || s.tasksRepo != nil || s.conduit != nil {
		var eo []capability.ExecOption
		if s.newID != nil {
			eo = append(eo, capability.WithExecNewID(s.newID))
		}
		if s.concurrency != 0 {
			eo = append(eo, capability.WithExecDispatchConcurrency(s.concurrency))
		}
		opts = append(opts, capability.WithExecution(s.jobsRepo, s.tasksRepo, s.conduit, eo...))
	}
	return &capLayer{Service: capability.New(ctl, read, opts...), ReadLane: read, Control: ctl}
}
