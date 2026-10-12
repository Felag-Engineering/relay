package mcp_test

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the option is not emitted and capability.New
// keeps its default.
type capSeams struct {
	reg    registry.Repository
	authz  capability.Authorizer
	cap    capability.CapChecker
	audit  capability.AuditSink
	freeze capability.FreezeStore

	policyView capability.PolicyViewSource
	nodeVocab  capability.TemplateVocabularySource
	idem       jobs.IdempotencyRepository

	jobsRepo    jobs.JobRepository
	tasksRepo   jobs.TaskRepository
	conduit     capability.Conduit
	newID       func() (string, error)
	concurrency int
}

// newCapService builds the capability layer for a test: a thin wrapper over
// capability.New and the With* options, so the layer's constructor changes in
// one place.
func newCapService(t *testing.T, s capSeams) *capability.Service {
	t.Helper()
	var opts []capability.Option
	if s.authz != nil {
		opts = append(opts, capability.WithAuthorizer(s.authz))
	}
	if s.cap != nil {
		opts = append(opts, capability.WithCapChecker(s.cap))
	}
	if s.audit != nil {
		opts = append(opts, capability.WithAuditSink(s.audit))
	}
	if s.freeze != nil {
		opts = append(opts, capability.WithFreeze(s.freeze))
	}
	if s.policyView != nil {
		opts = append(opts, capability.WithPolicyView(s.policyView))
	}
	if s.nodeVocab != nil {
		opts = append(opts, capability.WithTemplateVocabulary(s.nodeVocab))
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
	return capability.New(s.reg, opts...)
}
