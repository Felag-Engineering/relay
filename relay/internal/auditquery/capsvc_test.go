package auditquery

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

	auditQ capability.AuditQuery
	jobQ   capability.JobQuery

	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
	conduit   capability.Conduit
	newID     func() (string, error)
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
	if s.auditQ != nil || s.jobQ != nil {
		opts = append(opts, capability.WithQueries(s.auditQ, s.jobQ))
	}
	if s.jobsRepo != nil || s.tasksRepo != nil || s.conduit != nil {
		var eo []capability.ExecOption
		if s.newID != nil {
			eo = append(eo, capability.WithExecNewID(s.newID))
		}
		opts = append(opts, capability.WithExecution(s.jobsRepo, s.tasksRepo, s.conduit, eo...))
	}
	return capability.New(s.reg, opts...)
}
