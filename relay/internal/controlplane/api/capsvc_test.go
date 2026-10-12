package api

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the service that needs it is not built. audit is
// required, as capability.NewRecorder requires it.
type capSeams struct {
	reg        registry.Repository
	authz      capability.Authorizer
	audit      capability.AuditSink
	now        func() time.Time
	certWindow time.Duration

	accountsStore capability.AccountStore
	apiTokens     capability.APITokenStore
}

// capLayer is what a test holds a built capability layer as: the leaf services
// embedded, so a test calls any of their methods unqualified, and a call site
// that hands one to an adapter seam names the narrow embedded field, as the
// composition root does. Control and AccountAdmin are nil unless supplied.
type capLayer struct {
	*capability.ReadLane
	*capability.Control
	*capability.AccountAdmin
}

// neverFrozen is a FreezeStore that is never frozen, standing in for
// capability's unexported no-op store: NewControl requires a store.
type neverFrozen struct{}

func (neverFrozen) Frozen(context.Context) (bool, error)          { return false, nil }
func (neverFrozen) Engage(context.Context, string) error          { return nil }
func (neverFrozen) Release(context.Context, string, string) error { return nil }

// emptyQueries implements capability.AuditQuery and capability.JobQuery with
// zero values: NewReadLane requires both query seams, and no api test reads
// either.
type emptyQueries struct{}

func (emptyQueries) QueryAudit(context.Context, capability.AuditFilter, capability.PageRequest) (capability.AuditPage, error) {
	return capability.AuditPage{}, nil
}

func (emptyQueries) AuditCounts(context.Context, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (emptyQueries) AuditReach(context.Context, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

func (emptyQueries) QueryJobs(context.Context, capability.JobFilter, capability.PageRequest) (capability.JobPage, error) {
	return capability.JobPage{}, nil
}

func (emptyQueries) QueryTasks(context.Context, capability.TaskFilter, capability.PageRequest) (capability.TaskPage, error) {
	return capability.TaskPage{}, nil
}

// newCapService builds the capability layer for a test: a thin wrapper over the
// capability constructors, so the layer's shape changes in one place.
func newCapService(t *testing.T, s capSeams) *capLayer {
	t.Helper()
	if s.audit == nil {
		t.Fatalf("newCapService: audit is required")
	}
	rec := capability.NewRecorder(s.audit, nil, nil)
	layer := &capLayer{
		ReadLane: capability.NewReadLane(rec, s.reg, emptyQueries{}, emptyQueries{}, nil, nil, s.certWindow, s.now),
	}
	if s.authz != nil {
		layer.Control = capability.NewControl(rec, s.authz, neverFrozen{})
	}
	if s.accountsStore != nil || s.apiTokens != nil {
		layer.AccountAdmin = capability.NewAccountAdmin(layer.Control, s.accountsStore, s.apiTokens)
	}
	return layer
}
