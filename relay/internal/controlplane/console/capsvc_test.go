package console

import (
	"context"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the service that needs it is not built. audit is
// required, as capability.NewRecorder requires it. If neither query seam is
// supplied both default to the empty fakes; a half-wired pair is passed
// through, and NewReadLane panics on it.
type capSeams struct {
	reg   registry.Repository
	authz capability.Authorizer
	audit capability.AuditSink

	auditQ     capability.AuditQuery
	jobQ       capability.JobQuery
	policyView capability.PolicyViewSource
	nodeVocab  capability.TemplateVocabularySource
	aliases    capability.PolicyAliasSource

	accountsStore capability.AccountStore
	apiTokens     capability.APITokenStore
}

// capLayer is what a test holds a built capability layer as: the leaf services
// embedded, so a test calls any of their methods unqualified, and a call site
// that hands one to a Deps seam names the narrow embedded field, as the
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

// newCapService builds the capability layer for a test: a thin wrapper over the
// capability constructors, so the layer's shape changes in one place.
//
// Takes no *testing.T because realLaneDeps (read_audit_test.go) builds its lane
// for a fixture that has none; a wiring mistake here panics, which fails the
// calling test just as loudly.
func newCapService(s capSeams) *capLayer {
	rec := capability.NewRecorder(s.audit, nil, nil)
	auditQ, jobQ := s.auditQ, s.jobQ
	if auditQ == nil && jobQ == nil {
		auditQ, jobQ = emptyAuditQuery{}, emptyJobQuery{}
	}
	var laneOpts []capability.ReadLaneOption
	if s.aliases != nil {
		laneOpts = append(laneOpts, capability.WithPolicyAliasSource(s.aliases))
	}
	layer := &capLayer{
		ReadLane: capability.NewReadLane(rec, s.reg, auditQ, jobQ, s.policyView, s.nodeVocab, &capability.StaticOperatorSettings{S: capability.OperatorSettings{DispatchConcurrency: capability.DefaultDispatchConcurrency}}, nil, laneOpts...),
	}
	if s.authz != nil {
		layer.Control = capability.NewControl(rec, s.authz, neverFrozen{})
	}
	if s.accountsStore != nil || s.apiTokens != nil {
		layer.AccountAdmin = capability.NewAccountAdmin(layer.Control, s.accountsStore, s.apiTokens)
	}
	return layer
}
