package console

import (
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the option is not emitted and capability.New
// keeps its default.
type capSeams struct {
	reg   registry.Repository
	authz capability.Authorizer
	audit capability.AuditSink

	auditQ     capability.AuditQuery
	jobQ       capability.JobQuery
	policyView capability.PolicyViewSource
	nodeVocab  capability.TemplateVocabularySource

	accountsStore capability.AccountStore
	apiTokens     capability.APITokenStore
}

// newCapService builds the capability layer for a test: a thin wrapper over
// capability.New and the With* options, so the layer's constructor changes in
// one place.
func newCapService(s capSeams) *capability.Service {
	var opts []capability.Option
	if s.authz != nil {
		opts = append(opts, capability.WithAuthorizer(s.authz))
	}
	if s.audit != nil {
		opts = append(opts, capability.WithAuditSink(s.audit))
	}
	if s.auditQ != nil || s.jobQ != nil {
		opts = append(opts, capability.WithQueries(s.auditQ, s.jobQ))
	}
	if s.policyView != nil {
		opts = append(opts, capability.WithPolicyView(s.policyView))
	}
	if s.nodeVocab != nil {
		opts = append(opts, capability.WithTemplateVocabulary(s.nodeVocab))
	}
	if s.accountsStore != nil || s.apiTokens != nil {
		opts = append(opts, capability.WithAccountAdmin(s.accountsStore, s.apiTokens))
	}
	return capability.New(s.reg, opts...)
}
