package api

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// capSeams is the set of collaborators a test hands to newCapService. A zero
// field means "not supplied": the option is not emitted and capability.New
// keeps its default.
type capSeams struct {
	reg        registry.Repository
	authz      capability.Authorizer
	audit      capability.AuditSink
	now        func() time.Time
	certWindow time.Duration

	accountsStore capability.AccountStore
	apiTokens     capability.APITokenStore
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
	if s.audit != nil {
		opts = append(opts, capability.WithAuditSink(s.audit))
	}
	if s.now != nil {
		opts = append(opts, capability.WithClock(s.now))
	}
	if s.certWindow != 0 {
		opts = append(opts, capability.WithCertExpiringWindow(s.certWindow))
	}
	if s.accountsStore != nil || s.apiTokens != nil {
		opts = append(opts, capability.WithAccountAdmin(s.accountsStore, s.apiTokens))
	}
	return capability.New(s.reg, opts...)
}
