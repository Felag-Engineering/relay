// Package authz is the Relay's real, production capability.Authorizer
// (ADR-0010's staged adoption): pre-Account, role-based, deny-by-default.
//
// v0.0.5 has no Account or Grant yet — the seeded control-plane credential
// (v0.0.6) authenticates as exactly one Principal, controlplane.FoundingAdmin
// (Account: "founding-admin", Role: "admin") — and Accounts/Grants land in
// v0.3.0 (ADR-0010). Staged built against ROLE, not a hardcoded Account
// match, so v0.3.0 is additive: a later Grant-based Authorizer narrows
// authorization WITHIN this deny-by-default seam rather than replacing it.
//
// Staged imports only capability and jobs — the same allowlist package
// capability enforces on itself (TestCapabilityImportsOnlyRegistryAndJobs) —
// so there is no import cycle: capability never imports authz.
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// ErrUnauthorized is returned by Staged.Authorize when p is denied. It is
// exported and typed, mirroring capability.FrozenError/CapExceededError, so a
// refusal is recognizable via errors.Is without string-matching — legible in
// the audit trail (capability.Service.Run records refusalErr.Error() as
// AuditEntry.Reason).
var ErrUnauthorized = errors.New("authz: unauthorized")

// unauthorizedError wraps ErrUnauthorized with the denied Principal, so the
// audit Reason states who was denied while errors.Is(err, ErrUnauthorized)
// still recognizes the refusal class.
type unauthorizedError struct {
	principal capability.Principal
}

func (e *unauthorizedError) Error() string {
	return fmt.Sprintf("authz: principal %q denied: role %q is not admin", e.principal.Account, e.principal.Role)
}

func (e *unauthorizedError) Unwrap() error {
	return ErrUnauthorized
}

// Staged is the pre-Account staged Authorizer (ADR-0010): every Action —
// both ActionOperation and ActionRawExec, every RiskClass — is authorized
// for a Principal whose Role is "admin", and denied for everyone/everything
// else, deny-by-default. This is not scoped by Selector or Action today
// (there is only one real Principal to authorize); v0.3.0's Grant-based
// Authorizer narrows this per-Account/per-Selector/per-Action, but a Staged
// refusal must never become more permissive than "admin allowed, everyone
// else denied" until that lands.
type Staged struct{}

// NewStaged returns a Staged Authorizer. It holds no state — construction
// never fails.
func NewStaged() *Staged {
	return &Staged{}
}

// Authorize implements capability.Authorizer.
func (*Staged) Authorize(_ context.Context, p capability.Principal, _ jobs.Action, _ capability.Selector) error {
	if p.Role == "admin" {
		return nil
	}
	return &unauthorizedError{principal: p}
}
