// Package authz is the Relay's production capability.Authorizer (ADR-0010):
// role-based, deny-by-default, and the single place the "who may run what"
// question is answered for every surface.
//
// The v0.0.5 predecessor (`Staged`) authorized exactly one thing: an Account
// whose role was admin. That was correct while the seeded credential
// authenticated as the one and only Principal. With real Accounts (#295),
// real credentials (#296), and both on the wire (#297), the gate is now the
// role ladder ADR-0010 describes:
//
//	viewer    — may read. May never dispatch anything.
//	operator  — may additionally run structured Operations (the typed path).
//	admin     — may additionally use Raw Exec.
//
// **Raw Exec being admin-only is the centrally-enforced half of ADR-0001's
// safety model.** Node Policy still gates every command that arrives, and
// remains the last line of defense (ADR-0002) — this gate decides who may
// even *ask* for the arbitrary-command path. Neither substitutes for the
// other: Policy cannot know which Account asked, and the Relay cannot know
// what a Node will permit.
//
// It lives here, behind capability.Authorizer, rather than in any surface,
// because invariant 10 requires MCP, the Control API, and the Console to
// inherit the same answer. A surface that gated Raw Exec itself would be a
// second control path, and the first one to be forgotten.
//
// authz imports capability, jobs, and accounts — no proto, no store, no HTTP.
// capability never imports authz, so there is no cycle.
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// ErrUnauthorized is returned by RoleGate.Authorize when p is denied. It is
// exported and typed, mirroring capability.FrozenError/CapExceededError, so a
// refusal is recognizable via errors.Is without string-matching — legible in
// the audit trail (capability.Service.Run records refusalErr.Error() as
// AuditEntry.Reason).
var ErrUnauthorized = errors.New("authz: unauthorized")

// unauthorizedError wraps ErrUnauthorized with the denied Principal and what
// the Action needed, so the audit Reason states who was denied and why while
// errors.Is(err, ErrUnauthorized) still recognizes the refusal class.
//
// It names the *required* role rather than echoing anything the caller
// supplied: an audit reader needs "operator tried Raw Exec, which needs
// admin", and a caller learns only the rule, which is public.
type unauthorizedError struct {
	principal capability.Principal
	action    string
	required  accounts.Role
	// unknownKind marks the deny-the-Action-itself case, which no role
	// satisfies. Rendering it as "requires admin" would be actively
	// misleading to an audit reader holding an admin token.
	unknownKind bool
}

func (e *unauthorizedError) Error() string {
	if e.unknownKind {
		return fmt.Sprintf("authz: principal %q denied: %s; no role may dispatch it",
			e.principal.Account, e.action)
	}
	return fmt.Sprintf("authz: principal %q denied: %s requires role %q, has %q",
		e.principal.Account, e.action, e.required, e.principal.Role)
}

func (e *unauthorizedError) Unwrap() error {
	return ErrUnauthorized
}

// RoleGate authorizes an Action against the acting Account's role.
//
// Deny-by-default in both directions: an Action kind it does not recognize is
// denied (a future kind is refused until someone decides its floor, rather
// than inheriting the weakest one), and an unknown or corrupted role satisfies
// nothing (accounts.Role.AtLeast fails closed).
//
// Not scoped by Selector yet: per-Account/per-Selector Grants are the next
// narrowing (ADR-0010, and see #285 on whether to adopt Cedar rather than
// hand-roll one). A later Authorizer must narrow *within* this seam — no
// version of it may ever be more permissive than the ladder above.
type RoleGate struct{}

// NewRoleGate returns a RoleGate. It holds no state — construction never
// fails.
func NewRoleGate() *RoleGate {
	return &RoleGate{}
}

// requiredRole returns the minimum role for an Action kind, and false for a
// kind this gate does not recognize.
//
// The floor is chosen by Action *kind*, not by risk class. Risk class picks
// the blast cap (ADR-0012); it must never double as an authorization input,
// or a `read`-class Raw Exec would authorize as though it were a structured
// read — and "this command only reads" is exactly the claim an
// arbitrary-command path cannot make on its own behalf.
func requiredRole(kind jobs.ActionKind) (accounts.Role, string, bool) {
	switch kind {
	case jobs.ActionOperation:
		return accounts.RoleOperator, "running an Operation", true
	case jobs.ActionRawExec:
		return accounts.RoleAdmin, "Raw Exec", true
	default:
		return "", "", false
	}
}

// Authorize implements capability.Authorizer.
func (*RoleGate) Authorize(_ context.Context, p capability.Principal, act jobs.Action, _ capability.Selector) error {
	required, label, known := requiredRole(act.Kind)
	if !known {
		// An unspecified or future Action kind is denied outright, for every
		// role including admin: a kind added later must have its floor decided
		// deliberately here, not inherit the weakest one by falling through.
		return &unauthorizedError{
			principal:   p,
			action:      fmt.Sprintf("unrecognized action kind %v", act.Kind),
			unknownKind: true,
		}
	}
	if !accounts.Role(p.Role).AtLeast(required) {
		return &unauthorizedError{principal: p, action: label, required: required}
	}
	return nil
}

// AuthorizeApprovalDecision implements capability.ApprovalAuthorizer (#270,
// ADR-0027): may p answer a parked dispatch whose Action is of this kind?
//
// The floor is **the same requiredRole table** the request itself passed, and
// that identity is the point rather than a convenience. Approval must not be a
// side door around the ladder: if approving used a lower floor, an operator
// could release an admin's Raw Exec and the "admin-only" half of ADR-0001's
// safety model would hold for asking and not for granting. Deciding what you
// could not have asked for is exactly the escalation this closes.
//
// It is deliberately not *more* restrictive than the request floor either. An
// approver drawn from a narrower pool than the requesters is a real policy, but
// it is the gate rule's `audience` — operator configuration, per rule — not a
// hard-coded second ladder that no deployment could tune.
//
// Deny-by-default is inherited whole: an unrecognized Action kind is refused
// for every role, so a Request stored by a build that knew a kind this one does
// not is undecidable rather than decidable by the weakest floor.
func (*RoleGate) AuthorizeApprovalDecision(_ context.Context, p capability.Principal, kind jobs.ActionKind) error {
	required, label, known := requiredRole(kind)
	if !known {
		return &unauthorizedError{
			principal:   p,
			action:      fmt.Sprintf("deciding an approval for unrecognized action kind %v", kind),
			unknownKind: true,
		}
	}
	if !accounts.Role(p.Role).AtLeast(required) {
		return &unauthorizedError{principal: p, action: "approving " + label, required: required}
	}
	return nil
}
