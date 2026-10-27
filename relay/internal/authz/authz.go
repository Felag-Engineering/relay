// Package authz is the Relay's production capability.Authorizer (ADR-0010):
// role-based, deny-by-default, and the single place the "who may run what"
// question is answered for every surface.
//
// The v0.0.5 predecessor (`Staged`) authorized exactly one thing: an Account
// whose role was admin. That was correct while the seeded credential
// authenticated as the one and only Principal. With real Accounts,
// real credentials, and both on the wire, the gate is now the
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
// # The administrative half
//
// The ladder above answers "who may dispatch". It could not answer "who may
// mint an Enrollment Token, revoke a Node, or engage the Freeze", because
// none of those constructs a jobs.Action — so RoleGate was never consulted
// for any of them and a viewer could do all three. AuthorizeControl adds
// that table (capability.ControlAction), in this one object, for the same
// reason the dispatch ladder is here: a floor that each surface keeps for
// itself is a floor that drifts.
//
// One rule there is not a role at all. Engaging the Freeze additionally
// requires a HUMAN Account: a machine Account at operator halting the fleet
// is an AI-agent switching off its own overseers, and the fire-alarm
// argument for cheap engagement ("anyone may pull the handle") is an
// argument about people. Authority remains the Role, but capability.
// Principal's Kind IS an authorization input for three specific decisions
// Role alone cannot answer — this is one of them. The other two are decided
// elsewhere, deliberately not here: CancelJob's machine-Account scoping (a
// human Account may cancel any Job, a machine Account only one whose
// recorded requester is itself) lives in capability.Execution.CancelJob/
// authorizeMachineCancel, because it needs Job data this package does not
// hold; ADR-0027's confirmation ladder rung 2 (self-confirmation is
// human-requesters-only) lives in capability's approval decision path. This
// package's own use of Kind begins and ends with the Freeze rule above.
//
// authz imports capability, jobs, and accounts — no proto, no store, no HTTP.
// capability never imports authz, so there is no cycle.
package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// ErrUnauthorized is returned by RoleGate.Authorize when p is denied. It is
// exported and typed, mirroring capability.FrozenError/CapExceededError, so a
// refusal is recognizable via errors.Is without string-matching — legible in
// the audit trail (capability.Execution.Run records refusalErr.Error() as
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

// notHumanError is the refusal for a control Action that no machine Account
// may perform at any role (Freeze engage; ADR-0013). It is a distinct type from
// unauthorizedError because the two say genuinely different things to an
// audit reader — "your role is too low" invites an escalation request, while
// "this act is human-only" says no amount of role will help — but it unwraps
// to the same ErrUnauthorized sentinel so every surface's existing
// refusal-to-403 mapping covers it without knowing it exists.
//
// The Principal's KIND is named in the message on purpose: the refusal is
// audited with it, and the reason string is what reaches the trail.
type notHumanError struct {
	principal capability.Principal
	action    string
}

func (e *notHumanError) Error() string {
	kind := e.principal.Kind
	if kind == "" {
		// Principal.Kind's empty value means "unknown", and every check
		// written against it must treat unknown as machine (principal.go).
		// Rendering it as an empty string would read as a missing field
		// rather than as the reason for the refusal.
		kind = "unknown"
	}
	return fmt.Sprintf("authz: principal %q denied: %s is human-only; account kind is %q",
		e.principal.Account, e.action, kind)
}

func (e *notHumanError) Unwrap() error {
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
// narrowing (ADR-0010; whether to adopt Cedar rather than hand-roll one is an
// open question in ADR-0041). A later Authorizer must narrow *within* this seam — no
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

// AuthorizeApprovalDecision implements capability.ApprovalAuthorizer
// (ADR-0027): may p answer a parked dispatch whose Action is of this kind?
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

// requiredControlRole returns the minimum role for an administrative
// ControlAction, whether the act is additionally human-only, and false for an
// action this gate does not recognize.
//
// The floors are not new policy — each was already written down and simply
// never enforced:
//
//	mint an Enrollment Token     admin      ADR-0032 §5
//	revoke an Enrollment Token   admin      ADR-0020's incident ladder
//	revoke a Node                admin      ADR-0020's incident ladder
//	engage the Freeze            operator   ADR-0013 (+ human-only)
//	release the Freeze           admin      ADR-0013
//	cancel a Job                 operator   execution.md §Cancellation (owner decision 2026-09-14)
//	read Accounts                admin      accounts-and-access.md: "Administer Accounts and API Tokens — admin"
//	create an Account            admin      accounts-and-access.md
//	change an Account's role     admin      accounts-and-access.md
//	enable an Account            admin      accounts-and-access.md
//	disable an Account           admin      accounts-and-access.md
//	read API Tokens              admin      accounts-and-access.md
//	mint an API Token            admin      accounts-and-access.md
//	revoke an API Token          admin      accounts-and-access.md
//	set, rename or clear a
//	  Policy alias               admin      query.md (+ human-only)
//	write a tag                  operator   ADR-0050 (+ human-only)
//
// The eight Account/API-Token rows are humanOnly: false — STATUS-QUO
// PRESERVATION, not a claim that admin is already the strongest role (that
// conflates authority breadth with PERSISTENCE: a machine admin minting a
// Token converts a transient session compromise into durable access that
// outlives revoking the AI-agent's own credential, exactly ADR-0009's concern).
// These nine routes are shipped, and
// TestIdentityAPI_AccountTokenAuthenticatesAndRevocationCutsAccess and
// TestIdentityAPI_SelfDisableAndSelfRoleAreRefused both drive them as MACHINE
// ADMINS today — humanOnly: true would be a silent behaviour change on a live
// surface. Narrowing to human-only is an owner decision, to be recorded on
// the issue, not settled here.
// Enrollment sits at admin because a token admits Nodes to the fleet carrying
// the initial tags it names, which a Selector then targets (ADR-0050), so
// minting manufactures Nodes dispatches will reach. That is a more durable
// position than any single dispatch, which is why it cannot sit below the role
// that may run one.
//
// Cancel's ROLE floor is not human-only: an AI-agent must be able to stop
// its own dispatch. Whether it may reach ANY Job or only its own is a
// separate question this gate does not decide — it needs the Job's recorded
// requester, which is capability-layer data this package does not hold.
// capability.Execution.CancelJob layers that machine-Account scoping on top of
// this floor (owner decision 2026-09-17, execution.md §Cancellation):
// a human Account may still cancel any Job, but a machine Account may cancel
// only a Job whose recorded requester is itself.
func requiredControlRole(act capability.ControlAction) (role accounts.Role, label string, humanOnly, known bool) {
	switch act {
	case capability.ControlMintEnrollmentToken:
		return accounts.RoleAdmin, "minting an Enrollment Token", false, true
	case capability.ControlRevokeEnrollmentToken:
		return accounts.RoleAdmin, "revoking an Enrollment Token", false, true
	case capability.ControlRevokeNode:
		return accounts.RoleAdmin, "revoking a Node", false, true
	case capability.ControlFreezeEngage:
		return accounts.RoleOperator, "engaging the Freeze", true, true
	case capability.ControlFreezeRelease:
		return accounts.RoleAdmin, "releasing the Freeze", false, true
	case capability.ControlCancelJob:
		return accounts.RoleOperator, "cancelling a Job", false, true
	case capability.ControlAccountRead:
		return accounts.RoleAdmin, "reading Accounts", false, true
	case capability.ControlAccountCreate:
		return accounts.RoleAdmin, "creating an Account", false, true
	case capability.ControlAccountRole:
		return accounts.RoleAdmin, "changing an Account's role", false, true
	case capability.ControlAccountEnable:
		return accounts.RoleAdmin, "enabling an Account", false, true
	case capability.ControlAccountDisable:
		return accounts.RoleAdmin, "disabling an Account", false, true
	case capability.ControlAPITokenRead:
		return accounts.RoleAdmin, "reading API Tokens", false, true
	case capability.ControlAPITokenMint:
		return accounts.RoleAdmin, "minting an API Token", false, true
	case capability.ControlAPITokenRevoke:
		return accounts.RoleAdmin, "revoking an API Token", false, true
	case capability.ControlPolicyAlias:
		return accounts.RoleAdmin, "setting, renaming or clearing a Policy alias", true, true
	case capability.ControlTagWrite:
		return accounts.RoleOperator, "writing a tag", true, true
	default:
		return "", "", false, false
	}
}

// AuthorizeControl implements capability.ControlAuthorizer: may p
// perform this administrative act on the control plane itself?
//
// Deny-by-default in both directions, exactly as Authorize is: an action this
// gate does not recognize is refused for every role including admin, so a
// ControlAction added later has its floor decided deliberately in
// requiredControlRole rather than inheriting the weakest one by falling
// through — and an unknown or corrupted role satisfies nothing, because
// accounts.Role.AtLeast fails closed.
//
// Order is role first, then kind. A machine viewer is told the ladder answer
// ("needs operator") rather than the kind answer, which is the more
// actionable of the two and does not disclose that a kind rule exists to a
// caller who would fail the role check anyway.
func (*RoleGate) AuthorizeControl(_ context.Context, p capability.Principal, act capability.ControlAction) error {
	required, label, humanOnly, known := requiredControlRole(act)
	if !known {
		return &unauthorizedError{
			principal:   p,
			action:      fmt.Sprintf("unrecognized control action %q", string(act)),
			unknownKind: true,
		}
	}
	if !accounts.Role(p.Role).AtLeast(required) {
		return &unauthorizedError{principal: p, action: label, required: required}
	}
	if humanOnly && !p.Human() {
		return &notHumanError{principal: p, action: label}
	}
	return nil
}
