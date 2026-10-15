package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// approval_grant.go is the management half of batch/window approvals
// (ADR-0027 decision 12): requesting one, reading the queue, and revoking one.
// The dispatch half — claiming a grant — is in approval.go.
//
// Requesting a grant is deliberately NOT the same act as being granted one.
// This layer creates an approval Request whose subject is a Scope instead of a
// Plan, and the existing decision endpoint answers it. Everything that makes a
// single approval trustworthy therefore applies unchanged: the quorum, the
// audience, the requester exclusion, the machine-cannot-self-decide rule, the
// channel strength, and the role floor. A grant is not a second, cheaper way to
// get approved on count, channel, requester exclusion or decision deadline
// (TTL) — it is the same approval, with a wider subject; its approver audience
// is the union of what the dispatches it could cover would have faced, which
// can be wider (owner-accepted residual risk, ADR-0027 amendment 2026-09-16).

// GrantRequest is what a surface asks for when it wants a batch/window
// approval. The Relay derives everything else: the requirement, the summary,
// and the hash the approver's decision binds to.
type GrantRequest struct {
	Scope     approval.Scope
	StartsAt  time.Time
	ExpiresAt time.Time
	MaxUses   int
}

// ErrGrantCoversNothingGated is returned when nothing the proposed Scope could
// cover would have parked in the first place.
//
// Refusing is deliberate, and is not merely tidiness. A grant covering only
// ungated work grants nothing, so creating one would put a live authorization
// in the table that no dispatch needs — an object with real reach and no
// purpose, which is exactly the sort of thing that later gets widened by
// somebody who assumes it must have been there for a reason.
var ErrGrantCoversNothingGated = errors.New("capability: nothing in this scope requires approval, so a grant would authorize nothing")

// RequestGrant creates the approval Request for a batch/window Grant and the
// (not yet claimable) Grant it authorizes.
//
// The Grant row is written immediately because the Request has to point at
// something, but it cannot be claimed until that Request reaches approved —
// enforced in the store's claim query, not here (see store/grants.go). So the
// window this opens is closed until a human opens it.
func (a *Approvals) RequestGrant(ctx context.Context, p Principal, in GrantRequest) (approval.Grant, approval.Request, error) {
	if a.store == nil || a.grants == nil {
		return approval.Grant{}, approval.Request{}, ErrApprovalUnavailable
	}
	if err := in.Scope.Validate(); err != nil {
		return approval.Grant{}, approval.Request{}, err
	}

	// The requirement is DERIVED from the gate at the Scope's worst case, never
	// supplied by the caller: a grant's count, channel, requester exclusion and
	// decision deadline (TTL) must be at least as strict as the strictest
	// dispatch it could release, or it would be a way of buying approval more
	// cheaply than the work it replaces. Its approver audience is the union of
	// those dispatches' audiences instead, which can be wider (ADR-0027
	// amendment 2026-09-16).
	req, rules, gated := approval.RequirementForScope(in.Scope, a.gate.Evaluate)
	if !gated {
		return approval.Grant{}, approval.Request{}, ErrGrantCoversNothingGated
	}

	// The role floor for the grant's own approval is the floor for the most
	// powerful thing it can release (Scope.ActionKind). Checked here on the
	// REQUESTER so an operator cannot even ask for a Raw Exec window; the
	// approver is checked again on the way in through DecideApproval.
	if a.authz != nil {
		if err := a.authz.AuthorizeApprovalDecision(withoutAssertions(ctx), p, in.Scope.ActionKind()); err != nil {
			return approval.Grant{}, approval.Request{}, err
		}
	}

	// A blank audience entry never becomes an approver: refused here, before
	// any ID is minted or anything written, so a non-validating ApprovalGate
	// cannot leave an Approval grant whose authorizing Request reads back
	// unrestricted.
	//
	// req.Audience is the MERGED audience RequirementForScope derives across
	// every namespace probe (mergeStricter/unionAudience), and that merge
	// itself never lets an unrestricted probe absorb a malformed one — a blank
	// entry survives the merge (see unionAudience) — so this check still fires
	// even when only one probe's Requirement was malformed. A real
	// *approval.Gate cannot produce a malformed Requirement in the
	// first place (Rule.Validate), so this guards any other ApprovalGate
	// implementation.
	if err := approval.ValidateAudience(req.Audience); err != nil {
		return approval.Grant{}, approval.Request{}, fmt.Errorf(
			"capability: grant approval requirement from rules %s: require.audience: %w", strings.Join(rules, ", "), err)
	}

	now := a.clock()
	startsAt := in.StartsAt
	if startsAt.IsZero() {
		startsAt = now
	}

	mint := a.newApprovalID
	if mint == nil {
		mint = defaultID
	}
	requestID, err := mint()
	if err != nil {
		return approval.Grant{}, approval.Request{}, err
	}
	grantID, err := mint()
	if err != nil {
		return approval.Grant{}, approval.Request{}, err
	}

	summary := approval.SummarizeScope(in.Scope, startsAt, in.ExpiresAt, in.MaxUses)
	grant := approval.Grant{
		ID:        grantID,
		RequestID: requestID,
		Scope:     in.Scope,
		StartsAt:  startsAt,
		ExpiresAt: in.ExpiresAt,
		MaxUses:   in.MaxUses,
		Summary:   summary,
		CreatedAt: now,
	}
	// Validate before writing anything at all, so a refused grant leaves no
	// orphaned approval Request behind for a human to wonder about.
	if err := grant.Validate(); err != nil {
		return approval.Grant{}, approval.Request{}, err
	}

	// The Request is built FROM the Grant, so its hash, its summary, and its
	// deadline all describe that grant and cannot drift from it. Binding to a
	// hash over the Scope means an approver's answer cannot be replayed onto a
	// grant whose walls have since moved — the same property plan-hash binding
	// gives a single dispatch.
	request := approval.NewGrantRequest(grant, p.AccountID, p.Account, rules, req, now)

	if err := a.store.Create(ctx, request); err != nil {
		return approval.Grant{}, approval.Request{}, fmt.Errorf("capability: create grant approval request: %w", err)
	}
	if err := a.grants.CreateGrant(ctx, grant); err != nil {
		return approval.Grant{}, approval.Request{}, fmt.Errorf("capability: create approval grant: %w", err)
	}

	entry := AuditEntry{
		// Its own kind, not AuditKindApprovalRequested. GrantID distinguishes
		// the two structurally, but only for a surface that remembers to check
		// it; a kind that is wrong is caught by audit's partition machinery
		// instead of rendering a wrong sentence.
		Kind: AuditKindApprovalGrantRequested, Principal: p,
		ApprovalID: requestID, PlanHash: request.PlanHash, GrantID: grantID,
		Reason:   "batch/window grant requested: " + summary,
		Asserted: AssertionsFromContext(ctx),
	}
	if auditErr := a.rec.audit.Record(ctx, entry); auditErr != nil {
		return grant, request, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	if a.notifier != nil {
		a.notifier.NotifyParked(ctx, ApprovalNotice{
			RequestID: requestID, PlanHash: request.PlanHash, Summary: summary,
			RequestedBy: p.Account, Rules: rules, Progress: request.Progress(),
			Count: req.Count, Channel: req.Channel.String(), ExpiresAt: request.ExpiresAt,
		})
	}
	return grant, request, nil
}

// ActiveGrants returns every Grant that could still cover something now.
func (a *Approvals) ActiveGrants(ctx context.Context) ([]approval.Grant, error) {
	if a.grants == nil {
		return nil, ErrApprovalUnavailable
	}
	out, err := a.grants.ActiveGrants(ctx, a.clock())
	if err != nil {
		return nil, fmt.Errorf("capability: list approval grants: %w", err)
	}
	return out, nil
}

// Grant returns one Grant by ID, in whatever state it is in — including
// revoked and expired ones, because "what did that window actually cover, and
// who closed it" is the question asked after the fact.
func (a *Approvals) Grant(ctx context.Context, id string) (approval.Grant, error) {
	if a.grants == nil {
		return approval.Grant{}, ErrApprovalUnavailable
	}
	g, err := a.grants.GetGrant(ctx, id)
	if err != nil {
		if errors.Is(err, approval.ErrGrantNotFound) {
			return approval.Grant{}, err
		}
		return approval.Grant{}, fmt.Errorf("capability: read approval grant: %w", err)
	}
	return g, nil
}

// GrantForApproval resolves "is this Request a Grant request, and what Scope
// did it authorize?" — in every Grant state, including revoked, expired,
// exhausted and not-yet-started.
//
// It is the read a surface needs to render a Grant's approval, and the read the
// approval object's diff callout needs to compare one Grant's Scope against the
// one it supersedes: the prior Grant is usually spent or lapsed, which is
// exactly the set ActiveGrants cannot return.
//
// approval.ErrGrantNotFound travels UNWRAPPED, so a surface can render "this is
// not a Grant request" by matching the sentinel rather than the text.
func (a *Approvals) GrantForApproval(ctx context.Context, requestID string) (approval.Grant, error) {
	if a.grants == nil {
		return approval.Grant{}, ErrApprovalUnavailable
	}
	g, err := a.grants.GrantByRequest(ctx, requestID)
	if err != nil {
		if errors.Is(err, approval.ErrGrantNotFound) {
			return approval.Grant{}, err
		}
		return approval.Grant{}, fmt.Errorf("capability: read grant for approval request: %w", err)
	}
	return g, nil
}

// RevokeGrant ends a Grant early, attributed to p.
//
// Revocation needs the same role floor as approving the Grant would have,
// which sounds asymmetric — closing a window is safer than opening one — but
// is not: a Grant is how a batch of work is proceeding, and cancelling it
// mid-flight is an operational act with real consequences for whoever is
// relying on it. It is not, however, gated on being the original approver:
// during an incident the person at the keyboard is whoever is there.
func (a *Approvals) RevokeGrant(ctx context.Context, p Principal, id, reason string) (approval.Grant, error) {
	if a.grants == nil {
		return approval.Grant{}, ErrApprovalUnavailable
	}

	current, err := a.Grant(ctx, id)
	if err != nil {
		return approval.Grant{}, err
	}
	if a.authz != nil {
		if err := a.authz.AuthorizeApprovalDecision(withoutAssertions(ctx), p, current.Scope.ActionKind()); err != nil {
			return approval.Grant{}, err
		}
	}

	revoked, err := a.grants.RevokeGrant(ctx, id, p.Account, reason, a.clock())
	if err != nil {
		if errors.Is(err, approval.ErrGrantNotFound) || errors.Is(err, approval.ErrGrantNotActive) {
			return approval.Grant{}, err
		}
		return approval.Grant{}, fmt.Errorf("capability: revoke approval grant: %w", err)
	}

	entry := AuditEntry{
		Kind: AuditKindApprovalDecided, Principal: p,
		ApprovalID: revoked.RequestID, GrantID: revoked.ID,
		Reason: fmt.Sprintf("batch/window grant %s revoked by %s after %s: %s — %s",
			revoked.ID, p.Account, revoked.Progress(), revoked.Summary, reason),
		Asserted: AssertionsFromContext(ctx),
		// ApprovalAnswer and DecisionChannel are deliberately left zero:
		// a revocation is not a Decision — nobody answered a parked
		// Job — and GrantID above is already this entry's structural
		// discriminator from a real answer.
	}
	if auditErr := a.rec.audit.Record(ctx, entry); auditErr != nil {
		return revoked, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return revoked, nil
}
