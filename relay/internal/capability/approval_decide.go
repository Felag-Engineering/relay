package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)

// approval_decide.go is the answering half of the approval callout (#270,
// ADR-0027): reading the queue of parked dispatches, and recording a human's
// decision against one.
//
// It lives in the capability layer, not in a surface, because the decision is
// the same act however it arrives — the Control API's out-of-band endpoint
// today, the MCP elicitation envelope ([5/6]) and the Console's approval queue
// (v0.7.0) later. Invariant 10 is not just about dispatch: a surface that
// recorded its own decisions would be a second control path, and the role
// floor, the machine-self-decision rule, and the audit record would each have to
// be remembered again in every door.
//
// What this file deliberately does NOT do is dispatch. Satisfying a Requirement
// does not run anything; it makes the same Plan proceed the next time it is
// driven, matched by plan hash (see checkApproval). Keeping release out of the
// decision path is what makes registry drift re-park automatically instead of
// needing a drift detector, and it means an approval can never execute
// something the requester never re-asked for.

// ApprovalDecision is one answer to a parked dispatch, as a surface presents it
// to the capability layer.
//
// Channel is set by the SURFACE, never taken from a request body: the Control
// API's decision endpoint is out-of-band because of what it is. A channel the
// caller could name is a channel the caller could upgrade, which would make
// ADR-0027's whole in-band/out-of-band distinction decoration.
type ApprovalDecision struct {
	// RequestID names the parked Request being answered.
	RequestID string

	// PlanHash is what the decider believes they are approving. It is checked
	// against the Request's own hash, so an answer cannot be replayed onto a
	// different Plan, and a client that read a stale queue entry is told its
	// view moved rather than silently approving today's version.
	PlanHash string

	// Approve is the answer. False is a denial, and one denial is terminal.
	Approve bool

	// Reason is the decider's free-text note, bounded by the surface.
	Reason string

	// Channel is how the decision arrived.
	Channel approval.Channel
}

// ErrApprovalUnavailable is returned by the approval read/decide methods on
// an Approvals assembled without a store (in-package tests only — NewApprovals
// requires one). It is a wiring fault, surfaced as a
// legible error rather than a nil-map panic reaching the caller as a reset
// connection.
var ErrApprovalUnavailable = errors.New("capability: approvals are not configured on this Relay")

// PendingApprovals returns every Request still awaiting a decision, oldest
// deadline first.
//
// Every authenticated caller may read the queue; the audience on a rule
// restricts who may DECIDE, not who may see that a decision is owed. Narrowing
// visibility to the audience would hide the fleet's pending state from the
// operators watching it, and the queue's contents are Relay-authored summaries
// of actions those operators can already read in the audit trail.
//
// Requests whose deadline has passed are filtered out even if the sweeper has
// not retired them yet, so the queue never advertises something undecidable.
func (a *Approvals) PendingApprovals(ctx context.Context) ([]approval.Request, error) {
	if a.store == nil {
		return nil, ErrApprovalUnavailable
	}
	all, err := a.store.Pending(ctx)
	if err != nil {
		return nil, fmt.Errorf("capability: list pending approvals: %w", err)
	}
	now := a.clock()
	out := make([]approval.Request, 0, len(all))
	for _, r := range all {
		if r.Expired(now) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Approval returns one Request by ID, in whatever state it is in — including
// terminal ones, because "what became of that request?" is exactly the question
// a decider asks after being told their answer was too late.
func (a *Approvals) Approval(ctx context.Context, id string) (approval.Request, error) {
	if a.store == nil {
		return approval.Request{}, ErrApprovalUnavailable
	}
	r, err := a.store.Get(ctx, id)
	if err != nil {
		// approval.ErrNotFound travels unwrapped so a surface can map it to a
		// 404 with errors.Is without matching on text.
		if errors.Is(err, approval.ErrNotFound) {
			return approval.Request{}, err
		}
		return approval.Request{}, fmt.Errorf("capability: read approval request: %w", err)
	}
	return r, nil
}

// LastApprovedOfSameShape returns the most recent approved Request sharing r's
// shape key, for the approval object's anti-fatigue diff callout (#415, D10,
// spec console/08): "same as what you approved Tuesday, except the fan-out grew
// 1,180 -> 2,214".
//
// It is a READ, like PendingApprovals — approving nothing and releasing
// nothing. r itself is excluded, so rendering a record never finds itself.
//
// approval.ErrNotFound travels unwrapped when there is no comparable prior, so
// a surface can say so plainly rather than manufacture a diff. A record with an
// empty or legacy shape key has no comparable prior BY CONSTRUCTION and is
// refused before the store is touched: its true shape is unknown, and a diff
// against an unknown shape is exactly the misleading grouping the shape key
// exists to avoid.
func (a *Approvals) LastApprovedOfSameShape(ctx context.Context, r approval.Request) (approval.Request, error) {
	if a.store == nil {
		return approval.Request{}, ErrApprovalUnavailable
	}
	if r.ShapeKey == "" || approval.IsLegacyShapeKey(r.ShapeKey) {
		return approval.Request{}, approval.ErrNotFound
	}
	prior, err := a.store.LastApprovedByShape(ctx, r.ShapeKey, r.ID)
	if err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			return approval.Request{}, err
		}
		return approval.Request{}, fmt.Errorf("capability: read last approved request of same shape: %w", err)
	}
	return prior, nil
}

// DecideApproval records p's answer to a parked Request and returns the
// Request's resulting state.
//
// The order of checks matters and is deliberate:
//
//  1. Read the Request, so the role floor can be computed from what is actually
//     being released rather than from anything the caller claimed.
//  2. Authorize p for that Action kind — an operator may not release a Raw Exec
//     they could not have requested (ApprovalAuthorizer).
//  3. Hand the whole eligibility question to the domain, inside the store's
//     transaction (requester exclusion, machine self-decision, audience,
//     duplicate decider, plan hash, channel strength, quorum arithmetic).
//
// Nothing dispatches here. A satisfied Requirement means the next drive of the
// same Plan proceeds; see this file's header.
//
// On ErrNotPending or ErrDuplicateDecider, the returned Request is the one as
// it now stands, read atomically with the refusal (state, decisions, bound
// JobID) — see requestOnRefusal and the rationale on Approvals.Approval. A
// lapsed Request the sweeper has not retired yet comes back as StatePending
// with ExpiresAt in the past; a caller asks Expired(now) or PastDeadline(now)
// to tell it apart from one still genuinely open. Every other refusal returns
// the zero value.
//
// On ErrNotPending specifically, this Request comes back whether or not p
// would have been eligible to decide it: eligibility (requester exclusion,
// machine self-decision, audience, channel strength) is checked after
// Terminal/Expired inside the domain, so a caller who fails every eligibility
// check still gets the terminal or lapsed Request here — it is a read of what
// the Request now is, not proof p could have decided it. A surface that
// exposes this value must narrow it to what that surface may already read.
func (a *Approvals) DecideApproval(ctx context.Context, p Principal, in ApprovalDecision) (approval.Request, error) {
	if a.store == nil {
		return approval.Request{}, ErrApprovalUnavailable
	}
	if strings.TrimSpace(in.RequestID) == "" {
		return approval.Request{}, fmt.Errorf("capability: decide approval: request id is required")
	}

	current, err := a.Approval(ctx, in.RequestID)
	if err != nil {
		return approval.Request{}, err
	}

	if a.authz != nil {
		// withoutAssertions for the same reason Run uses it: an authorization
		// decision must never be able to read anything the caller asserted
		// about itself (assertions.go).
		if err := a.authz.AuthorizeApprovalDecision(withoutAssertions(ctx), p, current.ActionKind); err != nil {
			return approval.Request{}, err
		}
	}

	d := approval.Decision{
		AccountID: p.AccountID,
		Account:   p.Account,
		Approve:   in.Approve,
		Reason:    in.Reason,
		Channel:   in.Channel,
		PlanHash:  in.PlanHash,
		// The verified Account kind, not a surface-supplied flag: ADR-0027's
		// rung 2 is human-only, and the fact that makes it so is established at
		// the authentication boundary.
		DeciderHuman: p.Human(),
		// The ASSERTED approver, read from the caller's attribution lane
		// rather than from the decision body. Doing it this way means one
		// mechanism carries "who is this really for" across every surface —
		// the API's X-Relay-On-Behalf-Of header and a tool's approver argument
		// land in the same field and audit identically (ADR-0029 decision 2).
		//
		// Read from the UNMASKED ctx on purpose: withoutAssertions above hides
		// this from the Authorizer, because an assertion must never be an
		// authorization input. It is attribution, and attribution is exactly
		// what it is used for here.
		OnBehalfOf: AssertionsFromContext(ctx).OnBehalfOf,
		At:         a.clock(),
	}

	updated, err := a.store.RecordDecision(ctx, in.RequestID, d, d.At)
	if err != nil {
		// Every eligibility error from the domain is returned unwrapped so a
		// surface maps it with errors.Is; only genuine store failures are
		// wrapped as internal.
		if isApprovalDomainError(err) {
			return requestOnRefusal(updated, err), err
		}
		return approval.Request{}, fmt.Errorf("capability: record approval decision: %w", err)
	}

	// The decision is audited whether it approved or denied, and whether or not
	// it completed a quorum: ADR-0027 makes each decision its own first-class
	// record, so "1 of 2 signed and then it expired" is answerable rather than
	// being an absence.
	//
	// The audit write is attempted after the decision is durably recorded, and
	// its failure is joined to the (real, already-persisted) result rather than
	// pretending the decision did not happen — the same posture Run takes.
	entry := AuditEntry{
		Kind:            AuditKindApprovalDecided,
		Principal:       p,
		ApprovalID:      updated.ID,
		PlanHash:        updated.PlanHash,
		Reason:          approvalDecisionReason(updated, d),
		Asserted:        AssertionsFromContext(ctx),
		ApprovalAnswer:  approvalAnswerOf(d.Approve),
		DecisionChannel: d.Channel,
	}
	if auditErr := a.rec.audit.Record(ctx, entry); auditErr != nil {
		return updated, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return updated, nil
}

// isApprovalDomainError reports whether err is one of the domain's eligibility
// refusals, as opposed to a store failure. Listed explicitly rather than
// matched by prefix so a new sentinel has to be classified deliberately.
func isApprovalDomainError(err error) bool {
	for _, sentinel := range []error{
		approval.ErrNotFound,
		approval.ErrNotPending,
		approval.ErrRequesterExcluded,
		approval.ErrNotInAudience,
		approval.ErrDuplicateDecider,
		approval.ErrPlanChanged,
		approval.ErrMachineSelfDecision,
		approval.ErrWeakChannel,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// requestOnRefusal decides which refusals carry the Request back to the
// caller. It is an explicit allow-list, like isApprovalDomainError, so a new
// sentinel has to be classified deliberately rather than inheriting a value by
// accident.
//
// Only ErrNotPending and ErrDuplicateDecider get r: those are exactly the
// refusals where "what became of it" is the caller's next question — S4a's
// answered retry branches on the bound Job, the resolved state, or the
// still-open deadline. Every other refusal keeps the zero value it always
// returned, because nothing downstream needs to distinguish, say, one
// audience mismatch from another.
//
// r on ErrNotPending is not proof that the caller was eligible to decide it:
// the domain checks Terminal/Expired before requester exclusion, machine
// self-decision, audience, and channel strength, so an ineligible caller
// hitting an already-terminal or lapsed Request gets the same r an eligible
// one would. An adapter that exposes r must narrow it to what that surface
// may already read (state, JobID, deadline — never raw Decisions to a caller
// who could not otherwise see them).
func requestOnRefusal(r approval.Request, err error) approval.Request {
	if errors.Is(err, approval.ErrNotPending) || errors.Is(err, approval.ErrDuplicateDecider) {
		return r
	}
	return approval.Request{}
}

// approvalAnswerOf maps a Decision's boolean Approve onto the structured
// ApprovalAnswer vocabulary. There is no third case: DecideApproval
// only ever calls this with a real decider's answer, so
// ApprovalAnswerUnrecorded is reserved for entries that never went through
// here at all (RevokeGrant's revocation).
func approvalAnswerOf(approve bool) ApprovalAnswer {
	if approve {
		return ApprovalAnswerApproved
	}
	return ApprovalAnswerDenied
}

// approvalDecisionReason renders the audit Reason for one decision: the answer,
// the resulting state, the quorum progress, and the decider's own note.
//
// The decider's note is included because it is the only part of the record that
// says WHY; it is caller-supplied text, bounded by the surface, and it goes into
// the same Reason column every other refusal's text does.
//
// Reason is no longer the only copy of the answer (#545: see AuditEntry.
// ApprovalAnswer) — it remains the human sentence a reader wants, and its
// prose format is unchanged by that split.
func approvalDecisionReason(r approval.Request, d approval.Decision) string {
	answer := "denied"
	if d.Approve {
		answer = "approved"
	}
	line := fmt.Sprintf("approval request %s %s by %s over %s (%s, request now %s): %s",
		r.ID, answer, d.Account, d.Channel, r.Progress(), r.State, r.Summary)
	if note := strings.TrimSpace(d.Reason); note != "" {
		line += " — reason: " + note
	}
	return line
}

// clock returns the Approvals' time source, defaulting to wall time for an
// Approvals built as a struct literal (in-package tests) rather than by NewApprovals.
func (a *Approvals) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now().UTC()
}
