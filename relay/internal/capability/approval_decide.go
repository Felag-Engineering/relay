package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// approval_decide.go is the answering half of the approval callout
// (ADR-0027): reading the queue of parked dispatches, and recording a human's
// decision against one.
//
// It lives in the capability layer, not in a surface, because the decision is
// the same act however it arrives — the Control API's out-of-band endpoint,
// or the MCP elicitation answer (AnswerElicited). Invariant 10 is not just
// about dispatch: a surface that recorded its own decisions would be a second control path, and the role
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
// Every authenticated caller may read the queue; the role floor restricts who
// may DECIDE, not who may see that a decision is owed. Narrowing visibility
// would hide the fleet's pending state from the operators watching it, and the
// queue's contents are Relay-authored summaries of actions those operators can
// already read in the audit trail.
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
//     transaction (pending, machine self-decision, plan hash). The first
//     Decision no refusal stops ends the request (AP-82).
//
// Nothing dispatches here. A satisfied Requirement means the next drive of the
// same Plan proceeds; see this file's header.
//
// On ErrNotPending, the returned Request is the one as
// it now stands, read atomically with the refusal (state, decisions, bound
// JobID) — see requestOnRefusal and the rationale on Approvals.Approval. A
// lapsed Request the sweeper has not retired yet comes back as StatePending
// with ExpiresAt in the past; a caller asks Expired(now) or PastDeadline(now)
// to tell it apart from one still genuinely open. Every other refusal returns
// the zero value.
//
// On ErrNotPending specifically, this Request comes back whether or not p
// would have been eligible to decide it: eligibility (machine self-decision)
// is checked after Terminal/Expired inside the domain, so a caller who fails
// every eligibility check still gets the terminal or lapsed Request here. It is
// a read of what the Request now is, not proof p could have decided it. A surface that
// exposes this value must narrow it to what that surface may already read.
func (a *Approvals) DecideApproval(ctx context.Context, p Principal, in ApprovalDecision) (approval.Request, error) {
	return a.decide(ctx, p, in, approval.IdentifiedByUnrecorded)
}

// decide is DecideApproval's body. identifiedBy is a parameter, not a field of
// ApprovalDecision, so no surface can name it, just as none can name the
// channel (AP-12): only AnswerElicited passes anything but Unrecorded.
func (a *Approvals) decide(ctx context.Context, p Principal, in ApprovalDecision, identifiedBy approval.IdentifiedBy) (approval.Request, error) {
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
		// the API's X-Relay-On-Behalf-Of header and an elicited answer's
		// responder assertion land in the same field and audit identically
		// (ADR-0029 decision 2).
		//
		// Read from the UNMASKED ctx on purpose: withoutAssertions above hides
		// this from the Authorizer, because an assertion must never be an
		// authorization input. It is attribution, and attribution is exactly
		// what it is used for here.
		OnBehalfOf:   AssertionsFromContext(ctx).OnBehalfOf,
		IdentifiedBy: identifiedBy,
		At:           a.clock(),
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
	// it ended the request: ADR-0027 makes each decision its own first-class
	// record.
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

// ResponderRule says what an elicited answer's responder assertion means on a
// session.
type ResponderRule int

const (
	// ResponderRequired is the zero value, so it fails closed: any session not
	// listed below needs a responder assertion (the last sentence of AP-87).
	ResponderRequired ResponderRule = iota
	// ResponderRecorded is an API-token session, of either Account kind: the
	// responder is optional, and recorded as asserted when present (AP-87).
	ResponderRecorded
	// ResponderIgnored is an OAuth session of a human Account: the responder is
	// never read and never recorded (AP-79).
	ResponderIgnored
)

// ElicitedResponderRule is the rule for an elicited answer on p's session. It
// is decided here, once, for the capability layer and the MCP adapter alike.
func ElicitedResponderRule(p Principal) ResponderRule {
	return ruleFor(elicitedIdentification(p))
}

func ruleFor(id approval.IdentifiedBy) ResponderRule {
	switch id {
	case approval.IdentifiedByOAuthSession:
		return ResponderIgnored
	case approval.IdentifiedByAPITokenSession:
		return ResponderRecorded
	default:
		return ResponderRequired
	}
}

// elicitedIdentification is how the Relay identifies the decider of an
// elicited answer on p's session (AP-88). An API-token session of a Kind that
// is not human gets DeciderHuman=false downstream: the restrictive reading.
func elicitedIdentification(p Principal) approval.IdentifiedBy {
	switch {
	case p.AuthMethod == AuthMethodOAuth && p.Human():
		return approval.IdentifiedByOAuthSession
	case p.AuthMethod == AuthMethodAPIToken:
		return approval.IdentifiedByAPITokenSession
	default:
		return approval.IdentifiedByResponderAssertion
	}
}

// AnswerElicited records an answer to a parked dispatch that arrived in-band,
// as an MRTR elicitation answer on the requesting session's retried call.
//
// It is the single in-band entry point: the channel is fixed here, so the
// surface that calls it names neither a decision input nor a channel
// (ADR-0047 decision 4; approval.md AP-12, AP-63). Everything else, the role
// floor, eligibility, audit and the refusal set, is DecideApproval's.
//
// It also decides how the decider was identified (AP-88) and what a responder
// assertion means on the session (ElicitedResponderRule): on a human's OAuth
// session any assertion is cleared (AP-79); on a session that is neither that
// nor an API-token session, an answer without one is a machine
// self-decision (AP-87).
//
// The capability layer sees only whether ctx carries an asserted OnBehalfOf,
// never the wire shape it came from. A caller sets OnBehalfOf only from a
// responder assertion it has validated as a permission-gate answer (AP-87,
// AP-10), and clears it otherwise, so a header or a responder of another gate
// never reaches the asserted lane. The MCP answered retry is the one caller.
func (a *Approvals) AnswerElicited(ctx context.Context, p Principal, requestID, planHash string, approve bool) (approval.Request, error) {
	id := elicitedIdentification(p)
	switch ruleFor(id) {
	case ResponderIgnored:
		asserted := AssertionsFromContext(ctx)
		asserted.OnBehalfOf = ""
		ctx = WithAssertions(ctx, asserted)
	case ResponderRequired:
		// A human principal on neither an OAuth nor an API-token session is
		// refused here too: the fail-closed reading.
		if strings.TrimSpace(AssertionsFromContext(ctx).OnBehalfOf) == "" {
			return approval.Request{}, approval.ErrMachineSelfDecision
		}
	}
	return a.decide(ctx, p, ApprovalDecision{
		RequestID: requestID,
		PlanHash:  planHash,
		Approve:   approve,
		Channel:   approval.ChannelInBand,
	}, id)
}

// isApprovalDomainError reports whether err is one of the domain's eligibility
// refusals, as opposed to a store failure. Listed explicitly rather than
// matched by prefix so a new sentinel has to be classified deliberately.
func isApprovalDomainError(err error) bool {
	for _, sentinel := range []error{
		approval.ErrNotFound,
		approval.ErrNotPending,
		approval.ErrPlanChanged,
		approval.ErrMachineSelfDecision,
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
// Only ErrNotPending gets r: it is exactly the refusal where "what became of
// it" is the caller's next question — S4a's answered retry branches on the
// bound Job, the resolved state, or the still-open deadline. Every other
// refusal keeps the zero value it always returned.
//
// r on ErrNotPending is not proof that the caller was eligible to decide it:
// the domain checks Terminal/Expired before machine self-decision, so an
// ineligible caller hitting an already-terminal or lapsed Request gets the same
// r an eligible one would. An adapter that exposes r must narrow it to what that surface
// may already read (state, JobID, deadline — never raw Decisions to a caller
// who could not otherwise see them).
func requestOnRefusal(r approval.Request, err error) approval.Request {
	if errors.Is(err, approval.ErrNotPending) {
		return r
	}
	return approval.Request{}
}

// approvalAnswerOf maps a Decision's boolean Approve onto the structured
// ApprovalAnswer vocabulary. There is no third case: DecideApproval
// only ever calls this with a real decider's answer, so
// ApprovalAnswerUnrecorded is reserved for entries that never went through
// here at all.
func approvalAnswerOf(approve bool) ApprovalAnswer {
	if approve {
		return ApprovalAnswerApproved
	}
	return ApprovalAnswerDenied
}

// approvalDecisionReason renders the audit Reason for one decision: the answer,
// the resulting state, and the decider's own note.
//
// The decider's note is included because it is the only part of the record that
// says WHY; it is caller-supplied text, bounded by the surface, and it goes into
// the same Reason column every other refusal's text does.
//
// Reason is not the only copy of the answer (see AuditEntry.ApprovalAnswer)
// — it is the human sentence a reader wants.
func approvalDecisionReason(r approval.Request, d approval.Decision) string {
	answer := "denied"
	if d.Approve {
		answer = "approved"
	}
	identified := ""
	if d.IdentifiedBy != approval.IdentifiedByUnrecorded {
		identified = ", decider identified by " + d.IdentifiedBy.String()
	}
	line := fmt.Sprintf("approval request %s %s by %s over %s%s (request now %s): %s",
		r.ID, answer, d.Account, d.Channel, identified, r.State, r.Summary)
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
