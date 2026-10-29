// Package approval is the Relay's domain model for the approval callout
// (ADR-0027, ADR-0047): which dispatches must wait for a human, what a human is
// being asked to approve, and when that answer stops counting. A gate rule only
// gates; one Decision ends a request.
//
// Two things this package deliberately is NOT:
//
//   - It is not authorization. A satisfied Requirement lets one already-legal
//     Plan proceed; it never widens what a Node's Policy allows (ADR-0002) and
//     never substitutes for the Selector -> authz -> blast-cap chain in front
//     of it. Everything here can only *add* a reason to stop.
//   - It is not a delivery mechanism. How an approver is reached — elicitation,
//     a webhook — is the surfaces' problem ([4/6], [5/6]).
//     This package decides whether to park, what the approval is bound to, and
//     whether the Decision received ends the request.
//
// Following the jobs package's precedent, it carries no proto dependency and no
// database/sql dependency, so the store swap stays a single-package change.
package approval

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// Errors returned by the state machine. They are sentinel values so callers
// (and the store) can distinguish "this decision is invalid" from "this Request
// is gone".
var (
	// ErrNotFound is returned when a Request ID does not exist.
	ErrNotFound = errors.New("approval: request not found")

	// ErrNotPending is returned when a decision arrives for a Request that has
	// already reached a terminal state. Approvals are not re-openable: an
	// expired or denied Request must be re-requested, never revived, or a
	// late-arriving approval could resurrect a Plan the fleet has moved past.
	ErrNotPending = errors.New("approval: request is not pending")

	// ErrPlanChanged is returned when a decision cites a plan hash that is not
	// the one the Request is bound to (ADR-0027: approvals bind to a
	// content-addressed Plan, never to a Job in the abstract).
	ErrPlanChanged = errors.New("approval: decision does not match the request's plan hash")

	// ErrMachineSelfDecision is returned when a machine Account tries to decide
	// a Request it made itself, other than by the two in-band forms of
	// inBandSelfConfirmation.
	//
	// Self-confirmation is for HUMAN REQUESTERS ONLY (ADR-0047 decision 1): an
	// AI-agent confirming its own proposal is the same actor answering twice.
	// A human may confirm their own request; a machine may not, and no rule can
	// change that.
	ErrMachineSelfDecision = errors.New("approval: a machine Account may never decide its own request")

	// ErrAlreadyReleased is returned when Release is called on a Request that
	// already has a Job bound. AP-77: an approval releases one execution. The
	// caller re-attaches to r.JobID and never dispatches.
	ErrAlreadyReleased = errors.New("approval: request has already released a Job")

	// ErrNotReleasable is returned when Release is called on a Request that is
	// not Satisfied (pending, denied, expired or past its deadline) or with an
	// empty Job ID. A refusal here means the caller must not dispatch: the
	// release claim failed, so nothing may run.
	ErrNotReleasable = errors.New("approval: request is not satisfied, so it cannot release a Job")
)

// Channel is how a Decision arrived (ADR-0027): in-band means the answer came
// back over the same MCP session that requested the action, out-of-band means
// it landed on an authenticated Relay endpoint. It is recorded for the audit
// trail and never demanded: no gate rule requires a channel (ADR-0047).
type Channel int

const (
	// ChannelUnspecified is the zero value: a Decision whose surface recorded no
	// channel. It is deliberately not a silent alias for in-band.
	ChannelUnspecified Channel = iota
	ChannelInBand
	ChannelOutOfBand
)

func (c Channel) String() string {
	switch c {
	case ChannelInBand:
		return "in-band"
	case ChannelOutOfBand:
		return "out-of-band"
	default:
		return "unspecified"
	}
}

// State is a Request's position in its lifecycle. Every terminal state is
// final: there is no path back to StatePending.
type State int

const (
	StatePending State = iota
	StateApproved
	StateDenied
	StateExpired
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateApproved:
		return "approved"
	case StateDenied:
		return "denied"
	case StateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Terminal reports whether s is a final state.
func (s State) Terminal() bool { return s != StatePending }

// Requirement is what a Gate rule demands before a parked Job may run: a
// lifetime and nothing else (ADR-0047). One Decision ends the request.
type Requirement struct {
	// TTL bounds how long the parked Job waits. Zero means DefaultTTL; a
	// Request always expires, because a parked Job that waits forever is a
	// resource leak and an approval that is redeemable forever is a liability.
	TTL time.Duration
}

// DefaultTTL is the expiry applied when a rule sets none. Deliberately short
// enough that a forgotten parked Job clears itself within a working day.
const DefaultTTL = 4 * time.Hour

// normalized returns r with defaults applied.
func (r Requirement) normalized() Requirement {
	if r.TTL <= 0 {
		r.TTL = DefaultTTL
	}
	return r
}

// Decision is one recorded answer. Each is its own audit-worthy fact: who
// decided, when, over which channel, and against which Plan.
type Decision struct {
	// AccountID and Account identify the decider — the verified lane. Both are
	// stored for the same reason Principal stores both: the name is what a
	// human reads, the ID is what joins after a rename.
	AccountID string
	Account   string

	// Approve is the answer. The first Decision, approving or denying, ends the
	// request.
	Approve bool

	// Reason is the decider's free-text note, bounded by the caller.
	Reason string

	// Channel is how this decision arrived, recorded rather than assumed so an
	// auditor can see which surface the answer came from.
	//
	// It is set by the SURFACE that received the decision, never by the caller:
	// the Control API's decision endpoint is out-of-band because of what it is,
	// not because a request body said so. A channel a client could name is a
	// channel a client could upgrade.
	Channel Channel

	// PlanHash is the Plan this decision was made against. It is checked
	// against the Request's hash on record, so an answer cannot be replayed
	// onto a different Plan.
	PlanHash string

	// DeciderHuman reports whether the deciding Account is a human one. It
	// gates self-decision (see ErrMachineSelfDecision) and is deliberately
	// FALSE-BY-DEFAULT: an unset or unknown Account kind is treated as a
	// machine, so the restrictive answer is the one you get by forgetting to
	// set it.
	DeciderHuman bool

	// OnBehalfOf is the ASSERTED approver identity: who the deciding surface's
	// client says actually answered. It is never verified — a client supplies
	// it — and it exists so an in-band decision can name a human without
	// pretending Relay authenticated one (ADR-0029).
	//
	// Its one behavioural effect is to permit a machine Account to relay a
	// self-decision (see Decide); everywhere else it is attribution the audit
	// trail carries in the asserted lane, never the verified one.
	OnBehalfOf string

	// IdentifiedBy is how the capability layer identified the decider of an
	// in-band answer (AP-88). Only capability.Approvals.AnswerElicited sets it;
	// no surface can. Unrecorded for every out-of-band decision.
	IdentifiedBy IdentifiedBy

	At time.Time
}

// IdentifiedBy says how an elicited answer's decider was identified (AP-88).
type IdentifiedBy int

const (
	// IdentifiedByUnrecorded is the zero value: every out-of-band decision, and
	// every row written before the Relay kept this.
	IdentifiedByUnrecorded IdentifiedBy = iota
	// IdentifiedByOAuthSession is a human Account's verified OAuth session.
	IdentifiedByOAuthSession
	// IdentifiedByAPITokenSession is the session's own Account, on an API Token.
	IdentifiedByAPITokenSession
	// IdentifiedByResponderAssertion is a responder the client asserted, on any
	// other session.
	IdentifiedByResponderAssertion
)

// ErrUnknownIdentifiedBy is returned by ParseIdentifiedBy for a value the
// store should never hold. It is a store-integrity error, not an eligibility
// refusal.
var ErrUnknownIdentifiedBy = errors.New("approval: unknown identified_by value")

// String returns the stored and rendered form: "" for Unrecorded.
func (i IdentifiedBy) String() string {
	switch i {
	case IdentifiedByOAuthSession:
		return "oauth_session"
	case IdentifiedByAPITokenSession:
		return "api_token_session"
	case IdentifiedByResponderAssertion:
		return "responder_assertion"
	default:
		return ""
	}
}

// ParseIdentifiedBy is String's inverse.
func ParseIdentifiedBy(s string) (IdentifiedBy, error) {
	switch s {
	case "":
		return IdentifiedByUnrecorded, nil
	case "oauth_session":
		return IdentifiedByOAuthSession, nil
	case "api_token_session":
		return IdentifiedByAPITokenSession, nil
	case "responder_assertion":
		return IdentifiedByResponderAssertion, nil
	}
	return IdentifiedByUnrecorded, fmt.Errorf("%w: %q", ErrUnknownIdentifiedBy, s)
}

// inBandSelfConfirmation reports whether d is an in-band answer a machine
// Account may give to its own request: a relayed, asserted human (ADR-0029
// decision 3), or the session's own answer on an API Token (AP-87).
//
// Deliberately a method on Decision rather than an inline condition: it is the
// single place the carve-out is defined, so widening it is one visible edit
// rather than a condition drifting apart across call sites.
func (d Decision) inBandSelfConfirmation() bool {
	return d.Channel == ChannelInBand &&
		(d.IdentifiedBy == IdentifiedByAPITokenSession || strings.TrimSpace(d.OnBehalfOf) != "")
}

// Request is one parked Job awaiting its Requirement.
type Request struct {
	ID    string
	JobID string

	// PlanHash content-addresses what was approved: the Operation, its
	// arguments, and the resolved fan-out (see HashPlan). Binding to the hash
	// rather than to the Job is what closes park-something-innocuous-then-
	// mutate-the-world.
	PlanHash string

	// RequestedByID and RequestedBy are the verified requester, needed here (as
	// well as in audit) because self-decision is evaluated against it.
	RequestedByID string
	RequestedBy   string

	// Summary is the Relay-authored description the approver was shown. It is
	// STORED rather than recomputed at read time: the fleet moves, and an audit
	// trail that re-renders "what was approved" from today's registry would
	// quietly rewrite history. What the human saw is a fact about the past.
	Summary string

	// MatchedRules names the Gate rules that parked this dispatch, so the
	// approval queue and the audit record can both answer "why am I being
	// asked?". A gate that cannot explain itself trains operators to disable it.
	MatchedRules []string

	// ActionKind and RiskClass are the structured facts about what was parked,
	// stored alongside the rendered Summary rather than left to be read out of
	// it.
	//
	// ActionKind is security-relevant, not decorative: the role floor for
	// DECIDING a Request is the same floor that Action would have needed to be
	// REQUESTED (authz.RoleGate), so an operator can never release a Raw Exec
	// they could not have asked for themselves. Deriving that from prose would
	// make the ladder depend on string formatting.
	ActionKind jobs.ActionKind
	RiskClass  jobs.RiskClass

	Require   Requirement
	Decisions []Decision

	State     State
	CreatedAt time.Time
	ExpiresAt time.Time

	// ResolvedAt is when the Request reached a terminal state.
	ResolvedAt time.Time
}

// NewRequest builds a pending Request for act over nodeIDs.
//
// It renders the approver-facing Summary itself (via Summarize) rather than
// taking one, so the stored prose and the stored ActionKind/RiskClass can never
// describe different things — the summary is what a human reads and the kind is
// what the role floor is computed from, and those two disagreeing is precisely
// the approval-view fidelity gap.
//
// There is deliberately no Job ID: a gated dispatch parks BEFORE the Job engine
// runs, so no Job exists yet. Creating one at park time would leave Pending
// Tasks in the store for work that may never be approved — rows a restart
// reconciler could mistake for interrupted work. The Job ID is bound once, by
// the release claim, before the Job is dispatched (AP-77) — see Release and
// Repository.BindJob.
func NewRequest(id, planHash, requestedByID, requestedBy string, act jobs.Action, nodeIDs []string, rules []string, req Requirement, now time.Time) Request {
	req = req.normalized()
	return Request{
		ID:            id,
		PlanHash:      planHash,
		RequestedByID: requestedByID,
		RequestedBy:   requestedBy,
		Summary:       Summarize(act, nodeIDs).String(),
		MatchedRules:  rules,
		ActionKind:    act.Kind,
		RiskClass:     act.RiskClass,
		Require:       req,
		State:         StatePending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(req.TTL),
	}
}

// PastDeadline reports the pure clock fact: now is at or after ExpiresAt. It
// says nothing about state.
//
// This is separate from Expired on purpose, and the separation is load-bearing.
// Expired answers "should the sweeper retire this?", which is only meaningful
// for a pending Request. PastDeadline answers "is this still redeemable?",
// which must ALSO be asked of an approved one — an approval that outlives its
// window is exactly the liability ADR-0027's TTL exists to prevent. Folding the
// two together silently made every granted approval permanent.
func (r Request) PastDeadline(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// Expired reports whether r is a pending Request that has lapsed — the
// sweeper's predicate. It is pure: it does not mutate r.
//
// A Request that is past its deadline but still StatePending in the store reads
// as expired to every caller, so a sweeper outage can never leave a stale
// approval decidable.
func (r Request) Expired(now time.Time) bool {
	if r.State.Terminal() {
		return false
	}
	return r.PastDeadline(now)
}

// Satisfied reports whether r is approved and still inside its window at now.
// It is the single predicate the dispatch path asks.
func (r Request) Satisfied(now time.Time) bool {
	if r.State != StateApproved {
		return false
	}
	// PastDeadline, not Expired: an approved Request is terminal, so Expired is
	// false for it by definition. Asking the clock directly is what makes a
	// granted approval stop being redeemable when its window closes.
	return !r.PastDeadline(now)
}

// Released reports whether r has already bound a Job. AP-77: an approval
// releases one execution, so a Released Request must never dispatch again —
// every later dispatch that matches its plan hash re-attaches to r.JobID
// instead.
func (r Request) Released() bool {
	return r.JobID != ""
}

// Release claims r's one execution for jobID, returning the updated Request.
//
// This is the release claim itself (AP-77), not a record of one already
// decided: the store's BindJob calls this inside the transaction that makes
// the claim atomic, and jobID becomes the sole Job this approval ever binds.
//
// The checks run in a deliberate order. jobID == "" is refused first — a
// defensive check, since no real caller passes one — because binding an empty
// ID would read back as unbound and defeat the whole claim. Released is
// checked NEXT, before Satisfied, so a caller that lost a concurrent claim
// always learns the winner's Job ID even if the deadline has passed in the
// meantime.
func (r Request) Release(jobID string, now time.Time) (Request, error) {
	if jobID == "" {
		return r, ErrNotReleasable
	}
	if r.Released() {
		return r, ErrAlreadyReleased
	}
	if !r.Satisfied(now) {
		return r, ErrNotReleasable
	}
	r.JobID = jobID
	return r, nil
}

// Decide records d against r, returning the updated Request. The first
// Decision no refusal stops ends it: an approving Decision approves, a denying
// one denies, and any later Decision is refused as not pending (AP-82).
//
// The checks run in a deliberate order — pending, then the machine
// self-decision guard, then plan binding — so the error a caller sees names the
// first thing actually wrong rather than a downstream symptom.
func (r Request) Decide(d Decision, now time.Time) (Request, error) {
	if r.State.Terminal() {
		return r, ErrNotPending
	}
	if r.Expired(now) {
		// An expired Request is not decidable, and saying so is more useful
		// than silently recording a decision that can never be redeemed.
		return r, fmt.Errorf("%w: expired at %s", ErrNotPending, r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// A human may confirm their own request. A machine may not, except by the
	// two in-band forms of inBandSelfConfirmation (ADR-0029, AP-87); an
	// out-of-band decision is never a self-confirmation (AP-11, AP-48).
	if d.AccountID != "" && d.AccountID == r.RequestedByID && !d.DeciderHuman && !d.inBandSelfConfirmation() {
		return r, ErrMachineSelfDecision
	}
	if d.PlanHash != r.PlanHash {
		return r, ErrPlanChanged
	}

	r.Decisions = append(r.Decisions, d)
	r.ResolvedAt = d.At
	if d.Approve {
		r.State = StateApproved
	} else {
		r.State = StateDenied
	}
	return r, nil
}

// Expire moves a pending Request to StateExpired at now.
func (r Request) Expire(now time.Time) (Request, error) {
	if r.State.Terminal() {
		return r, ErrNotPending
	}
	r.State = StateExpired
	r.ResolvedAt = now
	return r, nil
}
