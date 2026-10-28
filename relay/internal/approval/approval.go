// Package approval is the Relay's domain model for the approval callout
// (ADR-0027): which dispatches must wait for a human, what a human is being
// asked to approve, and when that answer stops counting.
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
//     whether the answers received are enough.
//
// Following the jobs package's precedent, it carries no proto dependency and no
// database/sql dependency, so the store swap stays a single-package change.
package approval

import (
	"errors"
	"fmt"
	"sort"
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

	// ErrRequesterExcluded is returned when the requester tries to decide their
	// own Request under a rule with RequesterAllowed=false — the separation-of-
	// duties knob (ADR-0027 rung 3).
	ErrRequesterExcluded = errors.New("approval: requester may not decide their own request")

	// ErrNotInAudience is returned when a decider is outside the rule's
	// audience.
	ErrNotInAudience = errors.New("approval: decider is not in the required audience")

	// ErrAudienceBlankEntry is returned where an audience containing an empty
	// or whitespace-only entry would be accepted. A blank entry names no
	// Account; it is refused rather than dropped, because dropping the last
	// named entry turns a restricted audience into an unrestricted one.
	ErrAudienceBlankEntry = errors.New("approval: audience contains an empty or whitespace-only entry")

	// ErrDuplicateDecider is returned when one Account tries to satisfy two
	// slots of a count:2 requirement. Quorum means *distinct* people; without
	// this, count:2 is decoration.
	ErrDuplicateDecider = errors.New("approval: this account has already decided this request")

	// ErrPlanChanged is returned when a decision cites a plan hash that is not
	// the one the Request is bound to (ADR-0027: approvals bind to a
	// content-addressed Plan, never to a Job in the abstract).
	ErrPlanChanged = errors.New("approval: decision does not match the request's plan hash")

	// ErrMachineSelfDecision is returned when a machine Account tries to decide
	// a Request it made itself.
	//
	// This is ADR-0027's confirmation ladder made structural: rung 2
	// (self-confirmation) is HUMAN REQUESTERS ONLY, because an AI-agent confirming
	// its own proposal is not a confirmation — it is the same actor answering
	// twice. So a machine requester's minimum rung is 3, and it is enforced
	// here rather than left to `requester_allowed`: that knob is operator
	// configuration, and a misconfigured `requester_allowed: true` must not be
	// able to hand an AI-agent its own approval.
	ErrMachineSelfDecision = errors.New("approval: a machine Account may never decide its own request")

	// ErrWeakChannel is returned when a decision arrives over a channel weaker
	// than the Requirement demands — an in-band answer against an out-of-band
	// rule (ADR-0027 decision 4).
	//
	// In-band is an assumption about the client; out-of-band is evidence. A
	// rule that asked for evidence must not be satisfiable by an assumption, or
	// the channel setting is decoration. The check is applied to DENIALS too,
	// not just approvals: a denial is terminal, so accepting a weak-channel
	// deny would let a compromised harness terminate work it could not
	// authorize.
	ErrWeakChannel = errors.New("approval: decision channel is weaker than the requirement demands")

	// ErrAlreadyReleased is returned when Release is called on a Request that
	// already has a Job bound. AP-77: an approval releases one execution. The
	// caller re-attaches to r.JobID and never dispatches.
	ErrAlreadyReleased = errors.New("approval: request has already released a Job")

	// ErrNotReleasable is returned when Release is called on a Request that is
	// not Satisfied — pending, denied, expired, past its deadline, or short of
	// quorum — or with an empty Job ID. A refusal here means the caller must
	// not dispatch: the release claim failed, so nothing may run.
	ErrNotReleasable = errors.New("approval: request is not satisfied, so it cannot release a Job")
)

// Channel is how strongly a decision's delivery path is trusted (ADR-0027).
//
// The distinction is not cosmetic: in-band means the answer came back over the
// same MCP session that requested the action, so it is only as trustworthy as
// the harness. Out-of-band means the answer landed on an authenticated Relay
// endpoint carrying a credential the requesting session does not hold. In-band
// is an assumption about the client; out-of-band is evidence.
type Channel int

const (
	// ChannelUnspecified is the zero value and is never a valid configured
	// channel — a rule must say which it means. It is deliberately the least
	// useful value rather than a silent alias for in-band.
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

// stricter reports whether c is a stronger requirement than other. Used by
// Requirement merging, where the strictest matching rule wins.
func (c Channel) stricter(other Channel) bool { return c > other }

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

// Requirement is what a Gate rule demands before a parked Job may run: the
// "requirement" half of ADR-0027's grammar.
//
// The stored shape is deliberately requirement-vs-set-of-decisions rather than
// a boolean "approved" flag, from day one, even though v1 configuration only
// exposes Count 1 or 2. N-of-M, richer audiences, and per-rule channel policy
// then arrive as a config-language change with no data migration — the same
// discipline the Job engine used for Stages.
type Requirement struct {
	// Count is how many distinct approvals are needed. v1 config accepts 1 or 2.
	Count int

	// Audience is the set of Account names that may decide. Empty means "any
	// Account the surface would let decide" — the surface enforces the role
	// floor, since role gating belongs to the capability layer, not here. An
	// audience containing a blank entry is malformed and admits no decider; it
	// is never read as empty.
	Audience []string

	// RequesterAllowed permits the requesting Account to satisfy a slot. False
	// is the two-person tier: approved_by must differ from requested_by.
	RequesterAllowed bool

	// Channel is the decision-channel strength required.
	Channel Channel

	// TTL bounds how long the parked Job waits. Zero means DefaultTTL; a
	// Request always expires, because a parked Job that waits forever is a
	// resource leak and an approval that is redeemable forever is a liability.
	TTL time.Duration
}

// DefaultTTL is the expiry applied when a rule sets none. Deliberately short
// enough that a forgotten parked Job clears itself within a working day.
const DefaultTTL = 4 * time.Hour

// MaxCount bounds the configured quorum in v1. The stored schema handles any N;
// this is the config surface's limit, so an operator cannot accidentally
// require more approvers than the deployment has.
const MaxCount = 2

// ValidateAudience reports whether audience contains a blank entry: empty or
// whitespace-only. A nil or empty slice is the documented "unrestricted" and
// returns nil.
//
// It NEVER trims, filters or rewrites audience — it only reports. Dropping a
// blank entry rather than refusing it is exactly the widening this guards
// against: [""] would become [] (unrestricted) and ["ana", ""] would become
// ["ana"], silently changing what the rule meant.
func ValidateAudience(audience []string) error {
	for i, a := range audience {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("%w (entry %d of %d)", ErrAudienceBlankEntry, i+1, len(audience))
		}
	}
	return nil
}

// AudienceMalformed reports whether q's Audience contains a blank entry. A
// malformed audience admits no decider (fail closed): see Request.inAudience
// and Request.Decide.
func (q Requirement) AudienceMalformed() bool {
	return ValidateAudience(q.Audience) != nil
}

// normalized returns r with defaults applied.
func (r Requirement) normalized() Requirement {
	if r.Count < 1 {
		r.Count = 1
	}
	if r.TTL <= 0 {
		r.TTL = DefaultTTL
	}
	if r.Channel == ChannelUnspecified {
		// A rule that does not state its channel gets the stronger one. This
		// is the fail-closed direction: an unstated channel must never silently
		// mean "whatever the harness says is fine".
		r.Channel = ChannelOutOfBand
	}
	return r
}

// mergeStricter combines two matching Requirements into the more restrictive
// one, field by field. This is the approval analog of Policy's
// deny-beats-allow: when several Gate rules match one dispatch, the operator
// gets the strongest protection any of them asked for, never the weakest.
//
// Merging this way is what makes rule authoring safe. An operator adding "and
// anything touching prod needs two people" cannot accidentally *weaken* an
// existing broad rule by also matching it.
func mergeStricter(a, b Requirement) Requirement {
	out := a
	if b.Count > out.Count {
		out.Count = b.Count
	}
	if b.Channel.stricter(out.Channel) {
		out.Channel = b.Channel
	}
	// false is stricter than true.
	if !b.RequesterAllowed {
		out.RequesterAllowed = false
	}
	// The shorter TTL wins: a narrower window is the more restrictive one.
	if b.TTL > 0 && (out.TTL <= 0 || b.TTL < out.TTL) {
		out.TTL = b.TTL
	}
	// Audience intersection would be the strict reading, but an empty
	// intersection would make the Request undecidable by anyone — a
	// configuration mistake that presents as a mysterious permanent park. The
	// union is used instead, and the narrowing that matters (Count,
	// RequesterAllowed, Channel) is applied above. This is an owner-accepted
	// residual risk (ADR-0027 amendment 2026-09-16): overlapping rules can
	// widen who may decide; Count, Channel, RequesterAllowed and TTL still
	// merge strictest-wins.
	out.Audience = unionAudience(out.Audience, b.Audience)
	return out
}

// unionAudience merges two audiences, deduplicated and ordered. A genuinely
// empty audience means "unrestricted" (ADR-0027), so it absorbs a WELL-FORMED
// restricted side — that absorption is the accepted amendment-2026-09-16 risk
// and is unchanged here.
//
// It must never absorb a MALFORMED side the same way. A blank entry means
// "this rule's own audience is broken", not "this rule has no audience", so an
// unrestricted probe merging with a malformed one must not launder it into
// unrestricted: the malformed side's blank entry is carried into the result
// instead, so the merged Requirement is still AudienceMalformed() and every
// caller that checks it (Request.Decide, capability.checkApproval) still
// fires. Only when NEITHER side is malformed does the "empty absorbs" shortcut
// apply.
func unionAudience(a, b []string) []string {
	if ValidateAudience(a) == nil && ValidateAudience(b) == nil {
		if len(a) == 0 || len(b) == 0 {
			return nil
		}
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Decision is one recorded answer. Each is its own audit-worthy fact: who
// decided, when, over which channel, and against which Plan.
type Decision struct {
	// AccountID and Account identify the decider — the verified lane. Both are
	// stored for the same reason Principal stores both: the name is what a
	// human reads, the ID is what joins after a rename.
	AccountID string
	Account   string

	// Approve is the answer. False is a denial, and one denial is terminal.
	Approve bool

	// Reason is the decider's free-text note, bounded by the caller.
	Reason string

	// Channel is how this decision arrived, recorded rather than assumed so an
	// auditor can see whether the answer was evidence or an assumption.
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

	At time.Time
}

// relaysAnAssertedHuman reports whether d is a machine Account relaying an
// answer a human gave it, rather than one it made itself (ADR-0029 decision 3).
//
// Deliberately a method on Decision rather than an inline condition: it is the
// single place the carve-out is defined, so widening it is one visible edit
// rather than a condition drifting apart across call sites.
func (d Decision) relaysAnAssertedHuman() bool {
	return d.Channel == ChannelInBand && strings.TrimSpace(d.OnBehalfOf) != ""
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
	// well as in audit) because RequesterAllowed is evaluated against it.
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

// Approvals returns the recorded approving decisions.
func (r Request) Approvals() []Decision {
	out := make([]Decision, 0, len(r.Decisions))
	for _, d := range r.Decisions {
		if d.Approve {
			out = append(out, d)
		}
	}
	return out
}

// Satisfied reports whether r has enough approvals to dispatch at now. It is
// the single predicate the dispatch path asks, and it is deliberately strict on
// every axis: state, clock, and count.
func (r Request) Satisfied(now time.Time) bool {
	if r.State != StateApproved {
		return false
	}
	// PastDeadline, not Expired: an approved Request is terminal, so Expired is
	// false for it by definition. Asking the clock directly is what makes a
	// granted approval stop being redeemable when its window closes.
	if r.PastDeadline(now) {
		return false
	}
	return len(r.Approvals()) >= r.Require.Count
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

// Decide records d against r, returning the updated Request.
//
// The checks run in a deliberate order — identity eligibility before plan
// binding before count — so the error a caller sees names the first thing
// actually wrong rather than a downstream symptom.
func (r Request) Decide(d Decision, now time.Time) (Request, error) {
	if r.State.Terminal() {
		return r, ErrNotPending
	}
	if r.Expired(now) {
		// An expired Request is not decidable, and saying so is more useful
		// than silently recording a decision that can never be redeemed.
		return r, fmt.Errorf("%w: expired at %s", ErrNotPending, r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if d.AccountID != "" && d.AccountID == r.RequestedByID {
		if !r.Require.RequesterAllowed {
			return r, ErrRequesterExcluded
		}
		// The rule permits self-confirmation (ladder rung 2), but only a HUMAN
		// may take it. A machine confirming its own proposal is the same actor
		// answering twice, so its minimum rung is 3 regardless of configuration
		// — see ErrMachineSelfDecision.
		//
		// ADR-0029 carves out exactly one exception: a machine may RELAY an
		// answer it did not author. That is credible only when both facts hold
		// together — the decision arrived in-band (so a client with a human in
		// front of it was the surface), and it names an asserted approver (so
		// the trail records who that human was said to be). Either alone is
		// not enough: an in-band decision with no named approver is a machine
		// answering anonymously, and an asserted approver on an out-of-band
		// decision is a verified credential that needs no relay.
		if !d.DeciderHuman && !d.relaysAnAssertedHuman() {
			return r, ErrMachineSelfDecision
		}
	}
	if r.Require.AudienceMalformed() {
		return r, fmt.Errorf("%w: the audience of this request contains an empty or whitespace-only entry, so no Account may decide it", ErrNotInAudience)
	}
	if !r.inAudience(d.Account) {
		return r, ErrNotInAudience
	}
	// An answer must arrive over a channel at least as strong as the rule
	// demanded. ChannelUnspecified is weaker than both real channels, so a
	// decision whose channel was never set is refused rather than defaulted.
	if d.Channel < r.Require.Channel {
		return r, fmt.Errorf("%w: got %s, requires %s", ErrWeakChannel, d.Channel, r.Require.Channel)
	}
	for _, prev := range r.Decisions {
		if prev.AccountID != "" && prev.AccountID == d.AccountID {
			return r, ErrDuplicateDecider
		}
	}
	if d.PlanHash != r.PlanHash {
		return r, ErrPlanChanged
	}

	r.Decisions = append(r.Decisions, d)

	// One denial is terminal. Deny-beats-approve mirrors Policy's
	// deny-beats-allow: the cautious answer wins, and a second approver cannot
	// override a colleague's refusal.
	if !d.Approve {
		r.State = StateDenied
		r.ResolvedAt = d.At
		return r, nil
	}
	if len(r.Approvals()) >= r.Require.Count {
		r.State = StateApproved
		r.ResolvedAt = d.At
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

// inAudience reports whether account may decide. An empty Audience is
// unrestricted (the surface still applies its role floor). A MALFORMED
// audience — one containing a blank entry — admits nobody: it is never read as
// empty, so a stored row that somehow carries one fails closed instead of
// widening to unrestricted.
func (r Request) inAudience(account string) bool {
	// Unreachable today: Decide already returns before calling inAudience when
	// AudienceMalformed() is true, so both checks never fire on the same call.
	// Kept anyway as a backstop against any future caller of inAudience that
	// does not go through Decide's ordering — this method's own doc comment
	// promises the malformed answer regardless of caller.
	if r.Require.AudienceMalformed() {
		return false
	}
	if len(r.Require.Audience) == 0 {
		return true
	}
	for _, a := range r.Require.Audience {
		if strings.EqualFold(a, account) {
			return true
		}
	}
	return false
}

// Progress renders partial quorum for a human ("1 of 2"). The approval queue
// shows this, and the second approver seeing that a colleague already signed is
// itself a fatigue mitigation (ADR-0027).
func (r Request) Progress() string {
	return fmt.Sprintf("%d of %d", len(r.Approvals()), r.Require.Count)
}
