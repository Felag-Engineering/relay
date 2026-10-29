package capability

import (
	"context"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// toolApprovalReattach names the KindRead tool/OperationName recorded when a
// re-drive re-attaches to a Request's already-released Job instead of
// dispatching (AP-77), alongside readlane.go's tool constants. The join from
// this read to the approval is approval_requests.job_id = jobID.
const toolApprovalReattach = "approval_reattach"

// ApprovalGate decides whether a resolved dispatch must wait for a human
// (ADR-0027). It is a seam, like FreezeStore and CapChecker, so the
// composition root owns the loaded rules and this package owns only the
// question.
//
// The nil Gate (and the zero Gate) gates nothing, which is the behaviour of a
// deployment with no approval rules configured. That default is safe because a
// Gate can only ever ADD a reason to stop — never grant one. The dangerous
// case, an empty Gate produced by a config file the Relay failed to read, is
// prevented at load time (approval.Load fails rather than returning an empty
// Gate), not here.
type ApprovalGate interface {
	Evaluate(d approval.Dispatch) (approval.Requirement, []string, bool)
}

// noopApprovalGate gates nothing. It is not a default: NewApprovals
// requires a gate, so only newApprovals (in-package tests) can install this one.
type noopApprovalGate struct{}

func (noopApprovalGate) Evaluate(approval.Dispatch) (approval.Requirement, []string, bool) {
	return approval.Requirement{}, nil, false
}

// ApprovalStore is the subset of approval.Repository the capability layer
// needs: the dispatch path's create/lookup/claim, plus the queue reads and the
// decision write the surfaces adapt ([3/6]).
//
// Decisions land HERE rather than in the Control API handler for the same
// reason dispatch does (invariant 10): the decision endpoint, the MCP
// elicitation envelope ([5/6]), and the Console's approval queue (v0.7.0) are
// three doors onto one act, and a door that recorded its own decisions would be
// a second control path — the first one to be forgotten when a rule changes.
type ApprovalStore interface {
	Create(ctx context.Context, r approval.Request) error
	ByPlanHash(ctx context.Context, planHash string) (approval.Request, error)
	// BindJob is the release claim (AP-77): it binds jobID to the Request only
	// if the Request is Satisfied at now AND has no Job already bound. On
	// ErrAlreadyReleased the returned Request carries the bound JobID a loser
	// re-attaches to; see approval.Repository.BindJob.
	BindJob(ctx context.Context, id, jobID string, now time.Time) (approval.Request, error)
	Get(ctx context.Context, id string) (approval.Request, error)
	Pending(ctx context.Context) ([]approval.Request, error)
	// RecordDecision returns the domain's usual (Request, error) pair. On a
	// domain refusal, the Request is the one read inside the refusing
	// transaction — see approval.Repository.
	RecordDecision(ctx context.Context, id string, d approval.Decision, now time.Time) (approval.Request, error)
}

// ApprovalAuthorizer answers "may this Principal decide a Request for an Action
// of this kind?".
//
// It is a seam for the same reason Authorizer is: the role ladder lives in
// package authz, which is the single place "who may run what" is answered, and
// capability must not grow a second copy of it. *authz.RoleGate implements both.
//
// The floor it enforces is the one that makes approval non-escalating: deciding
// a Request requires the role that Action would have needed to be REQUESTED. An
// operator who cannot ask for Raw Exec cannot release someone else's, so no
// approval path hands out authority the requester's own ladder withheld.
type ApprovalAuthorizer interface {
	AuthorizeApprovalDecision(ctx context.Context, p Principal, kind jobs.ActionKind) error
}

// ApprovalNotice is what an ApprovalNotifier is told about a freshly parked
// dispatch. Every field is Relay-authored (ADR-0027): the requesting AI-agent
// supplies the Action, never the words describing it.
//
// It carries no credential, no token, and no captured output. Summary DOES
// carry the Operation's arguments, because arguments are what the approver is
// deciding about — see the notifier's own documentation for what that means for
// the endpoint an operator points it at.
type ApprovalNotice struct {
	RequestID   string
	PlanHash    string
	Summary     string
	RequestedBy string
	Rules       []string
	ExpiresAt   time.Time
}

// ApprovalNotifier is told when a dispatch parks, so an operator's own
// notification plumbing can reach the approver (ADR-0027's out-of-band
// envelope). It is best-effort observability of a security event, NOT part of
// the guarantee: the decision endpoint stands alone, and a deployment whose
// webhook is down loses a notification, never safety.
//
// It returns nothing, and Execution.Run ignores its timing entirely, because a
// park must not be able to fail — or stall — on someone else's HTTP server.
type ApprovalNotifier interface {
	NotifyParked(ctx context.Context, n ApprovalNotice)
}

// noopApprovalNotifier is the default: parks are recorded and returned to the
// caller, and nothing is pushed anywhere.
type noopApprovalNotifier struct{}

func (noopApprovalNotifier) NotifyParked(context.Context, ApprovalNotice) {}

// Approvals is the approval callout (ADR-0027): the gate, the parked-Request
// store, the role floor on a decision and
// the notifier. It never dispatches — it cannot reach Run, Start or CancelJob —
// which is what lets the approval seams of every adapter be handed this and not
// the Execution. Build it with NewApprovals.
type Approvals struct {
	rec *Recorder

	// gate decides which dispatches must wait for a human. A gate can only add a
	// reason to stop, so the no-op gate is safe. store is only consulted when
	// gate says a dispatch is gated, so a nil store is unreachable unless a real
	// gate was wired without one, which NewApprovals refuses.
	gate  ApprovalGate
	store ApprovalStore

	// authz is the role floor on a DECISION: deciding a Request
	// requires the role that Action would have needed to be requested. Nil only
	// on an Approvals assembled by newApprovals, where there is nothing to
	// decide.
	authz ApprovalAuthorizer

	// notifier pushes a parked dispatch to the operator's own
	// notification plumbing. Best-effort by construction — see ApprovalNotifier.
	notifier ApprovalNotifier

	// now is the approval clock (clock()); Selector resolution uses
	// ReadLane.now. newApprovalID is a seam so tests get deterministic parks.
	now           func() time.Time
	newApprovalID idGen
}

// NewApprovals wires the approval callout (ADR-0027): gate decides which
// dispatches must wait for a human, store persists the parked Requests, and
// authz is the role floor on answering one.
//
// rec, gate, store and authz are required together. A gate with no store could
// decide a dispatch needs approval and then have nowhere to record it — which
// would either drop the dispatch silently or, worse, let it through. A store
// with no gate is inert. A store with no authorizer would accept a decision from
// any authenticated caller, including a viewer releasing a Raw Exec, which is the
// approval mechanism handing out authority instead of withholding it. Passing an
// incomplete set is a composition-root bug, so it panics rather than degrading.
//
// notifier is the out-of-band notification envelope (ADR-0027): where to push a
// freshly parked dispatch so an approver hears about it. Optional, and
// deliberately so. The notification is a delivery convenience; the guarantee is
// the authenticated decision endpoint, which stands alone. Nil maps to a no-op:
// a deployment with no notifier configured still parks, still audits, and still
// waits — approvers just have to poll the queue.
//
// now is the approval clock, a test seam: approval expiry and park timestamps
// are time-dependent, and a test that sleeps is a test that flakes. Nil is the
// wall clock in UTC.
func NewApprovals(rec *Recorder, gate ApprovalGate, store ApprovalStore, authz ApprovalAuthorizer, notifier ApprovalNotifier, now func() time.Time) *Approvals {
	if rec == nil {
		panic("capability: NewApprovals: recorder must not be nil")
	}
	if gate == nil {
		panic("capability: NewApprovals: gate must not be nil")
	}
	if store == nil {
		panic("capability: NewApprovals: store must not be nil")
	}
	if authz == nil {
		panic("capability: NewApprovals: approval authorizer must not be nil; without it any authenticated caller could release a parked dispatch")
	}
	if notifier == nil {
		notifier = noopApprovalNotifier{}
	}
	return newApprovals(rec, gate, store, authz, notifier, now)
}

// newApprovals assembles an Approvals with no checks. Only NewApprovals and
// _test.go files call it; it is the only route to an Approvals with the no-op
// gate or no store.
func newApprovals(rec *Recorder, gate ApprovalGate, store ApprovalStore, authz ApprovalAuthorizer, notifier ApprovalNotifier, now func() time.Time) *Approvals {
	return &Approvals{
		rec:           rec,
		gate:          gate,
		store:         store,
		authz:         authz,
		notifier:      notifier,
		now:           now,
		newApprovalID: defaultID,
	}
}

// bindRelease is the release claim (AP-77) on the approval's store, stamped by
// the approval clock.
func (a *Approvals) bindRelease(ctx context.Context, requestID, jobID string) (approval.Request, error) {
	return a.store.BindJob(ctx, requestID, jobID, a.clock())
}

// notifyParked tells the notifier about a Request this call created.
func (a *Approvals) notifyParked(ctx context.Context, r approval.Request) {
	a.notifier.NotifyParked(ctx, noticeFor(r))
}

// ParkedError is returned by Execution.Run when a dispatch is gated and now waits
// for a human. It is exported and typed so a surface can recognize a park via
// errors.As and render it as "accepted, pending approval" rather than as a
// failure — mirroring FrozenError and CapExceededError.
//
// A park is NOT a refusal. Nothing was denied and nothing ran; the dispatch is
// suspended awaiting a decision it may well receive. Surfaces that render it as
// an error teach operators that the approval mechanism is something breaking,
// which is how a safety feature gets switched off.
type ParkedError struct {
	// RequestID is the approval Request to decide. A caller needs it to point
	// a human at the right thing.
	RequestID string

	// PlanHash is what any decision must cite.
	PlanHash string

	// Summary is the Relay-authored description of what is waiting.
	Summary string

	// Rules names the gate rules that parked this dispatch, so the answer to
	// "why is this waiting?" travels with the error.
	Rules []string

	// ExpiresAt is when the parked request lapses.
	ExpiresAt time.Time

	// Askable reports whether THIS park can be asked about in-band on THIS call
	// — the fact an MCP surface needs to decide whether to render an actual
	// question or the opaque `pending_approval` result (docs/specs/approval.md
	// AP-62, AP-81).
	//
	// It is true exactly when this call CREATED the park, rather than observing
	// one already pending — the same created/observed distinction that gates
	// NotifyParked and AP-41's audit. No rule term can make a park unaskable: a
	// rule names no channel, audience or requester exclusion (AP-81). It is
	// decided here, in checkApproval, because the capability layer is the one
	// place that knows whether the call created the park (invariant 10): a
	// surface reads this field and never recomputes it.
	//
	// There is deliberately no role-floor term: the caller already passed
	// Authorize for this Action, and the decision floor
	// (ApprovalAuthorizer.AuthorizeApprovalDecision) is the same floor that
	// Action needed to be REQUESTED — see TestRoleFloorCannotRefuseAnAskablePark.
	//
	// A re-drive after a DENIAL parks a brand-new Request (checkApproval's
	// ByPlanHash lookup only ever finds a satisfied or still-pending row, never
	// a terminal one), so that park is askable exactly like any other freshly
	// created one.
	//
	// The zero value (false) is the safe direction: a literal-built
	// ParkedError and an observed re-drive render as the opaque
	// pending_approval.
	Askable bool
}

func (e *ParkedError) Error() string {
	return fmt.Sprintf(
		"capability: dispatch parked for approval (ADR-0027): %s — request %s, gated by %v, expires %s. "+
			"Nothing has been dispatched; the Job runs only once the requirement is satisfied.",
		e.Summary, e.RequestID, e.Rules, e.ExpiresAt.UTC().Format(time.RFC3339))
}

// approvalDecision is the internal result of consulting the gate for one
// resolved dispatch.
type approvalDecision struct {
	// proceed reports whether dispatch may continue now.
	proceed bool
	// requestID is the satisfied Request that released this dispatch, empty
	// when no approval was required — the satisfied Request whose release this
	// dispatch must claim (or re-attach to). For a single-Plan approval,
	// Execution.Run must claim it with approvals.BindJob before dispatching
	// (AP-77), or re-attach to it.
	requestID string
	// reattachJobID is set when the satisfied Request named by requestID has
	// ALREADY bound a Job (AP-77: an approval releases one execution). Set
	// only together with requestID. Execution.Run must re-attach to this Job and
	// dispatch nothing.
	reattachJobID string
	// parked is set when the dispatch was parked instead.
	parked *ParkedError
	// created is set only when THIS call created the Request, so a notification
	// fires once per park rather than once per retry. A caller re-driving a
	// dispatch that is already waiting must not re-page the approver: an
	// approval mechanism that pages on every poll is one operators mute.
	created *approval.Request
}

// checkApproval consults the gate for a resolved dispatch and either lets it
// proceed, releases it against an existing satisfied approval, or parks it.
//
// The lookup is by PLAN HASH, not by Job or by caller. That is what makes drift
// re-park automatically: if the registry changed between approval and retry,
// the resolved fan-out differs, the hash differs, no satisfied Request is found
// for it, and the dispatch parks again — exactly ADR-0027's requirement, with
// no separate drift detector to get wrong. There is no code path that compares
// "close enough" plans, because there is no such thing.
func (a *Approvals) checkApproval(ctx context.Context, p Principal, sel Selector, act jobs.Action, nodes []string) (approvalDecision, error) {
	// A nil gate gates nothing. NewApprovals requires a gate, so this
	// only fires for an Approvals built as a struct literal (in-package tests) —
	// but it is written as a guard rather than an assumption, because the
	// failure mode of getting it wrong is a nil-panic on the dispatch path.
	if a.gate == nil {
		return approvalDecision{proceed: true}, nil
	}

	d := approval.Dispatch{
		RiskClass:  act.RiskClass,
		FanOut:     len(nodes),
		Namespaces: sel.NamespaceNames(),
		Account:    p.Account,
		Operation:  act.OperationName,
		RawExec:    act.Kind == jobs.ActionRawExec,
	}

	req, rules, gated := a.gate.Evaluate(d)
	if !gated {
		return approvalDecision{proceed: true}, nil
	}
	now := time.Now().UTC()
	if a.now != nil {
		now = a.now()
	}

	planHash := approval.HashPlan(act, nodes)

	// An already-satisfied approval for exactly this Plan releases the
	// dispatch. Anything else — pending, denied, expired, or absent — does not.
	//
	// The lookup is by PLAN HASH and nothing else: the plan hash covers the
	// resolved fan-out, so no other key may release a dispatch over a Node set
	// nobody approved.
	existing, lookupErr := a.store.ByPlanHash(ctx, planHash)

	// An approval releases one execution (AP-77): a Request that is Satisfied
	// (approved and inside its deadline) and has already bound a Job
	// never falls into the unbound case below, so a re-drive re-attaches to that
	// Job and dispatches nothing. Once the deadline passes, Satisfied is false,
	// the approved row is not pending, and the dispatch falls through to a fresh
	// park. That keeps a spent approval from becoming a permanent replay of one
	// Job (AP-77).
	if lookupErr == nil && existing.Satisfied(now) && existing.Released() {
		return approvalDecision{requestID: existing.ID, reattachJobID: existing.JobID}, nil
	}

	// A store failure reading THIS plan's existing Request fails the dispatch
	// closed (AP-77): a released Request the Relay cannot currently read must
	// never be treated as absent and run a second time. Only ErrNotFound — "no
	// Request exists for this plan" — falls through to the switch below.
	if lookupErr != nil && lookupErr != approval.ErrNotFound { //nolint:errorlint // a wrapped ErrNotFound would take the fail-closed branch, never the permissive one
		return approvalDecision{}, fmt.Errorf("capability: read approval for plan: %w", lookupErr)
	}

	// lookupErr is nil or approval.ErrNotFound here — anything else already
	// returned above.
	switch {
	case lookupErr == nil && existing.Satisfied(now):
		return approvalDecision{proceed: true, requestID: existing.ID}, nil
	case lookupErr == nil && existing.State == approval.StatePending && !existing.Expired(now):
		// Already waiting. Return the same park rather than creating a second
		// Request for the same Plan: two Requests for one Plan would let a
		// requester farm a second opinion after the first approver said no
		// yet, and would double every notification.
		//
		// An OBSERVED park is never askable (AP-62; the same created/observed
		// distinction that gates NotifyParked and AP-41's audit):
		// parkedErrorFor leaves Askable at its zero value, false, and nothing
		// below sets it for this branch.
		return approvalDecision{parked: parkedErrorFor(existing)}, nil
	}

	// Park: create the Request and report it. No Job and no Task exist yet, by
	// design — see approval.NewRequest.
	mint := a.newApprovalID
	if mint == nil {
		mint = defaultID
	}
	id, err := mint()
	if err != nil {
		return approvalDecision{}, err
	}
	r := approval.NewRequest(id, planHash, p.AccountID, p.Account, act, nodes, rules, req, now)
	if err := a.store.Create(ctx, r); err != nil {
		return approvalDecision{}, fmt.Errorf("capability: park dispatch for approval: %w", err)
	}
	// This call CREATED r (as opposed to the "already waiting" branch above,
	// which observed one), so — and only so — the park is askable.
	pe := parkedErrorFor(r)
	pe.Askable = true
	return approvalDecision{parked: pe, created: &r}, nil
}

// noticeFor projects a parked Request into the value an ApprovalNotifier is
// given. It carries the Relay-authored summary and nothing the requester wrote.
func noticeFor(r approval.Request) ApprovalNotice {
	return ApprovalNotice{
		RequestID:   r.ID,
		PlanHash:    r.PlanHash,
		Summary:     r.Summary,
		RequestedBy: r.RequestedBy,
		Rules:       r.MatchedRules,
		ExpiresAt:   r.ExpiresAt,
	}
}

func parkedErrorFor(r approval.Request) *ParkedError {
	return &ParkedError{
		RequestID: r.ID,
		PlanHash:  r.PlanHash,
		Summary:   r.Summary,
		Rules:     r.MatchedRules,
		ExpiresAt: r.ExpiresAt,
	}
}

// nodeIDs projects resolved Nodes to their IDs for plan hashing. The Plan is
// hashed over IDs rather than whole Node records deliberately: a Node's facts,
// labels, and last-seen time change constantly, and hashing them would re-park
// every Job on every heartbeat. What the approver is agreeing to is WHICH Nodes
// are touched, not what those Nodes happened to report at the moment they were
// asked.
func nodeIDs(nodes []registry.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.NodeID)
	}
	return out
}
