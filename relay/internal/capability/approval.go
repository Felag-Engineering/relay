package capability

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
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

// noopApprovalGate gates nothing. It is no longer a default: NewApprovals
// requires a gate, so only newApprovals (in-package tests) can install this one.
type noopApprovalGate struct{}

func (noopApprovalGate) Evaluate(approval.Dispatch) (approval.Requirement, []string, bool) {
	return approval.Requirement{}, nil, false
}

// ApprovalStore is the subset of approval.Repository the capability layer
// needs: the dispatch path's create/lookup/claim, plus the queue reads and the
// decision write the surfaces adapt ([3/6], #270).
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
	// LastApprovedByShape is the approval object's anti-fatigue read (#415,
	// D10): the newest approved record of the same SHAPE. It releases nothing
	// — see approval.Repository for why that separation is structural.
	LastApprovedByShape(ctx context.Context, shapeKey, excludeID string) (approval.Request, error)
	// RecordDecision returns the domain's usual (Request, error) pair. On a
	// domain refusal, the Request is the one read inside the refusing
	// transaction — see approval.Repository.
	RecordDecision(ctx context.Context, id string, d approval.Decision, now time.Time) (approval.Request, error)
}

// ApprovalGrantStore is the batch/window Grant persistence the capability layer
// needs (ADR-0027 decision 12): consuming a Grant on the dispatch path, and
// creating, reading, and revoking one on the management path
// (approval_grant.go).
//
// It mirrors approval.GrantRepository exactly rather than narrowing to the
// claim, because both halves live behind this one Approvals — the surfaces adapt
// the capability layer, they do not reach past it to a store (invariant 10).
//
// Nil means grants are not wired, which behaves exactly as "no grant covers
// anything" on dispatch — the safe direction, and the behaviour of every
// deployment that never creates one — and ErrApprovalUnavailable on the
// management path, so a surface that offers grants against a Relay that has not
// enabled them fails loudly rather than silently doing nothing.
type ApprovalGrantStore interface {
	CreateGrant(ctx context.Context, g approval.Grant) error
	GetGrant(ctx context.Context, id string) (approval.Grant, error)
	GrantByRequest(ctx context.Context, requestID string) (approval.Grant, error)
	ActiveGrants(ctx context.Context, now time.Time) ([]approval.Grant, error)
	ClaimGrant(ctx context.Context, d approval.Dispatch, now time.Time) (approval.Grant, bool, error)
	RevokeGrant(ctx context.Context, id, revokedBy, reason string, now time.Time) (approval.Grant, error)
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
	Progress    string
	Count       int
	Channel     string
	ExpiresAt   time.Time
}

// ApprovalNotifier is told when a dispatch parks, so an operator's own
// notification plumbing can reach the approver (ADR-0027's out-of-band
// envelope). It is best-effort observability of a security event, NOT part of
// the guarantee: the decision endpoint stands alone, and a deployment whose
// webhook is down loses a notification, never safety.
//
// It returns nothing, and Service.Run ignores its timing entirely, because a
// park must not be able to fail — or stall — on someone else's HTTP server.
type ApprovalNotifier interface {
	NotifyParked(ctx context.Context, n ApprovalNotice)
}

// noopApprovalNotifier is the default: parks are recorded and returned to the
// caller, and nothing is pushed anywhere.
type noopApprovalNotifier struct{}

func (noopApprovalNotifier) NotifyParked(context.Context, ApprovalNotice) {}

// Approvals is the approval callout (ADR-0027): the gate, the parked-Request
// store, the Grant store, the MCP task handles, the role floor on a decision and
// the notifier. It never dispatches — it cannot reach Run, Start or CancelJob —
// which is what lets the approval seams of every adapter be handed this and not
// the Service. Build it with NewApprovals.
type Approvals struct {
	rec *Recorder

	// gate decides which dispatches must wait for a human. A gate can only add a
	// reason to stop, so the no-op gate is safe. store is only consulted when
	// gate says a dispatch is gated, so a nil store is unreachable unless a real
	// gate was wired without one, which NewApprovals refuses.
	gate  ApprovalGate
	store ApprovalStore

	// grants is the batch/window Grant store (ADR-0027 decision 12). Nil means
	// no grant ever covers anything, which is both the default and the safe
	// direction.
	grants ApprovalGrantStore

	// tasks persists MCP task handles (#374, ADR-0028). Nil disables the
	// Tasks extension entirely, which is the pre-#374 behaviour and loses
	// nothing: the universal pending_approval result path does not use handles.
	tasks MCPTaskStore

	// authz is the role floor on a DECISION (#270): deciding a Request
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
// authz is the role floor on answering one (#270).
//
// rec, gate, store and authz are required together. A gate with no store could
// decide a dispatch needs approval and then have nowhere to record it — which
// would either drop the dispatch silently or, worse, let it through. A store
// with no gate is inert. A store with no authorizer would accept a decision from
// any authenticated caller, including a viewer releasing a Raw Exec, which is the
// approval mechanism handing out authority instead of withholding it. Passing an
// incomplete set is a composition-root bug, so it panics rather than degrading.
//
// grants is the batch/window Grant store (ADR-0027 decision 12). Optional.
// Nil means no grant ever covers anything, which is the safe direction and the
// behaviour of every deployment that never creates one — a grant can only ever
// RELEASE a dispatch the gate already gated, so its absence can never let
// something through.
//
// tasks is the MCP task-handle store (#374, ADR-0028), enabling the Tasks
// extension's server side. Optional, and its absence is not a degraded mode but
// the prior one: with no store, dispatches park and return the universal
// `pending_approval` result (#371) exactly as before. ADR-0028 requires that
// path to keep working with the shim deleted, so nothing below it may come to
// depend on a handle existing.
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
func NewApprovals(rec *Recorder, gate ApprovalGate, store ApprovalStore, authz ApprovalAuthorizer, grants ApprovalGrantStore, tasks MCPTaskStore, notifier ApprovalNotifier, now func() time.Time) *Approvals {
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
	return newApprovals(rec, gate, store, authz, grants, tasks, notifier, now)
}

// newApprovals assembles an Approvals with no checks. Only NewApprovals and
// _test.go files call it; it is the only route to an Approvals with the no-op
// gate or no store.
func newApprovals(rec *Recorder, gate ApprovalGate, store ApprovalStore, authz ApprovalAuthorizer, grants ApprovalGrantStore, tasks MCPTaskStore, notifier ApprovalNotifier, now func() time.Time) *Approvals {
	return &Approvals{
		rec:           rec,
		gate:          gate,
		store:         store,
		authz:         authz,
		grants:        grants,
		tasks:         tasks,
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

// ParkedError is returned by Service.Run when a dispatch is gated and now waits
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

	// Progress renders partial quorum ("0 of 2").
	Progress string

	// Rules names the gate rules that parked this dispatch, so the answer to
	// "why is this waiting?" travels with the error.
	Rules []string

	// ExpiresAt is when the parked request lapses.
	ExpiresAt time.Time

	// TaskID is the MCP task handle attached to this park (#374, ADR-0028), or
	// empty when Tasks are not wired or the handle could not be minted.
	//
	// Empty is a fully supported answer, not a failure: a surface renders the
	// universal `pending_approval` result either way, and only a Tasks-capable
	// client is ever told about a handle at all. Nothing below this line may
	// come to require one.
	TaskID string

	// TaskExpiresAt is when that handle stops being pollable — at or before
	// ExpiresAt above, and never more than mcptask.MaxTTL away.
	//
	// Carried separately rather than let a surface reuse ExpiresAt, because the
	// two answer different questions: ExpiresAt is when the APPROVAL lapses,
	// TaskExpiresAt is when the HANDLE does. A shim rendering SEP-2663's ttlMs
	// from the wrong one would tell a client to keep polling something that has
	// already been swept.
	TaskExpiresAt time.Time

	// Askable reports whether THIS park can be asked about in-band by THIS
	// caller, on THIS call — the fact an MCP surface needs to decide whether to
	// render an actual question or the opaque `pending_approval` result (S2b;
	// docs/specs/approval.md AP-61, AP-62, AP-69).
	//
	// It is decided here, in checkApproval, because the capability layer is the
	// one place the merged Requirement and the calling Principal are held
	// together (invariant 10): a surface reads this field and never
	// recomputes any of its terms.
	//
	// All four of these hold, or the park is not askable:
	//  1. the rule's channel is satisfiable in-band;
	//  2. the rule does not exclude the requester (RequesterAllowed) — an
	//     in-band answer is authenticated as the requesting session's own
	//     Account, so a requester-excluded rule refuses it unconditionally;
	//  3. the rule's audience admits that Account (an empty audience admits
	//     it; a malformed one admits no one);
	//  4. this call CREATED the park, rather than observing one already
	//     pending — the same created/observed distinction that gates
	//     NotifyParked and AP-41's audit.
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
	// ParkedError, an observed re-drive, and every non-askable park all render
	// as today's opaque pending_approval.
	Askable bool
}

func (e *ParkedError) Error() string {
	return fmt.Sprintf(
		"capability: dispatch parked for approval (ADR-0027): %s — request %s, %s approved, gated by %v, expires %s. "+
			"Nothing has been dispatched; the Job runs only once the requirement is satisfied.",
		e.Summary, e.RequestID, e.Progress, e.Rules, e.ExpiresAt.UTC().Format(time.RFC3339))
}

// approvalDecision is the internal result of consulting the gate for one
// resolved dispatch.
type approvalDecision struct {
	// proceed reports whether dispatch may continue now.
	proceed bool
	// requestID is the satisfied Request that released this dispatch, empty
	// when no approval was required — the satisfied Request whose release this
	// dispatch must claim (or re-attach to). For a single-Plan approval,
	// Service.Run must claim it with approvals.BindJob before dispatching
	// (AP-77); for a grant-released dispatch (grantID non-empty) it is never
	// claimed — see Run's grant-rationale comment.
	requestID string
	// reattachJobID is set when the satisfied Request named by requestID has
	// ALREADY bound a Job (AP-77: an approval releases one execution). Set
	// only together with requestID. Service.Run must re-attach to this Job and
	// dispatch nothing.
	reattachJobID string
	// parked is set when the dispatch was parked instead.
	parked *ParkedError
	// grantID is the batch/window Grant that released this dispatch, empty when
	// a single-Plan approval or no gate did. Carried into audit so "which grant
	// authorised this" is a join rather than a reconstruction, and so a grant's
	// full blast radius — every Job it released — is one query.
	grantID string
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
	// A blank audience entry never becomes an approver: refused here, before
	// any Approval grant is claimed or any Request is created, so a non-validating
	// ApprovalGate cannot park a dispatch behind a Request that reads back
	// unrestricted. This is the single call site for whatever Evaluate
	// returns, including a Requirement *approval.Gate merged from several
	// matching rules (mergeStricter): that merge never lets an unrestricted
	// rule's audience absorb a malformed one — a blank entry survives the
	// merge (see unionAudience) — so a merge upstream cannot defeat this
	// check. A real *approval.Gate can no longer produce a malformed
	// Requirement in the first place (approval.Rule.Validate).
	if err := approval.ValidateAudience(req.Audience); err != nil {
		return approvalDecision{}, fmt.Errorf("capability: dispatch approval requirement from rules %s: require.audience: %w", strings.Join(rules, ", "), err)
	}

	now := time.Now().UTC()
	if a.now != nil {
		now = a.now()
	}

	planHash := approval.HashPlan(act, nodes)

	// An already-satisfied approval for exactly this Plan releases the
	// dispatch. Anything else — pending, denied, expired, or absent — does not.
	//
	// The lookup is by PLAN HASH and nothing else. The shape key (#415) is
	// never consulted here and must never be: it deliberately excludes the
	// resolved fan-out, so releasing on it would release a dispatch over a Node
	// set nobody approved.
	existing, lookupErr := a.store.ByPlanHash(ctx, planHash)

	// An approval releases one execution (AP-77), and that check runs BEFORE a
	// batch/window Grant is even consulted — deliberately ahead of the Grant
	// check below, not folded into the switch after it. AP-77's text is
	// unconditional ("any later dispatch ... re-attaches"): if a Grant covering
	// this exact plan were claimed first, a timeout re-drive of an
	// already-released approval would run a genuinely new Job under the Grant
	// whenever one happened to exist, which is exactly the second execution
	// AP-77 forbids. Re-attaching first is the more restrictive reading, and it
	// costs a covering Grant nothing it needed: the Grant's OWN uses are
	// untouched (a re-attach consumes no Grant use), and the Grant still
	// releases every dispatch that does NOT match an already-released Request.
	//
	// Checked only while the Request is Satisfied (approved, inside its
	// deadline, quorum met) — a Request that has already bound a Job never
	// falls into the unbound case below. Once the deadline passes, Satisfied
	// is false, the approved row is not pending, and the dispatch falls through
	// to the Grant check and then a fresh park. That keeps a spent approval
	// from becoming a permanent replay of one Job (the concern #646 and this
	// issue's body record).
	if lookupErr == nil && existing.Satisfied(now) && existing.Released() {
		return approvalDecision{requestID: existing.ID, reattachJobID: existing.JobID}, nil
	}

	// A store failure reading THIS plan's existing Request is refused HERE,
	// before a Grant is ever consulted (SEC-2/C2-S1, #713 security review): a
	// released Request the Relay cannot currently read must never be silently
	// shadowed by a covering Grant that goes on to run the plan a second time.
	// Only ErrNotFound — "no Request exists for this plan" — falls through to
	// the Grant check and the switch below; any other error fails the
	// dispatch closed, and a covering Grant's own uses are left untouched
	// (ClaimGrant below is never reached).
	if lookupErr != nil && lookupErr != approval.ErrNotFound { //nolint:errorlint // a wrapped ErrNotFound would take the fail-closed branch, never the permissive one
		return approvalDecision{}, fmt.Errorf("capability: read approval for plan: %w", lookupErr)
	}

	// A batch/window Grant (ADR-0027 decision 12) is consulted only AFTER the
	// gate said this dispatch is gated AND after the checks above found no
	// already-released Request for this exact plan (and no store failure
	// reading for one), and that order is the point: a Grant answers a
	// requirement that already exists, and it must never re-run a plan an
	// approval already spent (AP-77, above). It can never create a
	// requirement, and it can never reach a dispatch the gate did not gate —
	// so an ungated deployment is unaffected by grants entirely.
	//
	// Everything before this line still ran: Freeze, Selector resolution,
	// authz, and the blast cap. A Grant substitutes for the HUMAN, not for the
	// pipeline, so it cannot release something Policy or the cap would refuse.
	//
	// The claim is atomic (see GrantRepository.ClaimGrant): find-and-consume in
	// one transaction, because a bound enforced outside a transaction is not a
	// bound under concurrency.
	if a.grants != nil {
		g, ok, err := a.grants.ClaimGrant(ctx, d, now)
		if err != nil {
			return approvalDecision{}, fmt.Errorf("capability: claim approval grant: %w", err)
		}
		if ok {
			return approvalDecision{proceed: true, requestID: g.RequestID, grantID: g.ID}, nil
		}
	}

	// lookupErr is nil or approval.ErrNotFound here — anything else already
	// returned above, before the Grant was ever consulted.
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
	// The Selector is normalised into shape terms BEFORE the Request exists,
	// and a failure fails the dispatch rather than parking with a meaningless
	// key: a record whose shape key means nothing is a record the approval
	// object could later group wrongly.
	shape, err := sel.Shape()
	if err != nil {
		return approvalDecision{}, fmt.Errorf("capability: normalise selector for shape key: %w", err)
	}
	r := approval.NewRequest(id, planHash, p.AccountID, p.Account, act, nodes, shape, rules, req, now)
	if err := a.store.Create(ctx, r); err != nil {
		return approvalDecision{}, fmt.Errorf("capability: park dispatch for approval: %w", err)
	}
	// This call CREATED r (as opposed to the "already waiting" branch above,
	// which observed one), so — and only so — Askable is computed against it.
	// r.Require is the normalized Requirement a.gate.Evaluate returned, already
	// merged across every matching rule for a real *approval.Gate
	// (mergeStricter): the boolean below is read from that merge, never from
	// one rule.
	pe := parkedErrorFor(r)
	pe.Askable = askableBy(r, p)
	return approvalDecision{parked: pe, created: &r}, nil
}

// askableBy decides ParkedError.Askable's non-channel, non-created terms: does
// r's Requirement admit p as an in-band decider? It mirrors
// approval.Request.inAudience's own reading of an audience exactly —
// TestAskableAudienceReadsAsDecideDoes pins the two together — rather than
// exporting inAudience out of package approval, which is out of this issue's
// scope.
func askableBy(r approval.Request, p Principal) bool {
	// Equality, not "at least in-band": the stored Requirement is normalized
	// (approval.Requirement.normalized), so ChannelUnspecified cannot occur
	// here, and if it somehow did it must fail closed rather than read as
	// satisfiable.
	if r.Require.Channel != approval.ChannelInBand {
		return false
	}
	// An in-band answer is authenticated as the requesting session's own
	// Account, and on a created park that Account is always
	// r.RequestedByID == p.AccountID — so a requester-excluded rule refuses it
	// unconditionally (ErrRequesterExcluded, AP-43).
	if !r.Require.RequesterAllowed {
		return false
	}
	if r.Require.AudienceMalformed() {
		return false
	}
	if len(r.Require.Audience) == 0 {
		return true
	}
	for _, a := range r.Require.Audience {
		if strings.EqualFold(a, p.Account) {
			return true
		}
	}
	return false
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
		Progress:    r.Progress(),
		Count:       r.Require.Count,
		Channel:     r.Require.Channel.String(),
		ExpiresAt:   r.ExpiresAt,
	}
}

func parkedErrorFor(r approval.Request) *ParkedError {
	return &ParkedError{
		RequestID: r.ID,
		PlanHash:  r.PlanHash,
		Summary:   r.Summary,
		Progress:  r.Progress(),
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
