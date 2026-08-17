package capability

import (
	"context"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

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

// noopApprovalGate is the default: nothing is ever gated.
type noopApprovalGate struct{}

func (noopApprovalGate) Evaluate(approval.Dispatch) (approval.Requirement, []string, bool) {
	return approval.Requirement{}, nil, false
}

// ApprovalStore is the subset of approval.Repository the capability layer
// needs: the dispatch path's create/lookup/bind, plus the queue reads and the
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
	BindJob(ctx context.Context, id, jobID string) error
	Get(ctx context.Context, id string) (approval.Request, error)
	Pending(ctx context.Context) ([]approval.Request, error)
	RecordDecision(ctx context.Context, id string, d approval.Decision, now time.Time) (approval.Request, error)
}

// ApprovalGrantStore is the batch/window Grant persistence the capability layer
// needs (ADR-0027 decision 12): consuming a Grant on the dispatch path, and
// creating, reading, and revoking one on the management path
// (approval_grant.go).
//
// It mirrors approval.GrantRepository exactly rather than narrowing to the
// claim, because both halves live behind this one Service — the surfaces adapt
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
// dispatch. Every field is Relay-authored (ADR-0027): the requesting agent
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
	// when no approval was required. Bound to the Job after dispatch so audit
	// can join "what ran" to "who approved it".
	requestID string
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
func (s *Service) checkApproval(ctx context.Context, p Principal, sel Selector, act jobs.Action, nodes []string) (approvalDecision, error) {
	// A nil gate gates nothing. New always installs noopApprovalGate, so this
	// only fires for a Service built as a struct literal (in-package tests) —
	// but it is written as a guard rather than an assumption, because the
	// failure mode of getting it wrong is a nil-panic on the dispatch path.
	if s.gate == nil {
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

	req, rules, gated := s.gate.Evaluate(d)
	if !gated {
		return approvalDecision{proceed: true}, nil
	}

	now := time.Now().UTC()
	if s.now != nil {
		now = s.now()
	}

	// A batch/window Grant (ADR-0027 decision 12) is consulted only AFTER the
	// gate said this dispatch is gated, and that order is the point: a Grant
	// answers a requirement that already exists. It can never create one, and
	// it can never reach a dispatch the gate did not gate — so an ungated
	// deployment is unaffected by grants entirely.
	//
	// Everything before this line still ran: Freeze, Selector resolution,
	// authz, and the blast cap. A Grant substitutes for the HUMAN, not for the
	// pipeline, so it cannot release something Policy or the cap would refuse.
	//
	// The claim is atomic (see GrantRepository.ClaimGrant): find-and-consume in
	// one transaction, because a bound enforced outside a transaction is not a
	// bound under concurrency.
	if s.grants != nil {
		g, ok, err := s.grants.ClaimGrant(ctx, d, now)
		if err != nil {
			return approvalDecision{}, fmt.Errorf("capability: claim approval grant: %w", err)
		}
		if ok {
			return approvalDecision{proceed: true, requestID: g.RequestID, grantID: g.ID}, nil
		}
	}

	planHash := approval.HashPlan(act, nodes)

	// An already-satisfied approval for exactly this Plan releases the
	// dispatch. Anything else — pending, denied, expired, or absent — does not.
	existing, err := s.approvals.ByPlanHash(ctx, planHash)
	switch {
	case err == nil && existing.Satisfied(now):
		return approvalDecision{proceed: true, requestID: existing.ID}, nil
	case err == nil && existing.State == approval.StatePending && !existing.Expired(now):
		// Already waiting. Return the same park rather than creating a second
		// Request for the same Plan: two Requests for one Plan would let a
		// requester farm a second opinion after the first approver said no
		// yet, and would double every notification.
		return approvalDecision{parked: parkedErrorFor(existing)}, nil
	case err != nil && err != approval.ErrNotFound:
		return approvalDecision{}, fmt.Errorf("capability: read approval for plan: %w", err)
	}

	// Park: create the Request and report it. No Job and no Task exist yet, by
	// design — see approval.NewRequest.
	mint := s.newApprovalID
	if mint == nil {
		mint = defaultID
	}
	id, err := mint()
	if err != nil {
		return approvalDecision{}, err
	}
	r := approval.NewRequest(id, planHash, p.AccountID, p.Account, act, nodes, rules, req, now)
	if err := s.approvals.Create(ctx, r); err != nil {
		return approvalDecision{}, fmt.Errorf("capability: park dispatch for approval: %w", err)
	}
	return approvalDecision{parked: parkedErrorFor(r), created: &r}, nil
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
