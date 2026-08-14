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

// ApprovalStore is the subset of approval.Repository the dispatch path needs.
// Kept narrow deliberately: the capability layer creates parked Requests and
// reads back satisfied ones, but it is not where decisions are recorded — that
// is the decision endpoint's job ([3/6]).
type ApprovalStore interface {
	Create(ctx context.Context, r approval.Request) error
	ByPlanHash(ctx context.Context, planHash string) (approval.Request, error)
	BindJob(ctx context.Context, id, jobID string) error
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

	req, rules, gated := s.gate.Evaluate(approval.Dispatch{
		RiskClass:  act.RiskClass,
		FanOut:     len(nodes),
		Namespaces: sel.NamespaceNames(),
		Account:    p.Account,
		Operation:  act.OperationName,
		RawExec:    act.Kind == jobs.ActionRawExec,
	})
	if !gated {
		return approvalDecision{proceed: true}, nil
	}

	now := time.Now().UTC()
	if s.now != nil {
		now = s.now()
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
	summary := approval.Summarize(act, nodes)
	r := approval.NewRequest(id, planHash, p.AccountID, p.Account, summary, rules, req, now)
	if err := s.approvals.Create(ctx, r); err != nil {
		return approvalDecision{}, fmt.Errorf("capability: park dispatch for approval: %w", err)
	}
	return approvalDecision{parked: parkedErrorFor(r)}, nil
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
