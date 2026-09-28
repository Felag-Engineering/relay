package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// approvals.go is the OUT-OF-BAND DECISION CHANNEL (#270, ADR-0027) — the
// universal path, and the only one that is a guarantee rather than a delivery
// convenience.
//
// The security property is where the decision arrives, not what it says. A
// gated dispatch is proposed over one channel (an AI-agent's MCP session, an
// IaC pipeline's API call) and answered over this one, which requires an
// Account credential the requesting session does not hold. That is what puts
// the proposing agent structurally outside the trust path: a jailbroken harness
// can ask for anything and cannot answer for anybody.
//
// Three consequences are load-bearing and are enforced elsewhere on purpose:
//
//   - **The MCP surface may surface a pending approval and must never accept a
//     decision.** Guarded structurally by mcp/no_decision_test.go, not by this
//     file's existence.
//   - **The role floor and every eligibility rule live below this handler** —
//     in capability.Service.DecideApproval and the approval domain. This file
//     decodes, calls, and renders; it decides nothing, so the Console's
//     approval queue (v0.7.0) and the MCP elicitation envelope ([5/6]) inherit
//     one answer rather than each re-deriving it (invariant 10).
//   - **Channel strength is set here, not by the caller.** Every decision this
//     file records is ChannelOutOfBand because of the door it came through. A
//     channel a request body could name is a channel a request body could
//     upgrade.
//
// Deciding does not dispatch. Satisfying a requirement lets the SAME Plan
// proceed the next time it is driven, matched by plan hash — which is why
// registry drift re-parks with no drift detector anywhere.

// ApprovalService is the capability-layer entry point the approval routes use,
// declared locally so this package never names *capability.Service (mirroring
// Executor). *capability.Service satisfies it structurally.
type ApprovalService interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
	Approval(ctx context.Context, id string) (approval.Request, error)
	DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error)
}

// maxDecisionReasonLen bounds the decider's free-text note. It is echoed into
// an audit Record, so an unbounded one lets a caller size a row in the trail.
const maxDecisionReasonLen = 1024

// -----------------------------------------------------------------------
// Wire shapes
// -----------------------------------------------------------------------

// decisionResponse is one recorded answer, rendered.
//
// It carries `human`, the verified fact that a person answered, because the
// second approver of a count:2 request is entitled to know what kind of
// signature is already on it — and because ADR-0027's ladder turns on exactly
// that distinction.
type decisionResponse struct {
	Account   string `json:"account"`
	AccountID string `json:"account_id,omitempty"`
	Approve   bool   `json:"approve"`
	Reason    string `json:"reason,omitempty"`
	Channel   string `json:"channel"`
	Human     bool   `json:"human"`
	At        string `json:"at"`
}

// approvalResponse is a parked dispatch as an approver sees it.
//
// Summary is the RELAY-AUTHORED description — the agent chose the Action, but
// not one word a human reads about it (ADR-0027). A surface must render this
// text, never re-derive its own from the fields around it: three places now
// render a Plan (plan mode, this queue, the Console composer), and a Plan that
// reads differently in the approval queue than at execution *is* the
// approval-view fidelity gap, reintroduced by us.
type approvalResponse struct {
	RequestID     string   `json:"request_id"`
	State         string   `json:"state"`
	PlanHash      string   `json:"plan_hash"`
	Summary       string   `json:"summary"`
	ActionKind    string   `json:"action_kind"`
	RiskClass     string   `json:"risk_class"`
	RequestedBy   string   `json:"requested_by"`
	RequestedByID string   `json:"requested_by_id,omitempty"`
	MatchedRules  []string `json:"matched_rules"`
	RequiredCount int      `json:"required_count"`
	Audience      []string `json:"audience,omitempty"`
	// RequesterAllowed and Channel are the rule's terms, published so a
	// would-be decider can tell why they are (or are not) eligible before
	// spending a round trip on a refusal.
	RequesterAllowed bool               `json:"requester_allowed"`
	Channel          string             `json:"channel"`
	Progress         string             `json:"progress"`
	Decisions        []decisionResponse `json:"decisions"`
	JobID            string             `json:"job_id,omitempty"`
	CreatedAt        string             `json:"created_at"`
	ExpiresAt        string             `json:"expires_at"`
	ResolvedAt       string             `json:"resolved_at,omitempty"`
}

type listApprovalsResponse struct {
	Approvals []approvalResponse `json:"approvals"`
}

// decideApprovalRequest is POST /api/v1/approvals/{id}/decision's body.
//
// PlanHash is REQUIRED, not optional. An approval binds to a content-addressed
// Plan, so a decision that did not cite one would be an answer to "whatever
// this request means now" — and the whole point of the binding is that a
// decider commits to the Operation, its arguments, and the resolved fan-out
// they were shown. A client that read a stale queue entry is told its view
// moved rather than silently approving today's version.
//
// There is deliberately NO channel field: see this file's header.
type decideApprovalRequest struct {
	Approve  bool   `json:"approve"`
	PlanHash string `json:"plan_hash"`
	Reason   string `json:"reason"`
}

// -----------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------

func renderApproval(r approval.Request) approvalResponse {
	decisions := make([]decisionResponse, 0, len(r.Decisions))
	for _, d := range r.Decisions {
		decisions = append(decisions, decisionResponse{
			Account:   d.Account,
			AccountID: d.AccountID,
			Approve:   d.Approve,
			Reason:    d.Reason,
			Channel:   d.Channel.String(),
			Human:     d.DeciderHuman,
			At:        rfc3339(d.At),
		})
	}
	rules := r.MatchedRules
	if rules == nil {
		rules = []string{}
	}
	return approvalResponse{
		RequestID:        r.ID,
		State:            r.State.String(),
		PlanHash:         r.PlanHash,
		Summary:          r.Summary,
		ActionKind:       approval.ActionKindName(r.ActionKind),
		RiskClass:        jobs.RiskClassName(r.RiskClass),
		RequestedBy:      r.RequestedBy,
		RequestedByID:    r.RequestedByID,
		MatchedRules:     rules,
		RequiredCount:    r.Require.Count,
		Audience:         r.Require.Audience,
		RequesterAllowed: r.Require.RequesterAllowed,
		Channel:          r.Require.Channel.String(),
		Progress:         r.Progress(),
		Decisions:        decisions,
		JobID:            r.JobID,
		CreatedAt:        rfc3339(r.CreatedAt),
		ExpiresAt:        rfc3339(r.ExpiresAt),
		ResolvedAt:       rfc3339(r.ResolvedAt),
	}
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

// handleListApprovals implements GET /api/v1/approvals: the queue of parked
// dispatches still awaiting a decision.
//
// Any authenticated caller may read it. A rule's `audience` restricts who may
// DECIDE, not who may see that a decision is owed — narrowing the queue to the
// audience would hide pending fleet state from the operators watching it, and
// every entry is a Relay-authored summary of an action the same caller can
// already read in the audit trail.
//
// Not audited as a read (ADR-0025): this returns no captured Task output. It is
// the same posture list_nodes has — fleet shape, not somebody else's command
// results.
func handleListApprovals(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		if d.Approvals == nil {
			writeApprovalsUnavailable(w)
			return
		}

		pending, err := d.Approvals.PendingApprovals(r.Context())
		if err != nil {
			writeApprovalError(w, "", err)
			return
		}
		out := make([]approvalResponse, 0, len(pending))
		for _, req := range pending {
			out = append(out, renderApproval(req))
		}
		writeJSON(w, http.StatusOK, listApprovalsResponse{Approvals: out})
	}
}

// handleGetApproval implements GET /api/v1/approvals/{id}, in whatever state
// the request is in — including terminal ones. "What became of that request?"
// is exactly the question asked after being told an answer arrived too late,
// and a queue that only shows live entries cannot answer it.
func handleGetApproval(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		if d.Approvals == nil {
			writeApprovalsUnavailable(w)
			return
		}

		id := r.PathValue("id")
		if id == "" {
			writeProblem(w, http.StatusBadRequest, "approval request id required", "")
			return
		}

		req, err := d.Approvals.Approval(r.Context(), id)
		if err != nil {
			writeApprovalError(w, id, err)
			return
		}
		writeJSON(w, http.StatusOK, renderApproval(req))
	}
}

// handleDecideApproval implements POST /api/v1/approvals/{id}/decision: the
// authenticated out-of-band answer.
//
// This handler enforces exactly two things — that a plan hash was cited and
// that the reason is bounded — and delegates everything that decides anything.
// The role floor (deciding requires the role the Action would have needed to be
// requested), the requester exclusion, the machine-self-decision rule, the
// audience, the duplicate-decider rule, quorum arithmetic, and the audit record
// are all below the capability layer's door, where the Console and the MCP
// envelope reach them too.
func handleDecideApproval(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Approvals == nil {
			writeApprovalsUnavailable(w)
			return
		}

		id := r.PathValue("id")
		if id == "" {
			writeProblem(w, http.StatusBadRequest, "approval request id required", "")
			return
		}

		var req decideApprovalRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		if req.PlanHash == "" {
			writeProblem(w, http.StatusBadRequest, "plan_hash required",
				"a decision binds to the Plan it was shown (ADR-0027); cite the plan_hash from the approval request")
			return
		}
		if len(req.Reason) > maxDecisionReasonLen {
			writeProblem(w, http.StatusBadRequest, "reason too long",
				"reason must be at most 1024 bytes")
			return
		}

		updated, err := d.Approvals.DecideApproval(r.Context(), p, capability.ApprovalDecision{
			RequestID: id,
			PlanHash:  req.PlanHash,
			Approve:   req.Approve,
			Reason:    req.Reason,
			// Out-of-band because of the door, never because a body said so.
			Channel: approval.ChannelOutOfBand,
		})
		if err != nil {
			writeApprovalError(w, id, err)
			return
		}
		writeJSON(w, http.StatusOK, renderApproval(updated))
	}
}

// -----------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------

func writeApprovalsUnavailable(w http.ResponseWriter) {
	writeProblem(w, http.StatusInternalServerError, "approvals unavailable",
		"the Control API was mounted without its approval dependencies")
}

// writeApprovalError maps a capability/domain error onto the status that
// describes it truthfully.
//
// Every eligibility refusal is a 409 Conflict rather than a 403: the caller's
// credential is fine and the route is theirs to call — it is the REQUEST'S
// state (already decided, expired, already signed by you, bound to a different
// Plan) that refuses. A 403 would tell an approver to go find a bigger token,
// which is the wrong lesson. The two genuine authorization failures — the role
// floor and the audience — do render as 403.
//
// Detail carries the domain error's own text in every case. These are rule
// statements: which role is required, that the plan moved, that a second
// distinct decider is needed. None of them is a secret, and an approver who
// cannot tell WHY their answer bounced will eventually stop answering.
func writeApprovalError(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, approval.ErrNotFound):
		detail := "no approval request with that id"
		if id != "" {
			detail = "no approval request with id " + id
		}
		writeProblem(w, http.StatusNotFound, "approval request not found", detail)
	case errors.Is(err, authz.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, approval.ErrNotInAudience):
		writeProblem(w, http.StatusForbidden, "not in the approval audience", err.Error())
	case errors.Is(err, approval.ErrNotPending):
		writeProblem(w, http.StatusConflict, "approval request is not pending", err.Error())
	case errors.Is(err, approval.ErrRequesterExcluded),
		errors.Is(err, approval.ErrMachineSelfDecision):
		writeProblem(w, http.StatusConflict, "requester may not decide this request", err.Error())
	case errors.Is(err, approval.ErrDuplicateDecider):
		writeProblem(w, http.StatusConflict, "already decided by this account", err.Error())
	case errors.Is(err, approval.ErrPlanChanged):
		writeProblem(w, http.StatusConflict, "plan hash mismatch", err.Error())
	case errors.Is(err, approval.ErrWeakChannel):
		writeProblem(w, http.StatusConflict, "decision channel is too weak", err.Error())
	case errors.Is(err, capability.ErrApprovalUnavailable):
		writeApprovalsUnavailable(w)
	default:
		writeProblem(w, http.StatusInternalServerError, "approval request failed", err.Error())
	}
}
