package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// tools_approval.go is THE ONE FILE in this package permitted to name a
// decision path, and it exists because of a decision recorded in ADR-0029.
//
// Everything else about ADR-0027 is unchanged and is enforced by
// no_decision_test.go, which still scans every other file here and in
// internal/mcptask. The exemption is a single filename in that test, so the
// whole of this hole is one `git show` away for any reviewer, and a second
// decision path cannot appear anywhere else by accident.
//
// # What this file may and may not assume
//
// It may record a decision. It may NOT decide what a decision means: the
// eligibility rules — requester exclusion, audience, quorum, plan binding,
// channel strength, expiry — all live in package approval and are enforced by
// Request.Decide on the way to the store. This file supplies three facts and
// nothing else: WHO was authenticated, WHAT they answered, and that the answer
// arrived IN-BAND.
//
// That last fact is set here and is never read from the caller's input.
// approval.Decision's own comment is the reason: "A channel a client could
// name is a channel a client could upgrade." A tool argument asking for
// out-of-band strength would be exactly that, so the channel is a constant
// below and there is no field for it in the input type.
//
// # Why the approver is asserted, never verified
//
// The call arrives on the requesting session's credential. Relay therefore
// knows which Account made the call and cannot know whether a human answered —
// only that the client says one did. So the approver travels in the ASSERTED
// attribution lane (capability.Assertions.OnBehalfOf), which is masked from
// authorization by construction and lands in the audit trail's asserted
// columns. `approved_by` stays the verified Account; `on_behalf_of` carries
// the claim. An auditor can always tell the two apart, which is the entire
// point of recording them separately (ADR-0029 decision 2).

// ApprovalDecider records a decision against a parked approval Request.
//
// Deliberately one method wide. The MCP surface has no business reading the
// approval queue through this seam, listing grants, or reaching anything else
// on capability.Service — a narrow interface is what keeps "this file may
// record a decision" from drifting into "this file has the approval API".
type ApprovalDecider interface {
	DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error)
}

// WithApprovalDecider enables the in-band approval tool (ADR-0029).
//
// Absent, `approve_request` is not registered at all and the Relay behaves
// exactly as it did before: parked dispatches are answered only on the
// authenticated /api/v1 decision endpoint. That is the same graceful-absence
// posture the Tasks resolver takes, and it means the in-band rung is opt-in at
// the composition root rather than something a deployment gets by upgrading.
func WithApprovalDecider(d ApprovalDecider) Option {
	return func(o *serverOptions) { o.approvals = d }
}

// approveRequestInput is the tool's argument shape.
//
// There is deliberately no `channel` field. See the file header: the surface
// that receives a decision sets its strength, never the caller.
type approveRequestInput struct {
	RequestID string `json:"request_id" jsonschema:"The parked approval request to answer, exactly as reported in a pending_approval result's request_id."`
	PlanHash  string `json:"plan_hash" jsonschema:"The plan_hash from the same pending_approval result. A decision binds to the Plan it was shown; if the fleet changed since, this is refused rather than silently approving a different set of Nodes."`
	Approve   bool   `json:"approve" jsonschema:"true approves, false denies. A denial is terminal — it cannot be reversed by approving afterwards."`
	Approver  string `json:"approver" jsonschema:"Who actually made this decision — the human you asked, not you. Recorded as an ASSERTED identity: Relay cannot verify it, and the audit trail marks it as a claim rather than as a verified approver. Required: an in-band approval with nobody named is a machine approving its own request."`
	Reason    string `json:"reason,omitempty" jsonschema:"Optional note from the decider, recorded in the audit trail."`
}

// ApprovalDecisionOutput is what the tool returns.
type ApprovalDecisionOutput struct {
	RequestID  string `json:"request_id" jsonschema:"The request that was answered."`
	State      string `json:"state" jsonschema:"The request's state after this decision: pending (more approvals still required), approved, denied, or expired."`
	Progress   string `json:"progress" jsonschema:"Quorum progress, e.g. '1 of 2'."`
	Channel    string `json:"channel" jsonschema:"Always 'in-band' for a decision made through this tool — the answer arrived over the same session that requested the action. Rules requiring out-of-band strength are not satisfied by it."`
	OnBehalfOf string `json:"on_behalf_of" jsonschema:"The asserted approver identity recorded for this decision. Asserted, never verified."`
	NextStep   string `json:"next_step" jsonschema:"What to do next."`
}

const approveRequestNextStep = "If state is 'approved', re-issue the original call unchanged to run it — approving releases the Plan, it does not itself dispatch. " +
	"If state is still 'pending', the rule requires more approvals than this one. If it is 'denied', do not retry: a denial is terminal."

// registerApprovalTools adds approve_request when a decider is configured.
func registerApprovalTools(srv *sdkmcp.Server, decider ApprovalDecider) {
	if decider == nil {
		return
	}

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "approve_request",
		Description: "Answer a parked approval request — the in-band decision path (ADR-0029). " +
			"Use this ONLY to relay a decision a human actually made: surface the pending_approval summary verbatim, " +
			"ask, and pass their answer here with their identity in `approver`. " +
			"Never decide on your own initiative and never infer approval from context — you are the messenger, not the approver. " +
			"A decision made here is recorded as in-band, which is weaker than a decision landing on the authenticated " +
			"/api/v1 endpoint: rules configured to require out-of-band strength are NOT satisfied by this tool and will " +
			"still refuse. Denials are terminal.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in approveRequestInput) (*sdkmcp.CallToolResult, ApprovalDecisionOutput, error) {
		logPrincipal(ctx, "approve_request")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, ApprovalDecisionOutput{}, err
		}

		// Refused here rather than in the domain so the caller gets a legible
		// message naming the argument. The domain refuses it too, on the
		// stricter reading that a machine relaying nobody is a machine
		// deciding — see Decision.relaysAnAssertedHuman.
		approver := strings.TrimSpace(in.Approver)
		if approver == "" {
			return nil, ApprovalDecisionOutput{}, fmt.Errorf(
				"approver is required: an in-band approval must name the human who made the decision, " +
					"because this call is authenticated as the requesting session and cannot prove one was asked")
		}

		// The asserted approver joins the caller's existing attribution rather
		// than replacing it: a traceparent or session_ref already on the
		// context is attribution too, and dropping it here would lose the
		// thread between the request and its answer.
		asserted := capability.AssertionsFromContext(ctx)
		asserted.OnBehalfOf = approver
		ctx = capability.WithAssertions(ctx, asserted)

		updated, err := decider.DecideApproval(ctx, p, capability.ApprovalDecision{
			RequestID: strings.TrimSpace(in.RequestID),
			PlanHash:  strings.TrimSpace(in.PlanHash),
			Approve:   in.Approve,
			Reason:    in.Reason,
			// Constant, never caller-supplied. See the file header.
			Channel: approval.ChannelInBand,
		})
		if err != nil {
			return nil, ApprovalDecisionOutput{}, renderApprovalError(err)
		}

		return nil, ApprovalDecisionOutput{
			RequestID:  updated.ID,
			State:      updated.State.String(),
			Progress:   updated.Progress(),
			Channel:    approval.ChannelInBand.String(),
			OnBehalfOf: approver,
			NextStep:   approveRequestNextStep,
		}, nil
	})
}

// renderApprovalError maps a decision refusal to a message that tells the agent
// what to do about it.
//
// The domain's errors are deliberately not collapsed into one "refused": an
// agent that reads "already decided" should stop, one that reads "plan changed"
// should re-read the queue, and one that reads "requires out-of-band" must send
// a human elsewhere entirely. Same refusal, three different next actions.
func renderApprovalError(err error) error {
	switch {
	case errors.Is(err, approval.ErrNotFound):
		return fmt.Errorf("no such approval request — check request_id, or it may have expired and been swept: %w", err)
	case errors.Is(err, approval.ErrWeakChannel):
		return fmt.Errorf("this request requires an out-of-band decision and cannot be approved through this tool. "+
			"A human must answer it on the Control API decision endpoint with their own credential: %w", err)
	case errors.Is(err, approval.ErrRequesterExcluded):
		return fmt.Errorf("this request requires a second person: the Account that asked for it may not answer it, "+
			"whoever is relaying the answer. A different human must decide it out-of-band: %w", err)
	case errors.Is(err, approval.ErrMachineSelfDecision):
		return fmt.Errorf("refused: an in-band answer must name the human who gave it. Pass their identity in `approver`: %w", err)
	case errors.Is(err, approval.ErrNotInAudience):
		return fmt.Errorf("this request names a specific audience, and this Account is not in it: %w", err)
	case errors.Is(err, approval.ErrDuplicateDecider):
		return fmt.Errorf("this Account has already decided this request; a second answer from the same Account is not a second approval: %w", err)
	case errors.Is(err, approval.ErrPlanChanged):
		return fmt.Errorf("the Plan moved since this request was shown — re-read the pending approval and answer the current plan_hash "+
			"rather than approving something different from what was reviewed: %w", err)
	case errors.Is(err, approval.ErrNotPending):
		return fmt.Errorf("this request is no longer open (already decided, or expired): %w", err)
	case errors.Is(err, capability.ErrApprovalUnavailable):
		return err
	}
	return fmt.Errorf("mcp: approval decision failed: %w", err)
}
