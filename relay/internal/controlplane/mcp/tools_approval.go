package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp/requeststate"
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
//
// # The second envelope (ADR-0029 decision 6)
//
// acceptElicitedAnswer, below, is the MRTR answer path: a retried tool call
// carrying an elicitation response to a parked approval. It lives here, in
// the one exempt file, by the same choice that put approve_request here —
// the seal check (package requeststate), the responder-assertion rule, the
// verified-decision rule (AP-78/AP-79, below), and the classification of what
// capability.Service.DecideApproval returned are ALL written in this file, so
// a reviewer can audit the whole of this hole by opening one file, and that
// promise is kept by what is written in the file rather than by the AST scan
// (no_decision_test.go still enforces the scan; this paragraph is the
// reviewer's map of what to read).
//
// A present responder assertion always takes the named path first, whatever
// the declared client name (AP-64). Absent that, a retry that declares client
// name "claude-code" (elicit.go's clientNameClaudeCode) on a session that
// authenticated by OAuth with a human Account (claudeCodeAnswerCounts, below)
// is that human's own verified in-band decision (AP-79): nothing is written
// to the asserted lane. Every other retry — an unrecognised name, or
// "claude-code" off that specific session shape — is refused as a machine
// self-decision, exactly as approve_request with no approver is. The declared
// name is read from the RETRIED call's own `_meta` (elicitedAnswer.CallMeta),
// never from the ElicitResult's own `_meta` and never from the sealed state —
// so a call first asked under one recognised name and retried declaring
// "claude-code" is judged, on the retry, by the retry's own declared name.
//
// tools_execution.go's run_operation and raw_exec are the only callers of
// acceptElicitedAnswer (#727, S4a-2): a retry carrying requestState/
// inputResponses is decided here first, and tools_execution.go's
// answerThenDispatch then re-enters the whole dispatch pipeline once. The
// composition root passes WithApprovalElicitation, so this path is reachable
// from main (#730).

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
	Approver  string `json:"approver" jsonschema:"Who actually made this decision — the human you asked, not you. Recorded as an ASSERTED identity: Relay cannot verify it, and the audit trail marks it as a claim rather than as a verified approver. Required: an in-band approval with nobody named is a machine approving its own request. At most 256 bytes, no control characters; a longer or malformed value is refused, never truncated."`
	Reason    string `json:"reason,omitempty" jsonschema:"Optional note from the decider, recorded in the audit trail."`
}

// noNamedApproverError is the "no named human" refusal shared, byte-for-byte,
// by approve_request (an empty or whitespace-only `approver`) and
// acceptElicitedAnswer (a machine self-decision on the answered retry) —
// AP-64: "refused exactly as an approve_request carrying no approver is
// refused (AP-48)". Sharing one type, rather than two error literals with the
// same string, is what keeps the message identical by construction as either
// side is edited.
//
// Unwrap returns approval.ErrMachineSelfDecision so a caller — and the
// domain's own eligibility rule, see Decision.relaysAnAssertedHuman — can
// recognise this refusal with errors.Is regardless of which surface produced
// it.
type noNamedApproverError struct{}

func (noNamedApproverError) Error() string {
	return "approver is required: an in-band approval must name the human who made the decision, " +
		"because this call is authenticated as the requesting session and cannot prove one was asked"
}

func (noNamedApproverError) Unwrap() error { return approval.ErrMachineSelfDecision }

var errNoNamedApprover error = noNamedApproverError{}

// assertedApprover validates and trims a caller-asserted approver identity —
// the bound shared by approve_request's `approver` argument and the answered
// retry's responder username (owner decision 2, AP-70 as amended).
//
// Order is load-bearing:
//
//  1. Blank after trimming (including a lone tab, CR, or nothing at all) is
//     read as NO assertion — a machine self-decision — not a malformed value.
//  2. Everything else is validated on the UNTRIMMED raw value against
//     audit.ValidateAsserted's rule (at most audit.MaxAssertedFieldBytes
//     bytes, no control characters), reusing that rule rather than
//     reimplementing it. This is deliberate: strings.TrimSpace strips
//     leading/trailing tab, LF, VT, FF, CR and U+0085, which are themselves
//     control characters, so validating the TRIMMED value would silently
//     remove them — truncation by another name. Validating raw refuses
//     "alice\r\n", "alice"+U+0085, and "\talice" outright. The 256-byte bound
//     also applies to the raw value as received: a value whose raw length
//     exceeds the bound is refused even if trimming would bring it under.
//  3. The value RETURNED is trimmed: surrounding ASCII spaces (not control
//     characters) still pass validation and are trimmed from what gets
//     recorded, preserving approve_request's existing "  alice  " -> "alice"
//     behaviour.
func assertedApprover(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errNoNamedApprover
	}
	if err := audit.ValidateAsserted(audit.Asserted{OnBehalfOf: raw}); err != nil {
		return "", fmt.Errorf("the asserted approver is refused, not truncated: it must be at most %d bytes "+
			"and contain no control characters: %w", audit.MaxAssertedFieldBytes, err)
	}
	return trimmed, nil
}

// withAssertedApprover attaches approver to ctx's asserted attribution —
// the same lane approve_request has always used — without discarding
// whatever else the caller already asserted (a traceparent or session_ref
// already on ctx survives).
func withAssertedApprover(ctx context.Context, approver string) context.Context {
	asserted := capability.AssertionsFromContext(ctx)
	asserted.OnBehalfOf = approver
	return capability.WithAssertions(ctx, asserted)
}

// ApprovalDecisionOutput is what the tool returns. It is also reused,
// unchanged, as the decision block an answered retry's response carries
// (RunOrPlanOutput.Decision, #727) — the Channel and State descriptions below
// are written to be true of both.
type ApprovalDecisionOutput struct {
	RequestID  string `json:"request_id" jsonschema:"The request that was answered."`
	State      string `json:"state" jsonschema:"The request's state: after this decision on approve_request, or at the moment this answer was evaluated on an answered retry's decision block — the dispatch that follows may have moved the request on further (for example a concurrent approval completing the quorum). One of pending (more approvals still required), approved, denied, or expired."`
	Progress   string `json:"progress" jsonschema:"Quorum progress, e.g. '1 of 2'."`
	Channel    string `json:"channel" jsonschema:"'in-band' when this decision was recorded through this tool — the answer arrived over the same session that requested the action, and rules requiring out-of-band strength are not satisfied by it. On an answered retry's decision block this is empty when THIS call's answer was not recorded (for example the request was already decided by someone else); approve_request always sets it, because it returns a tool error rather than this shape when nothing was recorded."`
	OnBehalfOf string `json:"on_behalf_of" jsonschema:"The asserted approver identity recorded for this decision. Asserted, never verified. Empty when channel is empty, and also when the decision was the calling human's own verified answer with no asserted approver (a Claude Code answer on that human's OAuth session)."`
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
		approver, err := assertedApprover(in.Approver)
		if err != nil {
			return nil, ApprovalDecisionOutput{}, err
		}

		// The asserted approver joins the caller's existing attribution rather
		// than replacing it: a traceparent or session_ref already on the
		// context is attribution too, and dropping it here would lose the
		// thread between the request and its answer.
		ctx = withAssertedApprover(ctx, approver)

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

// -----------------------------------------------------------------------
// The answered retry (ADR-0029 decision 6). See the file header, "The
// second envelope", for why this lives here rather than in tools_execution.go.
// -----------------------------------------------------------------------

// responderMetaKey is the one recognised form of a responder assertion
// today: an object carrying "gate" and "username", read from an
// sdkmcp.ElicitResult's _meta. A general assertion with one recognised form,
// so a standard key later is additive rather than a breaking change to this
// file's shape.
const responderMetaKey = "io.gleipnir/responder"

// claudeCodeAnswerCounts reports whether p is a session on which a
// claude-code answer is the caller's own verified decision (AP-78, AP-79):
// an OAuth session AND a human Account. Both elicit.go's asking predicate and
// this file's acceptance path call this one definition, so the rule cannot
// drift between "whether to ask" and "whether to accept".
//
// The OAuth resolver copies the Account's Kind through unchecked
// (controlplane/oauth.go), so "human" is checked here explicitly, never
// inferred from AuthMethod alone: an OAuth session of a machine Account, or
// any other auth method entirely (API Token, Console session, unspecified),
// fails closed. p.Human() itself fails closed on an unset or unrecognised
// Kind (capability.Principal.Human).
func claudeCodeAnswerCounts(p capability.Principal) bool {
	return p.AuthMethod == capability.AuthMethodOAuth && p.Human()
}

// replayedFromMetaKey marks a response as a client-side replay of an earlier
// answer rather than a fresh one — present on either the elicitation
// response's own _meta or the retried call's params._meta, checked in both
// places (fail closed on either).
const replayedFromMetaKey = "io.gleipnir/replayed-from"

// responderGatePermission is the one gate value that makes a responder
// assertion count as a decision. "information" (or any other gate) is a
// client answering a question that was never a permission grant.
const responderGatePermission = "permission"

// responderAssertion is a recognised io.gleipnir/responder object.
type responderAssertion struct {
	Gate     string
	Username string
}

// recognisedResponder reads meta[responderMetaKey] as a responderAssertion,
// or reports ok=false if it is absent, not an object, or missing either
// field as a string.
//
// Deliberately exact-key map lookups with .(string) assertions rather than a
// JSON round-trip into a tagged struct: encoding/json matches field names
// CASE-INSENSITIVELY when no exact match exists, so an object keyed "Gate",
// or one carrying both "gate":"information" and "GATE":"permission", would
// be ambiguous on a security gate. Only the exact lowercase keys "gate" and
// "username" count; a case-variant key is unrecognised, not merely
// differently-cased.
func recognisedResponder(meta sdkmcp.Meta) (responderAssertion, bool) {
	v, ok := meta[responderMetaKey]
	if !ok {
		return responderAssertion{}, false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return responderAssertion{}, false
	}
	gate, ok := obj["gate"].(string)
	if !ok {
		return responderAssertion{}, false
	}
	username, ok := obj["username"].(string)
	if !ok {
		return responderAssertion{}, false
	}
	return responderAssertion{Gate: gate, Username: username}, true
}

// elicitedOutcome classifies what acceptElicitedAnswer's caller (S4a-2)
// should do about an answered retry, without it having to re-decide
// anything itself.
type elicitedOutcome int

const (
	// elicitedRefused is the zero value: a forgotten assignment fails closed
	// rather than silently reading as an approval. Err is always set when the
	// outcome is this.
	elicitedRefused elicitedOutcome = iota
	// elicitedApproved is a satisfied Requirement with no Job bound yet — the
	// caller re-issues the original call once to dispatch it.
	elicitedApproved
	// elicitedApprovedJobBound is a satisfied Requirement whose Job already
	// exists — the caller re-attaches to it (AP-67) rather than dispatching
	// again.
	elicitedApprovedJobBound
	// elicitedDenied is terminal (AP-68): one denial ends the Request.
	elicitedDenied
	// elicitedStillPending is a partial quorum: more distinct approvals are
	// required than this one answer supplied.
	elicitedStillPending
	// elicitedLapsed is a Request that is expired, or that is no longer
	// dispatchable because its deadline passed before a Job was bound.
	elicitedLapsed
)

// elicitedAnswerResult is acceptElicitedAnswer's return value.
//
// It holds NO approval.Request and NO approval.Decision, deliberately: a
// refused decision's Request can carry OTHER approvers' identities and
// reasons (capability.DecideApproval returns it whatever the caller's
// eligibility turned out to be — see requestOnRefusal), so from a refusal
// only State, JobID and ExpiresAt are copied here, and nothing that renders
// this type can reach Decisions, RequestedBy, Summary or Require (#735
// review).
//
// Err nil means this answer was recorded AND audited. A non-nil Err does NOT
// by itself mean nothing was recorded: a non-domain error — the audit write
// failing after the decision was already made durable — can follow a
// recorded decision. Such an Err is still classified elicitedRefused with no
// state copied, and a caller rendering it must not claim the answer was
// ignored; it must say the decision may have been recorded and point at
// approve_request or the Control API to confirm. Every refusal THIS FILE
// makes before the decider is even called (an unbound state, a malformed
// responder, a machine self-decision) records nothing, full stop.
//
// A decline never yields elicitedApproved. A human's "no" that capability
// refuses because the Request was already approved out of band (a different
// approver, a different channel) is classified elicitedRefused with Err kept
// and State/JobID/ExpiresAt copied, so a caller can say "your decline was
// not recorded; the request was already approved" without dispatching on the
// decliner's behalf. The one exception is an approved Request with a Job
// already bound: that stays elicitedApprovedJobBound for EITHER answer,
// because re-attaching to an existing Job (AP-67) dispatches nothing new.
//
// Callers branch on Outcome alone, never on whether Err is nil: Err is not a
// "did this fail" flag. elicitedApproved and elicitedApprovedJobBound can
// both carry a non-nil Err (ErrNotPending or ErrDuplicateDecider, the
// requestOnRefusal shape above) when the Request had already moved before
// this answer landed — that is a recorded decision, not a failure, and the
// Outcome says so. elicitedApprovedJobBound returned for a DECLINE means
// THIS decline was never recorded: a Job was already bound by another
// approver's answer before this one arrived. A caller must render that as
// "your decline was not recorded; the request was already approved and
// dispatched" — never as if the decliner had approved it — even though
// re-attaching to the existing Job (AP-67) is still safe, because it
// dispatches nothing new.
//
// The contract for elicitedStillPending: the caller re-drives Service.Run
// with the same call to observe the park. The park it observes is not
// askable (AP-62: a partial quorum is an OBSERVED park, not a created one),
// so the caller renders pending_approval and asks no new question — it does
// NOT "re-emit the elicitation", which does not happen for an observed park.
// This type must never be widened to carry the Request or its Decisions just
// to render progress — Progress (a count string) is the only quorum detail a
// caller gets, and it is set ONLY when Err is nil (a recorded decision);
// every refusal leaves it empty.
type elicitedAnswerResult struct {
	Outcome elicitedOutcome
	// RequestID and PlanHash are read from the verified SEAL, never from the
	// Request capability returns — a refused decision's Request may not even
	// be the one this call asked about (a zero Request on some refusals).
	RequestID string
	PlanHash  string
	State     approval.State
	JobID     string
	ExpiresAt time.Time
	// stateReported is true only where State/JobID/ExpiresAt were actually
	// copied from capability's Request: classifyElicitedDecision's err == nil
	// branch, and its ErrNotPending/ErrDuplicateDecider branch when req.ID !=
	// "". approval.StatePending is the zero value, so a zero State does not
	// by itself mean "unknown" — without this flag, a refusal made before the
	// decider was even called (an unbound state, a malformed responder), or a
	// non-domain failure, would render as state "pending", which may be
	// untrue. A caller rendering a refusal (refusalOutput) must copy
	// State/JobID/ExpiresAt only when this is true.
	stateReported bool
	// Progress is set only when Err is nil; empty on every refusal.
	Progress string
	// OnBehalfOf is the asserted approver value (a responder's username)
	// handed to the decider. EMPTY on an AP-79 verified decision — nothing is
	// written to the asserted lane for a claude-code answer on its own
	// human's OAuth session — and on every refusal before the decider was
	// reached. See deciderReached for whether the decider was actually
	// called; that, not this field, is the was-it-recorded signal.
	OnBehalfOf string
	// deciderReached is true once acceptElicitedAnswer has called the
	// decider (whatever it returned) — set right alongside OnBehalfOf. It
	// replaces "OnBehalfOf is empty" as the was-the-decider-called signal:
	// under AP-79 the decider is reached with OnBehalfOf left empty, so that
	// old signal would mis-render a post-record failure (an audit write that
	// failed after a real decision) as "this call left the request
	// unchanged" — a false-safe reading security review #727 finding 1
	// forbade.
	deciderReached bool
	Err            error
}

// elicitedAnswer is what a retried tool call carries into acceptElicitedAnswer.
type elicitedAnswer struct {
	// RequestState is the MRTR requestState the client echoed back.
	RequestState string
	// InputResponses is the retry's answered elicitations.
	InputResponses sdkmcp.InputResponseMap
	// CallMeta is the retried call's params._meta — checked for a replay
	// marker alongside the elicitation response's own _meta (may be nil).
	// It is also where the retried call's declared client name is read
	// (AP-79).
	CallMeta sdkmcp.Meta
	// Tool is the retried call's params.name.
	Tool string
	// ArgsDigest must be computed EXACTLY as emission computes it:
	// requeststate.DigestArgs(json.Marshal(the handler's TYPED input value —
	// runOperationInput or rawExecInput)), the same computation elicit.go's
	// callArgsDigest performs when the tool handler parks the dispatch and
	// seals the state (#725). NEVER over the raw wire bytes of
	// params.arguments: a retry's arguments can reorder keys, add
	// whitespace, or otherwise differ byte-for-byte from what was
	// originally sent while still decoding to an identical typed value, and
	// only digesting the re-marshalled typed value survives that. Supplying
	// this digest on the retried call is the caller wiring's job (#727 /
	// S4a-2), not this function's — a caller that digests a different
	// representation (e.g. the raw bytes) makes every answer refuse (fail
	// closed, but a functional bug, not a security one). This function never
	// digests arguments itself.
	ArgsDigest requeststate.Digest
}

// acceptElicitedAnswer verifies and records one MRTR answer to a parked
// approval, returning a classification the caller can render without
// re-deciding anything.
//
// AP-64/AP-79 govern which approver gets recorded: a present responder
// assertion always takes the named path, never downgraded; only absent that
// does a retry declaring claude-code, on a session claudeCodeAnswerCounts
// admits, count as that human's own verified decision, with nothing written
// to the asserted lane.
//
// open and now are parameters rather than server fields so this function
// stays testable in isolation and so this issue does not have to touch
// mcp.go. open is the questioner's binding-checked stateOpener (elicit.go,
// questioner.opener) — never the Sealer itself: key custody stays in
// elicit.go's newQuestioner, and this file can only open a state bound to
// the call it is given, never unbound. tools_execution.go's answerThenDispatch
// wires this function into run_operation/raw_exec's retry path (#727,
// S4a-2).
//
// The machine-self-decision refusal (errNoNamedApprover) must be rendered
// AS-IS by the caller, never through renderApprovalError: AP-64 requires the
// identical message an approve_request carrying no approver returns (AP-48),
// and renderApprovalError's ErrMachineSelfDecision text tells the caller to
// pass an "approver" argument that an MRTR client does not have.
//
// Every failure before step 6 (calling the decider) returns elicitedRefused
// with Err set and the decider NOT called — nothing is recorded.
func acceptElicitedAnswer(ctx context.Context, decider ApprovalDecider, open stateOpener, now time.Time, p capability.Principal, in elicitedAnswer) elicitedAnswerResult {
	if decider == nil {
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: capability.ErrApprovalUnavailable}
	}
	if p.AccountID == "" {
		// A Principal with no stored Account never has a state sealed for it
		// (requeststate.Sealer.Seal refuses an empty AccountID).
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: errAnswerStateRefused}
	}
	var zeroDigest requeststate.Digest
	if in.ArgsDigest == zeroDigest {
		// Seal never seals a zero digest either, so a zero here means the
		// caller skipped digesting — explicit rather than relying on the
		// binding mismatch it would otherwise produce.
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: errAnswerStateRefused}
	}

	// Exactly one response, keyed by the request it answers.
	if len(in.InputResponses) != 1 {
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: errAnswerShape}
	}
	var requestID string
	for k := range in.InputResponses {
		requestID = k
	}

	// The seal, bound to this caller/request/tool/arguments in one call
	// (open is requeststate's OpenFor, never Open — a bare Open does not
	// check the binding, and a response keyed by any ID but the sealed
	// request ID fails Bind with ErrBindingMismatch here rather than needing
	// a separate comparison). No opener means no key: refuse, fail closed.
	if open == nil {
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: fmt.Errorf("%w: %w", errAnswerStateRefused, requeststate.ErrInvalidKey)}
	}
	st, err := open(in.RequestState, now, requeststate.Call{
		AccountID:  p.AccountID,
		RequestID:  requestID,
		Tool:       in.Tool,
		ArgsDigest: in.ArgsDigest,
	})
	if err != nil {
		return elicitedAnswerResult{Outcome: elicitedRefused, Err: fmt.Errorf("%w: %w", errAnswerStateRefused, err)}
	}

	// From here on, RequestID and PlanHash are always read from the SEAL, so
	// every remaining refusal still tells the caller which request it was
	// about.
	refused := func(err error) elicitedAnswerResult {
		return elicitedAnswerResult{Outcome: elicitedRefused, RequestID: st.RequestID, PlanHash: st.PlanHash, Err: err}
	}

	result, ok := in.InputResponses[requestID].(*sdkmcp.ElicitResult)
	if !ok || result == nil {
		return refused(errAnswerShape)
	}

	// Machine self-decision: any of these collapses into the same refusal as
	// approve_request with no approver (AP-64).
	if result.Action != "accept" && result.Action != "decline" {
		return refused(errNoNamedApprover)
	}
	if _, replayed := result.Meta[replayedFromMetaKey]; replayed {
		return refused(errNoNamedApprover)
	}
	if _, replayed := in.CallMeta[replayedFromMetaKey]; replayed {
		return refused(errNoNamedApprover)
	}
	// AP-64/AP-79: a two-way choice between the named form and this caller's
	// own verified decision, or refusal. A present responder key ALWAYS takes
	// the named path first, whatever the declared client name (AP-64): the
	// verified form only fills the gap the named form leaves, and it can
	// never rescue an answer the named form refused.
	declaredName, named := declaredClientName(in.CallMeta)
	isClaudeCodeCaller := named && declaredName == clientNameClaudeCode

	// Defence in depth (plan review #765, finding 1): production only ever
	// reaches this function for a claude-code retry on a session
	// claudeCodeAnswerCounts admits — isAnsweredRetry gates it via
	// clientCanBeAsked (tools_execution.go, elicit.go) before this file is
	// even called. This file re-checks anyway, rather than trusting that
	// gate: acceptElicitedAnswer is callable on its own, and a future caller
	// that skipped the gate must not be able to turn a claude-code CallMeta
	// carrying a real responder assertion into a named decision on a session
	// AP-78 would never have asked in the first place.
	if isClaudeCodeCaller && !claudeCodeAnswerCounts(p) {
		return refused(errNoNamedApprover)
	}

	_, hasResponder := result.Meta[responderMetaKey]

	var username string
	switch {
	case hasResponder:
		// The named form (AP-64). A responder that is present but malformed
		// (recognisedResponder not ok) or not gate "permission" is refused
		// with errNoNamedApprover and NEVER downgraded to the verified form
		// below.
		responder, recognised := recognisedResponder(result.Meta)
		if !recognised || responder.Gate != responderGatePermission {
			return refused(errNoNamedApprover)
		}
		// assertedApprover itself returns errNoNamedApprover for a blank (or
		// whitespace-only) username, and the bound audit error — never
		// truncated, never trimmed-then-accepted — for anything malformed.
		u, err := assertedApprover(responder.Username)
		if err != nil {
			return refused(err)
		}
		username = u
		ctx = withAssertedApprover(ctx, username)
	case isClaudeCodeCaller && claudeCodeAnswerCounts(p):
		// AP-79: this caller's own verified decision. username stays "" —
		// nothing is written to the asserted lane — and the clear is
		// explicit rather than merely skipping withAssertedApprover:
		// controlplane/auth.go's Middleware puts X-Relay-On-Behalf-Of into
		// ctx for every authenticated route including /mcp, so without this
		// a stray header would otherwise write the asserted lane anyway.
		// withAssertedApprover preserves the ctx's other assertions (a
		// traceparent, session_ref).
		ctx = withAssertedApprover(ctx, "")
	default:
		return refused(errNoNamedApprover)
	}

	approve := result.Action == "accept"
	updated, err := decider.DecideApproval(ctx, p, capability.ApprovalDecision{
		RequestID: st.RequestID,
		PlanHash:  st.PlanHash,
		Approve:   approve,
		// Reason is empty: nothing on the answered-retry envelope carries a
		// free-text note today.
		Channel: approval.ChannelInBand,
	})

	out := classifyElicitedDecision(updated, err, approve, now)
	out.RequestID = st.RequestID
	out.PlanHash = st.PlanHash
	out.OnBehalfOf = username
	out.deciderReached = true
	return out
}

// classifyElicitedDecision turns what capability.Service.DecideApproval
// returned into an elicitedOutcome, deciding nothing itself: it only reads
// the state the domain already decided.
//
// req is the Request DecideApproval returned; err is its error, or nil. On
// ErrNotPending or ErrDuplicateDecider capability returns the Request as it
// now stands (requestOnRefusal); on every other domain refusal, and on a
// non-domain (store/audit) failure, req is the zero value. approve is the
// answer THAT WAS SENT (Action == "accept"), passed in rather than read off
// req so the decline rule below is decided in exactly one place and directly
// testable.
func classifyElicitedDecision(req approval.Request, err error, approve bool, now time.Time) elicitedAnswerResult {
	if err == nil {
		out := elicitedAnswerResult{
			State:         req.State,
			JobID:         req.JobID,
			ExpiresAt:     req.ExpiresAt,
			Progress:      req.Progress(),
			stateReported: true,
		}
		switch {
		case req.State == approval.StateApproved && !approve:
			// A recorded decline that capability reports as an approval is
			// not a state this function can explain — unreachable while a
			// denial is terminal (approval.Request.Decide), and fail closed
			// if that ever changes. Ordered ABOVE the JobID-bound case so a
			// (currently impossible) recorded-decline-reporting-approved-
			// with-Job can never read as elicitedApprovedJobBound with Err
			// nil — that would present the decliner's answer as an approval.
			out.Outcome = elicitedRefused
			out.Err = errDeclineNotHonoured
			out.Progress = ""
		case req.State == approval.StateApproved && req.JobID != "":
			out.Outcome = elicitedApprovedJobBound
		case req.State == approval.StateApproved:
			out.Outcome = elicitedApproved
		case req.State == approval.StateDenied:
			out.Outcome = elicitedDenied
		case req.State == approval.StatePending:
			out.Outcome = elicitedStillPending
		case req.State == approval.StateExpired:
			out.Outcome = elicitedLapsed
		default:
			// Fail closed: an approval.State this switch does not recognise
			// must never fall through to elicitedRefused's zero value with
			// Err left nil — that would read as "nothing happened" rather
			// than "refused", contradicting the doc on elicitedAnswerResult.
			out.Outcome = elicitedRefused
			out.Progress = ""
			out.Err = errUnknownRequestState
		}
		return out
	}

	if errors.Is(err, approval.ErrNotPending) || errors.Is(err, approval.ErrDuplicateDecider) {
		if req.ID == "" {
			// Eligibility (requester exclusion, machine self-decision,
			// audience, channel strength) is checked AFTER Terminal/Expired
			// inside the domain, so these two sentinels can also fire with no
			// Request read at all (capability.Approval itself failed). See
			// capability.requestOnRefusal.
			return elicitedAnswerResult{Outcome: elicitedRefused, Err: err}
		}
		out := elicitedAnswerResult{State: req.State, JobID: req.JobID, ExpiresAt: req.ExpiresAt, Err: err, stateReported: true}
		switch {
		case req.State == approval.StateApproved && req.JobID != "":
			// Re-attaching to an existing Job (AP-67) dispatches nothing new,
			// for either answer.
			out.Outcome = elicitedApprovedJobBound
		case req.State == approval.StateApproved && !approve:
			// The human said no. Another approver's out-of-band approval must
			// never be turned into "call Run" on the decliner's answer.
			out.Outcome = elicitedRefused
		case req.State == approval.StateApproved && approve && req.PastDeadline(now):
			// Approved, but its Job was never bound before its deadline: not
			// dispatchable, so this is not a "call Run" outcome.
			out.Outcome = elicitedLapsed
		case req.State == approval.StateApproved && approve:
			out.Outcome = elicitedApproved
		case req.State == approval.StateDenied:
			out.Outcome = elicitedDenied
		case req.State == approval.StateExpired:
			out.Outcome = elicitedLapsed
		case req.State == approval.StatePending && errors.Is(err, approval.ErrNotPending):
			// capability refuses a Pending Request as not pending ONLY
			// because its own clock found the deadline passed — so a Pending
			// Request that is not yet past the deadline by THIS clock is
			// clock skew between the two reads, and the Request is lapsed
			// either way.
			out.Outcome = elicitedLapsed
		case req.State == approval.StatePending && errors.Is(err, approval.ErrDuplicateDecider):
			if req.PastDeadline(now) {
				out.Outcome = elicitedLapsed
			} else {
				out.Outcome = elicitedStillPending
			}
		}
		return out
	}

	// Every other domain sentinel (ErrRequesterExcluded, ErrNotInAudience,
	// ErrMachineSelfDecision, ErrWeakChannel, ErrPlanChanged, ErrNotFound),
	// capability.ErrApprovalUnavailable, and any non-domain error (including
	// the audit-write failure, where capability still returns the updated
	// Request — see capability.DecideApproval) all land here: refused, no
	// state copied.
	return elicitedAnswerResult{Outcome: elicitedRefused, Err: err}
}

var (
	// errAnswerStateRefused is returned when the retried call's requestState
	// fails to open or fails to bind to this caller, request, tool or
	// arguments.
	errAnswerStateRefused = errors.New("mcp: the retried call's request state is not valid for this caller, request and call — " +
		"it may be tampered, expired, sealed for another request or call, or the elicitation response is keyed to a different request than the one sealed; " +
		"the request can still be answered with approve_request or on the Control API")

	// errAnswerShape is returned when the retry does not carry exactly one
	// elicitation response keyed by the sealed request ID.
	errAnswerShape = errors.New("mcp: an answered retry must carry exactly one elicitation response, keyed by the request it answers")

	// errDeclineNotHonoured is classifyElicitedDecision's fail-closed
	// backstop for a state approval.Request.Decide should never produce.
	errDeclineNotHonoured = errors.New("mcp: the decline was recorded but the request reports approved; it is not treated as an approval of this call")

	// errUnknownRequestState is classifyElicitedDecision's fail-closed
	// backstop when err is nil but req.State is none of approval.State's
	// known values — never reachable today, kept so an unrecognised state
	// refuses rather than silently reading as elicitedRefused with Err nil.
	errUnknownRequestState = errors.New("mcp: the decision was recorded but the request's resulting state is not recognised")
)

// -----------------------------------------------------------------------
// Rendering an answered retry's outcome (#727). tools_execution.go calls
// only these methods and answerStateRefusedOutput — it never builds a
// decision or a refusal message of its own. See the file header, "The
// second envelope", for why the rendering lives here.
// -----------------------------------------------------------------------

// The four "what happened to the call" texts decisionOutput's NextStep opens
// with, chosen from (Outcome, what the dispatch actually returned) rather
// than from Outcome alone (plan review suggestion 3): a partial quorum
// completing concurrently, a rule changing mid-retry, or a re-park can each
// make the Outcome alone contradict what this response actually carries.
const (
	nextStepDenialIsTerminal      = "a denial is terminal. Nothing ran; do not retry."
	nextStepReattachedExistingJob = "the results shown are the Job this approval already released, re-attached. Nothing new was dispatched."
	nextStepRanThePipeline        = "the call was re-entered through the full dispatch pipeline once in this response, and the Job shown ran. Do not re-issue it."
	nextStepReParkedOnApproval    = "the call was re-entered once and is parked on approval (see pending_approval for what it waits on). Nothing ran in this response."
	nextStepNothingWasDispatched  = "nothing was dispatched in this response."
)

// The two "what became of the answer" texts decisionOutput's NextStep ends
// with. Chosen by r.Err rather than collapsed into one "not recorded" string
// (plan review cycle 2, suggestion 2): ErrDuplicateDecider means THIS
// Account already decided — the request need not be decided at all, quorum
// may still be open — while every other non-nil r.Err reaching this function
// (only ErrNotPending) means the request had already reached a resolution
// before this answer arrived.
const (
	nextStepAnswerRecorded = "the answer was recorded (progress shown when the rule needs more)."

	// nextStepAnswerNotRecordedAlreadyDecided must never read as if the
	// person who declined had approved — the state shown is the request's
	// actual outcome, not this call's answer.
	nextStepAnswerNotRecordedAlreadyDecided = "your answer was NOT recorded: the request had already reached a resolution " +
		"(decided, or lapsed) before this call arrived (state shown)."

	nextStepAnswerNotRecordedDuplicateDecider = "your answer was NOT recorded: this Account had already decided this request before " +
		"this call arrived. Any progress or Job shown reflects other approvers' decisions, not this one."
)

// decisionOutput renders r as the decision block a successful branch of an
// answered retry carries alongside "after" — the dispatch's own output on
// the pipeline branch, the re-attached Job on the Job-bound branch, or a
// zero value on the denied branch. Built only from r's own fields plus two
// facts read from after: whether a Job id is present, and whether a park is
// present. Never called for Outcome == elicitedRefused; see refusalOutput
// for that branch.
func (r elicitedAnswerResult) decisionOutput(after RunOrPlanOutput) *ApprovalDecisionOutput {
	out := &ApprovalDecisionOutput{
		RequestID: r.RequestID,
		State:     r.State.String(),
		Progress:  r.Progress,
	}
	if r.Err == nil {
		// Channel names an IN-BAND DECISION; it stays empty whenever r.Err is
		// non-nil, because an answer that was not recorded made no in-band
		// decision at all (plan review suggestion 4). OnBehalfOf is r's own
		// asserted-approver value as-is: empty here means AP-79's verified
		// decision wrote nothing to the asserted lane, never that the
		// decision itself was not recorded.
		out.Channel = approval.ChannelInBand.String()
		out.OnBehalfOf = r.OnBehalfOf
	}

	var part1 string
	switch {
	case r.Outcome == elicitedDenied:
		part1 = nextStepDenialIsTerminal
	case r.Outcome == elicitedApprovedJobBound && after.JobID != "":
		part1 = nextStepReattachedExistingJob
	case after.JobID != "":
		part1 = nextStepRanThePipeline
	case after.PendingApproval != nil:
		part1 = nextStepReParkedOnApproval
	default:
		part1 = nextStepNothingWasDispatched
	}

	var part2 string
	switch {
	case r.Err == nil:
		part2 = nextStepAnswerRecorded
	case errors.Is(r.Err, approval.ErrDuplicateDecider):
		part2 = nextStepAnswerNotRecordedDuplicateDecider
	default:
		part2 = nextStepAnswerNotRecordedAlreadyDecided
	}

	out.NextStep = part1 + " " + part2
	return out
}

// isKnownApprovalRefusal reports whether err is one of package approval's
// eligibility sentinels or capability.ErrApprovalUnavailable — the refusals
// renderApprovalError already has a specific, actionable message for.
// Listed explicitly, in the style of capability.isApprovalDomainError, so a
// new sentinel has to be classified deliberately rather than inheriting a
// message by accident.
func isKnownApprovalRefusal(err error) bool {
	for _, sentinel := range []error{
		approval.ErrNotFound,
		approval.ErrWeakChannel,
		approval.ErrRequesterExcluded,
		approval.ErrMachineSelfDecision,
		approval.ErrNotInAudience,
		approval.ErrDuplicateDecider,
		approval.ErrPlanChanged,
		approval.ErrNotPending,
		capability.ErrApprovalUnavailable,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// answerRefusalNextStepUnchanged is refusalOutput's NextStep for a refusal
// made before the decider was ever reached (!r.deciderReached), and for
// approval.ErrPlanChanged: in both cases the request, if one exists, is
// still open and still answerable exactly as this text says — re-reading the
// queue for the current plan_hash is what ErrPlanChanged itself asks for.
const answerRefusalNextStepUnchanged = "this call left the request (if any) unchanged. " +
	"It can still be answered with approve_request or on the Control API endpoint."

// answerRefusalNextStepCannotAnswerHere is refusalOutput's NextStep for
// approval.ErrWeakChannel: the rule requires an out-of-band decision, so —
// unlike every other refusal isKnownApprovalRefusal recognises — no in-band
// tool, approve_request included, can ever satisfy it. Sharing
// answerRefusalNextStepUnchanged's "it can still be answered with
// approve_request" here would contradict this refusal's own Reason (PR #738
// follow-up review, finding 1).
const answerRefusalNextStepCannotAnswerHere = "no in-band tool — approve_request included — can decide this one. " +
	"A human must decide it on the Control API's decision endpoint, with their own out-of-band credential."

// answerRefusalNextStepIneligibleAccount is refusalOutput's NextStep for
// approval.ErrNotInAudience: THIS Account is not in the request's named
// audience, so saying "it can still be answered" without naming who by would
// read as an invitation to retry with the same Account — but a different,
// eligible Account can still answer it in-band, so approve_request stays
// on the table (unlike approval.ErrRequesterExcluded, which never can: see
// answerRefusalNextStepRequesterExcluded).
const answerRefusalNextStepIneligibleAccount = "this Account is not in the request's audience. An Account in the " +
	"audience must decide it, with approve_request from that Account's own session or on the Control API."

// answerRefusalNextStepRequesterExcluded is refusalOutput's NextStep for
// approval.ErrRequesterExcluded: this call runs in the requesting Account's
// own MCP session, and approve_request is the in-band channel — so unlike
// answerRefusalNextStepIneligibleAccount, no Account reachable from this
// session can ever decide the request. Only the Control API's decision
// endpoint, exercised by a different human with their own credential, can.
const answerRefusalNextStepRequesterExcluded = "the Account that asked cannot decide it. A different human must " +
	"decide it out-of-band, on the Control API's decision endpoint with their own credential."

// answerRefusalNextStepNoSuchRequest is refusalOutput's NextStep for
// approval.ErrNotFound: there is no request at this id to answer at all, so
// nothing is "still answerable" until the caller finds the right one.
const answerRefusalNextStepNoSuchRequest = "there is no request to answer at this request_id — it may never have " +
	"existed, or have expired and been swept. Check request_id."

// answerRefusalNextStepRequestClosed is refusalOutput's NextStep for
// approval.ErrNotPending outside the approved-with-no-Job decline (which gets
// answerRefusalNextStepDeclineNotRecorded instead): the request has already
// reached a resolution, so nobody can decide it again.
const answerRefusalNextStepRequestClosed = "this request is no longer open (already decided, or expired); " +
	"it cannot be decided again."

// answerRefusalNextStepAlreadyDecidedByThisAccount is refusalOutput's
// NextStep for approval.ErrDuplicateDecider outside the approved-with-no-Job
// decline: only THIS Account's answer is redundant — unlike
// answerRefusalNextStepRequestClosed, the request itself may still need more
// approvals from someone else.
const answerRefusalNextStepAlreadyDecidedByThisAccount = "this Account already decided this request; answering again " +
	"from the same Account changes nothing. If the rule still needs more approvals, a different Account must supply " +
	"them, with approve_request or the Control API."

// answerRefusalNextStepApprovalsUnavailable is refusalOutput's NextStep for
// capability.ErrApprovalUnavailable: no decider is configured on this Relay
// at all, so there is no endpoint — in-band or on the Control API — that can
// decide the request.
const answerRefusalNextStepApprovalsUnavailable = "approvals are not configured on this Relay: there is no endpoint, " +
	"in-band or on the Control API, that can decide this request."

// answerRefusalNextStepDeclineNotRecorded is refusalOutput's NextStep when a
// decline was refused with ErrNotPending or ErrDuplicateDecider because the
// request already stands approved with no Job bound: the caller must never
// read this as if the decline had won.
const answerRefusalNextStepDeclineNotRecorded = "the decline was not recorded: the request stands approved. This call dispatched nothing."

// answerRefusalNextStepDeclineRecordedButNotHonoured is refusalOutput's
// NextStep for errDeclineNotHonoured — deliberately its own text rather than
// answerRefusalNextStepDeclineNotRecorded's, because that text would
// contradict errDeclineNotHonoured's own Reason (which says the decline WAS
// recorded, just not honoured as an approval of this call) (security review
// #727 finding 2 / code review suggestion 1).
const answerRefusalNextStepDeclineRecordedButNotHonoured = "the decline was recorded, but the request still reports approved and is not treated " +
	"as an approval of this call. This call dispatched nothing."

// answerRefusalNextStepMayAlreadyReflectAnswer is refusalOutput's NextStep
// for the default arm below: the decider WAS reached (r.deciderReached) and
// something non-domain failed afterwards, so — unlike
// answerRefusalNextStepUnchanged — this must never say the request is
// unchanged or safe to answer again outright; the decision may already be
// durable (security review #727 finding 1).
const answerRefusalNextStepMayAlreadyReflectAnswer = "the request may already reflect this answer. Confirm its state with the Control " +
	"API's approval read before answering again or re-issuing the call."

// knownRefusalNextStep picks refusalOutput's NextStep for a refusal
// isKnownApprovalRefusal recognises. Chosen per sentinel rather than the one
// generic "can still be answered with approve_request" text every sentinel
// used to share: that text is true of exactly one of these
// (approval.ErrPlanChanged) and false, in a different way, of the rest — see
// each NextStep constant's own doc for which way (PR #738 follow-up review,
// finding 1). Called only once r.Err is known to satisfy
// isKnownApprovalRefusal; every branch below assumes that.
func (r elicitedAnswerResult) knownRefusalNextStep() string {
	switch {
	case errors.Is(r.Err, approval.ErrNotFound):
		return answerRefusalNextStepNoSuchRequest
	case errors.Is(r.Err, approval.ErrWeakChannel):
		return answerRefusalNextStepCannotAnswerHere
	case errors.Is(r.Err, approval.ErrRequesterExcluded):
		return answerRefusalNextStepRequesterExcluded
	case errors.Is(r.Err, approval.ErrNotInAudience):
		return answerRefusalNextStepIneligibleAccount
	case errors.Is(r.Err, approval.ErrNotPending), errors.Is(r.Err, approval.ErrDuplicateDecider):
		// The decline-not-recorded text applies only when this landed on a
		// request that stands approved with no Job bound — a decline that
		// lost the race to an out-of-band approval (security review #727
		// finding 2). Otherwise ErrNotPending means the REQUEST is closed to
		// everyone, while ErrDuplicateDecider means only THIS Account's say
		// in it is spent — the request itself may still need more approvals
		// from someone else, so the two get different text.
		switch {
		case r.stateReported && r.State == approval.StateApproved && r.JobID == "":
			return answerRefusalNextStepDeclineNotRecorded
		case errors.Is(r.Err, approval.ErrDuplicateDecider):
			return answerRefusalNextStepAlreadyDecidedByThisAccount
		default:
			return answerRefusalNextStepRequestClosed
		}
	case errors.Is(r.Err, approval.ErrPlanChanged):
		return answerRefusalNextStepUnchanged
	default:
		// capability.ErrApprovalUnavailable is the only sentinel left in
		// isKnownApprovalRefusal's list that reaches here:
		// approval.ErrMachineSelfDecision is intercepted by refusalOutput's
		// earlier arm, before isKnownApprovalRefusal is even consulted.
		return answerRefusalNextStepApprovalsUnavailable
	}
}

// answerStateRefusedOutput builds the AnswerRefusalOutput for a call whose
// arguments could not even be digested (tools_execution.go's callArgsDigest
// failing before acceptElicitedAnswer is ever called) — the one refusal
// shape tools_execution.go needs without writing refusal text of its own.
// RequestID stays empty: the requestState was never opened, so which request
// this call named is not known.
func answerStateRefusedOutput() *AnswerRefusalOutput {
	return &AnswerRefusalOutput{
		Reason:   errAnswerStateRefused.Error(),
		NextStep: answerRefusalNextStepUnchanged,
	}
}

// refusalOutput renders r as the refusal block an answered retry carries
// when Outcome == elicitedRefused. It exposes only RequestID, State, JobID
// and ExpiresAt (#735 review; issue #727 comment 1) — never the raw
// Decisions elicitedAnswerResult itself cannot even carry.
func (r elicitedAnswerResult) refusalOutput() *AnswerRefusalOutput {
	out := &AnswerRefusalOutput{RequestID: r.RequestID}
	if r.stateReported {
		out.State = r.State.String()
		out.JobID = r.JobID
		out.ExpiresAt = controlplane.RFC3339(r.ExpiresAt)
	}

	out.NextStep = answerRefusalNextStepUnchanged
	switch {
	case errors.Is(r.Err, approval.ErrMachineSelfDecision):
		// AP-64: byte-for-byte the same message approve_request gives a
		// caller who names no approver, never renderApprovalError's "pass
		// their identity in `approver`" wording, which an MRTR client has no
		// argument to act on. This arm must come before the
		// isKnownApprovalRefusal arm below, which would otherwise also match
		// ErrMachineSelfDecision with renderApprovalError's text instead.
		out.Reason = errNoNamedApprover.Error()
	case errors.Is(r.Err, errAnswerStateRefused), errors.Is(r.Err, errAnswerShape):
		// Both messages already point at approve_request and the Control API.
		out.Reason = r.Err.Error()
	case errors.Is(r.Err, audit.ErrAssertedFieldTooLong), errors.Is(r.Err, audit.ErrAssertedFieldInvalid):
		// assertedApprover's malformed-responder refusal: never truncated,
		// never trimmed-then-accepted (see assertedApprover's own doc).
		out.Reason = r.Err.Error()
	case errors.Is(r.Err, errDeclineNotHonoured):
		// The Reason says the decline WAS recorded, just not honoured as an
		// approval of this call, so this gets its own NextStep rather than
		// answerRefusalNextStepDeclineNotRecorded's "was not recorded" text,
		// which would contradict it (security review #727 finding 2 / code
		// review suggestion 1).
		out.Reason = r.Err.Error()
		out.NextStep = answerRefusalNextStepDeclineRecordedButNotHonoured
	case errors.Is(r.Err, errUnknownRequestState):
		// classifyElicitedDecision's own fail-closed backstop; says the
		// decision was recorded, so the default arm's "left the request
		// unchanged" text would contradict that Reason.
		out.Reason = r.Err.Error()
		out.NextStep = answerRefusalNextStepMayAlreadyReflectAnswer
	case isKnownApprovalRefusal(r.Err):
		out.Reason = renderApprovalError(r.Err).Error()
		out.NextStep = r.knownRefusalNextStep()
	case !r.deciderReached:
		// The decider was never reached (see elicitedAnswerResult's doc on
		// deciderReached) — nothing could have been recorded, whatever the
		// error.
		out.Reason = fmt.Sprintf("this answer was not recorded: %v. The request, if any, can still be answered "+
			"with approve_request or on the Control API.", r.Err)
	default:
		// A non-domain failure reaching us AFTER the decider was called: the
		// decision may already be durable (e.g. an audit write that failed
		// afterwards — capability.DecideApproval's own doc). This must never
		// claim the answer was ignored (issue #727 comment 2, point 2), and
		// the NextStep must not say the request is unchanged either
		// (security review #727 finding 1).
		//
		// One case in this arm never actually recorded anything: an
		// ApprovalAuthorizer refusal (capability.DecideApproval's
		// AuthorizeApprovalDecision step, e.g. authz.RoleGate) fires before
		// any decision is attempted. This file has no capability-level
		// sentinel to distinguish that from a post-recording failure without
		// coupling to a specific ApprovalAuthorizer implementation, so the
		// text stays the safe over-approximation: telling a caller who was
		// never recorded to confirm the request's state is redundant, never
		// wrong — unlike the reverse (code review #727 finding 2).
		out.Reason = fmt.Sprintf("the answer may have been recorded, but recording or auditing it failed: %v. "+
			"Confirm the request's state by reading it back — GET /api/v1/approvals/{id} on the Control API — "+
			"before acting; approve_request records a new decision, it does not read one back.", r.Err)
		out.NextStep = answerRefusalNextStepMayAlreadyReflectAnswer
	}

	return out
}

// dispatchError wraps an error dispatch() returned AFTER this answer was
// already taken (BLOCKING 2, plan review cycle 1). It is deliberately
// neutral about whether anything ran: Service.Run can return per-Node
// results together with an error (a failed dispatch audit write, or a
// failed BindJob), and dispatch() also returns an error when renderJob fails
// AFTER a successful Run — in both cases a Job may already exist, so the
// text must never say nothing ran, nothing was dispatched, or that the
// dispatch "was refused" as a fact.
func (r elicitedAnswerResult) dispatchError(err error) error {
	recorded := "no"
	if r.Err == nil {
		recorded = "yes"
	}
	return fmt.Errorf("the answer to approval request %s left it %s (answer recorded: %s). The call was then "+
		"re-entered once, and that dispatch returned an error. It may have been refused before anything ran, "+
		"or it may have run and then failed to record or read back its results. Do not assume either: check "+
		"get_job and the audit trail before re-issuing the call: %w", r.RequestID, r.State.String(), recorded, err)
}

// reattachError wraps an error reading back the Job-bound branch's already-
// released Job — either the read-audit write itself (BLOCKING 1, ADR-0025:
// an unauditable read must fail closed rather than silently happen) or the
// Job read-back that follows it. Either way the approval decision already
// stands and nothing new was dispatched; this is an infrastructure read
// failure, not a row of the decision table, so it must never say the Job
// did not run.
func (r elicitedAnswerResult) reattachError(err error) error {
	return fmt.Errorf("approval request %s already released Job %s: the decision stands and nothing new was "+
		"dispatched, but reading it back failed: %w; retry with get_job", r.RequestID, r.JobID, err)
}
