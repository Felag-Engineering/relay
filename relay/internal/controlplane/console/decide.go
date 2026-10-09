package console

// decide.go is the Console's approve/deny control (#453, specs 08 and 14):
// the Console's SECOND write route, after Cancel (#595, cancel.go). It lives
// in its own file, exactly as Cancel does, so seams.go's "every seam here is
// read-only" claim stays true unqualified.
//
// The role floor, the requester exclusion, the machine-self-decision rule,
// the audience, the duplicate-decider rule, the plan-hash binding, channel
// strength and the quorum arithmetic are ALL decided in
// capability.Service.DecideApproval, exactly as they are for the Control
// API's out-of-band endpoint and the MCP surface — and are re-decided
// NOWHERE in this file. The audit record is capability's too
// (approval_decide.go:226-239); this file holds no appender and writes none.
//
// Deciding happens on the approval OBJECT and never on a queue row —
// approvals.go's header explains why, and that reasoning survives this
// change intact: a row-level Approve would let someone approve without
// reading what they approved.
//
// # The asymmetry with Cancel, stated rather than elided
//
// Cancel can only ever REDUCE what runs: it asks something already
// dispatched to stop, and the request itself changes no outcome that is not
// already true. An approval is the opposite shape — it RELEASES execution
// that would otherwise never happen. That difference is real, and three
// things make the release acceptable on this surface:
//
//  1. The Plan being released is Relay-authored and content-addressed, and it
//     already passed Freeze, Selector resolution, authz and the blast cap
//     before it ever parked (capability/approval.go:223, checkApproval,
//     called from the end of Run). Nothing about THIS decision widens what
//     was already checked.
//  2. DecideApproval dispatches NOTHING. Satisfying a Requirement only lets
//     the same Plan proceed the next time the original requester re-drives
//     it, matched by plan hash — which is also why registry drift re-parks
//     with no drift detector anywhere: a changed fan-out is a changed hash,
//     and a changed hash finds no satisfied Request.
//  3. Step-up here binds a human's intent to THIS decision, not to the
//     session — see the key-decisions note below.
//
// Given that, the conclusion ADR-0026 decision 5 already draws applies
// unchanged: this route is NOT gated behind console_execution. That flag
// scopes to the composer and to dispatch routes, and this route composes
// nothing — it answers a Plan the Relay already built. See console.go's
// Routes for the route-table half of this argument.
//
// # Step-up: a credential in the request, never a window check
//
// There is no re-auth round trip, and therefore nothing to replay. The
// password is verified INSIDE this handler, in the same HTTP request as the
// decision it authorises, immediately before DecideApproval is called. What
// binds the re-authenticated request to THIS approval:
//
//  1. It is literally the same request — the credential is checked in the
//     same goroutine as the decision, with no artefact crossing a request
//     boundary.
//  2. The approval id is in the PATH and the plan hash in a hidden field; the
//     domain refuses a hash that does not match the record
//     (approval.ErrPlanChanged).
//  3. The session CSRF token binds the submission to this session, and
//     form-action 'self' plus frame-ancestors 'none' (security.go) close
//     form-hijack and clickjack.
//  4. ConsoleSessionFromContext is browser-lane only, so the Account
//     d.Auth.StepUp verifies is necessarily the Account principal() attributes
//     — there is no lane on which they can differ.
//  5. Nothing is stored server-side that a later request could redeem AS
//     THIS DECISION. (The session's AuthenticatedAt stamp IS refreshed as a
//     normal side effect of StepUp and IS stored; this claim is about a
//     bearer credential for the decision itself, not about that stamp.)
//
// Rejected: stash the pending decision (a server-side map, or a signed
// cookie keyed by a nonce) and replay it after a separate re-auth POST. That
// artefact WOULD BE a bearer credential for an approval — it would need its
// own expiry and its own store, and the replay request's decision identity
// would come from the stash rather than from what the human is looking at,
// which is a confused deputy: anything that can plant or swap the stash
// forges an approval while the password is genuine.
//
// The ladder is the shared requireStepUp (stepup.go) in stepUpPerAct mode, as
// approval.md AP-16 requires ("re-authenticates at the moment of deciding"):
// the window is never a bypass here. consoleauth remains the one owner of the
// step-up window; this handler never consults it, and every decision costs its
// own password. That is STRICTER than the window the Account acts use (#879),
// which invariant 10 permits (an adapter may offer less, never more), and it
// is what spec 08 asks for: a one-click second approval is the rubber-stamp
// failure this whole screen exists to prevent. A successful step-up rotates
// the session identifier (#879), and the page carries the new CSRF token.
//
// A decision's successful step-up still stamps the session, so it opens the
// window for the Account acts. That is stated in stepup.go, not a surprise.
//
// # Import-scope
//
// This file is the Console's SECOND importer of internal/authz (cancel.go
// was the first), and it names exactly one symbol from it —
// authz.ErrUnauthorized — to recognise a refusal the capability layer already
// made. The authz allowlist in no_dispatch_test.go is package-wide, not
// per-file, so this needs no change there; only that file's comment does.

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// ApprovalDecider is the one write seam this file holds. Its single method
// mirrors capability.Service.DecideApproval's signature EXACTLY, so
// *capability.Service satisfies it with no adapter — the same shape
// JobCanceller (cancel.go) takes for CancelJob. The returned approval.Request
// is discarded by the handler; it stays in the signature only to keep the
// mirror exact.
type ApprovalDecider interface {
	DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error)
}

// decideApprovalPattern is this route's ServeMux pattern, named so
// decideOffered can compare against routesFor's output rather than
// restating the path (mirrors cancelJobPattern, cancel.go).
const decideApprovalPattern = "POST /console/approvals/{approval_id}/decision"

// decideStepUp is the decide route's step-up ask. stepUpPerAct: a decision
// always costs its own password and never consults the window (approval.md
// AP-16).
var decideStepUp = stepUpAsk{
	mode:     stepUpPerAct,
	required: "Step-up re-authentication is required to decide an approval.",
	undone:   "Nothing was decided.",
	act:      "an approval decision",
	render: func(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
		renderDecideResult(w, pg, status, decideResultView{Heading: heading, ApprovalHref: href, ApprovalLabel: label})
	},
}

// decideApprovalAction builds the form action for approvalID.
func decideApprovalAction(approvalID string) string {
	return "/console/approvals/" + url.PathEscape(approvalID) + "/decision"
}

// Bounds for this route's own input, declared beside the code that uses
// them.
const (
	// maxApprovalIDBytes mirrors maxJobIDBytes (job.go).
	maxApprovalIDBytes = 128

	// maxPlanHashBytes bounds the hidden plan_hash field.
	maxPlanHashBytes = 128

	// maxDecideReasonBytes is the SAME 1024 the Control API enforces
	// (api/approvals.go's maxDecisionReasonLen), restated with a
	// cross-reference rather than imported, because each surface bounds its
	// own input independently. The reason is echoed into an audit Reason
	// column, so an unbounded one lets a caller size a row in the trail.
	maxDecideReasonBytes = 1024
)

// decideOffered reports whether role may reach the decide route at all —
// mount-time absence, never authorization, exactly as cancelOffered documents
// for Cancel. capability's ApprovalAuthorizer inside DecideApproval is the
// authority.
//
// Both d.Decide and d.Auth are required: a decision that cannot be
// step-up-verified must not be offered at all, so an operator wiring one seam
// without the other gets an absent control rather than a control that always
// fails.
func decideOffered(d Deps, role accounts.Role) bool {
	if d.Decide == nil || d.Auth == nil {
		return false
	}
	for _, r := range routesFor(d, role) {
		if r.Pattern() == decideApprovalPattern {
			return true
		}
	}
	return false
}

// handleDecideApproval implements POST /console/approvals/{approval_id}/decision.
func handleDecideApproval(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Decide == nil || d.Auth == nil || d.Approvals == nil {
			unavailable(w, "deciding an approval")
			return
		}

		id, ok := pathID(w, r, "approval_id", maxApprovalIDBytes)
		if !ok {
			return
		}

		_, ok = controlplane.ConsoleSessionFromContext(r.Context())
		if !ok {
			// FAIL CLOSED, the same shape handleLogout's identical branch
			// takes (login.go): an authenticated request reached a gated
			// /console/ route with no resolved browser session, which the
			// cookie lane cannot produce. The only way here is a bearer-lane
			// caller reaching this POST — not browser-reachable, so this is a
			// wiring alarm, and there is no session to step up.
			d.logger().ErrorContext(r.Context(), "console decide-approval reached without a resolved browser session",
				"path", r.URL.Path)
			http.Error(w, "the Relay could not identify the session to step up", http.StatusInternalServerError)
			return
		}

		// ParseForm, then PostFormValue, never r.Body: submittedCSRFToken
		// (security.go) reads the X-CSRF-Token HEADER first and only falls
		// back to the form field, and the layout puts the token in hx-headers
		// on <body> — so for an HTMX submission Secure takes the header path
		// and never parses the body at all. Calling ParseForm here is
		// therefore REQUIRED, not merely idempotent; it is also safe for the
		// plain-form path, where PostFormValue has already cached r.PostForm.
		// ParseForm caps a urlencoded body at 10 MB, which is the only body
		// bound this route gets — the field-by-field bounds below are the
		// real control.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not read the decision form", http.StatusBadRequest)
			return
		}

		pg, ok := page(d, w, r, "Decide")
		if !ok {
			return
		}

		// Accept only "approve" or "deny". Anything else — including an
		// absent field — is refused rather than defaulted in either
		// direction: the boolean must never be inferred from silence.
		answer := r.PostFormValue("answer")
		if answer != "approve" && answer != "deny" {
			renderDecideResult(w, pg, http.StatusBadRequest, decideResultView{
				Heading: "This form did not carry a recognisable answer. Nothing was decided.",
			})
			return
		}

		planHash := r.PostFormValue("plan_hash")
		if planHash == "" || len(planHash) > maxPlanHashBytes {
			renderDecideResult(w, pg, http.StatusBadRequest, decideResultView{
				Heading: "A decision binds to the Plan it was shown, and this form carried no usable plan hash. Nothing was decided.",
			})
			return
		}

		reason := r.PostFormValue("reason")
		if len(reason) > maxDecideReasonBytes {
			renderDecideResult(w, pg, http.StatusBadRequest, decideResultView{
				Heading: "That reason is too long (over 1024 bytes). Nothing was decided.",
			})
			return
		}

		if r.PostFormValue("password") == "" {
			decideStepUp.refuseMissing(w, pg)
			return
		}

		// Console-side narrowing: a Grant request is refused here, never
		// decided. Spec 08 requires a Grant's Scope to have been expanded at
		// least once before it is approved, and this Console does not
		// enforce that yet — invariant 10's "offer less, never widen".
		// grantUnreadable refuses too: the card already refuses to render
		// either block in that state (approvals.go), and deciding while not
		// knowing which kind of Request this is is the dangerous direction
		// (approvals.go's "the most dangerous sentence this screen could
		// produce").
		switch _, lookup := grantForApproval(r.Context(), d, id); lookup {
		case grantIsAPlan:
			// Proceed — this Request authorizes a Plan, not a Scope.
		case grantFound:
			renderDecideResult(w, pg, http.StatusConflict, decideResultView{
				Heading: "This Request authorizes a Scope; its Scope must be expanded before approval, " +
					"and this Console does not enforce that yet. Nothing was decided; answer it through " +
					"the Control API.",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Back to this Request.",
			})
			return
		default: // grantUnreadable
			renderDecideResult(w, pg, http.StatusConflict, decideResultView{
				Heading: "The Approval grant store could not be read, so this Console cannot tell whether " +
					"this Request authorizes a Scope or one Plan. Nothing was decided.",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Back to this Request.",
			})
			return
		}

		// Step-up, last before the decision: no call to d.Decide on any false
		// return. The early empty-password check above makes requireStepUp's
		// own per-act empty branch unreachable from here; it is kept anyway
		// as defence in depth, so moving that check can never open a
		// password-less decision.
		if !requireStepUp(d, w, r, &pg, decideStepUp) {
			return
		}

		// Channel is a constant here, never read from the request body: the
		// Console carries a browser credential the requesting AI-agent session
		// does not hold, which is the definition of out-of-band (ADR-0027).
		_, err := d.Decide.DecideApproval(r.Context(), caller, capability.ApprovalDecision{
			RequestID: id,
			PlanHash:  planHash,
			Approve:   answer == "approve",
			Reason:    reason,
			Channel:   approval.ChannelOutOfBand,
		})
		if err == nil {
			// Post-redirect-get to the card, never to a caller-supplied
			// return URL — no open redirect, exactly as Cancel's redirect
			// (cancel.go:121).
			http.Redirect(w, r, decideApprovalPageHref(id), http.StatusSeeOther)
			return
		}

		// Error mapping, classification copied from api.writeApprovalError
		// (api/approvals.go) so the two surfaces agree on what each refusal
		// MEANS. The domain error's own text is included on the 403/409
		// branches for the same reason the API states: "an approver who
		// cannot tell WHY their answer bounced will eventually stop
		// answering" — rendered through newScreen (html/template), so it is
		// escaped.
		switch {
		case errors.Is(err, approval.ErrNotFound):
			renderDecideResult(w, pg, http.StatusNotFound, decideResultView{
				Heading: "No approval request with the id " + id + " appears in this Relay's records.",
			})
		case errors.Is(err, authz.ErrUnauthorized), errors.Is(err, approval.ErrNotInAudience):
			renderDecideResult(w, pg, http.StatusForbidden, decideResultView{
				Heading:       "The Relay refused this decision: " + err.Error() + ".",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Back to this Request.",
			})
		case errors.Is(err, approval.ErrPlanChanged):
			renderDecideResult(w, pg, http.StatusConflict, decideResultView{
				Heading: "The Plan moved since this page was rendered; reload and read it again — " +
					"your answer was not recorded.",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Reload this Request.",
			})
		case errors.Is(err, approval.ErrNotPending), errors.Is(err, approval.ErrRequesterExcluded),
			errors.Is(err, approval.ErrMachineSelfDecision), errors.Is(err, approval.ErrDuplicateDecider),
			errors.Is(err, approval.ErrWeakChannel):
			renderDecideResult(w, pg, http.StatusConflict, decideResultView{
				Heading:       "The Relay refused this decision: " + err.Error() + ".",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Back to this Request.",
			})
		case errors.Is(err, capability.ErrApprovalUnavailable):
			unavailable(w, "deciding an approval")
		default:
			// Security review, cycle 2: this branch must NOT claim the
			// decision was not recorded, because it is also what
			// DecideApproval returns when the decision WAS durably
			// recorded and only the AUDIT WRITE failed
			// (approval_decide.go: "record audit entry" joined to the
			// real, already-persisted result — deliberately, "rather than
			// pretending the decision did not happen"). Saying "not
			// recorded" here would be the opposite of true in exactly that
			// case: an operator denies a request, is told nothing
			// happened, and walks away believing it is still parked while
			// the denial is terminal — or approves, is told nothing
			// happened, and a quorum slot was silently spent. Distinguishing
			// the wrapped audit error properly is a capability-layer change
			// and is out of scope here; the honest sentence that does not
			// require it is "could not CONFIRM", not "did not happen".
			d.logger().ErrorContext(r.Context(), "console decide-approval request returned an error",
				"approval_id", id, "error", err)
			renderDecideResult(w, pg, http.StatusInternalServerError, decideResultView{
				Heading:       "The Relay could not confirm this decision was fully recorded. Reload this Request before answering again.",
				ApprovalHref:  decideApprovalPageHref(id),
				ApprovalLabel: "Reload this Request.",
			})
		}
	}
}

// decideApprovalPageHref is the approval object's own path, built once here
// so every branch above and the redirect on success agree byte-for-byte.
func decideApprovalPageHref(approvalID string) string {
	return "/console/approvals/" + url.PathEscape(approvalID)
}

// decideResultView is the shell rendered for a decision that did not
// redirect — every case but success. Deliberately small, modelled on
// cancelResultView: the interesting rendering (the card itself) lives on the
// approval object (approvals.go).
type decideResultView struct {
	Heading       string
	ApprovalHref  string
	ApprovalLabel string
}

// renderDecideResult answers a decision POST with the result card at the given
// status. The status is written before the body so no refusal can render as 200.
func renderDecideResult(w http.ResponseWriter, pg Page, status int, v decideResultView) {
	w.WriteHeader(status)
	renderScreen(w, pg, decideResultTmpl, v)
}

var decideResultTmpl = newScreen("decide-result", `
<div class="placeholder">
  <p>{{.Heading}}</p>
  {{with .ApprovalHref}}<p><a href="{{.}}">{{$.ApprovalLabel}}</a></p>{{end}}
</div>
`)
