package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// approval_grants.go is the surface for batch/window approvals (#378, ADR-0027
// decision 12): one human decision covering a bounded set of future dispatches
// instead of one Plan.
//
// It exists because fatigue is a security property. Forty elicitations produce
// forty rubber stamps, and a rubber-stamped approval is worse than none — it
// manufactures evidence that a human considered something they did not. So this
// is not a throughput feature; it is what keeps the audit trail from becoming
// fiction.
//
// Two things this file does NOT do, both deliberate:
//
//   - **It does not approve anything.** Requesting a grant creates an ordinary
//     approval Request whose subject is a Scope, answered through the EXISTING
//     `/api/v1/approvals/{id}/decision` route. Quorum, audience, requester
//     exclusion, the machine-self-decision rule, and channel strength therefore
//     apply to a grant exactly as they apply to a single dispatch, because it is
//     the same code path — a deployment requiring two approvers for one mutate
//     does not get single-approver grants covering a hundred of them.
//   - **It does not decide what a grant costs.** The Requirement is derived
//     below this layer, at the Scope's worst case: count, channel, requester
//     exclusion and decision deadline (TTL) are priced at the strictest a
//     covered dispatch would have faced, and the approver audience is the
//     union of those dispatches' audiences (owner-accepted residual risk,
//     ADR-0027 amendment 2026-09-16).
//
// Like every route in this package: decode, call, render. Everything that
// decides anything is in capability and approval (invariant 10).

// ApprovalGrantService is the capability-layer entry point the grant routes
// use, declared locally so this package never names *capability.Approvals.
// *capability.Approvals satisfies it structurally.
type ApprovalGrantService interface {
	RequestGrant(ctx context.Context, p capability.Principal, in capability.GrantRequest) (approval.Grant, approval.Request, error)
	ActiveGrants(ctx context.Context) ([]approval.Grant, error)
	Grant(ctx context.Context, id string) (approval.Grant, error)
	RevokeGrant(ctx context.Context, p capability.Principal, id, reason string) (approval.Grant, error)
}

// -----------------------------------------------------------------------
// Wire shapes
// -----------------------------------------------------------------------

// grantScopeRequest is the wall an operator is asking for. Every field is
// REQUIRED, which is the opposite of the gate's match grammar and deliberately
// so: on a Match an omitted field gates more dispatches (safe), on a Scope it
// would pre-approve more (unsafe). There is no field here whose omission
// quietly widens the grant, and the domain refuses any that is missing rather
// than filling in a default.
//
// There is deliberately no selector_namespace. decodeJSON refuses
// unknown fields, so a body still carrying one gets a 400 naming the field,
// never a Grant priced as if the field were honoured.
type grantScopeRequest struct {
	Account    string   `json:"account"`
	RiskClass  string   `json:"risk_class"`
	MaxFanOut  int      `json:"max_fan_out"`
	Operations []string `json:"operations"`
	RawExec    bool     `json:"raw_exec"`
}

// createGrantRequest is POST /api/v1/approval-grants' body.
//
// There is deliberately no `count`, `audience`, or `channel`: what this grant
// costs to approve is DERIVED from the gate at the Scope's worst case. A body
// that could name its own requirement would be a body that could name a cheap
// one.
type createGrantRequest struct {
	Scope     grantScopeRequest `json:"scope"`
	StartsAt  string            `json:"starts_at,omitempty"`
	ExpiresAt string            `json:"expires_at"`
	MaxUses   int               `json:"max_uses"`
}

// revokeGrantRequest is POST /api/v1/approval-grants/{id}/revoke's body.
type revokeGrantRequest struct {
	Reason string `json:"reason"`
}

// grantResponse is a Grant as an operator or an auditor sees it.
//
// Summary is the RELAY-AUTHORED description of the Scope — the requester
// proposed the walls, but not one word a human reads about them. A surface must
// render this text rather than composing its own from the fields beside it, for
// the same reason the approval queue must: a grant that reads more narrowly in
// one view than another is the approval-view fidelity gap reintroduced.
type grantResponse struct {
	GrantID string `json:"grant_id"`
	// RequestID is the approval Request that authorizes this Grant. Follow it
	// to see the requirement, the decisions, and who signed — this shape
	// deliberately does not duplicate them, so quorum is read from exactly one
	// place.
	RequestID string            `json:"request_id"`
	Scope     grantScopeRequest `json:"scope"`
	Summary   string            `json:"summary"`
	StartsAt  string            `json:"starts_at"`
	ExpiresAt string            `json:"expires_at"`
	MaxUses   int               `json:"max_uses"`
	Uses      int               `json:"uses"`
	Remaining int               `json:"remaining"`
	Progress  string            `json:"progress"`
	// Active is the single question a caller actually has — not revoked, inside
	// the window, and not exhausted — answered by the domain rather than left
	// for each client to recompute from the timestamps and get subtly wrong.
	Active       bool   `json:"active"`
	CreatedAt    string `json:"created_at"`
	RevokedAt    string `json:"revoked_at,omitempty"`
	RevokedBy    string `json:"revoked_by,omitempty"`
	RevokeReason string `json:"revoke_reason,omitempty"`
}

// createGrantResponse returns both halves of the two-step flow, so a caller is
// never left holding a grant ID with no idea what still has to happen to it.
type createGrantResponse struct {
	Grant grantResponse `json:"grant"`
	// Approval is the pending Request. The grant is NOT usable until this
	// reaches approved.
	Approval approvalResponse `json:"approval"`
	// DecisionPath is where that answer goes — the same out-of-band route a
	// parked dispatch uses, because it is the same kind of decision.
	DecisionPath string `json:"decision_path"`
}

type listGrantsResponse struct {
	Grants []grantResponse `json:"grants"`
}

// -----------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------

func renderGrant(g approval.Grant, now time.Time) grantResponse {
	ops := g.Scope.Operations
	if ops == nil {
		ops = []string{}
	}
	return grantResponse{
		GrantID:   g.ID,
		RequestID: g.RequestID,
		Scope: grantScopeRequest{
			Account:    g.Scope.Account,
			RiskClass:  jobs.RiskClassName(g.Scope.RiskClass),
			MaxFanOut:  g.Scope.MaxFanOut,
			Operations: ops,
			RawExec:    g.Scope.RawExec,
		},
		Summary:      g.Summary,
		StartsAt:     controlplane.RFC3339(g.StartsAt),
		ExpiresAt:    controlplane.RFC3339(g.ExpiresAt),
		MaxUses:      g.MaxUses,
		Uses:         g.Uses,
		Remaining:    g.Remaining(),
		Progress:     g.Progress(),
		Active:       g.Active(now),
		CreatedAt:    controlplane.RFC3339(g.CreatedAt),
		RevokedAt:    controlplane.RFC3339(g.RevokedAt),
		RevokedBy:    g.RevokedBy,
		RevokeReason: g.RevokeReason,
	}
}

// parseRiskClass maps the wire name onto the domain class.
//
// There is no "any" and no default: read and mutate are not interchangeable,
// and a grant written for a read sweep must never silently cover a mutate. An
// absent or unknown value is an error, not a fallback.
func parseRiskClass(s string) (jobs.RiskClass, bool) {
	return jobs.ParseRiskClass(strings.ToLower(strings.TrimSpace(s)))
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

// handleCreateGrant implements POST /api/v1/approval-grants: ask for a
// batch/window approval.
//
// It creates a PENDING request, never a usable grant. The window it describes
// stays closed until somebody answers through the ordinary decision route,
// which is why this handler can be as ordinary as it looks.
func handleCreateGrant(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.ApprovalGrants == nil {
			writeGrantsUnavailable(w)
			return
		}

		var body createGrantRequest
		if err := decodeJSON(w, r, &body); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}

		risk, riskOK := parseRiskClass(body.Scope.RiskClass)
		if !riskOK {
			writeProblem(w, http.StatusBadRequest, "risk_class required",
				`scope.risk_class must be "read" or "mutate"; a grant never covers both`)
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "expires_at required",
				"expires_at must be an RFC3339 timestamp; a grant without a window is a standing authorization")
			return
		}
		var startsAt time.Time
		if body.StartsAt != "" {
			if startsAt, err = time.Parse(time.RFC3339, body.StartsAt); err != nil {
				writeProblem(w, http.StatusBadRequest, "invalid starts_at",
					"starts_at must be an RFC3339 timestamp")
				return
			}
		}

		grant, request, err := d.ApprovalGrants.RequestGrant(r.Context(), p, capability.GrantRequest{
			Scope: approval.Scope{
				Account:    body.Scope.Account,
				RiskClass:  risk,
				MaxFanOut:  body.Scope.MaxFanOut,
				Operations: body.Scope.Operations,
				RawExec:    body.Scope.RawExec,
			},
			StartsAt:  startsAt,
			ExpiresAt: expiresAt,
			MaxUses:   body.MaxUses,
		})
		if err != nil {
			writeGrantError(w, "", err)
			return
		}

		writeJSON(w, http.StatusCreated, createGrantResponse{
			Grant:        renderGrant(grant, d.Now()),
			Approval:     renderApproval(request),
			DecisionPath: "/api/v1/approvals/" + request.ID + "/decision",
		})
	}
}

// handleListGrants implements GET /api/v1/approval-grants: every Grant that
// could still cover something right now.
//
// Any authenticated caller may read it, for the same reason the approval queue
// is readable by any of them: a live window is fleet state the operators
// watching the fleet are entitled to see. Narrowing it to the grant's own
// requester would hide reduced friction from precisely the people whose job is
// to notice it.
func handleListGrants(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		if d.ApprovalGrants == nil {
			writeGrantsUnavailable(w)
			return
		}

		grants, err := d.ApprovalGrants.ActiveGrants(r.Context())
		if err != nil {
			writeGrantError(w, "", err)
			return
		}
		now := d.Now()
		out := make([]grantResponse, 0, len(grants))
		for _, g := range grants {
			out = append(out, renderGrant(g, now))
		}
		writeJSON(w, http.StatusOK, listGrantsResponse{Grants: out})
	}
}

// handleGetGrant implements GET /api/v1/approval-grants/{id}, in whatever state
// the Grant is in — including revoked, expired, and exhausted ones. "What did
// that window actually cover, and who closed it" is the question asked after
// the fact, and a view that only shows live grants cannot answer it.
func handleGetGrant(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		if d.ApprovalGrants == nil {
			writeGrantsUnavailable(w)
			return
		}

		id := r.PathValue("id")
		if id == "" {
			writeProblem(w, http.StatusBadRequest, "grant id required", "")
			return
		}
		g, err := d.ApprovalGrants.Grant(r.Context(), id)
		if err != nil {
			writeGrantError(w, id, err)
			return
		}
		writeJSON(w, http.StatusOK, renderGrant(g, d.Now()))
	}
}

// handleRevokeGrant implements POST /api/v1/approval-grants/{id}/revoke: close
// a window early.
//
// This is the lever that exists because a grant is a period of reduced
// friction, and reduced friction against a compromised requester is exactly
// when somebody needs to shut it without reaching for the fleet-wide Freeze.
// It is not restricted to the original approver: during an incident the person
// at the keyboard is whoever is there.
func handleRevokeGrant(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.ApprovalGrants == nil {
			writeGrantsUnavailable(w)
			return
		}

		id := r.PathValue("id")
		if id == "" {
			writeProblem(w, http.StatusBadRequest, "grant id required", "")
			return
		}

		var body revokeGrantRequest
		if err := decodeJSON(w, r, &body); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		if len(body.Reason) > maxDecisionReasonLen {
			writeProblem(w, http.StatusBadRequest, "reason too long",
				"reason must be at most 1024 bytes")
			return
		}

		revoked, err := d.ApprovalGrants.RevokeGrant(r.Context(), p, id, body.Reason)
		if err != nil {
			writeGrantError(w, id, err)
			return
		}
		writeJSON(w, http.StatusOK, renderGrant(revoked, d.Now()))
	}
}

// -----------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------

func writeGrantsUnavailable(w http.ResponseWriter) {
	writeProblem(w, http.StatusInternalServerError, "approval grants unavailable",
		"the Control API was mounted without its approval-grant dependencies")
}

// writeGrantError maps a grant-lifecycle error onto the status that describes
// it truthfully, falling through to the shared approval mapping for everything
// the two paths have in common (the role floor, unavailability).
//
// An unbounded Scope is a 422 rather than a 400: the body parsed and every
// field was well-formed, but what it asked for is not a thing this system will
// create. The detail carries the domain's own sentence, because "your grant was
// rejected" without saying which wall was missing teaches an operator nothing
// except to try again with a wider request.
func writeGrantError(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, approval.ErrGrantNotFound):
		detail := "no approval grant with that id"
		if id != "" {
			detail = "no approval grant with id " + id
		}
		writeProblem(w, http.StatusNotFound, "approval grant not found", detail)
	case errors.Is(err, approval.ErrGrantNotActive):
		writeProblem(w, http.StatusConflict, "approval grant is not active", err.Error())
	case errors.Is(err, approval.ErrGrantUnbounded):
		writeProblem(w, http.StatusUnprocessableEntity, "approval grant is not bounded", err.Error())
	case errors.Is(err, approval.ErrGrantInvalid):
		writeProblem(w, http.StatusBadRequest, "approval grant is malformed", err.Error())
	case errors.Is(err, capability.ErrGrantCoversNothingGated):
		writeProblem(w, http.StatusUnprocessableEntity, "approval grant would authorize nothing", err.Error())
	default:
		writeApprovalError(w, id, err)
	}
}
