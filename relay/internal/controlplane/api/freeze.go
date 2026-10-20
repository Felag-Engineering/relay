package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// freezeReleaseRequest is the POST /api/v1/freeze/release request body.
type freezeReleaseRequest struct {
	Reason string `json:"reason"`
}

// freezeResponse is the response body for both freeze routes, reporting the
// resulting engaged state.
type freezeResponse struct {
	Engaged bool `json:"engaged"`
}

// handleFreezeEngage implements POST /api/v1/freeze/engage: engage the
// Relay-wide Freeze via Freezer.EngageFreeze (ADR-0013 — cheap, no reason
// required) and return 200. No request body. Freeze's audit trail
// (KindFreezeEngage) is written intrinsically by capability.Control, so this
// handler deliberately does NOT call recordLifecycle — doing so would
// double-audit the same event.
//
// **The floor — a human `operator`+ — is NOT checked here.** It lives
// in capability.Control.EngageFreeze, which consults the same authz.RoleGate
// every other authorization answer comes from, and audits the refusal in the
// same trail. This handler renders that refusal as 403; re-deriving the rule
// here would be the second control path invariant 10 forbids, and the one
// that would drift when the Console grows its own Freeze button.
func handleFreezeEngage(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		if err := d.Freeze.EngageFreeze(r.Context(), p); err != nil {
			writeFreezeError(w, err, "engage freeze failed")
			return
		}

		writeJSON(w, http.StatusOK, freezeResponse{Engaged: true})
	}
}

// handleFreezeRelease implements POST /api/v1/freeze/release: release the
// Relay-wide Freeze via Freezer.ReleaseFreeze. ADR-0013's asymmetric
// activation requires a non-empty reason to release (engage is reason-free,
// release is deliberate); an empty or absent reason is a 400. Freeze's audit
// trail (KindFreezeRelease) is written intrinsically by capability.Control —
// this handler does NOT call recordLifecycle (would double-audit).
//
// **Requires `admin`, checked in the capability layer**, exactly as
// engage's floor is — see handleFreezeEngage. The reason check below is kept
// as an early, well-worded 400 for API callers; capability.ReleaseFreeze
// enforces the same rule for every other surface.
func handleFreezeRelease(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		var req freezeReleaseRequest
		if !readJSONBody(w, r, &req) {
			return
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			writeProblem(w, http.StatusBadRequest, "reason required",
				"releasing the Freeze requires a non-empty reason (ADR-0013)")
			return
		}

		if err := d.Freeze.ReleaseFreeze(r.Context(), p, reason); err != nil {
			writeFreezeError(w, err, "release freeze failed")
			return
		}

		writeJSON(w, http.StatusOK, freezeResponse{Engaged: false})
	}
}

// writeFreezeError maps an error from the capability layer's Freeze methods
// onto an HTTP problem response.
//
// A role or human-kind refusal unwraps to authz.ErrUnauthorized and
// renders 403 with the gate's own reason — the same recognize-don't-re-decide
// pattern execution.go uses, and the reason is safe to disclose because it
// states only the public rule. capability.ErrFreezeReasonRequired renders 400
// even though handleFreezeRelease already rejects an empty reason: the
// capability layer is where the rule actually lives now, and a 500 for a rule
// this surface agrees with would be a lie about whose fault it was. Anything
// else is a bare 500 with no detail.
func writeFreezeError(w http.ResponseWriter, err error, title string) {
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, capability.ErrFreezeReasonRequired):
		writeProblem(w, http.StatusBadRequest, "reason required", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, title, "")
	}
}
