package api

import (
	"net/http"
	"strings"
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
// (KindFreezeEngage) is written intrinsically by capability.Service, so this
// handler deliberately does NOT call recordLifecycle — doing so would
// double-audit the same event.
func handleFreezeEngage(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		if err := d.Freeze.EngageFreeze(r.Context(), p); err != nil {
			writeProblem(w, http.StatusInternalServerError, "engage freeze failed", "")
			return
		}

		writeJSON(w, http.StatusOK, freezeResponse{Engaged: true})
	}
}

// handleFreezeRelease implements POST /api/v1/freeze/release: release the
// Relay-wide Freeze via Freezer.ReleaseFreeze. ADR-0013's asymmetric
// activation requires a non-empty reason to release (engage is reason-free,
// release is deliberate); an empty or absent reason is a 400. Freeze's audit
// trail (KindFreezeRelease) is written intrinsically by capability.Service —
// this handler does NOT call recordLifecycle (would double-audit).
func handleFreezeRelease(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		var req freezeReleaseRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			writeProblem(w, http.StatusBadRequest, "reason required",
				"releasing the Freeze requires a non-empty reason (ADR-0013)")
			return
		}

		if err := d.Freeze.ReleaseFreeze(r.Context(), p, reason); err != nil {
			writeProblem(w, http.StatusInternalServerError, "release freeze failed", "")
			return
		}

		writeJSON(w, http.StatusOK, freezeResponse{Engaged: false})
	}
}
