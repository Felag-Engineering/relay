package api

import (
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// handleRevokeNode implements POST /api/v1/nodes/{node_id}/revoke: revoke
// the Node via NodeRevoker.RevokeNode (denylist + immediate live Tunnel
// teardown, ADR-0006), audit the revoke (KindNodeRevoke), and return 204.
// Idempotent: revoking an already-revoked or unknown node_id still returns
// 204 (revocation.Service.RevokeNode is a no-op-safe denylist add).
//
// **Requires `admin`** (#397): revocation is the middle rung of ADR-0020's
// incident ladder (quarantine < revoke < Freeze), and unlike quarantine it is
// not reversible short of re-enrolling the Node. Until #397 a viewer could
// walk the fleet off the Relay one Node at a time.
//
// Step-up re-authentication, which ADR-0020 also asks for on this rung, is
// NOT implemented here — there is no step-up mechanism on the Control API
// yet. This closes the role hole; the step-up half remains owed.
func handleRevokeNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if !authorizeControl(w, r, d, p, capability.ControlRevokeNode) {
			return
		}

		nodeID := r.PathValue("node_id")
		if nodeID == "" {
			writeProblem(w, http.StatusBadRequest, "missing node id", "path parameter node_id must not be empty")
			return
		}

		d.Nodes.RevokeNode(nodeID)

		recordLifecycle(r.Context(), d, p, audit.KindNodeRevoke, nodeID, "")
		w.WriteHeader(http.StatusNoContent)
	}
}
