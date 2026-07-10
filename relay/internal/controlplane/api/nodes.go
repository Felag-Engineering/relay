package api

import (
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// handleRevokeNode implements POST /api/v1/nodes/{node_id}/revoke: revoke
// the Node via NodeRevoker.RevokeNode (denylist + immediate live Tunnel
// teardown, ADR-0006), audit the revoke (KindNodeRevoke), and return 204.
// Idempotent: revoking an already-revoked or unknown node_id still returns
// 204 (revocation.Service.RevokeNode is a no-op-safe denylist add).
func handleRevokeNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
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
