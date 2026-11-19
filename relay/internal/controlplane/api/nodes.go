package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// revokeNodeRequest is the POST /api/v1/nodes/{node_id}/revoke request body.
//
// Shaped like freezeReleaseRequest deliberately: both are irreversible-ish
// security acts whose whole body is the reason they happened.
type revokeNodeRequest struct {
	Reason string `json:"reason"`
}

// handleRevokeNode implements POST /api/v1/nodes/{node_id}/revoke: revoke the
// Node, tearing down its live Tunnel (ADR-0006), and return 204. Idempotent:
// revoking an already-revoked or unknown node_id still returns 204.
//
// **Requires `admin`**: revocation is the middle rung of ADR-0020's incident
// ladder (quarantine < revoke < Freeze) and is not reversible short of
// re-enrolling the Node. The floor is asked before the body is read, so a
// refused caller gets 403 whatever it sent; the entry point asks again. Step-up
// re-authentication, which ADR-0020 also asks for on this rung, is NOT
// implemented: there is no step-up mechanism on the Control API yet.
//
// **A non-empty `reason` is REQUIRED**: a request without one gets 400, before
// any act. The rule, the record-before-act ordering and the records are
// capability.Revocations'.
func handleRevokeNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if !gateControl(w, r, d, func(g ControlGate) error { return g.AuthorizeNodeRevoke(r.Context(), p) }) {
			return
		}

		nodeID, ok := requirePathValue(w, r, "node_id", "missing node id", "path parameter node_id must not be empty")
		if !ok {
			return
		}

		var req revokeNodeRequest
		if !readJSONBody(w, r, &req) {
			return
		}
		if d.Revocations == nil {
			writeRevocationsUnavailable(w)
			return
		}

		err := d.Revocations.RevokeNodeWithReason(r.Context(), p, nodeID, req.Reason)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case isRevokeReasonError(err):
			writeProblem(w, http.StatusBadRequest, "reason required", err.Error())
		case errors.Is(err, authz.ErrUnauthorized):
			writeControlRefusal(w, r, d, err)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// The request context ended while queued behind another revoke of
			// this Node, or inside the record once the lock was held; the error
			// does not say which, so the log does not either.
			d.logger().ErrorContext(r.Context(), "control api: node revoke abandoned: request context ended before the revoke was recorded",
				"node_id", nodeID, "error", err)
			writeNodeRevokeNotRecorded(w)
		default:
			d.logger().ErrorContext(r.Context(), "control api: node revoke not recorded", "node_id", nodeID, "error", err)
			writeNodeRevokeNotRecorded(w)
		}
	}
}

func writeNodeRevokeNotRecorded(w http.ResponseWriter) {
	writeProblem(w, http.StatusInternalServerError, "revoke not recorded",
		"the revocation was not performed because it could not be audited")
}

// NodeReader is the capability read lane's DescribeNode call, narrowed to
// the one method this route needs. capability.ReadLane satisfies it
// with no adapter, exactly as Exec/Approvals/AccountAdmin already do.
//
// The narrowing here is that there is one door to the registry, and it
// records the read before it answers (invariant 10, ADR-0025).
type NodeReader interface {
	DescribeNode(ctx context.Context, p capability.Principal, nodeID string) (capability.NodeDetail, error)
}

// nodeResponse is GET /api/v1/nodes/{node_id}'s body.
type nodeResponse struct {
	NodeID      string            `json:"node_id"`
	NodeLabels  map[string]string `json:"node_labels"`
	RelayLabels map[string]string `json:"relay_labels"`
	TagLabels   map[string]string `json:"tag_labels"`
	Facts       nodeFacts         `json:"facts"`

	LastSeen string `json:"last_seen,omitempty"`
	// Connected is whether the Node holds a live Tunnel right now. Not
	// inferable from last_seen: a Node that reported seconds ago and then
	// dropped its stream resolves `unreachable` for dispatch immediately
	// (ADR-0004), and a caller guessing from last_seen would disagree with the
	// dispatcher about its own fleet.
	Connected bool `json:"connected"`

	EnrollingTokenID       string `json:"enrolling_token_id,omitempty"`
	PolicyFingerprint      string `json:"policy_fingerprint,omitempty"`
	TemplateSetFingerprint string `json:"template_set_fingerprint,omitempty"`
	DaemonVersion          string `json:"daemon_version,omitempty"`
	Outdated               bool   `json:"outdated"`

	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at,omitempty"`

	Certificate nodeCertificate `json:"certificate"`

	// StateLabels are the `state:` namespace (ADR-0034): Relay-derived,
	// evaluated at read time, set by nobody. Rendered in Selector syntax with
	// the state: prefix — targetable verbatim in RunOperationRequest.selector
	// and RawExecRequest.selector. Always [], never null, when a Node carries
	// none (same normalization as node_labels/relay_labels).
	StateLabels []string `json:"state_labels"`
}

type nodeFacts struct {
	Hostname    string   `json:"hostname,omitempty"`
	OS          string   `json:"os,omitempty"`
	Kernel      string   `json:"kernel,omitempty"`
	Arch        string   `json:"arch,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

// nodeCertificate is the identity provenance the Relay issued.
//
// Recorded gates the rest. A Node that enrolled before provenance was stored
// has a zero expiry, and rendering that as a timestamp would report an identity
// that lapsed in 1970 rather than one the Relay has nothing to say about.
type nodeCertificate struct {
	Recorded      bool   `json:"recorded"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	NotAfter      string `json:"not_after,omitempty"`
	EnrolledAt    string `json:"enrolled_at,omitempty"`
	RenewalCount  int    `json:"renewal_count"`
	LastRenewedAt string `json:"last_renewed_at,omitempty"`
}

// handleGetNode implements GET /api/v1/nodes/{node_id}. The empty-nodeID 400
// guard stays HERE, before the lane call: QRY-22's Control API sentence
// (an empty id is refused with nothing recorded) is not retired by QRY-27 —
// only the MCP sentence is.
//
// An OVERSIZED node id (over 256 bytes) is refused FIRST by the lane's own
// bound (validateNodeID), as ErrInvalidFilter, and returns 400 "invalid node
// id" with nothing recorded. This makes neither QRY-21 (scoped to a
// well-formed id) nor QRY-22 (about an empty id, still guarded above)
// untrue; it is documented in docs/api/openapi.yaml.
func handleGetNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.NodeReader == nil {
			writeProblem(w, http.StatusInternalServerError, "registry unavailable",
				"the Control API was mounted without a registry reader")
			return
		}

		nodeID, ok := requirePathValue(w, r, "node_id", "node id required", "")
		if !ok {
			return
		}

		detail, err := d.NodeReader.DescribeNode(r.Context(), p, nodeID)
		if err != nil {
			switch {
			case errors.Is(err, capability.ErrNodeNotFound):
				writeProblem(w, http.StatusNotFound, "no such node",
					"no Node with that id is in this Relay's registry")
			case errors.Is(err, capability.ErrInvalidFilter):
				// The lane's own text carries a "capability: invalid query
				// filter: " prefix (readlane_registry.go's ErrInvalidFilter) —
				// an internal package name that must never reach a published
				// problem detail. Map to this route's own wording instead,
				// mirroring the ErrNodeNotFound case above (security review,
				// cycle 2, LOW 5).
				writeProblem(w, http.StatusBadRequest, "invalid node id", "must be 1-256 bytes")
			case errors.Is(err, capability.ErrReadUnaudited):
				writeProblem(w, http.StatusInternalServerError, "read not recorded",
					"the Node was not read because the access record could not be written")
			case errors.Is(err, capability.ErrQueriesUnavailable):
				writeProblem(w, http.StatusInternalServerError, "registry unavailable", err.Error())
			default:
				writeProblem(w, http.StatusInternalServerError, "describe node failed", err.Error())
			}
			return
		}
		writeJSON(w, http.StatusOK, nodeResponseFrom(detail.Node, detail.Eval))
	}
}

func nodeResponseFrom(n registry.Node, ev capability.StateEval) nodeResponse {
	out := nodeResponse{
		NodeID:                 n.NodeID,
		NodeLabels:             n.NodeLabels,
		RelayLabels:            n.RelayLabels,
		TagLabels:              n.TagLabels,
		Facts:                  nodeFacts(controlplane.RenderFacts(n)),
		Connected:              n.Connected,
		EnrollingTokenID:       n.EnrollingTokenID,
		PolicyFingerprint:      n.PolicyFingerprint,
		TemplateSetFingerprint: n.TemplateSetFingerprint,
		DaemonVersion:          n.DaemonVersion,
		Outdated:               n.Outdated,
		Revoked:                !n.RevokedAt.IsZero(),
		Certificate:            nodeCertificate(controlplane.RenderCertificate(n)),
		StateLabels:            controlplane.StateLabels(n, ev),
	}
	if out.NodeLabels == nil {
		out.NodeLabels = map[string]string{}
	}
	if out.RelayLabels == nil {
		out.RelayLabels = map[string]string{}
	}
	if out.TagLabels == nil {
		out.TagLabels = map[string]string{}
	}
	out.LastSeen = controlplane.RFC3339(n.LastSeen)
	out.RevokedAt = controlplane.RFC3339(n.RevokedAt)
	return out
}
