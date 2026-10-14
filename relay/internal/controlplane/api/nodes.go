package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// revokeNodeRequest is the POST /api/v1/nodes/{node_id}/revoke request body.
//
// Shaped like freezeReleaseRequest deliberately: both are irreversible-ish
// security acts whose whole body is the reason they happened.
type revokeNodeRequest struct {
	Reason string `json:"reason"`
}

// handleRevokeNode implements POST /api/v1/nodes/{node_id}/revoke: revoke
// the Node via NodeRevoker.RevokeNodeRecorded (record, then denylist +
// immediate live Tunnel teardown, ADR-0006), and return 204. Idempotent:
// revoking an already-revoked or unknown node_id still returns 204
// (revocation.Service.RevokeNode is a no-op-safe denylist add).
//
// **Requires `admin`**: revocation is the middle rung of ADR-0020's
// incident ladder (quarantine < revoke < Freeze), and unlike quarantine it is
// not reversible short of re-enrolling the Node. A lower floor would let a
// viewer walk the fleet off the Relay one Node at a time.
//
// Step-up re-authentication, which ADR-0020 also asks for on this rung, is
// NOT implemented here — there is no step-up mechanism on the Control API
// yet. This closes the role hole; the step-up half remains owed.
//
// **A non-empty `reason` is REQUIRED** and is a deliberate breaking
// change: this route took no body at all before, so a caller that sends none
// now gets 400. The trail could already say who revoked and when; an
// irreversible rung that cannot say WHY is the half of attribution that
// matters least. The rule itself lives in capability.ValidateRevokeReason so
// a second surface records the same thing — see its doc for why that is a
// weaker guarantee here than ReleaseFreeze's.
//
// ORDER MATTERS: the reason is validated BEFORE RevokeNodeRecorded is called.
// Revoking first and rejecting after would leave a Node revoked by a request
// that returned 400, which is the worst of both — an irreversible act whose
// caller was told it did not happen, and no audit record explaining it.
//
// RECORD BEFORE THE ACT lives inside revocation.Service.RevokeNodeRecorded
// now, under the Node's lock — the only place that ordering can be
// atomic against a concurrent token cascade revoking the same Node. This
// mirrors the read lane's posture (ADR-0025: record before the seam, fail
// closed) and handleGetNode's, which already 500s when its read audit cannot
// be written — so the same surface never disagrees with itself about
// whether an unrecorded act may proceed.
//
// ONE BEHAVIOUR NOTE: a Node whose cascade revocation
// this Relay process already recorded still gets 204 here and writes no
// second node_revoke record — the record that already exists is the
// causative one. A Node that is merely denylisted with no record (the enroll
// self-denylist path, a cascade chunk whose record failed, or denylist
// rehydration at startup) still gets a record: this route is the backstop
// that supplies attribution none of those paths can.
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

		var req revokeNodeRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		reason, err := capability.ValidateRevokeReason(req.Reason)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "reason required", err.Error())
			return
		}

		// The recorder's content (Principal, reason) is authored here, where
		// the operator is authenticated; the SET of Nodes it covers is always
		// this one node_id — RevokeNodeRecorded decides when to call it, not
		// this closure. Goes through recordLifecycleAllErr (an AppendAll of a
		// one-element batch), the same construction the token cascade uses,
		// rather than a second one: RevocationRecorder's contract is
		// all-or-nothing per call, and recordLifecycleAllErr is the
		// recorder-side half of it.
		record := func(nodeIDs []string) error {
			return recordLifecycleAllErr(r.Context(), d, p, audit.KindNodeRevoke, nodeIDs, reason)
		}

		// CONTEXT: r.Context(), not WithoutCancel — correct here because on
		// this path the record precedes the act, so a caller whose wait for
		// the Node's lock is cancelled has caused nothing at all. The
		// cascade's WithoutCancel (tokens.go) exists because there the acts
		// are already under way.
		if err := d.Nodes.RevokeNodeRecorded(r.Context(), nodeID, record); err != nil {
			// Distinguish the causes an on-call reader would otherwise have to
			// guess at from the error text alone: a request context that ended
			// (while queued behind another revoke of this Node, or inside the
			// audit append once the lock was held — the error does not say
			// which, so the log does not either), a caller bug (no
			// recorder — unreachable here, record above is never nil), and an
			// audit-store failure. The response body stays identical either
			// way: none of these differences are the caller's to act on.
			switch {
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				d.logger().ErrorContext(r.Context(), "control api: node revoke abandoned: request context ended before the revoke was recorded",
					"node_id", nodeID, "error", err)
			case errors.Is(err, revocation.ErrRecorderRequired):
				d.logger().ErrorContext(r.Context(), "control api: node revoke refused: no recorder supplied",
					"node_id", nodeID, "error", err)
			default:
				d.logger().ErrorContext(r.Context(), "control api: append node revoke audit record", "node_id", nodeID, "error", err)
			}
			writeProblem(w, http.StatusInternalServerError, "revoke not recorded",
				"the revocation was not performed because it could not be audited")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
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

		nodeID := r.PathValue("node_id")
		if nodeID == "" {
			writeProblem(w, http.StatusBadRequest, "node id required", "")
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
	out.LastSeen = controlplane.RFC3339(n.LastSeen)
	out.RevokedAt = controlplane.RFC3339(n.RevokedAt)
	return out
}
