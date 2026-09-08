package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// revokeNodeRequest is the POST /api/v1/nodes/{node_id}/revoke request body.
//
// Shaped like freezeReleaseRequest deliberately: both are irreversible-ish
// security acts whose whole body is the reason they happened.
type revokeNodeRequest struct {
	Reason string `json:"reason"`
}

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
//
// **A non-empty `reason` is REQUIRED** (#487) and is a deliberate breaking
// change: this route took no body at all before, so a caller that sends none
// now gets 400. The trail could already say who revoked and when; an
// irreversible rung that cannot say WHY is the half of attribution that
// matters least. The rule itself lives in capability.ValidateRevokeReason so
// a second surface records the same thing — see its doc for why that is a
// weaker guarantee here than ReleaseFreeze's.
//
// ORDER MATTERS: the reason is validated BEFORE RevokeNode is called. Revoking
// first and rejecting after would leave a Node revoked by a request that
// returned 400, which is the worst of both — an irreversible act whose caller
// was told it did not happen, and no audit record explaining it.
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

		d.Nodes.RevokeNode(nodeID)

		recordLifecycle(r.Context(), d, p, audit.KindNodeRevoke, nodeID, reason)
		w.WriteHeader(http.StatusNoContent)
	}
}

// NodeReader is the single-Node registry view this route needs.
//
// Deliberately not registry.Repository: a read route has no business holding
// Upsert, SetRelayLabels or SetRevoked, and the narrowing is what makes that a
// fact about the type rather than a promise about the handler.
type NodeReader interface {
	Get(nodeID string) (registry.Node, bool)
}

// readCapabilityDescribeNode is the name this surface records for a Node read.
const readCapabilityDescribeNode = "describe_node"

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

	// StateLabels are the `state:` namespace (ADR-0034, #414): Relay-derived,
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

// nodeCertificate is the identity provenance the Relay issued (#440).
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

// handleGetNode implements GET /api/v1/nodes/{node_id}.
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

		// Audited BEFORE any content is returned, and fail closed if it cannot
		// be recorded — a Relay that cannot write its access trail must stop
		// answering rather than answer invisibly. Recorded even when the Node
		// does not exist: an attempted read of a Node id is exactly what an
		// incident reviewer wants to see, and suppressing it would make
		// enumeration the one read that leaves no trace.
		if err := auditReadNode(r.Context(), d.Reads, p, readCapabilityDescribeNode, nodeID); err != nil {
			writeProblem(w, http.StatusInternalServerError, "read audit failed", err.Error())
			return
		}

		n, found := d.NodeReader.Get(nodeID)
		if !found {
			writeProblem(w, http.StatusNotFound, "no such node",
				"no Node with that id is in this Relay's registry")
			return
		}
		ev := capability.StateEval{Now: d.Now(), CertExpiringWithin: d.CertExpiringWithin}
		writeJSON(w, http.StatusOK, nodeResponseFrom(n, ev))
	}
}

func nodeResponseFrom(n registry.Node, ev capability.StateEval) nodeResponse {
	states := nodestate.Labels(nodestate.Input{Node: n, Now: ev.Now, CertExpiringWithin: ev.CertExpiringWithin})
	stateLabels := make([]string, 0, len(states))
	for _, l := range states {
		stateLabels = append(stateLabels, l.String())
	}

	out := nodeResponse{
		NodeID:      n.NodeID,
		NodeLabels:  n.NodeLabels,
		RelayLabels: n.RelayLabels,
		Facts: nodeFacts{
			Hostname:    n.Facts.Hostname,
			OS:          n.Facts.OS,
			Kernel:      n.Facts.Kernel,
			Arch:        n.Facts.Arch,
			IPAddresses: n.Facts.IPAddresses,
		},
		Connected:              n.Connected,
		EnrollingTokenID:       n.EnrollingTokenID,
		PolicyFingerprint:      n.PolicyFingerprint,
		TemplateSetFingerprint: n.TemplateSetFingerprint,
		DaemonVersion:          n.DaemonVersion,
		Outdated:               n.Outdated,
		Revoked:                !n.RevokedAt.IsZero(),
		Certificate: nodeCertificate{
			Recorded:     n.CertProvenanceKnown(),
			Fingerprint:  n.CertFingerprint,
			RenewalCount: n.RenewalCount,
		},
		StateLabels: stateLabels,
	}
	if out.NodeLabels == nil {
		out.NodeLabels = map[string]string{}
	}
	if out.RelayLabels == nil {
		out.RelayLabels = map[string]string{}
	}
	if !n.LastSeen.IsZero() {
		out.LastSeen = n.LastSeen.UTC().Format(time.RFC3339)
	}
	if !n.RevokedAt.IsZero() {
		out.RevokedAt = n.RevokedAt.UTC().Format(time.RFC3339)
	}
	if out.Certificate.Recorded {
		out.Certificate.NotAfter = n.CertNotAfter.UTC().Format(time.RFC3339)
		if !n.EnrolledAt.IsZero() {
			out.Certificate.EnrolledAt = n.EnrolledAt.UTC().Format(time.RFC3339)
		}
		if !n.LastRenewedAt.IsZero() {
			out.Certificate.LastRenewedAt = n.LastRenewedAt.UTC().Format(time.RFC3339)
		}
	}
	return out
}

// auditReadNode records a Node read. Mirrors auditRead, differing only in which
// positional field of the read event is populated — a Node id, not a Job id.
func auditReadNode(ctx context.Context, a ReadAuditor, p capability.Principal, capabilityName, nodeID string) error {
	if a == nil {
		return nil
	}
	if err := a.RecordRead(ctx, p, capabilityName, "", nodeID, ""); err != nil {
		return fmt.Errorf("record read audit for %s: %w", capabilityName, err)
	}
	return nil
}
