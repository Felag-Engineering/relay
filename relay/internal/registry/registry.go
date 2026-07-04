// Package registry keeps the Relay's live view of the Node fleet: identity,
// Facts, labels, last-seen timestamps, and enrollment-token provenance.
//
// Label authority is structural, not conventional. The two namespaces —
// node: (node-rooted, Relay-immutable) and relay: (Relay-set, Node-immutable) —
// are stored in two disjoint maps and written by two disjoint methods. There is
// no code path through which a Node report can write relay-space labels, and no
// code path through which the Relay can overwrite node-space labels via
// SetRelayLabels.
package registry

import (
	"errors"
	"time"
)

// ErrNotFound is returned when an operation targets a Node that is not in the registry.
var ErrNotFound = errors.New("registry: node not found")

// ErrEmptyNodeID is returned when an operation is given an empty node ID.
var ErrEmptyNodeID = errors.New("registry: empty node id")

// ErrAtCapacity is returned by Upsert on the INSERT path when the registry has
// reached its configured maxNodes cap. Updates to existing Nodes always succeed
// (reconnect and Hello Upserts must never be throttled by the cap).
//
// Note: after a Relay restart the in-memory registry is empty, so every
// reconnecting relay-daemon's Hello Upsert hits the INSERT path and is subject
// to the cap. The default cap (110 000) is intentionally 10 % above the 100 000
// Node target to leave headroom for this cold-start re-insertion window.
var ErrAtCapacity = errors.New("registry: at capacity")

// Facts are descriptive properties a relay-daemon self-reports about its Node.
// They inform decisions but are never used for targeting — that is the role of Labels.
// This is a domain mirror of gleipnirv1.Facts; the registry package carries no
// proto dependency.
type Facts struct {
	Hostname    string
	OS          string
	Kernel      string
	Arch        string
	IPAddresses []string
}

// Node is the stored record for a managed Node. Returned by Get and List.
//
// NodeLabels holds node-space labels (bare keys, namespace tracked by which map).
// RelayLabels holds relay-space labels. Each is written exclusively by its own
// method on Repository; neither can reach the other's map.
type Node struct {
	NodeID            string
	CertFingerprint   string // cert identity used for Node authentication
	Facts             Facts
	NodeLabels        map[string]string // node: namespace, bare keys; node-rooted, Relay-immutable
	RelayLabels       map[string]string // relay: namespace, bare keys; Relay-set, Node-immutable
	LastSeen          time.Time
	EnrollingTokenID  string // provenance: the Enrollment Token ID used at first enrollment
	PolicyFingerprint string // SHA-256 hex of the Node's loaded Policy, reported on Hello; report-only drift signal — the Relay never sets Policy (ADR-0002)
}

// Report is the input to Upsert. It deliberately carries no relay-label field —
// this is the structural half of the node-side immutability boundary. A relay-daemon
// can never supply relay-space labels through this type, regardless of what it sends.
type Report struct {
	NodeID            string
	CertFingerprint   string
	Facts             Facts
	NodeLabels        map[string]string
	EnrollingTokenID  string
	PolicyFingerprint string // SHA-256 hex of the Node's loaded Policy, sourced from Hello; report-only drift signal — the Relay never sets Policy (ADR-0002)
}

// Repository is the interface for the Node registry.
type Repository interface {
	// Upsert registers or updates a Node from a relay-daemon's own report. This is
	// the only write path for node-space labels, Facts, and PolicyFingerprint. It
	// cannot write relay-space labels — Report has no such field.
	//
	// On INSERT (new Node): returns ErrAtCapacity when a max-nodes cap is set and
	// reached. On UPDATE (existing Node): the cap is never checked — reconnects
	// and Hello Upserts must never be throttled.
	//
	// PolicyFingerprint is overwritten on both INSERT and UPDATE (like Facts and
	// NodeLabels), so each (re)connect refreshes the stored value to the currently
	// loaded Policy. RelayLabels and EnrollingTokenID provenance are never touched.
	Upsert(r Report) (Node, error)

	// UpdateLastSeen records the most recent contact time for a Node. Returns
	// ErrNotFound if the Node is not in the registry.
	UpdateLastSeen(nodeID string, at time.Time) error

	// SetRelayLabels replaces the relay-space label set for a Node. The provided
	// map becomes the complete new set — this is a replace, not a merge. Calling
	// with an empty or partial map replaces the whole relay: label set; a future
	// admin layer must not partially call it and accidentally lift a quarantine.
	// Facts and NodeLabels are never touched by this method. Returns ErrNotFound
	// if the Node is not in the registry.
	SetRelayLabels(nodeID string, labels map[string]string) error

	// Get returns a deep copy of the stored Node record, or (Node{}, false) if
	// the Node is not in the registry.
	Get(nodeID string) (Node, bool)

	// List returns deep copies of all stored Node records. Ordering is
	// unspecified; the InMemory implementation sorts by NodeID for determinism,
	// but callers must not rely on it.
	List() []Node
}
