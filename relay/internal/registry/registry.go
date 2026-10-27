// Package registry keeps the Relay's live view of the Node fleet: identity,
// Facts, labels, last-seen timestamps, and enrollment-token provenance.
//
// Label authority is structural, not conventional. The three stored
// namespaces — node: (node-rooted, Relay-immutable), relay: (Relay-set,
// Node-immutable) and tag: (human-written, Node-immutable) — are stored in
// three disjoint maps. node: is written only by Upsert, relay: only by
// SetRelayLabels, tag: only by the store's atomic tag write
// (audit.TagWriteAppender) and, for tests, InMemory.ApplyTagChanges. Report
// carries no tag field and Repository has no tag method, so no code path lets
// a Node report write relay-space or tag-space labels, and none lets the Relay
// overwrite node-space labels via SetRelayLabels.
package registry

import (
	"errors"
	"fmt"
	"maps"
	"time"
)

// ErrNotFound is returned when an operation targets a Node that is not in the registry.
var ErrNotFound = errors.New("registry: node not found")

// UnreadableNodesError is what ListChecked returns when the registry's Node
// IDs were read but one or more of those Nodes could not be: NodeIDs names
// every one of them (sorted), Scanned is how many IDs the scan found, and Err
// is the first read error. A caller can name the Nodes it could not see —
// which, for the revocation cascade, are exactly the Nodes that may still be
// trusted. A failure of the ID scan itself is returned as a plain error: no
// Node can be named then.
type UnreadableNodesError struct {
	NodeIDs []string
	Scanned int
	Err     error
}

func (e *UnreadableNodesError) Error() string {
	return fmt.Sprintf("registry: %d of %d nodes could not be read (first: %v)",
		len(e.NodeIDs), e.Scanned, e.Err)
}

func (e *UnreadableNodesError) Unwrap() error { return e.Err }

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
// This is a domain mirror of relayv1.Facts; the registry package carries no
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
// RelayLabels holds relay-space labels, and TagLabels tag-space labels. Each map
// is written exclusively by its own writer; none can reach another's map.
type Node struct {
	NodeID            string
	CertFingerprint   string // cert identity used for Node authentication
	Facts             Facts
	NodeLabels        map[string]string // node: namespace, bare keys; node-rooted, Relay-immutable
	RelayLabels       map[string]string // relay: namespace, bare keys; Relay-set, Node-immutable
	TagLabels         map[string]string // tag: namespace, bare keys; written only by a human Account through the capability layer (ADR-0050); Node-immutable
	LastSeen          time.Time
	EnrollingTokenID  string // provenance: the Enrollment Token ID used at first enrollment
	PolicyFingerprint string // SHA-256 hex of the Node's loaded Policy, reported on Hello; report-only drift signal — the Relay never sets Policy (ADR-0002)
	DaemonVersion     string // relay-daemon version self-reported on Hello; report-only, refreshed on each (re)connect (ADR-0014)
	// TemplateSetFingerprint is the SHA-256 hex of the Node's loaded Template
	// Operation set, reported on Hello beside PolicyFingerprint (ADR-0021).
	// Report-only drift signal — the Relay never sets a Node's templates, any
	// more than it sets Policy (ADR-0002). Empty means "no templates
	// installed"; the literal "unloadable" means the Node's local template set
	// failed to load and its template vocabulary is empty (fail closed).
	TemplateSetFingerprint string

	// RevokedAt is the persisted revocation state. Zero value means active
	// (never revoked). Relay-set, Node-immutable — the structural sibling of
	// RelayLabels: a daemon can never revoke or un-revoke itself, exactly as
	// it can never set relay: labels. Deliberately NOT settable via Report
	// (see below); only SetRevoked and its chunked twin SetRevokedAll write
	// it.
	RevokedAt time.Time

	// The certificate provenance the RELAY issued. Every field here is
	// Relay-knowledge, not Node-report: the Relay minted the certificate, so it
	// alone knows when it expires. Report has no field for any of them, exactly
	// as it has none for RelayLabels or RevokedAt.
	//
	// A zero value means NOT RECORDED, never "expires at the epoch" — Nodes
	// enrolled before this landed carry zeros until their next renewal. Callers
	// must distinguish the two; CertProvenanceKnown is the one place that test
	// is written.
	//
	// CertNotAfter is read off the certificate that was actually signed rather
	// than recomputed from the CA's validity constant, so a change to that
	// constant cannot retroactively rewrite what a Node is holding.
	CertNotAfter time.Time

	// EnrolledAt is when this Node FIRST joined, written once and never again.
	// Renewal is certificate-authenticated and preserves NodeID, so this anchors
	// an unbroken chain back to the Enrollment Token in EnrollingTokenID.
	EnrolledAt time.Time

	// RenewalCount and LastRenewedAt move on renewal only. A Node whose renewal
	// count has stopped climbing while CertNotAfter approaches is precisely the
	// silent failure `state:cert-expiring` exists to catch: nothing else notices
	// until the Node drops off the fleet.
	RenewalCount  int
	LastRenewedAt time.Time

	// Connected is DERIVED and NEVER STORED: whether this Node holds a live
	// Tunnel at the instant of the read.
	//
	// Not persisted, deliberately. A `connected = true` that survived a Relay
	// crash would be a lie the fleet view renders as a green dot, and the
	// correct answer after a restart is "nothing is connected" until each Node
	// dials back in. It is also NOT inferred from LastSeen: a Node that reported
	// four seconds ago and then dropped its stream is unreachable for dispatch
	// *now*, and ADR-0004 fails such a Task fast without sending it — a screen
	// that disagreed with the dispatcher would be telling an operator the fleet
	// is healthier than it is.
	Connected bool

	// Outdated is DERIVED, not stored: true when DaemonVersion is below the
	// Relay's configured min_daemon_version (ADR-0014). It is computed fresh
	// on every read from the Relay's current config, never persisted — the
	// config can change between restarts, so a stored value would go stale.
	// Fail-closed: a malformed or empty DaemonVersion is Outdated whenever a
	// minimum is configured. An unconfigured (empty) minimum means the gate
	// is off and Outdated is always false.
	Outdated bool
}

// The quarantine label, pinned as constants because the Console READS it today
// and a quarantine writer, when one is built, must WRITE exactly this —
// and those two must agree exactly.
//
// # Why the value is pinned and not just the key
//
// A reader that tests for the KEY treats `relay:quarantine=off` as quarantined.
// A Selector tests key AND value (capability.Predicate), so the set the Console
// draws and the set an operator can target would differ — on the security lane,
// which is the one namespace quarantine, remediation and secret distribution
// may target at all (invariant 7). "Fence these Nodes" resolving to a different
// set than the one shown is the failure this pins shut.
//
// Decided 2026-08-26, before any writer exists, which is the cheap moment: after
// a writer ships, changing the value is a fleet-wide migration of a
// security-lane label. These constants are the record of that decision.
//
// They live in this package because it owns the label maps and is imported by
// both sides; neither the reader nor the writer may spell the string itself.
const (
	// QuarantineKey is the bare key inside a Node's relay-space label map.
	// Selector syntax renders it `relay:quarantine`.
	QuarantineKey = "quarantine"

	// QuarantineOn is the only value that means quarantined. Any other value —
	// including the empty string and "off" — means the Node is not quarantined.
	// Fail-open is deliberate here and is not a weakening: the fence is the
	// PRESENCE of a deliberate admin act, so an ambiguous value must not be
	// read as one having happened.
	QuarantineOn = "on"
)

// NodeIDKey is the bare relay-space key every enrollment stamps with the Node's
// Relay-assigned ID. Selector syntax renders it `relay:node-id`; it is the only
// relay: label enrollment writes (ADR-0050, ADR-0048).
const NodeIDKey = "node-id"

// Quarantined reports whether n carries the quarantine fence.
//
// The one place the test is written. A caller that inlines
// `n.RelayLabels["quarantine"] != ""` has re-introduced the presence-versus-
// value bug this constant pair exists to close.
func (n Node) Quarantined() bool {
	return n.RelayLabels[QuarantineKey] == QuarantineOn
}

// CertProvenanceKnown reports whether the Relay has recorded this Node's
// certificate provenance.
//
// It exists so that "not recorded" and "expires at the epoch" can never be
// confused at a call site. A surface that finds this false must SAY the value is
// unknown rather than omitting the row: a missing expiry reads as "fine", and
// for the one signal that warns before a Node silently leaves the fleet, silence
// is the worst of the three possible answers.
func (n Node) CertProvenanceKnown() bool { return !n.CertNotAfter.IsZero() }

// Certificate is what the Relay issued to a Node, as read back off the signed
// certificate itself.
type Certificate struct {
	// Fingerprint is the SHA-256 of the DER bytes, hex-encoded — the same value
	// that identifies the Node on the wire.
	Fingerprint string

	// NotAfter is the expiry the CA actually set, parsed from the issued
	// certificate rather than recomputed from ca.LeafValidity.
	NotAfter time.Time
}

// Report is the input to Upsert. It deliberately carries no relay-label field and
// no tag field — this is the structural half of the node-side immutability
// boundary. A relay-daemon can never supply relay-space or tag-space labels
// through this type, regardless of what it sends.
//
// nodeLabels is unexported on purpose: the ONLY way to populate it is
// WithNodeLabels, so `rep.NodeLabels = someMap` — the bare field assignment
// that would silently create a third write path alongside cmd/relay/tunnel.go
// and internal/enroll/handler.go — is a compile error from any package
// outside registry, not a convention a reviewer has to notice was broken.
// protoconv/ingress_guard_test.go's TestReportNodeLabelsHasTwoWriters is the
// backstop on TOP of that structural guarantee, pinning that exactly those
// two files call WithNodeLabels; it is not the enforcement itself.
type Report struct {
	NodeID            string
	CertFingerprint   string
	Facts             Facts
	EnrollingTokenID  string
	PolicyFingerprint string // SHA-256 hex of the Node's loaded Policy, sourced from Hello; report-only drift signal — the Relay never sets Policy (ADR-0002)
	DaemonVersion     string // relay-daemon version self-reported on Hello; report-only drift/upgrade-progress signal (ADR-0014)
	// TemplateSetFingerprint is the Node's reported template-set fingerprint,
	// sourced from Hello; report-only drift signal (ADR-0021/ADR-0002).
	TemplateSetFingerprint string

	nodeLabels map[string]string
}

// WithNodeLabels returns a copy of r with its node-space label map set to
// labels, and is the only way to set it (see Report's doc). labels must
// already be well-formed bare key/value pairs — WellFormedLabel is the
// predicate — this method does no validation of its own; validation happens
// once, at the protoconv.ParseNodeLabel ingress seam, and every legitimate
// caller has already gone through it before reaching here.
func (r Report) WithNodeLabels(labels map[string]string) Report {
	r.nodeLabels = labels
	return r
}

// NodeLabels returns a COPY of the node-space label map r carries. Exported
// as a read-only accessor (rather than the field itself) so internal/store,
// which is outside this package, can read what Upsert is about to persist
// without being able to write it.
//
// It copies because unexporting the field bounds who may SET the map, not who
// may MUTATE it: handing out the live map would let any holder of a Report do
// `rep.NodeLabels()["role"] = "web, relay:quarantine=on"` and put back exactly
// the value the ingress gate exists to reject, with neither the compiler
// nor the ingress guard able to see it. The two writers are the only writers
// by construction only if this is a copy.
func (r Report) NodeLabels() map[string]string {
	return maps.Clone(r.nodeLabels)
}

// Repository is the interface for the Node registry.
type Repository interface {
	// Upsert registers or updates a Node from a relay-daemon's own report. This is
	// the only write path for node-space labels, Facts, PolicyFingerprint, and
	// DaemonVersion. It cannot write relay-space labels — Report has no such field.
	//
	// On INSERT (new Node): returns ErrAtCapacity when a max-nodes cap is set and
	// reached. On UPDATE (existing Node): the cap is never checked — reconnects
	// and Hello Upserts must never be throttled.
	//
	// PolicyFingerprint, DaemonVersion, and TemplateSetFingerprint are
	// overwritten on both INSERT and UPDATE (like Facts and NodeLabels), so
	// each (re)connect refreshes the stored values to what the Node currently
	// reports. RelayLabels, TagLabels and
	// EnrollingTokenID provenance are never touched.
	Upsert(r Report) (Node, error)

	// UpdateLastSeen records the most recent contact time for a Node. Returns
	// ErrNotFound if the Node is not in the registry.
	UpdateLastSeen(nodeID string, at time.Time) error

	// SetRelayLabels replaces the relay-space label set for a Node. The provided
	// map becomes the complete new set — this is a replace, not a merge. Calling
	// with an empty or partial map replaces the whole relay: label set; a future
	// admin layer must not partially call it and accidentally lift a quarantine.
	// Facts, NodeLabels and TagLabels are never touched by this method. Returns ErrNotFound
	// if the Node is not in the registry.
	SetRelayLabels(nodeID string, labels map[string]string) error

	// Get returns a deep copy of the stored Node record, or (Node{}, false) if
	// the Node is not in the registry.
	Get(nodeID string) (Node, bool)

	// List returns deep copies of all stored Node records. Ordering is
	// unspecified; the InMemory implementation sorts by NodeID for determinism,
	// but callers must not rely on it.
	//
	// List cannot report a read failure: a store-backed implementation logs
	// one and returns the Nodes it could read (possibly none). A caller whose
	// correctness depends on having seen EVERY Node must use ListChecked.
	List() []Node

	// ListChecked is List for a caller that must not mistake a failed read
	// for an empty or smaller fleet — today only the Enrollment-Token
	// revocation cascade, where a silently short list leaves Nodes enrolled
	// under a leaked token trusted (invariant 6). It returns every Node it
	// could read and a non-nil error whenever that is not every Node in the
	// registry, so the caller can act on what was read and still fail loudly.
	ListChecked() ([]Node, error)

	// RecordEnrollment persists the certificate provenance for a Node's FIRST
	// enrollment: the certificate the Relay just issued, and the moment it
	// joined. Returns ErrNotFound if the Node is not in the registry.
	//
	// Split from RecordRenewal rather than taking an is-renewal flag, because
	// the difference between them is an invariant and not a parameter: this
	// method writes EnrolledAt, that one has no SQL for it. "Provenance survives
	// renewal" is therefore a property of which function exists, not of a
	// boolean somebody has to pass correctly.
	RecordEnrollment(nodeID string, cert Certificate, at time.Time) error

	// RecordRenewal persists a reissued certificate: a new expiry, an
	// incremented renewal count, and the renewal time. It NEVER writes
	// EnrolledAt. Returns ErrNotFound if the Node is not in the registry.
	RecordRenewal(nodeID string, cert Certificate, at time.Time) error

	// SetConnected records that a Node's Tunnel opened or closed.
	//
	// In-memory and never persisted (see Node.Connected). Fed by the transport's
	// stream lifecycle, so a stream close flips the answer immediately rather
	// than waiting for a LastSeen timeout to expire — which is what lets the
	// fleet view and the dispatcher agree about reachability.
	//
	// Takes no error: connectedness is a fact the transport observed, not a
	// request that can be refused, and a caller in a defer has nothing useful to
	// do with a failure. An unknown nodeID is ignored.
	SetConnected(nodeID string, connected bool)

	// SetRevoked records that a Node is revoked as of at. It is the
	// structural sibling of SetRelayLabels: Relay-set, Node-immutable. It
	// and its chunked twin SetRevokedAll below are the only write paths for
	// RevokedAt. Returns ErrNotFound if the Node is not in the registry.
	SetRevoked(nodeID string, at time.Time) error

	// SetRevokedAll is SetRevoked's chunked twin: it writes the same column
	// for every id in nodeIDs, all under ONE transaction. On a nil error
	// every id that has a registry row was written; on a non-nil error none
	// were, and missing is nil. Same all-or-nothing contract as
	// audit.Repository.AppendAll, which the cascade uses for its
	// records — deliberately the same shape.
	//
	// A missing row is NOT an error. An id with no registry row is returned
	// in missing and does not abort the write for the rest of the batch.
	// This is the batch form of the ErrNotFound tolerance the per-Node
	// cascade already applies (revocation/service.go): a Node that never
	// connected has no row, and the in-memory denylist still holds for this
	// process. missing never aliases nodeIDs.
	//
	// Takes no context.Context, like every other method on this interface.
	// A durable revocation write must not become cancellable: if it were
	// bound to the Control API's cascade audit budget, a budget expiry
	// would stop persisting revocations while the in-memory denylist kept
	// adding them, and the next Relay restart — which rehydrates the
	// denylist from RevokedNodeIDs() — would let those Nodes back in
	// (ADR-0006). Over-denying beats under-denying; an un-persisted revoke is
	// under-denying.
	//
	// nodeIDs is a READ-ONLY BORROW: implementations must not modify it in
	// place, append within its spare capacity, or retain it after
	// returning.
	//
	// Empty nodeIDs is a no-op returning (nil, nil).
	SetRevokedAll(nodeIDs []string, at time.Time) (missing []string, err error)

	// RevokedNodeIDs returns the IDs of every Node with a non-zero
	// RevokedAt, for rehydrating a connect-time denylist after a restart.
	RevokedNodeIDs() ([]string, error)

	// Count returns aggregate Node counts for metrics: total enrolled and the
	// subset currently revoked. Backed by COUNT(*) in the store, never a full
	// List() deep-copy, so it stays cheap at fleet scale (100k Nodes;
	// scraping must not O(N) deep-copy).
	Count() (total int, revoked int, err error)
}
