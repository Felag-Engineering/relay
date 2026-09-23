package capability

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// readlane_registry.go is the read lane's REGISTRY half (#450), beside
// readlane.go's audit/Job half.
//
// readlane.go answers "what is on the trail"; this file answers "what is in
// the fleet". Both are non-dispatching reads that disclose the fleet's shape
// — Node names, all four Label namespaces, Facts, certificate provenance —
// and ADR-0025 decision 1 audits exactly that class of read. It follows
// readlane.go's order without exception: validate -> record the read, FAIL
// CLOSED -> read the seam. Recording BEFORE the registry is touched is what
// makes the record cover the attempt rather than the success, so "who probed
// for node X" is answerable even when X does not exist.
//
// # Why these are on the capability layer and not on each surface
//
// Invariant 10: one capability layer, three thin surfaces. The MCP surface
// and the Control API each call an AuditSink at their own door
// (mcp/readaudit.go, api/nodes.go) — a shape that predates the read lane and
// that #450 deliberately does not copy a third time. A surface that grows its
// own RecordRead call is a surface that can forget one, and the Admin Console
// is a screen count that only goes up. Here, the audit write and the read are
// the same call: there is no way to reach the registry through this lane
// without the record, because the record is written first and its failure
// returns before s.reg is touched.
//
// # Why the tool names are the MCP tools' names
//
// toolListNodes and toolDescribeNode are "list_nodes" and "describe_node" —
// deliberately the MCP tools' names rather than a Console screen name, on the
// precedent the Control API already set for get_job (api/jobs.go's
// readCapabilityGetJob): ADR-0025's question is "who enumerated the fleet",
// and an auditor asking it should get ONE answer across every surface instead
// of having to know each door's spelling. Which door was used stays
// recoverable from the verified lane, which records the Account, its auth
// method, its token and its source.
//
// They also have to render correctly where they land. tool becomes
// audit.Record.OperationName, which console/vocab.go's readTargetOf feeds to
// readTargetName on three screens — the Activity trail, read egress, and node
// detail. A KindRead record carries no Args, so readTargetName returns the
// name verbatim: "list_nodes" and "describe_node" read there exactly as the
// same records from MCP already do. (#463, #517 and #520 were each a case of
// these records rendering wrongly; the fix for all three was to make one
// vocabulary, not two.)
//
// toolListOperations joined with #680 on the same terms: it is the MCP
// tool's own name because ADR-0025's question is "who probed this Node's
// vocabulary" and an auditor should get one answer across surfaces, and it
// already renders correctly through console/vocab.go's readTargetName.

// Read-lane tool names for the registry half. Low-cardinality and stable for
// the same reason readlane.go's are: they land in the append-only trail.
const (
	toolListNodes      = "list_nodes"
	toolDescribeNode   = "describe_node"
	toolListOperations = "list_operations"
)

// ErrNodeNotFound is returned by DescribeNode for an id the registry does not
// hold. Distinct from an error: a surface renders "no such Node" for this and
// "this Relay is broken" for anything else, and collapsing the two would have
// a Console answer a probe for a non-existent Node with a 500.
var ErrNodeNotFound = errors.New("capability: node not found")

// ErrReadUnaudited reports a read REFUSED because its access record could not
// be written (ADR-0025 decision 4: "an unauditable read fails").
//
// It exists so a surface can say WHICH failure happened. Without it every
// read-lane error is one opaque value, and a Console rendering "could not be
// read" for an audit-trail outage sends an operator to look at the registry —
// the one component that was working. The distinction is also the honest one
// to put in front of a human: nothing was disclosed, and the trail is the
// thing to go and fix.
//
// Wrapped by recordQueryRead, so it covers BOTH halves of the read lane:
// errors.Is(err, ErrReadUnaudited) is true for an unauditable QueryAudit
// exactly as it is for an unauditable ListNodes.
var ErrReadUnaudited = errors.New("capability: read refused because it could not be audited")

// maxNodeIDBytes bounds a caller-supplied Node id on the read lane.
//
// The value is caller-controlled and lands in the append-only trail as the
// read record's own NodeID, which is the same reason readlane.go bounds a Job
// id (F2, #441 cycle-2 security review) and AuditFilter.validate bounds Kinds
// and Operations. A real Node id is a short identifier the enrollment path
// issued; 256 bytes is far above anything real and still a bound, and it is
// checked BEFORE the record is written so an oversized probe cannot use the
// trail as storage.
const maxNodeIDBytes = 256

// NodeDetail is one Node plus the fleet-wide fingerprint context a Node read
// needs.
//
// The peer counts are computed HERE rather than by the caller because the
// alternative is worse in both directions. A surface that wanted them would
// have to enumerate the whole registry to render two integers about one Node
// — a second, much wider disclosure than the read it actually made, and one
// that would have to be audited as an enumeration to stay honest. Computing
// them behind describe_node keeps a single-Node read a single-Node read.
//
// They are a domain question, not a rendering one: a Policy fingerprint
// exists precisely so an operator can confirm by string comparison that a
// rollout landed everywhere (GLOSSARY.md, ADR-0002). "How many Nodes report
// this one" is that comparison, counted.
type NodeDetail struct {
	// Node is the registry record, as registry.Get returns it (a deep copy).
	Node registry.Node

	// Eval is the StateEval this read was resolved at — the same instant/
	// window a surface must render `state:` Labels against, rather than
	// re-deriving one from a window it keeps its own copy of (#680).
	Eval StateEval

	// PolicyPeers is how many Nodes in the registry report the same
	// non-empty Policy fingerprint as Node, Node itself included. Zero when
	// Node reports no fingerprint at all — "nothing to compare", not "no
	// agreement".
	PolicyPeers int

	// TemplatePeers is the same count for the template-set fingerprint.
	TemplatePeers int

	// Policy and PolicyReported are the DISPLAY-ONLY Policy view (#680).
	// PolicyReported=false is the ONLY "nothing captured yet" signal — a
	// caller must never render it as an empty Policy — and is what a nil
	// PolicyViewSource, or one that has not yet seen this Node (re)connect,
	// produces.
	Policy         policyview.Snapshot
	PolicyReported bool

	// Templates and TemplatesReported are the DISPLAY-ONLY Template
	// vocabulary view (#680), following the same reported=false discipline.
	Templates         nodevocab.Snapshot
	TemplatesReported bool
}

// NodeListing is ListNodes' result: the matched Nodes plus the context a
// surface needs to render them (#680).
type NodeListing struct {
	// Nodes may be a NIL slice when the Selector matched nothing
	// (Selector.Resolve returns nil, never an empty non-nil slice) — every
	// surface rendering it must build its response array with an explicit
	// zero-length, pre-sized make, since arrays are never null on the wire
	// (#207/#253).
	Nodes []registry.Node

	// Eval is the StateEval this listing was resolved at.
	Eval StateEval

	// Selector is the canonical form (Selector.String()) that was actually
	// recorded — empty for the whole fleet.
	Selector string
}

// ListNodes parses and resolves selector, auditing the canonical Selector
// form before the registry is read.
//
// This is the fleet-shape disclosure ADR-0025 names first: Node names, all
// four Label namespaces, Facts and certificate provenance, for every
// matching Node at once. The order is validate -> record -> resolve, the
// same order DescribeNode uses for a Node ID: a malformed Selector must not
// be able to use the trail as storage. The recorded selector is the
// CANONICAL form (sel.String()), not the caller's bytes — the same
// precedent NoNodesMatchedError sets — which keeps the tag: sentinel and
// #430 pointer legible on every surface (QRY-20).
//
// Node-ID ordering within Nodes (QRY-3) comes from registry.InMemory.List
// and is preserved by Selector.Resolve, so no surface needs to sort again.
func (s *Service) ListNodes(ctx context.Context, p Principal, selector string) (NodeListing, error) {
	if err := s.registryReadable(); err != nil {
		return NodeListing{}, err
	}
	sel, err := ParseSelector(selector)
	if err != nil {
		return NodeListing{}, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	canonical := sel.String()
	if err := s.recordQueryRead(ctx, p, toolListNodes, canonical, "", ""); err != nil {
		return NodeListing{}, err
	}
	ev := s.stateEval()
	return NodeListing{Nodes: sel.Resolve(s.reg, ev), Eval: ev, Selector: canonical}, nil
}

// DescribeNode returns one Node, its fingerprint peer counts, and its
// DISPLAY-ONLY Policy/Template views, auditing the read against that Node
// id.
//
// The record is written for the id that was ASKED FOR, before the registry is
// consulted, so a probe for a Node that does not exist is on the trail exactly
// like a read of one that does. That is the interesting half: enumeration by
// guessing ids is precisely what an audited read surface is for, and a lane
// that recorded only successful lookups would record only the guesses that
// worked.
//
// Returns ErrNodeNotFound — after the record — for an unknown id.
//
// The Policy view and the Template vocabulary are filled from s.policyView/
// s.nodeVocab with NO second record: they are part of what describe_node
// discloses (ADR-0025 names a Node's Policy explicitly), and the record
// above already covers this Node ID.
//
// COST (security review, cycle 2, LOW 4): computing PolicyPeers/
// TemplatePeers below walks the WHOLE registry, so one authenticated
// single-Node read costs one O(N)-in-fleet-size scan, not O(1). Every caller
// pays it, whether or not it reads the two fields back — the Control API
// and MCP construct and discard them today (only the Console Node-detail
// screen renders PolicyShared/TemplateShared from them), and the Console's
// own pin bar (pinsKnown, node.go) and Compare screen (buildCompareView,
// compare.go) each call DescribeNode up to maxPins (3) further times per
// render without ever reading the counts back. In the worst observed case —
// a Node-detail page with a full pin bar — that is four scans for one page
// view; a Compare page with three pins is three more. This is in-memory and
// discloses nothing new (the fleet size and every fingerprint were already
// readable), so it is a performance bound, not a security one; it is
// written down here rather than fixed because making the count lazy or
// opt-in would widen this change across every adapter's DescribeNode
// signature, and that is out of scope for this issue.
func (s *Service) DescribeNode(ctx context.Context, p Principal, nodeID string) (NodeDetail, error) {
	if err := s.registryReadable(); err != nil {
		return NodeDetail{}, err
	}
	if err := validateNodeID(nodeID); err != nil {
		return NodeDetail{}, err
	}
	if err := s.recordQueryRead(ctx, p, toolDescribeNode, "", nodeID, ""); err != nil {
		return NodeDetail{}, err
	}
	n, ok := s.reg.Get(nodeID)
	if !ok {
		return NodeDetail{}, fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}
	d := NodeDetail{Node: n, Eval: s.stateEval()}
	for _, other := range s.reg.List() {
		if n.PolicyFingerprint != "" && other.PolicyFingerprint == n.PolicyFingerprint {
			d.PolicyPeers++
		}
		if n.TemplateSetFingerprint != "" && other.TemplateSetFingerprint == n.TemplateSetFingerprint {
			d.TemplatePeers++
		}
	}
	if s.policyView != nil {
		if snap, ok := s.policyView.Get(nodeID); ok {
			d.Policy, d.PolicyReported = snap, true
		}
	}
	if s.nodeVocab != nil {
		if snap, ok := s.nodeVocab.Get(nodeID); ok {
			d.Templates, d.TemplatesReported = snap, true
		}
	}
	return d, nil
}

// OperationVocabulary is ListOperations' Node-scoped half: the Template
// vocabulary a Node reported, display-only exactly like NodeDetail's.
type OperationVocabulary struct {
	Templates nodevocab.Snapshot
	Reported  bool
}

// ListOperations resolves the Template Operation vocabulary for one Node, or
// records the fleet-wide call when nodeID is empty (the Native vocabulary is
// a frozen, compile-time, fleet-wide table — ADR-0015/ADR-0021 — that
// discloses nothing about this fleet and reads no registry or cache, so it
// stays on the calling surface; this lane owns only the read that touches
// fleet state).
//
// registryReadable is checked UNCONDITIONALLY, fleet-wide call included: one
// discipline beats two, so a Relay with no registry wired fails closed on
// every lane method rather than on some of them.
//
// An empty nodeID is LEGAL here — it is the fleet-wide Native request
// (QRY-12), not a malformed one — but a NON-empty one is still bounded by
// validateNodeID before it is recorded, exactly like DescribeNode.
//
// The read is recorded ALWAYS, fleet-wide included: an empty nodeID writes a
// record with no target, the same shape queryJobs already writes
// (readlane.go). Recording only the per-Node call would leave the
// fleet-wide call unaudited and never fail closed — a regression against
// ADR-0025.
//
// An unknown, well-formed Node ID is refused as ErrNodeNotFound — after the
// record — so the refused probe is on the trail with the id it asked about
// (QRY-26).
func (s *Service) ListOperations(ctx context.Context, p Principal, nodeID string) (OperationVocabulary, error) {
	if err := s.registryReadable(); err != nil {
		return OperationVocabulary{}, err
	}
	if nodeID != "" {
		if err := validateNodeID(nodeID); err != nil {
			return OperationVocabulary{}, err
		}
	}
	if err := s.recordQueryRead(ctx, p, toolListOperations, "", nodeID, ""); err != nil {
		return OperationVocabulary{}, err
	}
	if nodeID == "" {
		return OperationVocabulary{}, nil
	}
	if _, ok := s.reg.Get(nodeID); !ok {
		return OperationVocabulary{}, fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}
	var vocab OperationVocabulary
	if s.nodeVocab != nil {
		if snap, ok := s.nodeVocab.Get(nodeID); ok {
			vocab.Templates, vocab.Reported = snap, true
		}
	}
	return vocab, nil
}

// registryReadable refuses the registry read lane on a Service that cannot
// actually audit — the read-lane analogue of New's fail-open guards.
//
// New already refuses WithQueries paired with the no-op sink (F5, #441),
// because a Service that answers every trail query while recording none of
// them is the "unauditable read succeeded" state ADR-0025 forbids. The
// registry half cannot be guarded the same way: reg is New's first ARGUMENT,
// always present, so there is no option whose use signals "this lane is
// wired" and no construction-time moment at which to panic without breaking
// every Service built for a dispatch test.
//
// So the check moves to the call. It is the same property, enforced later and
// narrower: a Service with the no-op sink refuses these three methods
// (ListNodes, DescribeNode, ListOperations) and nothing else. Fail closed,
// and it fails as ErrReadUnaudited rather than as a wiring error, because
// from the caller's side the two are the same fact — this Relay will not
// serve a read it cannot record.
func (s *Service) registryReadable() error {
	if s.reg == nil {
		return fmt.Errorf("%w: no registry is configured on this Relay", ErrQueriesUnavailable)
	}
	return s.auditSinkPresent()
}

// auditSinkPresent is registryReadable's sink guard, extracted (#539) so a
// read-lane method with no registry coupling of its own — RecordEventSubscription,
// readlane.go — can still refuse a Service built on the no-op sink.
// registryReadable keeps its own s.reg == nil check and then calls this.
//
// Without it, a Service constructed with New(reg) alone (no WithAuditSink)
// would "record" a subscription successfully through noopAuditSink.RecordRead,
// which unconditionally returns nil, and open an UNAUDITED live stream — the
// exact "unauditable read succeeded" state ADR-0025 forbids. New's own
// fail-open guards do not cover this: they trip on WithExecution or
// WithQueries, and a bare event-subscription lane needs neither.
func (s *Service) auditSinkPresent() error {
	if _, noop := s.audit.(noopAuditSink); noop {
		return fmt.Errorf("%w: no audit sink is configured on this Relay", ErrReadUnaudited)
	}
	return nil
}

func validateNodeID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: node id is required", ErrInvalidFilter)
	}
	if len(id) > maxNodeIDBytes {
		return fmt.Errorf("%w: node id exceeds %d bytes", ErrInvalidFilter, maxNodeIDBytes)
	}
	return nil
}
