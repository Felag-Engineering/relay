package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// readlane_registry.go is the read lane's REGISTRY half, beside
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
// (mcp/readaudit.go, api/nodes.go) — a shape this lane deliberately does not
// copy a third time. A surface that grows its
// own RecordRead call is a surface that can forget one, and the Admin Console
// is a screen count that only goes up. Here, the audit write and the read are
// the same call: there is no way to reach the registry through this lane
// without the record, because the record is written first and its failure
// returns before l.reg is touched.
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
// readTargetName on the Activity trail and node detail. A KindRead record
// carries no Args, so readTargetName returns the name verbatim: "list_nodes"
// and "describe_node" read there exactly as the same records from MCP
// do: one vocabulary, not two.
//
// toolListOperations is named on the same terms: it is the MCP
// tool's own name because ADR-0025's question is "who probed this Node's
// vocabulary" and an auditor should get one answer across surfaces, and it
// renders correctly through console/vocab.go's readTargetName.

// Read-lane tool names for the registry half. Low-cardinality and stable for
// the same reason readlane.go's are: they land in the append-only trail.
const (
	toolListNodes      = "list_nodes"
	toolDescribeNode   = "describe_node"
	toolListOperations = "list_operations"
)

// ReadLane is the capability layer's read side: the registry
// reads, the audit-trail and Job queries, and Selector resolution, each audited
// before it is served. Construct it with NewReadLane.
type ReadLane struct {
	rec *Recorder
	reg registry.Repository

	// auditQ and jobQ are the read lane: filtered, paginated queries
	// over the audit trail and over Jobs/Tasks. Nil means the read lane is
	// not wired — readlane.go's methods return ErrQueriesUnavailable rather
	// than an empty page, since an empty page is a claim ("there is nothing
	// here") and a nil seam has not actually looked. NewReadLane requires
	// both, so only the in-package assembler can produce a lane without them.
	auditQ AuditQuery
	jobQ   JobQuery

	// policyView and nodeVocab are the Policy-view and Template-vocabulary
	// reads (seams.go). policyView is display-only. nodeVocab is also
	// read by template.go to decide a Template dispatch's fan-out and class
	// (ADR-0042), and by nothing else outside the read lane. Both nil by
	// default: DescribeNode and ListOperations report *Reported=false for a
	// nil seam rather than an empty Policy or vocabulary — absence is never
	// rendered as "nothing restricted" (QRY-7) — and a Template dispatch with
	// no vocabulary wired excludes every Node rather than dispatching blind.
	policyView PolicyViewSource
	nodeVocab  TemplateVocabularySource

	// settings supplies the state:cert-expiring warning window (ADR-0034),
	// read per request and threaded into every Selector resolution via
	// stateEval. A zero window means the marker never fires; nil means zero
	// (struct-literal test lanes only). No API reads or sets it (invariant 11).
	settings OperatorSettingsSource

	// now is the clock Selector resolution reads; nil means time.Now().UTC().
	now func() time.Time

	// aliases is the Policy alias read (policyalias.go). Nil means not wired:
	// PolicyAliases returns ErrPolicyAliasesUnavailable, never an empty map.
	aliases PolicyAliasSource
}

// NewReadLane returns a ReadLane over rec, reg and the two query seams. rec,
// reg, auditQ and jobQ are required: a lane with no trail cannot audit its
// reads, one with no registry or query seam has nothing to read — all
// composition-root bugs, so each panics rather than degrading. A negative
// settings source panics for the same reason; a zero window means the
// state:cert-expiring marker never fires.
//
// NewReadLane also refuses a Recorder over the no-op AuditSink (F5,
// cycle-2 security review): a lane that answers every query while recording
// none of them is exactly the "unauditable read succeeded" state ADR-0025
// forbids. policyView, nodeVocab and now may be nil — absence is documented on
// the fields; a nil now means time.Now().UTC().
func NewReadLane(rec *Recorder, reg registry.Repository, auditQ AuditQuery, jobQ JobQuery, policyView PolicyViewSource, nodeVocab TemplateVocabularySource, settings OperatorSettingsSource, now func() time.Time, opts ...ReadLaneOption) *ReadLane {
	if rec == nil {
		panic("capability: NewReadLane: recorder must not be nil")
	}
	if reg == nil {
		panic("capability: NewReadLane: registry must not be nil")
	}
	if auditQ == nil {
		panic("capability: NewReadLane: audit query seam must not be nil")
	}
	if jobQ == nil {
		panic("capability: NewReadLane: job query seam must not be nil")
	}
	if settings == nil {
		panic("capability: NewReadLane: settings must not be nil")
	}
	if _, ok := rec.audit.(noopAuditSink); ok {
		panic("capability: NewReadLane: requires a real AuditSink (NewRecorder); noopAuditSink would answer every read while recording none of them")
	}
	return newReadLane(rec, reg, auditQ, jobQ, policyView, nodeVocab, settings, now, opts...)
}

// newReadLane assembles a ReadLane with no checks. Only NewReadLane and _test.go
// files call it; it is the only route to a lane with no query seams or over the
// no-op sink, which the QRY-17 call-time tests need.
func newReadLane(rec *Recorder, reg registry.Repository, auditQ AuditQuery, jobQ JobQuery, policyView PolicyViewSource, nodeVocab TemplateVocabularySource, settings OperatorSettingsSource, now func() time.Time, opts ...ReadLaneOption) *ReadLane {
	l := &ReadLane{rec: rec, reg: reg, auditQ: auditQ, jobQ: jobQ, policyView: policyView, nodeVocab: nodeVocab, settings: settings, now: now}
	for _, o := range opts {
		o(l)
	}
	return l
}

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
// id (F2, cycle-2 security review) and AuditFilter.validate bounds Kinds
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
	// re-deriving one from a window it keeps its own copy of.
	Eval StateEval

	// PolicyPeers is how many Nodes in the registry report the same
	// non-empty Policy fingerprint as Node, Node itself included. Zero when
	// Node reports no fingerprint at all — "nothing to compare", not "no
	// agreement".
	PolicyPeers int

	// TemplatePeers is the same count for the template-set fingerprint.
	TemplatePeers int

	// Policy and PolicyReported are the DISPLAY-ONLY Policy view.
	// PolicyReported=false is the ONLY "nothing captured yet" signal — a
	// caller must never render it as an empty Policy — and is what a nil
	// PolicyViewSource, or one that has not yet seen this Node (re)connect,
	// produces.
	Policy         policyview.Snapshot
	PolicyReported bool

	// Templates and TemplatesReported are the DISPLAY-ONLY Template
	// vocabulary view, following the same reported=false discipline.
	Templates         nodevocab.Snapshot
	TemplatesReported bool
}

// NodeListing is ListNodes' result: the matched Nodes plus the context a
// surface needs to render them.
type NodeListing struct {
	// Nodes may be a NIL slice when the Selector matched nothing
	// (Selector.Resolve returns nil, never an empty non-nil slice) — every
	// surface rendering it must build its response array with an explicit
	// zero-length, pre-sized make, since arrays are never null on the wire.
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
// precedent NoNodesMatchedError sets — which keeps the tag: sentinel and its
// issue pointer legible on every surface (QRY-20).
//
// Node-ID ordering within Nodes (QRY-3) comes from registry.InMemory.List
// and is preserved by Selector.Resolve, so no surface needs to sort again.
func (l *ReadLane) ListNodes(ctx context.Context, p Principal, selector string) (NodeListing, error) {
	if err := l.registryReadable(); err != nil {
		return NodeListing{}, err
	}
	sel, err := ParseSelector(selector)
	if err != nil {
		return NodeListing{}, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	canonical := sel.String()
	if err := l.recordQueryRead(ctx, p, toolListNodes, canonical, "", ""); err != nil {
		return NodeListing{}, err
	}
	ev := l.stateEval()
	return NodeListing{Nodes: sel.Resolve(l.reg, ev), Eval: ev, Selector: canonical}, nil
}

// stateEval is the StateEval every Selector resolution inside the capability
// layer evaluates against: the lane's own clock and its configured
// cert-expiring window. One method, so Run and Plan (through Execution.read) and
// the read lane can never resolve the same Selector against two different
// instants.
//
// Falls back to time.Now().UTC() when now is unset — a *ReadLane built as a
// struct literal in a test (bypassing NewReadLane) must stay callable rather
// than panic on a nil func field.
func (l *ReadLane) stateEval() StateEval {
	now := l.now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var window time.Duration
	if l.settings != nil {
		window = max(l.settings.OperatorSettings().CertExpiringWithin, 0)
	}
	return StateEval{Now: now(), CertExpiringWithin: window}
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
// The Policy view and the Template vocabulary are filled from l.policyView/
// l.nodeVocab with NO second record: they are part of what describe_node
// discloses (ADR-0025 names a Node's Policy explicitly), and the record
// above already covers this Node ID.
//
// COST (security review, cycle 2, LOW 4): computing PolicyPeers/
// TemplatePeers below walks the WHOLE registry, so one authenticated
// single-Node read costs one O(N)-in-fleet-size scan, not O(1). Every caller
// pays it, whether or not it reads the two fields back — the Control API
// and MCP construct and discard them today (only the Console Node-detail
// screen renders PolicyShared/TemplateShared from them), and the Console's
// own pin bar (pinsResolved, node.go) and Compare screen (buildCompareView,
// compare.go) each call DescribeNode up to maxPins (3) further times per
// render without ever reading the counts back. In the worst observed case —
// a Node-detail page with a full pin bar — that is four scans for one page
// view; a Compare page with three pins is three more. This is in-memory and
// discloses nothing new (the fleet size and every fingerprint were already
// readable), so it is a performance bound, not a security one; it is
// written down here rather than fixed because making the count lazy or
// opt-in would widen every adapter's DescribeNode signature.
func (l *ReadLane) DescribeNode(ctx context.Context, p Principal, nodeID string) (NodeDetail, error) {
	if err := l.registryReadable(); err != nil {
		return NodeDetail{}, err
	}
	if err := validateNodeID(nodeID); err != nil {
		return NodeDetail{}, err
	}
	if err := l.recordQueryRead(ctx, p, toolDescribeNode, "", nodeID, ""); err != nil {
		return NodeDetail{}, err
	}
	n, ok := l.reg.Get(nodeID)
	if !ok {
		return NodeDetail{}, fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}
	d := NodeDetail{Node: n, Eval: l.stateEval()}
	for _, other := range l.reg.List() {
		if n.PolicyFingerprint != "" && other.PolicyFingerprint == n.PolicyFingerprint {
			d.PolicyPeers++
		}
		if n.TemplateSetFingerprint != "" && other.TemplateSetFingerprint == n.TemplateSetFingerprint {
			d.TemplatePeers++
		}
	}
	if l.policyView != nil {
		if snap, ok := l.policyView.Get(nodeID); ok {
			d.Policy, d.PolicyReported = snap, true
		}
	}
	if l.nodeVocab != nil {
		if snap, ok := l.nodeVocab.Get(nodeID); ok {
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
func (l *ReadLane) ListOperations(ctx context.Context, p Principal, nodeID string) (OperationVocabulary, error) {
	if err := l.registryReadable(); err != nil {
		return OperationVocabulary{}, err
	}
	if nodeID != "" {
		if err := validateNodeID(nodeID); err != nil {
			return OperationVocabulary{}, err
		}
	}
	if err := l.recordQueryRead(ctx, p, toolListOperations, "", nodeID, ""); err != nil {
		return OperationVocabulary{}, err
	}
	if nodeID == "" {
		return OperationVocabulary{}, nil
	}
	if _, ok := l.reg.Get(nodeID); !ok {
		return OperationVocabulary{}, fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}
	var vocab OperationVocabulary
	if l.nodeVocab != nil {
		if snap, ok := l.nodeVocab.Get(nodeID); ok {
			vocab.Templates, vocab.Reported = snap, true
		}
	}
	return vocab, nil
}

// registryReadable refuses the registry read lane on a ReadLane that cannot
// actually audit — the read-lane analogue of NewExecution's fail-open guards.
//
// NewReadLane already refuses the no-op sink (F5), because a lane that
// answers every query while recording none of them is the "unauditable read
// succeeded" state ADR-0025 forbids. This check stays at the call as defence
// in depth for a lane built by the in-package assembler (newReadLane), and as
// QRY-17's cited proof: it is the same property, enforced at the read, and it
// refuses these three methods (ListNodes, DescribeNode, ListOperations) and
// nothing else. Fail closed, and it fails as ErrReadUnaudited rather than as
// a wiring error, because from the caller's side the two are the same fact —
// this Relay will not serve a read it cannot record.
func (l *ReadLane) registryReadable() error {
	if l.reg == nil {
		return fmt.Errorf("%w: no registry is configured on this Relay", ErrQueriesUnavailable)
	}
	return l.auditSinkPresent()
}

// auditSinkPresent is registryReadable's sink guard, extracted so a
// read-lane method with no registry coupling of its own — RecordEventSubscription,
// readlane.go — can still refuse a lane built on the no-op sink.
// registryReadable keeps its own l.reg == nil check and then calls this.
//
// Without it, a lane assembled over the no-op sink would "record" a
// subscription successfully through noopAuditSink.RecordRead, which
// unconditionally returns nil, and open an UNAUDITED live stream — the exact
// "unauditable read succeeded" state ADR-0025 forbids. NewReadLane refuses the
// no-op sink at construction; this is the same property enforced at the call.
func (l *ReadLane) auditSinkPresent() error {
	if _, noop := l.rec.audit.(noopAuditSink); noop {
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
