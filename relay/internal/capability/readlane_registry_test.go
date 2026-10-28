package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// fakePolicyView is a minimal PolicyViewSource test double: a map keyed by
// node id, mirroring policyview.Cache.Get's (Snapshot, bool) contract
// without carrying Set.
type fakePolicyView map[string]policyview.Snapshot

func (f fakePolicyView) Get(nodeID string) (policyview.Snapshot, bool) {
	s, ok := f[nodeID]
	return s, ok
}

// fakeTemplateVocab is TemplateVocabularySource's sibling.
type fakeTemplateVocab map[string]nodevocab.Snapshot

func (f fakeTemplateVocab) Get(nodeID string) (nodevocab.Snapshot, bool) {
	s, ok := f[nodeID]
	return s, ok
}

// registryLaneFixture builds a Service over a seeded registry with a spy
// AuditSink — the registry read lane's half of readLaneFixture.
//
// The query seams are supplied too, not because these methods use them, but
// because the production ReadLane always has them and a fixture that quietly
// differs from production is a fixture that proves less than it looks like it does.
func registryLaneFixture(t *testing.T, nodes ...registry.Report) (*testSvc, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, r := range nodes {
		if _, err := reg.Upsert(r); err != nil {
			t.Fatalf("Upsert(%s): %v", r.NodeID, err)
		}
	}
	sink := &spyAuditSink{}
	return build(t, seams{reg: reg, auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{}, audit: sink}), sink
}

// registryLaneFixtureWithViews is registryLaneFixture, additionally wired
// with a PolicyViewSource and a TemplateVocabularySource — the fixture for
// DescribeNode/ListOperations tests that need something to report.
func registryLaneFixtureWithViews(t *testing.T, policy PolicyViewSource, vocab TemplateVocabularySource, nodes ...registry.Report) (*testSvc, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, r := range nodes {
		if _, err := reg.Upsert(r); err != nil {
			t.Fatalf("Upsert(%s): %v", r.NodeID, err)
		}
	}
	sink := &spyAuditSink{}
	return build(t, seams{reg: reg,
		auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{},
		audit:      sink,
		policyView: policy,
		nodeVocab:  vocab,
	}), sink
}

// TestListNodes_RecordsTheEnumeration is QRY-16 (also ADR-0025 decision 1)
// for the fleet read: who enumerated, which tool, and when, with the record
// written before the enumeration's content is returned to the caller — and
// with the Selector that was resolved riding the record, even the empty one
// that means "the whole fleet".
func TestListNodes_RecordsTheEnumeration(t *testing.T) {
	svc, sink := registryLaneFixture(t,
		registry.Report{NodeID: "node-1"}, registry.Report{NodeID: "node-2"})

	listing, err := svc.ListNodes(context.Background(), testPrincipal, "")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(listing.Nodes) != 2 {
		t.Fatalf("ListNodes returned %d Nodes, want 2", len(listing.Nodes))
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("ListNodes wrote %d read records, want 1", len(sink.readCalls))
	}
	got := sink.readCalls[0]
	if got.Tool != toolListNodes {
		t.Errorf("tool = %q, want %q", got.Tool, toolListNodes)
	}
	if got.Principal.AccountID != testPrincipal.AccountID {
		t.Errorf("principal = %+v, want the caller %+v", got.Principal, testPrincipal)
	}
	// A fleet enumeration is aimed at no single thing, and saying otherwise
	// would put a Node id on a record that read every Node.
	if got.NodeID != "" || got.JobID != "" {
		t.Errorf("record carries %+v, want no NodeID/JobID for an enumeration", got)
	}
	// The Selector rides the record too, even the empty one that resolved to
	// the whole fleet — QRY-16 does not exempt an unfiltered enumeration from
	// carrying its Selector.
	if got.Selector != "" {
		t.Errorf("recorded Selector = %q, want the resolved (empty, fleet-wide) Selector", got.Selector)
	}
}

// TestListNodes_ResolvesTheSelectorAndRecordsItsCanonicalForm covers both
// halves of ListNodes' new shape (#680): it actually resolves selector
// against the registry (not just enumerates), and what lands on the trail is
// the CANONICAL Selector form, not the caller's raw bytes — the same
// precedent NoNodesMatchedError sets (QRY-42).
func TestListNodes_ResolvesTheSelectorAndRecordsItsCanonicalForm(t *testing.T) {
	svc, sink := registryLaneFixture(t,
		registry.Report{NodeID: "node-1"}.WithNodeLabels(map[string]string{"role": "web"}),
		registry.Report{NodeID: "node-2"}.WithNodeLabels(map[string]string{"role": "db"}),
	)

	listing, err := svc.ListNodes(context.Background(), testPrincipal, "  node:role=web  ")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(listing.Nodes) != 1 || listing.Nodes[0].NodeID != "node-1" {
		t.Fatalf("ListNodes(node:role=web) = %+v, want only node-1", listing.Nodes)
	}
	if listing.Selector != "node:role=web" {
		t.Errorf("NodeListing.Selector = %q, want the canonical form %q", listing.Selector, "node:role=web")
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("ListNodes wrote %d read records, want 1", len(sink.readCalls))
	}
	if got := sink.readCalls[0].Selector; got != "node:role=web" {
		t.Errorf("recorded Selector = %q, want the canonical form %q, not the caller's raw bytes", got, "node:role=web")
	}
}

// TestListNodes_ResolvesATagSelector is QRY-41's tag half at the lane: a tag:
// term resolves the tagged Nodes, in Node-ID order under a filtered Selector,
// and the canonical Selector is recorded.
func TestListNodes_ResolvesATagSelector(t *testing.T) {
	reg := registry.NewInMemory()
	for _, id := range []string{"node-c", "node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	// Seeded out of ID order, and node-b is left untagged.
	for _, id := range []string{"node-c", "node-a"} {
		if err := reg.ApplyTagChanges([]registry.TagChange{
			{NodeID: id, Key: "team", After: registry.TagValue{Set: true, Value: "payments"}},
		}); err != nil {
			t.Fatalf("ApplyTagChanges(%s): %v", id, err)
		}
	}
	sink := &spyAuditSink{}
	svc := build(t, seams{reg: reg, auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{}, audit: sink})

	listing, err := svc.ListNodes(context.Background(), testPrincipal, "  tag:team=payments ")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	var ids []string
	for _, n := range listing.Nodes {
		ids = append(ids, n.NodeID)
	}
	if strings.Join(ids, ",") != "node-a,node-c" {
		t.Errorf("ListNodes(tag:team=payments) = %v, want [node-a node-c] in Node-ID order", ids)
	}
	if listing.Selector != "tag:team=payments" {
		t.Errorf("NodeListing.Selector = %q, want the canonical form", listing.Selector)
	}
	if len(sink.readCalls) != 1 || sink.readCalls[0].Selector != "tag:team=payments" {
		t.Errorf("readCalls = %+v, want one record with the canonical Selector", sink.readCalls)
	}
}

// TestListNodes_RefusesAMalformedSelectorBeforeRecordingAnything mirrors
// DescribeNode's existing Node-ID bound: a malformed Selector must not be
// able to use the trail as storage.
func TestListNodes_RefusesAMalformedSelectorBeforeRecordingAnything(t *testing.T) {
	svc, sink := registryLaneFixture(t, registry.Report{NodeID: "node-1"})

	listing, err := svc.ListNodes(context.Background(), testPrincipal, "bare-key")
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("ListNodes(malformed) error = %v, want ErrInvalidFilter", err)
	}
	if listing.Nodes != nil {
		t.Errorf("ListNodes(malformed) returned %+v alongside its refusal", listing.Nodes)
	}
	if len(sink.readCalls) != 0 {
		t.Errorf("a malformed Selector was written to the trail (%+v) — the trail is not caller storage", sink.readCalls)
	}
}

// TestListNodes_ReturnsMatchesInNodeIdOrder pins that Node-ID ordering
// (QRY-41) survives the move onto Selector.Resolve: registry.InMemory.List
// sorts by NodeID and Resolve preserves that order, so no surface needs to
// sort again.
func TestListNodes_ReturnsMatchesInNodeIdOrder(t *testing.T) {
	svc, _ := registryLaneFixture(t,
		registry.Report{NodeID: "node-c"},
		registry.Report{NodeID: "node-a"},
		registry.Report{NodeID: "node-b"},
	)

	listing, err := svc.ListNodes(context.Background(), testPrincipal, "")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	var ids []string
	for _, n := range listing.Nodes {
		ids = append(ids, n.NodeID)
	}
	want := []string{"node-a", "node-b", "node-c"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("ListNodes order = %v, want %v", ids, want)
	}
}

// TestDescribeNode_RecordsTheNodeItWasAimedAt covers "what it was aimed at"
// and the peer counts the lane computes so a caller never has to enumerate.
func TestDescribeNode_RecordsTheNodeItWasAimedAt(t *testing.T) {
	svc, sink := registryLaneFixture(t,
		registry.Report{NodeID: "node-1", PolicyFingerprint: "a256aaa000000000000000000000000000000000000000000000000000000000", TemplateSetFingerprint: "a256000000000000000000000000000000000000000000000000000000000000"},
		registry.Report{NodeID: "node-2", PolicyFingerprint: "a256aaa000000000000000000000000000000000000000000000000000000000"},
		registry.Report{NodeID: "node-3", PolicyFingerprint: "a256bbb000000000000000000000000000000000000000000000000000000000"},
	)

	d, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1")
	if err != nil {
		t.Fatalf("DescribeNode: %v", err)
	}
	if d.Node.NodeID != "node-1" {
		t.Errorf("Node = %q, want node-1", d.Node.NodeID)
	}
	if d.PolicyPeers != 2 {
		t.Errorf("PolicyPeers = %d, want 2 (node-1 and node-2 report the same fingerprint)", d.PolicyPeers)
	}
	if d.TemplatePeers != 1 {
		t.Errorf("TemplatePeers = %d, want 1 (only node-1 reports one)", d.TemplatePeers)
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("DescribeNode wrote %d read records, want 1", len(sink.readCalls))
	}
	if sink.readCalls[0].Tool != toolDescribeNode || sink.readCalls[0].NodeID != "node-1" {
		t.Errorf("record = %+v, want tool %q aimed at node-1", sink.readCalls[0], toolDescribeNode)
	}
}

// TestDescribeNode_CountsFingerprintPeersAndSkipsEmptyFingerprints is QRY-5's
// arithmetic half under a citable name: the lane counts the registry Nodes
// sharing the subject Node's NON-EMPTY Policy and template-set fingerprints,
// counts the subject itself among them, and counts nothing at all when the
// subject's own fingerprint is empty — an absent report is not a fingerprint
// that every other silent Node happens to share.
//
// Residual: proves the lane's arithmetic and the empty-fingerprint skip only.
// Says nothing about which surface renders the counts, nothing about the
// counts' freshness, and nothing about the O(N)-per-read cost the method's own
// doc comment records — no benchmark is added.
func TestDescribeNode_CountsFingerprintPeersAndSkipsEmptyFingerprints(t *testing.T) {
	svc, _ := registryLaneFixture(t,
		registry.Report{NodeID: "node-1", PolicyFingerprint: "a256aaa000000000000000000000000000000000000000000000000000000000", TemplateSetFingerprint: "a256000000000000000000000000000000000000000000000000000000000000"},
		registry.Report{NodeID: "node-2", PolicyFingerprint: "a256aaa000000000000000000000000000000000000000000000000000000000"},
		registry.Report{NodeID: "node-3", PolicyFingerprint: "a256bbb000000000000000000000000000000000000000000000000000000000"},
		registry.Report{NodeID: "node-4"},
	)

	describe := func(t *testing.T, nodeID string) NodeDetail {
		t.Helper()
		d, err := svc.DescribeNode(context.Background(), testPrincipal, nodeID)
		if err != nil {
			t.Fatalf("DescribeNode(%s): %v", nodeID, err)
		}
		return d
	}

	// node-1 shares its Policy fingerprint with node-2 and is counted itself;
	// it is the only Node reporting a template-set fingerprint.
	if d := describe(t, "node-1"); d.PolicyPeers != 2 || d.TemplatePeers != 1 {
		t.Errorf("node-1: PolicyPeers = %d, TemplatePeers = %d; want 2 and 1 (self-inclusive)",
			d.PolicyPeers, d.TemplatePeers)
	}

	// node-2 is the empty-fingerprint skip: two other Nodes (node-3, node-4)
	// report none either — the count is still 0, not the 3 an
	// empty-matches-empty comparison would give — while its non-empty Policy
	// fingerprint is counted normally.
	if d := describe(t, "node-2"); d.TemplatePeers != 0 || d.PolicyPeers != 2 {
		t.Errorf("node-2: PolicyPeers = %d, TemplatePeers = %d; want 2 and 0 — an empty "+
			"template-set fingerprint matches nothing, not every other unreporting Node",
			d.PolicyPeers, d.TemplatePeers)
	}

	// node-4 reports neither fingerprint, so neither count sweeps up the Nodes
	// it shares that silence with: an empty-matches-empty comparison would give
	// 1 (node-4 is the only Node with no Policy fingerprint) and 3 (node-2,
	// node-3 and node-4 report no template set).
	if d := describe(t, "node-4"); d.PolicyPeers != 0 || d.TemplatePeers != 0 {
		t.Errorf("node-4: PolicyPeers = %d, TemplatePeers = %d; want 0 and 0, not the 1 and 3 an "+
			"empty-matches-empty comparison would give",
			d.PolicyPeers, d.TemplatePeers)
	}
}

// TestDescribeNode_RecordsAProbeForAMissingNode is why the record is written
// BEFORE the registry is consulted: enumeration by guessing ids is exactly
// what an audited read surface exists to make visible, and a trail that
// recorded only the lookups that found something would record only the
// successful half of a scan.
func TestDescribeNode_RecordsAProbeForAMissingNode(t *testing.T) {
	svc, sink := registryLaneFixture(t, registry.Report{NodeID: "node-1"})

	_, err := svc.DescribeNode(context.Background(), testPrincipal, "node-guessed")
	if !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("DescribeNode(unknown) error = %v, want ErrNodeNotFound", err)
	}
	if len(sink.readCalls) != 1 || sink.readCalls[0].NodeID != "node-guessed" {
		t.Fatalf("a probe for a Node that does not exist recorded %+v; want one record aimed "+
			"at the id that was probed for", sink.readCalls)
	}
}

// TestRegistryLane_FailsClosedWhenTheReadCannotBeAudited is ADR-0025 decision
// 4 at the lane: an unauditable read returns before the registry is touched,
// and the error is identifiable as an AUDIT failure so a surface can say so.
func TestRegistryLane_FailsClosedWhenTheReadCannotBeAudited(t *testing.T) {
	seeded := []registry.Report{{NodeID: "node-1"}}

	t.Run("ListNodes", func(t *testing.T) {
		svc, sink := registryLaneFixture(t, seeded...)
		sink.err = errors.New("the trail is unwritable")

		listing, err := svc.ListNodes(context.Background(), testPrincipal, "")
		if err == nil {
			t.Fatal("ListNodes answered with an unwritable audit trail — an unauditable read must fail")
		}
		if !errors.Is(err, ErrReadUnaudited) {
			t.Errorf("error = %v, want it to wrap ErrReadUnaudited so a surface can say which "+
				"component failed", err)
		}
		if listing.Nodes != nil {
			t.Errorf("ListNodes returned %d Nodes alongside its refusal — nothing may be "+
				"disclosed by a read that was not recorded", len(listing.Nodes))
		}
	})

	t.Run("DescribeNode", func(t *testing.T) {
		svc, sink := registryLaneFixture(t, seeded...)
		sink.err = errors.New("the trail is unwritable")

		d, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1")
		if err == nil {
			t.Fatal("DescribeNode answered with an unwritable audit trail")
		}
		if !errors.Is(err, ErrReadUnaudited) {
			t.Errorf("error = %v, want it to wrap ErrReadUnaudited", err)
		}
		if d.Node.NodeID != "" {
			t.Errorf("DescribeNode returned %q alongside its refusal", d.Node.NodeID)
		}
	})
}

// TestReadLane_TrailHalfAlsoWrapsErrReadUnaudited pins that the sentinel
// covers BOTH halves of the lane. A surface checks one error value; if only
// the registry half carried it, the four screens that migrated during #441
// would keep rendering an audit-trail outage as a generic failure.
func TestReadLane_TrailHalfAlsoWrapsErrReadUnaudited(t *testing.T) {
	svc, _, jobQ, sink := readLaneFixture(t)
	sink.err = errors.New("the trail is unwritable")

	_, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{}, PageRequest{})
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("QueryJobs error = %v, want it to wrap ErrReadUnaudited", err)
	}
	if jobQ.jobsCalled {
		t.Error("the Job seam ran despite the read being unauditable — the record is written FIRST")
	}
}

// TestRegistryLane_RefusesWithoutARealAuditSink is the fail-open guard for
// this half of the lane.
//
// NewReadLane already refuses the no-op sink (F5, #441); this is the same
// property enforced at the call, for a lane the in-package assembler built
// with no queries (build). A lane that cannot record must not answer a read,
// whichever way it was built.
func TestRegistryLane_RefusesWithoutARealAuditSink(t *testing.T) {
	svc := build(t, seams{reg: registry.NewInMemory()})

	if _, err := svc.ListNodes(context.Background(), testPrincipal, ""); !errors.Is(err, ErrReadUnaudited) {
		t.Errorf("ListNodes on a Service with the no-op sink = %v, want ErrReadUnaudited — it "+
			"would otherwise answer every fleet read while recording none of them", err)
	}
	if _, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1"); !errors.Is(err, ErrReadUnaudited) {
		t.Errorf("DescribeNode on a Service with the no-op sink = %v, want ErrReadUnaudited", err)
	}
}

// TestNewReadLaneRefusesNoopAuditSink is F5 (#441 cycle-2 security review):
// a ReadLane over a Recorder holding the no-op AuditSink must panic at
// construction, the same class of composition-root guard
// TestNewExecutionRefusesDefaultSeams asserts for a real dispatcher —
// otherwise every trail query is answered while recording nothing, exactly
// the "unauditable read succeeded" state ADR-0025 forbids. Every collaborator
// is built outside the recover scope, so only NewReadLane can be the panic.
func TestNewReadLaneRefusesNoopAuditSink(t *testing.T) {
	rec := NewRecorder(noopAuditSink{}, nil, nil)
	reg := registry.NewInMemory()
	auditQ := &spyAuditQuery{}
	jobQ := &spyJobQuery{}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewReadLane(...) without a real AuditSink should panic")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "capability: NewReadLane:") || !strings.Contains(msg, "noopAuditSink") {
			t.Errorf("panic = %v, want NewReadLane's noopAuditSink refusal", r)
		}
	}()
	NewReadLane(rec, reg, auditQ, jobQ, nil, nil, testSettings, nil)
}

// TestNewReadLaneAcceptsRealAuditSink is the positive twin of
// TestNewReadLaneRefusesNoopAuditSink: NewReadLane over a real (spy) AuditSink
// constructs successfully.
func TestNewReadLaneAcceptsRealAuditSink(t *testing.T) {
	reg := registry.NewInMemory()
	rec := NewRecorder(&spyAuditSink{}, nil, nil)

	if NewReadLane(rec, reg, &spyAuditQuery{}, &spyJobQuery{}, nil, nil, testSettings, nil) == nil {
		t.Fatal("NewReadLane over a real AuditSink returned nil")
	}
}

// TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt mirrors the Job id bound
// readlane.go applies (F2, #441 cycle-2 security review): the value is
// caller-controlled and would land in the append-only trail, so an oversized
// one is refused BEFORE anything is written rather than stored and truncated.
//
// This is QRY-22's proof row, at the capability seam. QRY-27's own proof
// (mcp_test.go's TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt) is
// deliberately separate: this test proves the LANE's ordering, that one
// proves the MCP surface actually goes through it.
func TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt(t *testing.T) {
	svc, sink := registryLaneFixture(t)

	_, err := svc.DescribeNode(context.Background(), testPrincipal, strings.Repeat("n", maxNodeIDBytes+1))
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("DescribeNode(oversized id) error = %v, want ErrInvalidFilter", err)
	}
	if len(sink.readCalls) != 0 {
		t.Errorf("an oversized id was written to the trail (%+v) — the trail is not caller "+
			"storage", sink.readCalls)
	}

	if _, err := svc.DescribeNode(context.Background(), testPrincipal, ""); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("DescribeNode(\"\") error = %v, want ErrInvalidFilter — an empty id is not a "+
			"Node, and recording a read aimed at nothing is worse than refusing it", err)
	}
}

// TestDescribeNode_CarriesThePolicyViewAndTemplateVocabulary is #680's
// disclosure half: describe_node's Policy/Template views come from the same
// call, with no second record — the record already covers this Node ID.
func TestDescribeNode_CarriesThePolicyViewAndTemplateVocabulary(t *testing.T) {
	policy := fakePolicyView{"node-1": policyview.Snapshot{PolicyFingerprint: "a256aaa000000000000000000000000000000000000000000000000000000000", RawExecEnabled: true}}
	vocab := fakeTemplateVocab{"node-1": nodevocab.Snapshot{Fingerprint: "a256000000000000000000000000000000000000000000000000000000000000"}}
	svc, sink := registryLaneFixtureWithViews(t, policy, vocab, registry.Report{NodeID: "node-1"})

	d, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1")
	if err != nil {
		t.Fatalf("DescribeNode: %v", err)
	}
	if !d.PolicyReported || d.Policy.PolicyFingerprint != "a256aaa000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("Policy/PolicyReported = %+v/%v, want the fake's reported Snapshot", d.Policy, d.PolicyReported)
	}
	if !d.TemplatesReported || d.Templates.Fingerprint != "a256000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("Templates/TemplatesReported = %+v/%v, want the fake's reported Snapshot", d.Templates, d.TemplatesReported)
	}
	// Still exactly one record — the Policy/Template views ride the SAME
	// describe_node read, not a second one.
	if len(sink.readCalls) != 1 {
		t.Errorf("DescribeNode wrote %d read records, want 1 (no second record for the Policy/Template views)", len(sink.readCalls))
	}
}

// TestDescribeNode_AnUnwiredCacheReportsNotReportedNotAnEmptyPolicy is QRY-7's
// "never absence as an unrestricted or empty Policy", proved at the lane: a
// nil PolicyViewSource/TemplateVocabularySource (the newReadLane default) must
// report *Reported=false, not a zero-value Snapshot that reads as "nothing
// restricted".
func TestDescribeNode_AnUnwiredCacheReportsNotReportedNotAnEmptyPolicy(t *testing.T) {
	svc, _ := registryLaneFixture(t, registry.Report{NodeID: "node-1"})

	d, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1")
	if err != nil {
		t.Fatalf("DescribeNode: %v", err)
	}
	if d.PolicyReported {
		t.Error("PolicyReported = true with no PolicyViewSource wired, want false")
	}
	if d.TemplatesReported {
		t.Error("TemplatesReported = true with no TemplateVocabularySource wired, want false")
	}
}

// TestListOperations_RecordsTheNodeItWasAimedAt covers ListOperations'
// per-Node happy path: the Template vocabulary comes back and the read is
// recorded aimed at that Node.
func TestListOperations_RecordsTheNodeItWasAimedAt(t *testing.T) {
	vocab := fakeTemplateVocab{"node-1": nodevocab.Snapshot{Fingerprint: "a256000000000000000000000000000000000000000000000000000000000000"}}
	svc, sink := registryLaneFixtureWithViews(t, fakePolicyView{}, vocab, registry.Report{NodeID: "node-1"})

	got, err := svc.ListOperations(context.Background(), testPrincipal, "node-1")
	if err != nil {
		t.Fatalf("ListOperations: %v", err)
	}
	if !got.Reported || got.Templates.Fingerprint != "a256000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("OperationVocabulary = %+v, want the fake's reported Snapshot", got)
	}
	if len(sink.readCalls) != 1 || sink.readCalls[0].Tool != toolListOperations || sink.readCalls[0].NodeID != "node-1" {
		t.Fatalf("record = %+v, want tool %q aimed at node-1", sink.readCalls, toolListOperations)
	}
}

// TestListOperations_RefusesAnUnknownNodeAndRecordsTheProbe is QRY-26's
// lane-seam proof: a well-formed but unknown Node ID is refused as
// ErrNodeNotFound, and the refused read is recorded with the probed id —
// written BEFORE the registry lookup, so the probe itself is never lost.
func TestListOperations_RefusesAnUnknownNodeAndRecordsTheProbe(t *testing.T) {
	svc, sink := registryLaneFixtureWithViews(t, fakePolicyView{}, fakeTemplateVocab{}, registry.Report{NodeID: "node-1"})

	_, err := svc.ListOperations(context.Background(), testPrincipal, "node-guessed")
	if !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("ListOperations(unknown) error = %v, want ErrNodeNotFound", err)
	}
	if len(sink.readCalls) != 1 || sink.readCalls[0].Tool != toolListOperations || sink.readCalls[0].NodeID != "node-guessed" {
		t.Fatalf("a probe for a Node that does not exist recorded %+v; want one record aimed "+
			"at the id that was probed for", sink.readCalls)
	}
}

// TestListOperations_WithNoNodeIdRecordsTheToolAndNoTarget is the fleet-wide
// shape (QRY-12: an empty Node ID is legal here, not malformed) — the same
// no-target record shape queryJobs already writes (readlane.go).
func TestListOperations_WithNoNodeIdRecordsTheToolAndNoTarget(t *testing.T) {
	svc, sink := registryLaneFixture(t, registry.Report{NodeID: "node-1"})

	got, err := svc.ListOperations(context.Background(), testPrincipal, "")
	if err != nil {
		t.Fatalf("ListOperations(fleet-wide): %v", err)
	}
	if got.Reported {
		t.Errorf("OperationVocabulary.Reported = true for a fleet-wide call, want false (no Node was named)")
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("ListOperations(fleet-wide) wrote %d read records, want 1", len(sink.readCalls))
	}
	if got := sink.readCalls[0]; got.Tool != toolListOperations || got.NodeID != "" || got.Selector != "" {
		t.Errorf("record = %+v, want tool %q with no target", got, toolListOperations)
	}
}

// TestListOperations_BoundsTheNodeIdBeforeRecordingIt mirrors DescribeNode's
// bound: a non-empty but oversized Node ID must not use the trail as
// storage.
func TestListOperations_BoundsTheNodeIdBeforeRecordingIt(t *testing.T) {
	svc, sink := registryLaneFixture(t)

	_, err := svc.ListOperations(context.Background(), testPrincipal, strings.Repeat("n", maxNodeIDBytes+1))
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("ListOperations(oversized id) error = %v, want ErrInvalidFilter", err)
	}
	if len(sink.readCalls) != 0 {
		t.Errorf("an oversized id was written to the trail (%+v) — the trail is not caller storage", sink.readCalls)
	}
}

// TestListOperations_FailsClosedWhenTheReadCannotBeAudited covers BOTH
// shapes — with a node_id and fleet-wide — since a lane that calls the sink
// only for the per-Node case would leave the fleet-wide call unrecorded and
// never fail closed (the gap BLOCKING finding 1 caught in plan review).
func TestListOperations_FailsClosedWhenTheReadCannotBeAudited(t *testing.T) {
	t.Run("with a node_id", func(t *testing.T) {
		svc, sink := registryLaneFixture(t, registry.Report{NodeID: "node-1"})
		sink.err = errors.New("the trail is unwritable")

		got, err := svc.ListOperations(context.Background(), testPrincipal, "node-1")
		if !errors.Is(err, ErrReadUnaudited) {
			t.Fatalf("ListOperations(node-1) error = %v, want ErrReadUnaudited", err)
		}
		if got.Reported {
			t.Error("ListOperations returned a reported vocabulary alongside its refusal")
		}
	})

	t.Run("fleet-wide", func(t *testing.T) {
		svc, sink := registryLaneFixture(t, registry.Report{NodeID: "node-1"})
		sink.err = errors.New("the trail is unwritable")

		got, err := svc.ListOperations(context.Background(), testPrincipal, "")
		if !errors.Is(err, ErrReadUnaudited) {
			t.Fatalf("ListOperations(fleet-wide) error = %v, want ErrReadUnaudited", err)
		}
		if got.Reported {
			t.Error("ListOperations returned a reported vocabulary alongside its refusal")
		}
	})
}

// failingFingerprints are Node-reported snapshot fingerprints the Hello bound
// refuses; the lane serves each as "" before any surface draws it.
func failingFingerprints() map[string]string {
	hex64 := strings.Repeat("ab", 32)
	return map[string]string{
		"sha256 prefix":         "sha256:" + hex64,
		"uppercase hex":         strings.ToUpper(hex64),
		"63 hex":                hex64[:63],
		"65 hex":                hex64 + "a",
		"bidi override":         "\u202e" + hex64[:60],
		"quote and angle":       `"><script>` + hex64[:40],
		"one mebibyte":          strings.Repeat("a", 1<<20),
		"snapshot of nonsense":  "sha256:snapfp",
		"whitespace-padded hex": " " + hex64,
	}
}

// TestBoundedSnapshots_ServeAFailingFingerprintAsEmpty pins the two pure
// bound functions: a well-formed (or empty) fingerprint is kept, any other is
// served as "", and no other field changes.
func TestBoundedSnapshots_ServeAFailingFingerprintAsEmpty(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	policyKept := []string{"", hex64}
	templateKept := []string{"", hex64, registry.TemplateUnloadable}
	for _, fp := range policyKept {
		in := policyview.Snapshot{PolicyFingerprint: fp, RawExecEnabled: true, AllowedOperations: []string{"system.facts"}}
		got := boundedPolicySnapshot(in)
		if got.PolicyFingerprint != fp || !got.RawExecEnabled || len(got.AllowedOperations) != 1 {
			t.Errorf("boundedPolicySnapshot(%q) = %+v, want it unchanged", fp, got)
		}
	}
	for _, fp := range templateKept {
		in := nodevocab.Snapshot{Fingerprint: fp, Templates: []nodevocab.Template{readTemplate("svc.status")}}
		got := boundedTemplateSnapshot(in)
		if got.Fingerprint != fp || len(got.Templates) != 1 {
			t.Errorf("boundedTemplateSnapshot(%q) = %+v, want it unchanged", fp, got)
		}
	}
	for name, fp := range failingFingerprints() {
		pin := policyview.Snapshot{PolicyFingerprint: fp, RawExecEnabled: true, AllowedOperations: []string{"system.facts"}}
		pgot := boundedPolicySnapshot(pin)
		if pgot.PolicyFingerprint != "" || !pgot.RawExecEnabled || len(pgot.AllowedOperations) != 1 {
			t.Errorf("%s: boundedPolicySnapshot = %+v, want the fingerprint served empty and every other field unchanged", name, pgot)
		}
		tin := nodevocab.Snapshot{Fingerprint: fp, Templates: []nodevocab.Template{readTemplate("svc.status")}}
		tgot := boundedTemplateSnapshot(tin)
		if tgot.Fingerprint != "" || len(tgot.Templates) != 1 {
			t.Errorf("%s: boundedTemplateSnapshot = %+v, want the fingerprint served empty and the Templates unchanged", name, tgot)
		}
	}
	// "unloadable" is a template-set marker only; as a Policy fingerprint it
	// is not a SHA-256.
	if got := boundedPolicySnapshot(policyview.Snapshot{PolicyFingerprint: registry.TemplateUnloadable}); got.PolicyFingerprint != "" {
		t.Errorf("boundedPolicySnapshot(unloadable) = %q, want empty", got.PolicyFingerprint)
	}
}

// TestDescribeNode_SnapshotFingerprintsThatFailTheBoundAreServedEmpty proves
// the bound holds at the lane every surface reads through, and that a served
// "" still reads as a reported snapshot.
func TestDescribeNode_SnapshotFingerprintsThatFailTheBoundAreServedEmpty(t *testing.T) {
	for name, fp := range failingFingerprints() {
		policy := fakePolicyView{"node-1": policyview.Snapshot{PolicyFingerprint: fp, RawExecEnabled: true}}
		vocab := fakeTemplateVocab{"node-1": nodevocab.Snapshot{Fingerprint: fp, Templates: []nodevocab.Template{readTemplate("svc.status")}}}
		svc, _ := registryLaneFixtureWithViews(t, policy, vocab, registry.Report{NodeID: "node-1"})

		d, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1")
		if err != nil {
			t.Fatalf("%s: DescribeNode: %v", name, err)
		}
		if !d.PolicyReported || d.Policy.PolicyFingerprint != "" || !d.Policy.RawExecEnabled {
			t.Errorf("%s: Policy = %+v reported=%v, want a reported snapshot with an empty fingerprint", name, d.Policy, d.PolicyReported)
		}
		if !d.TemplatesReported || d.Templates.Fingerprint != "" || len(d.Templates.Templates) != 1 {
			t.Errorf("%s: Templates = %+v reported=%v, want a reported snapshot with an empty fingerprint", name, d.Templates, d.TemplatesReported)
		}
	}
}

// TestListOperations_TemplateSnapshotFingerprintThatFailsTheBoundIsServedEmpty
// is the same proof for list_operations' per-Node half.
func TestListOperations_TemplateSnapshotFingerprintThatFailsTheBoundIsServedEmpty(t *testing.T) {
	for name, fp := range failingFingerprints() {
		vocab := fakeTemplateVocab{"node-1": nodevocab.Snapshot{Fingerprint: fp, Templates: []nodevocab.Template{readTemplate("svc.status")}}}
		svc, _ := registryLaneFixtureWithViews(t, fakePolicyView{}, vocab, registry.Report{NodeID: "node-1"})

		got, err := svc.ListOperations(context.Background(), testPrincipal, "node-1")
		if err != nil {
			t.Fatalf("%s: ListOperations: %v", name, err)
		}
		if !got.Reported || got.Templates.Fingerprint != "" || len(got.Templates.Templates) != 1 {
			t.Errorf("%s: OperationVocabulary = %+v, want a reported snapshot with an empty fingerprint", name, got)
		}
	}
}
