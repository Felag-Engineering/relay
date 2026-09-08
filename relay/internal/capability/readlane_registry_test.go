package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// registryLaneFixture builds a Service over a seeded registry with a spy
// AuditSink — the registry read lane's half of readLaneFixture.
//
// WithQueries is supplied too, not because these methods use it, but because
// the production Service always has it and a fixture that quietly differs from
// production is a fixture that proves less than it looks like it does.
func registryLaneFixture(t *testing.T, nodes ...registry.Report) (*Service, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, r := range nodes {
		if _, err := reg.Upsert(r); err != nil {
			t.Fatalf("Upsert(%s): %v", r.NodeID, err)
		}
	}
	sink := &spyAuditSink{}
	return New(reg, WithQueries(&spyAuditQuery{}, &spyJobQuery{}), WithAuditSink(sink)), sink
}

// TestListNodes_RecordsTheEnumeration is ADR-0025 decision 1 for the fleet
// read: who enumerated, which tool, and when — with no result on the record.
func TestListNodes_RecordsTheEnumeration(t *testing.T) {
	svc, sink := registryLaneFixture(t,
		registry.Report{NodeID: "node-1"}, registry.Report{NodeID: "node-2"})

	nodes, err := svc.ListNodes(context.Background(), testPrincipal)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("ListNodes returned %d Nodes, want 2", len(nodes))
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
	if got.NodeID != "" || got.JobID != "" || got.Selector != "" {
		t.Errorf("record carries %+v, want no NodeID/JobID/Selector for an enumeration", got)
	}
}

// TestDescribeNode_RecordsTheNodeItWasAimedAt covers "what it was aimed at"
// and the peer counts the lane computes so a caller never has to enumerate.
func TestDescribeNode_RecordsTheNodeItWasAimedAt(t *testing.T) {
	svc, sink := registryLaneFixture(t,
		registry.Report{NodeID: "node-1", PolicyFingerprint: "sha256:aaa", TemplateSetFingerprint: "sha256:ttt"},
		registry.Report{NodeID: "node-2", PolicyFingerprint: "sha256:aaa"},
		registry.Report{NodeID: "node-3", PolicyFingerprint: "sha256:bbb"},
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

		nodes, err := svc.ListNodes(context.Background(), testPrincipal)
		if err == nil {
			t.Fatal("ListNodes answered with an unwritable audit trail — an unauditable read must fail")
		}
		if !errors.Is(err, ErrReadUnaudited) {
			t.Errorf("error = %v, want it to wrap ErrReadUnaudited so a surface can say which "+
				"component failed", err)
		}
		if nodes != nil {
			t.Errorf("ListNodes returned %d Nodes alongside its refusal — nothing may be "+
				"disclosed by a read that was not recorded", len(nodes))
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
// New already refuses WithQueries paired with the no-op sink (F5, #441). The
// registry half cannot be guarded at construction — reg is New's first
// argument and is always present — so the check is at the call instead. A
// Service that cannot record must not answer a read, whichever way it was
// built.
func TestRegistryLane_RefusesWithoutARealAuditSink(t *testing.T) {
	svc := New(registry.NewInMemory())

	if _, err := svc.ListNodes(context.Background(), testPrincipal); !errors.Is(err, ErrReadUnaudited) {
		t.Errorf("ListNodes on a Service with the no-op sink = %v, want ErrReadUnaudited — it "+
			"would otherwise answer every fleet read while recording none of them", err)
	}
	if _, err := svc.DescribeNode(context.Background(), testPrincipal, "node-1"); !errors.Is(err, ErrReadUnaudited) {
		t.Errorf("DescribeNode on a Service with the no-op sink = %v, want ErrReadUnaudited", err)
	}
}

// TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt mirrors the Job id bound
// readlane.go applies (F2, #441 cycle-2 security review): the value is
// caller-controlled and would land in the append-only trail, so an oversized
// one is refused BEFORE anything is written rather than stored and truncated.
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
