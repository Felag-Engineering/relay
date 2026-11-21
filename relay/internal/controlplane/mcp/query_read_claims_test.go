package mcp_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestMCP_DescribeNode_ADisconnectedNodeIsReadFromItsLastRecord proves that
// describe_node reads exactly the one Node asked for, that a Node seen just
// now but holding no live Tunnel reports connected=false (never inferred from
// last_seen), and that a Node that has dropped its Tunnel stays readable from
// its last record. The assertions that matter are connected false, then true,
// then false again, with the record still read.
//
// Proves QRY-4.
func TestMCP_DescribeNode_ADisconnectedNodeIsReadFromItsLastRecord(t *testing.T) {
	ts := newTestServer(t)
	if err := ts.reg.RecordHeartbeat(ts.nodeA, time.Now().UTC(), registry.ClockSkewReading{}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	session := ts.connect(t)

	describe := func(t *testing.T) mcp.DescribeNodeOutput {
		t.Helper()
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		var out mcp.DescribeNodeOutput
		decodeResult(t, res, &out)
		if out.NodeID != ts.nodeA {
			t.Fatalf("NodeID = %q, want %q (describe_node reads exactly the Node asked for)", out.NodeID, ts.nodeA)
		}
		if out.Facts.Hostname != "web-1" {
			t.Errorf("Facts.Hostname = %q, want web-1 (node A's own record, not node B's)", out.Facts.Hostname)
		}
		return out
	}

	out := describe(t)
	if out.LastSeen == "" {
		t.Error("LastSeen is empty, want the heartbeat's time")
	}
	if out.Connected {
		t.Error("Connected = true for a Node seen just now that never held a Tunnel, want false: connected is never inferred from last_seen")
	}

	ts.reg.SetConnected(ts.nodeA, true)
	if out := describe(t); !out.Connected {
		t.Error("Connected = false for a Node holding a live Tunnel, want true")
	}

	ts.reg.SetConnected(ts.nodeA, false)
	if out := describe(t); out.Connected {
		t.Error("Connected = true after the Tunnel dropped, want false; the record is still read")
	}
}

// TestMCP_TemplateVocabulary_AnAbsentReportIsNotAnEmptyOne proves that a Node
// that never reported its Policy or its Template vocabulary reads as "not
// reported" on describe_node and list_operations, and that a Node reporting an
// empty vocabulary reads as reported with no Templates. The fixture needs the
// reported-but-empty Node to tell the two apart.
//
// Proves QRY-6, QRY-23.
func TestMCP_TemplateVocabulary_AnAbsentReportIsNotAnEmptyOne(t *testing.T) {
	ts := newTestServer(t)
	const nodeC = "node-c"
	if _, err := ts.reg.Upsert(registry.Report{NodeID: nodeC}); err != nil {
		t.Fatalf("seed node C: %v", err)
	}
	ts.vocab.Set(nodeC, nodevocab.Snapshot{Fingerprint: strings.Repeat("c", 64)})
	session := ts.connect(t)

	describe := func(nodeID string) mcp.DescribeNodeOutput {
		t.Helper()
		var out mcp.DescribeNodeOutput
		decodeResult(t, callTool(t, session, "describe_node", map[string]any{"node_id": nodeID}), &out)
		return out
	}
	operations := func(nodeID string) mcp.ListOperationsOutput {
		t.Helper()
		var out mcp.ListOperationsOutput
		decodeResult(t, callTool(t, session, "list_operations", map[string]any{"node_id": nodeID}), &out)
		return out
	}
	assertNativesOnly := func(t *testing.T, nodeID string, out mcp.ListOperationsOutput) {
		t.Helper()
		natives := 0
		for _, op := range out.Operations {
			switch op.Source {
			case "template":
				t.Errorf("list_operations(%s) carries Template Operation %q, want none", nodeID, op.Name)
			case "native":
				natives++
			}
		}
		if natives == 0 {
			t.Errorf("list_operations(%s) carries no Native Operation, want the frozen vocabulary", nodeID)
		}
	}

	absent := describe(ts.nodeB)
	if absent.TemplateVocabulary.Reported {
		t.Error("describe_node(node B).TemplateVocabulary.Reported = true, want false: an absent report must never read as an empty vocabulary")
	}
	if absent.EffectivePolicy.Reported {
		t.Error("describe_node(node B).EffectivePolicy.Reported = true, want false: an absent Policy report must read as not reported")
	}
	if ops := operations(ts.nodeB); ops.TemplatesReported {
		t.Error("list_operations(node B).TemplatesReported = true, want false: an absent report must never read as an empty vocabulary")
	} else {
		assertNativesOnly(t, ts.nodeB, ops)
	}

	empty := describe(nodeC)
	if !empty.TemplateVocabulary.Reported {
		t.Error("describe_node(node C).TemplateVocabulary.Reported = false, want true: an empty report is a report")
	}
	if n := len(empty.TemplateVocabulary.Templates); n != 0 {
		t.Errorf("describe_node(node C) lists %d Templates, want 0", n)
	}
	if ops := operations(nodeC); !ops.TemplatesReported {
		t.Error("list_operations(node C).TemplatesReported = false, want true: an empty report is a report")
	} else {
		assertNativesOnly(t, nodeC, ops)
	}
}

// TestMCP_DescribeNode_ThePolicyViewIsTheWholeReportAndNoTemplateBody proves
// that describe_node carries the Node's reported Policy whole and no Template
// body. TestMCP_DescribeNode covers the rules; this test also asserts
// the raw allow and deny patterns, AllowedOperations equality and the Policy
// fingerprint.
//
// Proves QRY-10.
func TestMCP_DescribeNode_ThePolicyViewIsTheWholeReportAndNoTemplateBody(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
	var out mcp.DescribeNodeOutput
	decodeResult(t, res, &out)

	p := out.EffectivePolicy
	if !p.Reported {
		t.Fatal("EffectivePolicy.Reported = false, want true (a snapshot was captured for node A)")
	}
	if !p.RawExecEnabled {
		t.Error("EffectivePolicy.RawExecEnabled = false, want true")
	}
	if want := []string{`^/usr/bin/systemctl restart .+$`}; !reflect.DeepEqual(p.RawAllowPatterns, want) {
		t.Errorf("RawAllowPatterns = %q, want %q", p.RawAllowPatterns, want)
	}
	if want := []string{`.*rm -rf.*`}; !reflect.DeepEqual(p.RawDenyPatterns, want) {
		t.Errorf("RawDenyPatterns = %q, want %q", p.RawDenyPatterns, want)
	}
	if want := []string{"system.facts", "file.read"}; !reflect.DeepEqual(p.AllowedOperations, want) {
		t.Errorf("AllowedOperations = %q, want %q", p.AllowedOperations, want)
	}
	wantRules := []mcp.OperationRuleOutput{
		{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
		{Name: "system.facts", AllowedArgs: [][]string{}},
	}
	if !reflect.DeepEqual(p.OperationRules, wantRules) {
		t.Errorf("OperationRules = %+v, want %+v", p.OperationRules, wantRules)
	}
	wantDeny := []mcp.DenyRuleOutput{{Name: "file.read", Args: [][]string{{"/etc/shadow"}}}}
	if !reflect.DeepEqual(p.DenyRules, wantDeny) {
		t.Errorf("DenyRules = %+v, want %+v", p.DenyRules, wantDeny)
	}
	if p.PolicyFingerprint != nodeAFingerprint {
		t.Errorf("PolicyFingerprint = %q, want %q", p.PolicyFingerprint, nodeAFingerprint)
	}

	// Armed: node A reports Template Operations, so a body field would have
	// something to carry.
	if !out.TemplateVocabulary.Reported || len(out.TemplateVocabulary.Templates) == 0 {
		t.Fatal("node A reports no Templates, so the body-absence checks below prove nothing")
	}
	if text := resultText(t, res); strings.Contains(text, `"body"`) {
		t.Errorf("describe_node JSON = %s, must never contain a %q key", text, "body")
	}
	flags, visited := walkFields(reflect.TypeOf(mcp.DescribeNodeOutput{}), flagBodyField)
	if visited == 0 {
		t.Fatal("walkFields visited no field of DescribeNodeOutput")
	}
	if len(flags) != 0 {
		t.Errorf("DescribeNodeOutput carries a Template body: %v", flags)
	}
}

// TestMCP_DescribeNode_AnUnknownNodeIsRefusedAndTheProbeIsRecorded proves that
// describe_node of a well-formed but unknown Node ID is refused as not found,
// and that the refused read is recorded with the probed ID.
//
// Proves QRY-21.
func TestMCP_DescribeNode_AnUnknownNodeIsRefusedAndTheProbeIsRecorded(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	const unknown = "no-such-node"
	res := callTool(t, session, "describe_node", map[string]any{"node_id": unknown})
	if !res.IsError {
		t.Fatalf("describe_node(%q): IsError = false, want true", unknown)
	}
	if msg := toolErrorText(t, res); !strings.Contains(msg, unknown) || !strings.Contains(msg, "not found") {
		t.Errorf("refusal text = %q, want it to name the unknown Node as not found", msg)
	}

	found := false
	for _, r := range auditReadRecords(t, ts) {
		if r.OperationName == "describe_node" && r.NodeID == unknown {
			found = true
		}
	}
	if !found {
		t.Error("no describe_node read record aimed at the probed unknown Node, want the refused read recorded with the probed id")
	}
}
