package capability

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// TestReadLane_NeverServesAStoredMalformedSelfReport drives the capability
// layer over the real SQLite store holding a row an older Relay wrote before
// the ingress bounds existed. Every surface (Console, MCP, the Control API) is
// an adapter over this lane (invariant 10), and Selector resolution runs
// inside it, so a value the read-back declines here is declined on all of them.
// Upsert applies no bound itself, which is what lets it seed that older row.
func TestReadLane_NeverServesAStoredMalformedSelfReport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	reg := st.Registry()

	badPolicy := strings.ToUpper(strings.Repeat("a", 64))
	badHost := "web‮01"
	longValue := strings.Repeat("v", registry.MaxLabelValueLen+1)
	if _, err := reg.Upsert(registry.Report{
		NodeID:            "node-forged",
		Facts:             registry.Facts{Hostname: badHost, OS: "linux"},
		PolicyFingerprint: badPolicy,
		DaemonVersion:     "1.0.0, tag:x=y",
	}.WithNodeLabels(map[string]string{"role": longValue, "env": "prod"})); err != nil {
		t.Fatalf("seed node-forged: %v", err)
	}
	goodPolicy := strings.Repeat("b", 64)
	if _, err := reg.Upsert(registry.Report{
		NodeID:            "node-good",
		Facts:             registry.Facts{Hostname: "web-02", OS: "linux"},
		PolicyFingerprint: goodPolicy,
		DaemonVersion:     "1.0.0",
	}); err != nil {
		t.Fatalf("seed node-good: %v", err)
	}

	svc := build(t, seams{reg: reg, auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{}, audit: &spyAuditSink{}})
	ctx := context.Background()

	d, err := svc.DescribeNode(ctx, testPrincipal, "node-forged")
	if err != nil {
		t.Fatalf("DescribeNode: %v", err)
	}
	n := d.Node
	if n.PolicyFingerprint != "" || n.Facts.Hostname != "" || n.DaemonVersion != "" {
		t.Errorf("DescribeNode served a stored malformed field: policy %.20q, hostname %q, version %q",
			n.PolicyFingerprint, n.Facts.Hostname, n.DaemonVersion)
	}
	if n.Facts.OS != "linux" || n.NodeLabels["env"] != "prod" {
		t.Errorf("DescribeNode dropped a well-formed field: os %q, node labels %v", n.Facts.OS, n.NodeLabels)
	}
	if _, ok := n.NodeLabels["role"]; ok {
		t.Error("DescribeNode served a stored node: Label over the length bound")
	}

	listing, err := svc.ListNodes(ctx, testPrincipal, "")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	for _, n := range listing.Nodes {
		if n.NodeID == "node-forged" && (n.PolicyFingerprint != "" || n.Facts.Hostname != "") {
			t.Error("ListNodes served a stored malformed field")
		}
		if n.NodeID == "node-good" && (n.PolicyFingerprint != goodPolicy || n.Facts.Hostname != "web-02") {
			t.Errorf("ListNodes changed a well-formed record: %.200v", n)
		}
	}

	// Selector resolution sees the same view: a term spelled with the
	// declined value matches nothing, and the well-formed one still matches.
	for _, sel := range []string{"node:role=" + longValue, "state:policy-fingerprint=" + badPolicy} {
		got, err := svc.ListNodes(ctx, testPrincipal, sel)
		if err != nil {
			t.Fatalf("ListNodes(%.40q): %v", sel, err)
		}
		if len(got.Nodes) != 0 {
			t.Errorf("Selector %.40q matched %d Node(s) on a declined stored value, want none", sel, len(got.Nodes))
		}
	}
	got, err := svc.ListNodes(ctx, testPrincipal, "state:policy-fingerprint="+goodPolicy)
	if err != nil {
		t.Fatalf("ListNodes(good fingerprint): %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].NodeID != "node-good" {
		t.Errorf("the well-formed fingerprint matched %d Node(s), want node-good alone", len(got.Nodes))
	}
}
