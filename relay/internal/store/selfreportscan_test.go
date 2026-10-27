package store

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// goodSelfReport is a record every self-report bound accepts.
func goodSelfReport(nodeID string) registry.Report {
	return registry.Report{
		NodeID:          nodeID,
		CertFingerprint: "fp-" + nodeID,
		Facts: registry.Facts{
			Hostname:    "web-01.example.com",
			OS:          "linux",
			Kernel:      "6.1.0",
			Arch:        "x86_64",
			IPAddresses: []string{"10.0.0.1", "fd00::1"},
		},
		PolicyFingerprint:      strings.Repeat("a", 64),
		TemplateSetFingerprint: strings.Repeat("b", 64),
		DaemonVersion:          "1.4.2",
	}
}

// forgeColumn overwrites one self-reported column of nodeID's row with raw SQL,
// the way a Relay that predates the ingress bounds would have stored it. column
// is one of the fixed literals the tests below pass, never input.
func forgeColumn(t *testing.T, st *Store, nodeID, column, value string) {
	t.Helper()
	if _, err := st.db.Exec(`UPDATE nodes SET `+column+` = ? WHERE node_id = ?`, value, nodeID); err != nil {
		t.Fatalf("forge %s for %s: %v", column, nodeID, err)
	}
}

// rawColumn reads one column of nodeID's row straight from the table.
func rawColumn(t *testing.T, st *Store, nodeID, column string) string {
	t.Helper()
	var v string
	if err := st.db.QueryRow(`SELECT `+column+` FROM nodes WHERE node_id = ?`, nodeID).Scan(&v); err != nil {
		t.Fatalf("read %s for %s: %v", column, nodeID, err)
	}
	return v
}

// forgedSelfReports is one malformed stored value per bounded column, with the
// field name the read-back declines it under and what the read returns, in
// registry.DeclineMalformedSelfReport's field order.
var forgedSelfReports = []struct {
	column, value, field string
	want                 func(*registry.Node) bool
}{
	{"hostname", "web\u202e10.example.com", registry.FieldHostname,
		func(n *registry.Node) bool { return n.Facts.Hostname == "" }},
	{"os", strings.Repeat("o", registry.MaxSelfReportedTextBytes+1), registry.FieldOS,
		func(n *registry.Node) bool { return n.Facts.OS == "" }},
	{"kernel", "6.1.0 (verified)", registry.FieldKernel,
		func(n *registry.Node) bool { return n.Facts.Kernel == "" }},
	{"arch", "x86\x00_64", registry.FieldArch,
		func(n *registry.Node) bool { return n.Facts.Arch == "" }},
	{"ip_addresses", `["10.0.0.1","fe80::1%eth0","not-an-ip"]`, registry.FieldIPAddresses,
		func(n *registry.Node) bool {
			return len(n.Facts.IPAddresses) == 1 && n.Facts.IPAddresses[0] == "10.0.0.1"
		}},
	{"policy_fingerprint", strings.Repeat("a", 1<<20), registry.FieldPolicyFingerprint,
		func(n *registry.Node) bool { return n.PolicyFingerprint == "" }},
	{"template_set_fingerprint", "sha256:" + strings.Repeat("b", 64), registry.FieldTemplateSetFingerprint,
		func(n *registry.Node) bool { return n.TemplateSetFingerprint == "" }},
	{"daemon_version", "1.4.2, tag:x=y", registry.FieldDaemonVersion,
		func(n *registry.Node) bool { return n.DaemonVersion == "" }},
}

// TestGetNode_DeclinesMalformedStoredSelfReport is the read-back half of the
// self-report bounds: a value stored before the ingress bound existed is
// absent from every read (Get, List, and Upsert's own read-back), the rest of
// the record is served as stored, and the row itself is never rewritten.
func TestGetNode_DeclinesMalformedStoredSelfReport(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(goodSelfReport("node-good")); err != nil {
		t.Fatalf("Upsert node-good: %v", err)
	}
	for _, c := range forgedSelfReports {
		nodeID := "node-" + c.column
		if _, err := reg.Upsert(goodSelfReport(nodeID)); err != nil {
			t.Fatalf("Upsert %s: %v", nodeID, err)
		}
		forgeColumn(t, st, nodeID, c.column, c.value)
	}

	// The good record reads back exactly as written.
	good := goodSelfReport("node-good")
	n, ok := reg.Get("node-good")
	if !ok {
		t.Fatal("Get node-good: not found")
	}
	if n.PolicyFingerprint != good.PolicyFingerprint || n.TemplateSetFingerprint != good.TemplateSetFingerprint ||
		n.DaemonVersion != good.DaemonVersion || n.Facts.Hostname != good.Facts.Hostname ||
		n.Facts.OS != good.Facts.OS || n.Facts.Kernel != good.Facts.Kernel || n.Facts.Arch != good.Facts.Arch ||
		strings.Join(n.Facts.IPAddresses, ",") != strings.Join(good.Facts.IPAddresses, ",") {
		t.Errorf("a well-formed record was changed on read: %+v", n)
	}

	listed := map[string]registry.Node{}
	for _, n := range reg.List() {
		listed[n.NodeID] = n
	}
	for _, c := range forgedSelfReports {
		t.Run(c.column, func(t *testing.T) {
			nodeID := "node-" + c.column
			got, ok := reg.Get(nodeID)
			if !ok {
				t.Fatalf("Get %s: not found", nodeID)
			}
			for what, n := range map[string]registry.Node{"Get": got, "List": listed[nodeID]} {
				if !c.want(&n) {
					t.Errorf("%s served the malformed stored %s", what, c.column)
				}
				// Every other field is served as stored.
				if c.column != "hostname" && n.Facts.Hostname != good.Facts.Hostname {
					t.Errorf("%s dropped the well-formed hostname beside a malformed %s", what, c.column)
				}
				if c.column != "policy_fingerprint" && n.PolicyFingerprint != good.PolicyFingerprint {
					t.Errorf("%s dropped the well-formed Policy fingerprint beside a malformed %s", what, c.column)
				}
			}
			if raw := rawColumn(t, st, nodeID, c.column); raw != c.value {
				t.Errorf("the stored %s was rewritten (%d bytes, want %d): declining to serve is not writing",
					c.column, len(raw), len(c.value))
			}
		})
	}
}

// TestGetNode_DeclinesOverLongStoredNodeLabel: a node: Label stored before the
// Label length bounds existed is declined on read, and one at the bounds is
// served.
func TestGetNode_DeclinesOverLongStoredNodeLabel(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	atKey := strings.Repeat("k", registry.MaxLabelKeyLen)
	atValue := strings.Repeat("v", registry.MaxLabelValueLen)
	insertLabel(t, st, nsNode, "node-a", atKey, atValue)
	insertLabel(t, st, nsNode, "node-a", strings.Repeat("k", registry.MaxLabelKeyLen+1), "web")
	insertLabel(t, st, nsNode, "node-a", "role", strings.Repeat("v", registry.MaxLabelValueLen+1))

	n, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get: not found")
	}
	if len(n.NodeLabels) != 1 || n.NodeLabels[atKey] != atValue {
		t.Errorf("NodeLabels = %d entries, want only the one at the bounds", len(n.NodeLabels))
	}
	if got, _ := st.LabelsDeclined(); got != 2 {
		t.Errorf("LabelsDeclined[node] = %d, want 2 (the two over-long pairs, one Get)", got)
	}
}

// TestScanDeclinedSelfReports_Logs: one WARN per (Node, field) naming both and
// never the value, then one summary; the rows are left as they are.
func TestScanDeclinedSelfReports_Logs(t *testing.T) {
	var logBuf bytes.Buffer
	st, _ := openTestStore(t, WithLogger(slog.New(slog.NewJSONHandler(&logBuf, nil))))
	reg := st.Registry()

	if _, err := reg.Upsert(goodSelfReport("node-good")); err != nil {
		t.Fatalf("Upsert node-good: %v", err)
	}
	if _, err := reg.Upsert(goodSelfReport("node-bad")); err != nil {
		t.Fatalf("Upsert node-bad: %v", err)
	}
	for _, c := range forgedSelfReports {
		forgeColumn(t, st, "node-bad", c.column, c.value)
	}

	set, err := st.ScanDeclinedSelfReports(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedSelfReports: %v", err)
	}
	if set.Fields != int64(len(forgedSelfReports)) || set.Nodes != 1 || set.Truncated {
		t.Errorf("scan = %d fields over %d Nodes (truncated %v), want %d over 1",
			set.Fields, set.Nodes, set.Truncated, len(forgedSelfReports))
	}

	const (
		findingMsg = "stored self-reported field declined on read-back"
		summaryMsg = "startup scan: stored self-reported fields declined on read-back"
	)
	type entry struct {
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		NodeID string `json:"node_id"`
		Field  string `json:"field"`
		Fields int64  `json:"fields_declined_at_scan"`
		Nodes  int64  `json:"nodes_affected_at_scan"`
	}
	var findings []entry
	var summaries int
	for _, line := range strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n") {
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		switch e.Msg {
		case findingMsg:
			if e.Level != "WARN" || e.NodeID != "node-bad" {
				t.Errorf("finding line = %#v, want a WARN naming node-bad", e)
			}
			findings = append(findings, e)
		case summaryMsg:
			summaries++
			if e.Fields != int64(len(forgedSelfReports)) || e.Nodes != 1 {
				t.Errorf("summary line = %#v", e)
			}
		}
	}
	if len(findings) != len(forgedSelfReports) || summaries != 1 {
		t.Fatalf("%d finding lines and %d summaries, want %d and 1; log:\n%.2000s",
			len(findings), summaries, len(forgedSelfReports), logBuf.String())
	}
	for i, c := range forgedSelfReports {
		if findings[i].Field != c.field {
			t.Errorf("finding %d names field %q, want %q", i, findings[i].Field, c.field)
		}
	}

	for _, leak := range []string{"tag:x=y", "\u202e", "(verified)", "not-an-ip", "fe80::1", "sha256:", strings.Repeat("a", 65), strings.Repeat("o", 64)} {
		if strings.Contains(logBuf.String(), leak) {
			t.Errorf("the scan logged a declined value (%q); it names the field, never the value", leak)
		}
	}
	for _, c := range forgedSelfReports {
		if raw := rawColumn(t, st, "node-bad", c.column); raw != c.value {
			t.Errorf("the scan rewrote the stored %s", c.column)
		}
	}
}

// TestScanDeclinedSelfReports_CleanStoreLogsOnce: a clean fleet still logs one
// INFO line, so a scan that never ran is distinguishable from a clean one.
func TestScanDeclinedSelfReports_CleanStoreLogsOnce(t *testing.T) {
	var logBuf bytes.Buffer
	st, _ := openTestStore(t, WithLogger(slog.New(slog.NewJSONHandler(&logBuf, nil))))
	if _, err := st.Registry().Upsert(goodSelfReport("node-good")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	set, err := st.ScanDeclinedSelfReports(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedSelfReports: %v", err)
	}
	if set.Fields != 0 || set.Nodes != 0 {
		t.Errorf("scan = %+v, want nothing declined", set)
	}
	lines := strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1; log:\n%s", len(lines), logBuf.String())
	}
	var e struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Level != "INFO" || e.Msg != "startup scan: no stored self-reported fields declined on read-back" {
		t.Errorf("line = %+v, want the INFO all-clear", e)
	}
}
