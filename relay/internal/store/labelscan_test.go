package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// insertLabel forges a row straight into ns's table via raw SQL, bypassing
// Upsert/SetRelayLabels entirely — the pattern
// TestGetNode_DoesNotServeMalformedLegacyNodeLabel established, since both
// write paths now refuse to write what a scan test needs already sitting in
// the table.
func insertLabel(t *testing.T, st *Store, ns labelNamespace, nodeID, key, value string) {
	t.Helper()
	if _, err := st.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (node_id, key, value) VALUES (?, ?, ?)`, ns.table()), // table is one of two fixed literals, never user input
		nodeID, key, value,
	); err != nil {
		t.Fatalf("insert %s row (%s=%s) for %s: %v", ns.table(), key, value, nodeID, err)
	}
}

// TestScanDeclinedLabels_BothNamespaces is the fixture no scan that merely
// runs can satisfy: two Nodes, a well-formed row, a malformed-VALUE row and
// a malformed-KEY row in each namespace, plus the real quarantine fence
// pair in relay-space — and the two namespaces' totals are DELIBERATELY
// UNEQUAL (3 node-space, 4 relay-space) so a namespace mix-up cannot pass.
func TestScanDeclinedLabels_BothNamespaces(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert %s: %v", id, err)
		}
		if err := reg.SetRelayLabels(id, map[string]string{"role": "web"}); err != nil {
			t.Fatalf("SetRelayLabels %s: %v", id, err)
		}
	}

	// node-space: node-a carries BOTH a malformed value and a malformed key;
	// node-b carries only a malformed key. Total = 3.
	insertLabel(t, st, nsNode, "node-a", "env", "prod, relay:quarantine=on") // malformed value
	insertLabel(t, st, nsNode, "node-a", "a=b", "c")                         // malformed key
	insertLabel(t, st, nsNode, "node-b", "a=b", "c")                         // malformed key

	// relay-space: both Nodes carry the same malformed value AND malformed
	// key, plus the quarantine fence pair (well-formed, must survive
	// untouched and unreported). Total = 4.
	insertLabel(t, st, nsRelay, "node-a", "env", "prod, relay:quarantine=on")
	insertLabel(t, st, nsRelay, "node-a", "a=b", "c")
	insertLabel(t, st, nsRelay, "node-a", registry.QuarantineKey, registry.QuarantineOn)
	insertLabel(t, st, nsRelay, "node-b", "env", "prod, relay:quarantine=on")
	insertLabel(t, st, nsRelay, "node-b", "a=b", "c")

	report, err := st.ScanDeclinedLabels(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}

	if report.Node.Labels != 3 || report.Node.Nodes != 2 {
		t.Errorf("Node = {Labels: %d, Nodes: %d}, want {3, 2}", report.Node.Labels, report.Node.Nodes)
	}
	if report.Relay.Labels != 4 || report.Relay.Nodes != 2 {
		t.Errorf("Relay = {Labels: %d, Nodes: %d}, want {4, 2}", report.Relay.Labels, report.Relay.Nodes)
	}

	wantNode := []DeclinedLabel{
		{NodeID: "node-a", Key: "a=b", Part: DeclinedPartKey},
		{NodeID: "node-a", Key: "env", Part: DeclinedPartValue},
		{NodeID: "node-b", Key: "a=b", Part: DeclinedPartKey},
	}
	assertReported(t, "node-space", report.Node.Reported, wantNode)

	wantRelay := []DeclinedLabel{
		{NodeID: "node-a", Key: "a=b", Part: DeclinedPartKey},
		{NodeID: "node-a", Key: "env", Part: DeclinedPartValue},
		{NodeID: "node-b", Key: "a=b", Part: DeclinedPartKey},
		{NodeID: "node-b", Key: "env", Part: DeclinedPartValue},
	}
	assertReported(t, "relay-space", report.Relay.Reported, wantRelay)

	// The scan READS. Every fixture row, well-formed or not, must still be
	// exactly what was inserted, and the row counts must not have moved.
	assertRowUnchanged(t, st, "node_labels", "node-a", "role", "web")
	assertRowUnchanged(t, st, "node_labels", "node-a", "env", "prod, relay:quarantine=on")
	assertRowUnchanged(t, st, "node_labels", "node-a", "a=b", "c")
	assertRowUnchanged(t, st, "node_labels", "node-b", "a=b", "c")
	assertRowUnchanged(t, st, "relay_labels", "node-a", "role", "web")
	assertRowUnchanged(t, st, "relay_labels", "node-a", registry.QuarantineKey, registry.QuarantineOn)
	assertRowCount(t, st, "node_labels", 5)  // role x2, env, a=b x2
	assertRowCount(t, st, "relay_labels", 7) // role x2, quarantine, env x2, a=b x2

	// The scan must never touch getNode's live read-back counters — reusing
	// wellFormedLabels here would inflate them and destroy the distinction
	// between the two #565 signals.
	if node, relay := st.LabelsDeclined(); node != 0 || relay != 0 {
		t.Errorf("LabelsDeclined() = (%d, %d) after the scan, want (0, 0) — the scan must not go through getNode/wellFormedLabels", node, relay)
	}
}

// assertReported asserts got matches want exactly, ignoring KeyTruncated
// (zero in every case here) and requiring the (node_id, key) order want is
// already written in — the scan's own contract, not an artifact of this
// helper re-sorting.
func assertReported(t *testing.T, label string, got, want []DeclinedLabel) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s Reported = %#v, want %#v", label, got, want)
	}
	for i := range want {
		if got[i].NodeID != want[i].NodeID || got[i].Key != want[i].Key || got[i].Part != want[i].Part {
			t.Errorf("%s Reported[%d] = %#v, want %#v", label, i, got[i], want[i])
		}
	}
}

func assertRowUnchanged(t *testing.T, st *Store, table, nodeID, key, want string) {
	t.Helper()
	var got string
	if err := st.db.QueryRow(
		fmt.Sprintf(`SELECT value FROM %s WHERE node_id = ? AND key = ?`, table), // table is a fixed test literal
		nodeID, key,
	).Scan(&got); err != nil {
		t.Fatalf("row %s/%s/%s must still exist: %v", table, nodeID, key, err)
	}
	if got != want {
		t.Errorf("row %s/%s/%s = %q, want %q — the scan must not rewrite a stored row", table, nodeID, key, got, want)
	}
}

func assertRowCount(t *testing.T, st *Store, table string, want int) {
	t.Helper()
	var got int
	if err := st.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table)).Scan(&got); err != nil { // table is a fixed test literal
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Errorf("%s row count = %d, want %d — the scan must not delete or insert a row", table, got, want)
	}
}

// TestScanDeclinedLabels_CapIsPerNamespace proves the cap is per-namespace,
// not global: a noisy node-space population must not starve relay-space's
// (much smaller) findings out of the report, in either scan order.
func TestScanDeclinedLabels_CapIsPerNamespace(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	const nodeCount = 5
	nodeIDs := make([]string, nodeCount)
	for i := 0; i < nodeCount; i++ {
		nodeIDs[i] = fmt.Sprintf("cap-node-%d", i)
		if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i]}); err != nil {
			t.Fatalf("Upsert %s: %v", nodeIDs[i], err)
		}
	}

	total := 0
	for i := 0; total < maxDeclinedReported+7; i++ {
		id := nodeIDs[i%nodeCount]
		insertLabel(t, st, nsNode, id, fmt.Sprintf("bad-%d", i), "prod, relay:quarantine=on")
		total++
	}
	insertLabel(t, st, nsRelay, nodeIDs[0], "env", "prod, relay:quarantine=on")

	report, err := st.ScanDeclinedLabels(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}

	if report.Node.Labels != int64(maxDeclinedReported+7) {
		t.Errorf("Node.Labels = %d, want %d (exact, never capped)", report.Node.Labels, maxDeclinedReported+7)
	}
	if len(report.Node.Reported) != maxDeclinedReported {
		t.Errorf("len(Node.Reported) = %d, want %d", len(report.Node.Reported), maxDeclinedReported)
	}
	if !report.Node.Truncated {
		t.Error("Node.Truncated = false, want true")
	}

	if len(report.Relay.Reported) != 1 {
		t.Errorf("len(Relay.Reported) = %d, want 1 — a single global cap would starve relay-space here", len(report.Relay.Reported))
	}
	if report.Relay.Truncated {
		t.Error("Relay.Truncated = true, want false")
	}
}

// TestScanDeclinedLabels_Logs pins the log shape: one WARN per finding, one
// WARN summary per non-empty namespace, relay-space before node-space, and —
// load-bearing — the declined VALUE never appears anywhere in the log.
func TestScanDeclinedLabels_Logs(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	st, _ := openTestStore(t, WithLogger(logger))
	reg := st.Registry()

	const secretValue = "prod, relay:quarantine=on"
	if _, err := reg.Upsert(registry.Report{NodeID: "node-relay-bad"}); err != nil {
		t.Fatalf("Upsert node-relay-bad: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-node-bad"}); err != nil {
		t.Fatalf("Upsert node-node-bad: %v", err)
	}
	insertLabel(t, st, nsRelay, "node-relay-bad", "env", secretValue)
	insertLabel(t, st, nsNode, "node-node-bad", "env", secretValue)

	if _, err := st.ScanDeclinedLabels(context.Background()); err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}

	// Scoped to THIS scan's own two messages rather than to the whole buffer.
	// The exact count still matters — it is what catches findings emitted with
	// no summary, or a summary emitted twice — but pinning the buffer's total
	// would make any unrelated future Open-time log line fail this test for a
	// reason that has nothing to do with what it asserts.
	const (
		findingMsg = "stored label declined on read-back"
		summaryMsg = "startup scan: stored labels declined on read-back"
	)
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n") {
		if strings.Contains(line, findingMsg) || strings.Contains(line, summaryMsg) {
			lines = append(lines, line)
		}
	}
	if len(lines) != 4 {
		t.Fatalf("scan log lines = %d, want 4 (2 findings + 2 summaries); log:\n%s", len(lines), logBuf.String())
	}

	type entry struct {
		Level         string `json:"level"`
		Msg           string `json:"msg"`
		Namespace     string `json:"namespace"`
		NodeID        string `json:"node_id"`
		Key           string `json:"key"`
		MalformedPart string `json:"malformed_part"`
		LabelsScan    int64  `json:"labels_declined_at_scan"`
		NodesScan     int64  `json:"nodes_affected_at_scan"`
	}
	var parsed []entry
	for _, line := range lines {
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}
		parsed = append(parsed, e)
	}

	if parsed[0].Namespace != "relay" || parsed[0].NodeID != "node-relay-bad" || parsed[0].Key != "env" || parsed[0].MalformedPart != "value" || parsed[0].Level != "WARN" {
		t.Errorf("line 0 (relay finding) = %#v", parsed[0])
	}
	if parsed[1].Namespace != "relay" || parsed[1].LabelsScan != 1 || parsed[1].NodesScan != 1 || parsed[1].Level != "WARN" {
		t.Errorf("line 1 (relay summary) = %#v", parsed[1])
	}
	if parsed[2].Namespace != "node" || parsed[2].NodeID != "node-node-bad" || parsed[2].Key != "env" || parsed[2].MalformedPart != "value" || parsed[2].Level != "WARN" {
		t.Errorf("line 2 (node finding) = %#v", parsed[2])
	}
	if parsed[3].Namespace != "node" || parsed[3].LabelsScan != 1 || parsed[3].NodesScan != 1 || parsed[3].Level != "WARN" {
		t.Errorf("line 3 (node summary) = %#v", parsed[3])
	}

	if strings.Contains(logBuf.String(), secretValue) {
		t.Errorf("the declined VALUE %q must never be logged; log:\n%s", secretValue, logBuf.String())
	}
}

// TestScanDeclinedLabels_CleanStoreLogsOnce proves a healthy fleet still
// produces exactly one line — a silent scan would be indistinguishable from
// one that was never wired at all.
func TestScanDeclinedLabels_CleanStoreLogsOnce(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	st, _ := openTestStore(t, WithLogger(logger))
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-clean"}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := reg.SetRelayLabels("node-clean", map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	report, err := st.ScanDeclinedLabels(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}
	if report.Any() {
		t.Errorf("report.Any() = true, want false: %#v", report)
	}

	lines := strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1; log:\n%s", len(lines), logBuf.String())
	}
	var entry struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.Level != "INFO" {
		t.Errorf("level = %q, want INFO", entry.Level)
	}
	if entry.Msg == "" {
		t.Error("message is empty")
	}
}

// TestScanDeclinedLabels_TruncatesLongKey proves a single log line stays
// bounded even against an attacker-influenced, arbitrarily long node-space
// key: WellFormedLabel has no length cap by design, so the scan's own
// per-line cap is the only thing bounding it.
func TestScanDeclinedLabels_TruncatesLongKey(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-long-key"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	longKey := strings.Repeat("k", registry.MaxLoggedLabelKeyBytes+50)
	// The value, not the key, is what makes this pair malformed — the key
	// alone is a well-formed (if oversized) run of allowed bytes.
	insertLabel(t, st, nsNode, "node-long-key", longKey, "prod, relay:quarantine=on")

	report, err := st.ScanDeclinedLabels(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}
	if len(report.Node.Reported) != 1 {
		t.Fatalf("len(Node.Reported) = %d, want 1", len(report.Node.Reported))
	}
	got := report.Node.Reported[0]
	if len(got.Key) != registry.MaxLoggedLabelKeyBytes {
		t.Errorf("reported key length = %d, want %d", len(got.Key), registry.MaxLoggedLabelKeyBytes)
	}
	if !utf8.ValidString(got.Key) {
		t.Errorf("reported key is not valid UTF-8: %q", got.Key)
	}
	if !got.KeyTruncated {
		t.Error("KeyTruncated = false, want true")
	}
}

// TestDeclinedPart_ClassifiesEveryQuadrant closes a coverage gap a code review
// found: DeclinedPartBoth is returned by production code but was asserted by no
// test, and declinedPart is the one function here whose correctness is argued
// entirely from a comment (the probe decomposition) rather than from cases.
//
// All four quadrants of (keyOK, valueOK) are covered, including the one the
// scan can never reach — a pair where BOTH halves are well-formed, which
// WellFormedLabel accepts so scanDeclinedNamespace skips it before
// declinedPart is consulted. It is asserted anyway: declinedPart is exported
// to nothing but it IS reachable by a future caller that does not pre-filter,
// and "what does it say about a valid pair" should have a written answer
// rather than being discovered.
//
// *Fails if*: the probe keys are swapped, either probe's empty-side argument
// changes (WellFormedLabel(key, "") isolates the key precisely because the
// empty value is accepted by design), or the switch arms are reordered so that
// a both-malformed pair reports as only one half.
func TestDeclinedPart_ClassifiesEveryQuadrant(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		key, value string
		want       DeclinedLabelPart
	}{
		// The three the scan actually produces.
		{"malformed key only", "a=b", "web", DeclinedPartKey},
		{"malformed value only", "env", "prod, relay:quarantine=on", DeclinedPartValue},
		{"both malformed", "a=b", "prod, relay:quarantine=on", DeclinedPartBoth},

		// An empty key is malformed BY ITSELF (WellFormedLabel's key != ""
		// check), with a value that is fine — so "key", not "both".
		{"empty key, well-formed value", "", "web", DeclinedPartKey},
		// An empty VALUE is well-formed by design, so a bad key with an empty
		// value is still "key" alone.
		{"malformed key, empty value", "a=b", "", DeclinedPartKey},
		// Empty key AND malformed value: both halves genuinely fail.
		{"empty key, malformed value", "", "a,b", DeclinedPartBoth},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := declinedPart(c.key, c.value); got != c.want {
				t.Errorf("declinedPart(%q, %q) = %q, want %q", c.key, c.value, got, c.want)
			}
		})
	}

	// The fourth quadrant, pinned because it is a TRAP rather than a
	// classification: declinedPart's documented precondition is that
	// WellFormedLabel has already refused the pair, so at least one half is
	// bad. Handed a pair that is actually FINE, the switch falls to its default
	// arm and answers DeclinedPartValue — confidently, and wrongly.
	//
	// That is tolerable today because the only caller pre-filters on exactly
	// that predicate, and widening the vocabulary to a fourth "nothing wrong"
	// value for a case the scan cannot produce would be over-building. But the
	// wrong answer should be written down rather than discovered, so a second
	// caller that forgets to pre-filter has something to find. If this
	// assertion ever fails, the fix is probably not to update it — it is to ask
	// whether the new caller is honouring the precondition.
	if got := declinedPart("env", "prod"); got != DeclinedPartValue {
		t.Errorf("declinedPart on a WELL-FORMED pair = %q, want %q — not because that is correct, "+
			"but because it is what the default arm does and a caller violating the precondition "+
			"needs the behaviour documented", got, DeclinedPartValue)
	}
}

// TestScanDeclinedLabels_TruncatesOnARuneBoundary is the case the all-ASCII
// fixture above structurally cannot see, and the one a security review caught:
// a refused key is BY DEFINITION outside WellFormedLabel's ASCII allowlist, so
// it may end in a multi-byte sequence, and a naive k[:128] would cut it in half.
//
// 127 ASCII bytes plus one U+2028 is the minimal witness — byte 128 lands
// inside the three-byte sequence, so a byte-cut yields a string ending in a
// lone 0xe2. The stdlib handlers escape that safely, but a log shipper or index
// requiring valid UTF-8 may drop the record — losing the finding for the most
// hostile key in the fleet, which is the one worth having.
//
// *Fails if*: registry.BoundLogKey loses its rune backoff, or the scan stops
// using it in favour of a local byte slice.
func TestScanDeclinedLabels_TruncatesOnARuneBoundary(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-multibyte"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	key := strings.Repeat("k", registry.MaxLoggedLabelKeyBytes-1) + " "
	if utf8.ValidString(key[:registry.MaxLoggedLabelKeyBytes]) {
		t.Fatalf("fixture is not exercising the hazard: a byte-cut of %d bytes is still valid UTF-8",
			registry.MaxLoggedLabelKeyBytes)
	}
	insertLabel(t, st, nsNode, "node-multibyte", key, "web")

	report, err := st.ScanDeclinedLabels(context.Background())
	if err != nil {
		t.Fatalf("ScanDeclinedLabels: %v", err)
	}
	if len(report.Node.Reported) != 1 {
		t.Fatalf("len(Node.Reported) = %d, want 1", len(report.Node.Reported))
	}
	got := report.Node.Reported[0]
	if !got.KeyTruncated {
		t.Error("KeyTruncated = false, want true")
	}
	if !utf8.ValidString(got.Key) {
		t.Errorf("reported key is not valid UTF-8 — the rune boundary was not honoured: %q", got.Key)
	}
	// Backing off to the boundary means strictly fewer bytes than the cap.
	if len(got.Key) >= registry.MaxLoggedLabelKeyBytes {
		t.Errorf("reported key length = %d, want < %d after the rune backoff",
			len(got.Key), registry.MaxLoggedLabelKeyBytes)
	}
}
