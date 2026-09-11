package store

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// This file is the one-shot boot answer to "which Nodes carry a stored Label
// this Relay will no longer serve" (threat model R13, #565). getNode's
// read-back filter (registry.go's wellFormedLabels) silently drops a pair
// registry.WellFormedLabel refuses, and does so on every read — Get, List,
// and Upsert's own read-back — which is exactly why a per-read log line is
// the wrong shape: List alone would re-log N lines per fleet listing,
// forever, for state that never changes on its own. A scan run once per
// process, before the listener accepts, answers the question as a QUESTION
// rather than as a side effect of traffic.
//
// It is EXACT, not approximate, because both write ingresses are gated:
// protoconv.ParseNodeLabel refuses a malformed node-space value at Hello/
// Enroll, and enroll.validateScope refuses a malformed relay-space value at
// both Service.Create and Service.Validate (label.go's five seams). So the
// population this scan finds — rows written before whichever gate now
// applies to that namespace — IS the entire affected set; there is no
// unaudited third path a scan could miss.
//
// It READS ONLY. Nothing here repairs, deletes, or rewrites a row: "decline
// to serve, never write" is settled (#504, #555), and a scan that "fixed"
// what it found would violate the same standing obligation wellFormedLabels'
// own doc records. It reads the RAW tables directly, not the filtered view
// getNode returns, so it cannot become the read-modify-write path that
// obligation forbids even by accident.

const (
	// maxDeclinedReported caps how many individual findings the scan
	// accumulates and logs, PER NAMESPACE — never a global cap. A global cap
	// would let whichever namespace happens to be scanned first (or simply
	// have the larger pre-gate population) crowd the other out of the log
	// entirely; a per-namespace cap guarantees sampled findings from BOTH
	// namespaces regardless of their relative populations, in either scan
	// order. Past the cap the scan keeps COUNTING but stops ACCUMULATING:
	// Labels/Nodes stay exact and Truncated says so, so the operator is told
	// precisely how many were not listed rather than losing them silently.
	maxDeclinedReported = 50

	// maxDeclinedKeyBytes bounds a single reported key. Node-space keys are
	// attacker-influenced (invariant 7, ADR-0017) and WellFormedLabel has no
	// length cap by design (label.go) — a capped LINE COUNT each carrying an
	// uncapped key would still be unbounded output, so the key itself must be
	// capped too.
	maxDeclinedKeyBytes = 128

	// declinedProbeKey is a fixed, well-formed one-byte key used only to
	// isolate a declined value from a declined key in declinedPart below. It
	// is not a Label and is never stored.
	declinedProbeKey = "k"

	// declinedLabelsRunbook is the operator-facing remediation this scan's
	// summary line points at: neither this scan nor the /metrics counter
	// repairs anything, so an operator needs a next step. Re-mint and
	// re-enroll is the only fix.
	declinedLabelsRunbook = "docs/operations/enrollment.md"
)

// DeclinedLabelPart identifies which half of a stored (key, value) pair
// registry.WellFormedLabel refused. A closed three-value vocabulary — never
// arbitrary bytes — because the dropped VALUE is deliberately never logged
// (see logNamespaceDeclined): this is the bounded substitute for the one
// thing the value would have told an operator that the key alone does not.
type DeclinedLabelPart string

const (
	// DeclinedPartKey means the key alone failed WellFormedLabel.
	DeclinedPartKey DeclinedLabelPart = "key"
	// DeclinedPartValue means the value alone failed WellFormedLabel.
	DeclinedPartValue DeclinedLabelPart = "value"
	// DeclinedPartBoth means both key and value failed WellFormedLabel.
	DeclinedPartBoth DeclinedLabelPart = "both"
)

// DeclinedLabel is one reported finding: a stored pair the read-back filter
// declines to serve. The VALUE is deliberately absent from this type — see
// logNamespaceDeclined for why.
type DeclinedLabel struct {
	NodeID       string
	Key          string
	KeyTruncated bool
	Part         DeclinedLabelPart
}

// DeclinedLabelSet is one namespace's scan result. Labels and Nodes are
// EXACT and never capped, even past the reporting cap; Reported is bounded by
// maxDeclinedReported, sorted by (node_id, key); Truncated says whether more
// findings existed than Reported holds.
type DeclinedLabelSet struct {
	Labels    int64
	Nodes     int64
	Reported  []DeclinedLabel
	Truncated bool
}

// DeclinedLabelReport is ScanDeclinedLabels' full result: both namespaces'
// DeclinedLabelSet. The Go field names stay Node/Relay — unambiguous in
// context — even though the scan's LOG lines use the more specific
// labels_declined_at_scan/nodes_affected_at_scan keys, deliberately distinct
// from the relay_labels_declined_total metric name so a boot log line and a
// dashboard panel are never mistaken for the same number (see
// logNamespaceDeclined).
type DeclinedLabelReport struct {
	Node  DeclinedLabelSet
	Relay DeclinedLabelSet
}

// Any reports whether either namespace has at least one declined Label.
func (r DeclinedLabelReport) Any() bool {
	return r.Node.Labels > 0 || r.Relay.Labels > 0
}

// ScanDeclinedLabels runs the one-shot startup scan over both stored label
// namespaces, logs what it finds through s.logger, and returns the report —
// the log is the operator's signal, the return value is what makes the scan
// assertable in a test without parsing log lines.
//
// Relay-space is scanned and logged FIRST: it is the namespace with no
// self-heal (node-space heals on the Node's next Hello) and the
// security-lane consequence (R13).
//
// This never repairs, deletes, or rewrites anything and it never touches
// getNode's read-back counters (Store.LabelsDeclined) — see scanDeclinedNamespace.
func (s *Store) ScanDeclinedLabels(ctx context.Context) (DeclinedLabelReport, error) {
	relay, err := scanDeclinedNamespace(ctx, s.db, nsRelay)
	if err != nil {
		return DeclinedLabelReport{}, fmt.Errorf("scan relay_labels: %w", err)
	}
	node, err := scanDeclinedNamespace(ctx, s.db, nsNode)
	if err != nil {
		return DeclinedLabelReport{}, fmt.Errorf("scan node_labels: %w", err)
	}

	report := DeclinedLabelReport{Node: node, Relay: relay}
	s.logNamespaceDeclined("relay", relay)
	s.logNamespaceDeclined("node", node)
	// A signal that is silent when healthy is indistinguishable from one
	// that was never wired; one INFO line per process is the cost of proving
	// this ran even on a large, fully-clean fleet.
	if !report.Any() {
		s.logger.Info("startup scan: no stored labels declined on read-back")
	}
	return report, nil
}

// scanDeclinedNamespace queries ns's table directly and classifies every row
// against registry.WellFormedLabel. It deliberately does NOT go through
// getNode, fetchLabels, or wellFormedLabels: loading whole Node records here
// is wasted work, and reusing wellFormedLabels would advance the SAME
// read-back counters getNode's readers advance (Store.LabelsDeclined),
// inflating that live, traffic-driven signal with a boot-time event it was
// never meant to count and destroying the distinction between the two
// signals #565 deliberately keeps separate.
//
// The query is ORDER BY node_id, key — the same fmt.Sprintf +
// //nolint:gosec table-literal idiom fetchLabels uses, since table is always
// one of the two fixed literals labelNamespace.table() returns. The ordering
// is not cosmetic: it is what lets distinct-Node counting stay O(1) memory
// (compare only against the previous row's node_id) rather than building a
// set the size of the affected fleet.
func scanDeclinedNamespace(ctx context.Context, q queryer, ns labelNamespace) (DeclinedLabelSet, error) {
	table := ns.table()
	rows, err := q.QueryContext(ctx,
		fmt.Sprintf(`SELECT node_id, key, value FROM %s ORDER BY node_id, key`, table)) //nolint:gosec // table is one of two fixed literals, never user input
	if err != nil {
		return DeclinedLabelSet{}, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()

	var set DeclinedLabelSet
	var prevNodeID string
	var haveRow bool
	for rows.Next() {
		var nodeID, key, value string
		if err := rows.Scan(&nodeID, &key, &value); err != nil {
			return DeclinedLabelSet{}, fmt.Errorf("scan %s row: %w", table, err)
		}
		if registry.WellFormedLabel(key, value) {
			continue
		}

		set.Labels++
		if !haveRow || nodeID != prevNodeID {
			set.Nodes++
			prevNodeID = nodeID
			haveRow = true
		}

		if len(set.Reported) >= maxDeclinedReported {
			set.Truncated = true
			continue
		}
		truncatedKey, wasTruncated := truncateKey(key)
		set.Reported = append(set.Reported, DeclinedLabel{
			NodeID:       nodeID,
			Key:          truncatedKey,
			KeyTruncated: wasTruncated,
			Part:         declinedPart(key, value),
		})
	}
	return set, rows.Err()
}

// declinedPart identifies which half of (key, value) registry.WellFormedLabel
// refused, using the ONE existing predicate rather than a second copy of its
// rule — label.go documents exactly five seams for this predicate, and a
// second predicate written just to answer "which half" would be the drift
// #488 exists to prevent.
//
// WellFormedLabel(key, value) decomposes to
// (key != "" && wellFormedLabelBytes(key)) && wellFormedLabelBytes(value).
// Probing each side in isolation, against a partner already known
// well-formed, recovers each term without re-deriving it:
//   - keyOK := WellFormedLabel(key, "") isolates the key, because the empty
//     value is accepted by design (label.go).
//   - valueOK := WellFormedLabel(declinedProbeKey, value) isolates the value,
//     because declinedProbeKey is a fixed well-formed key.
//
// This is correct for every input this function is called on (a pair
// registry.WellFormedLabel has already refused, so at least one of keyOK/
// valueOK is false), including an empty key (keyOK false, by
// WellFormedLabel's own key != "" check) and an empty value (valueOK true,
// since wellFormedLabelBytes("") is vacuously true).
func declinedPart(key, value string) DeclinedLabelPart {
	keyOK := registry.WellFormedLabel(key, "")
	valueOK := registry.WellFormedLabel(declinedProbeKey, value)
	switch {
	case !keyOK && !valueOK:
		return DeclinedPartBoth
	case !keyOK:
		return DeclinedPartKey
	default:
		return DeclinedPartValue
	}
}

// truncateKey byte-truncates k to maxDeclinedKeyBytes, reporting whether it
// did. See maxDeclinedKeyBytes for why an uncapped key would still make a
// capped line count unbounded output.
func truncateKey(k string) (truncated string, wasTruncated bool) {
	if len(k) <= maxDeclinedKeyBytes {
		return k, false
	}
	return k[:maxDeclinedKeyBytes], true
}

// logNamespaceDeclined logs namespace's findings: one WARN per reported
// finding, then — only when the namespace is not clean — one WARN summary
// naming the exact totals, the reporting cap, and the runbook.
//
// The dropped VALUE is never logged, and not merely because it "buys little
// over the key". In node-space the value is attacker-influenced (a
// compromised Node forges its own node: labels, invariant 7, ADR-0017), and
// by definition the values this filter declines are the ones containing the
// characters WellFormedLabel exists to refuse because they are misread when
// RE-RENDERED (`,` `:` whitespace `=`) — a log sink, a terminal, and a log
// dashboard are all renderers, so logging the declined value would pipe the
// hazard payload into a new renderer for no operational gain. In relay-space
// the value is operator-authored rather than forged, but node_id + namespace
// + key already identify the exact row, and the operator's authoritative
// source for the value is the store row or the token scope they are
// re-minting (both named in the runbook). Part is the deliberate substitute
// for what the value would have told an operator: one of three bounded
// values instead of arbitrary, possibly-hazardous bytes.
//
// The key IS logged, because without it the finding cannot identify which
// row is affected; it is passed through slog.String rather than
// pre-formatted with fmt.Sprintf("%q", key) so the HANDLER performs the
// quoting — pre-quoting double-quotes under the JSON handler and breaks
// machine parsing of the field.
//
// Log keys are labels_declined_at_scan/nodes_affected_at_scan — named
// distinctly from relay_labels_declined_total precisely because they are
// NOT the same number: the scan counts distinct stored pairs at one instant,
// the metric counts read-back events over the process's life, and an
// operator who conflates a boot log line with a dashboard panel because they
// share a name is the exact confusion these two names are chosen to avoid.
func (s *Store) logNamespaceDeclined(namespace string, set DeclinedLabelSet) {
	if set.Labels == 0 {
		return
	}
	for _, d := range set.Reported {
		s.logger.Warn("stored label declined on read-back",
			slog.String("namespace", namespace),
			slog.String("node_id", d.NodeID),
			slog.String("key", d.Key),
			slog.Bool("key_truncated", d.KeyTruncated),
			slog.String("malformed_part", string(d.Part)),
		)
	}
	s.logger.Warn("startup scan: stored labels declined on read-back",
		slog.String("namespace", namespace),
		slog.Int64("labels_declined_at_scan", set.Labels),
		slog.Int64("nodes_affected_at_scan", set.Nodes),
		slog.Int("reported", len(set.Reported)),
		slog.Bool("truncated", set.Truncated),
		slog.String("runbook", declinedLabelsRunbook),
	)
}
