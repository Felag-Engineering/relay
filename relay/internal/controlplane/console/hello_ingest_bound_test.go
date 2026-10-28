package console

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// Three Console places draw or cut the raw Policy fingerprint a Node reports in
// its Hello: the Node row's code title attribute, shortHash's 12-byte cut, and
// the Policy fingerprint facet keyed on the full value. #1068 bounds the value
// at ingest, so these tests send a hostile Hello through the real ingest
// conversion (protoconv.HelloReportFromProto) and the real registry write, then
// render the fleet from what the registry holds.

const (
	goodDaemonVersion = "0.1.0"
	bidiRune          = "\u202e"
)

// ingestHello records h for nodeID the way the tunnel does and reads the Node
// back, marked connected so the fleet lists it.
func ingestHello(t *testing.T, nodeID string, h *relayv1.Hello) registry.Node {
	t.Helper()
	reg := registry.NewInMemory()
	report, _ := protoconv.HelloReportFromProto(h)
	if _, err := reg.Upsert(registry.Report{
		NodeID:                 nodeID,
		Facts:                  report.Facts,
		PolicyFingerprint:      report.PolicyFingerprint,
		DaemonVersion:          report.DaemonVersion,
		TemplateSetFingerprint: report.TemplateSetFingerprint,
	}); err != nil {
		t.Fatalf("Upsert %s: %v", nodeID, err)
	}
	n, ok := reg.Get(nodeID)
	if !ok {
		t.Fatalf("Node %s not in the registry", nodeID)
	}
	n.Connected = true
	return n
}

// hostileFleet returns a Deps whose registry holds one honest Node and two
// whose Hello carried a hostile Policy fingerprint, and the three Node IDs.
func hostileFleet(t *testing.T) (d Deps, good, huge, bidi string) {
	t.Helper()
	good, huge, bidi = "node-good", "node-huge", "node-bidi"
	// U+202E straddles byte 12, where shortHash cuts.
	bidiFP := "abcdefghij" + bidiRune + strings.Repeat("a", 51)
	if len(bidiFP) != 64 {
		t.Fatalf("fixture is %d bytes, want 64", len(bidiFP))
	}
	nodes := []registry.Node{
		ingestHello(t, good, &relayv1.Hello{PolicyFingerprint: hexFP("d"), DaemonVersion: goodDaemonVersion}),
		ingestHello(t, huge, &relayv1.Hello{PolicyFingerprint: strings.Repeat("a", 1<<20), DaemonVersion: goodDaemonVersion}),
		ingestHello(t, bidi, &relayv1.Hello{PolicyFingerprint: bidiFP, DaemonVersion: goodDaemonVersion}),
	}
	return withFleet(renderableDeps(), nodes...), good, huge, bidi
}

// fleetBodyListing renders the fleet and fails unless it lists all of ids, so
// an assertion about what is absent cannot pass because the Node never showed.
func fleetBodyListing(t *testing.T, d Deps, ids ...string) string {
	t.Helper()
	body := fleetBody(t, d, "")
	for _, id := range ids {
		if !strings.Contains(body, id) {
			t.Fatalf("the fleet page does not list %s", id)
		}
	}
	return body
}

// policyCell returns the Policy cell of the table row for nodeID, found by the
// row's own Pin control so an earlier mention of the ID elsewhere on the page
// cannot be mistaken for it.
func policyCell(t *testing.T, body, nodeID string) string {
	t.Helper()
	for _, row := range strings.Split(body, "<tr>") {
		if !strings.Contains(row, `aria-label="Pin `+nodeID+` to compare"`) {
			continue
		}
		i := strings.Index(row, `data-label="Policy"`)
		if i < 0 {
			t.Fatalf("the row for %s has no Policy cell", nodeID)
		}
		cell := row[i:]
		end := strings.Index(cell, "</td>")
		if end < 0 {
			t.Fatalf("the Policy cell of %s is not closed", nodeID)
		}
		return cell[:end]
	}
	t.Fatalf("the fleet page has no table row for %s", nodeID)
	return ""
}

// TestFleet_NodeRowTitleNeverCarriesAMalformedHelloFingerprint covers the Node
// row's code title attribute, which carries the full stored value.
//
// MUTATION: storing hello.GetPolicyFingerprint() unbounded in
// HelloReportFromProto turns this red.
func TestFleet_NodeRowTitleNeverCarriesAMalformedHelloFingerprint(t *testing.T) {
	d, good, huge, bidi := hostileFleet(t)
	body := fleetBodyListing(t, d, good, huge, bidi)

	if strings.Contains(body, bidiRune) {
		t.Error("the page carries U+202E from a Hello fingerprint")
	}
	if regexp.MustCompile(`title="[^"]*a{65,}`).MatchString(body) {
		t.Error("a title attribute carries the oversized Hello fingerprint")
	}
	for _, id := range []string{huge, bidi} {
		if cell := policyCell(t, body, id); !strings.Contains(cell, "not reported") {
			t.Errorf("%s: Policy cell = %.200q, want \"not reported\"", id, cell)
		}
	}
	if cell := policyCell(t, body, good); !strings.Contains(cell, `<code class="fphash">`+hexFP("d")+`</code>`) {
		t.Errorf("%s: Policy cell = %.300q, want the honest fingerprint drawn in full", good, cell)
	}
}

// TestFleet_ShortHashCellNeverSplitsAHelloFingerprint covers shortHash's
// 12-byte cut: a value with a multi-byte rune across byte 12 is not recorded,
// so the cut can never split it.
//
// MUTATION: storing hello.GetPolicyFingerprint() unbounded in
// HelloReportFromProto turns this red.
func TestFleet_ShortHashCellNeverSplitsAHelloFingerprint(t *testing.T) {
	d, good, huge, bidi := hostileFleet(t)
	body := fleetBodyListing(t, d, good, huge, bidi)

	if !utf8.ValidString(body) {
		t.Error("the page is not valid UTF-8")
	}
	if strings.Contains(body, bidiRune) {
		t.Error("the page carries U+202E from a Hello fingerprint")
	}
	if cell := policyCell(t, body, good); !strings.Contains(cell, `<code class="fphash">`+hexFP("d")+`</code>`) ||
		strings.Contains(cell, shortHash(hexFP("d"))) {
		t.Errorf("%s: Policy cell = %.300q, want the whole fingerprint and no short form", good, cell)
	}
	for _, id := range []string{huge, bidi} {
		if cell := policyCell(t, body, id); strings.Contains(cell, "<code") {
			t.Errorf("%s: Policy cell draws a short text: %.200q", id, cell)
		}
	}
}

// TestFleet_FingerprintFacetLinksAreNeverKeyedOnAMalformedHelloValue covers the
// Policy fingerprint facet, keyed on the full value: every Node whose Hello
// fingerprint was refused lands in the one "not reported" row, which is not a
// link, and no row's label, term or link carries the hostile value.
//
// MUTATION: storing hello.GetPolicyFingerprint() unbounded in
// HelloReportFromProto turns this red.
func TestFleet_FingerprintFacetLinksAreNeverKeyedOnAMalformedHelloValue(t *testing.T) {
	d, _, _, _ := hostileFleet(t)
	v := buildFleetView(d, fleetNodes(d), 0, "", "-")
	if len(v.Groups) != 1 {
		t.Fatalf("the fleet view has %d groups, want the one ungrouped fleet", len(v.Groups))
	}

	hostile := 0
	for _, n := range fleetNodes(d) {
		if n.PolicyFingerprint == "" {
			hostile++
		}
	}
	if hostile != 2 {
		t.Fatalf("%d Nodes have no stored Policy fingerprint, want the 2 hostile ones: the ingest bound did not refuse them", hostile)
	}

	longHex := regexp.MustCompile(`[0-9a-f]{65,}`)
	for _, g := range v.Groups {
		var f *facet
		for i := range g.Facets {
			if g.Facets[i].Title == "Policy fingerprint" {
				f = &g.Facets[i]
			}
		}
		if f == nil {
			t.Fatalf("group %q has no Policy fingerprint facet", g.Key)
		}

		sum := 0
		for _, fv := range f.Values {
			sum += fv.Count
			if strings.Contains(fv.Label+fv.Term+fv.Href, bidiRune) || longHex.MatchString(fv.Label+fv.Term+fv.Href) {
				t.Errorf("facet value %q carries a hostile Hello value", fv.Label)
			}
			switch fv.Label {
			case "not reported":
				if fv.Term != "" || fv.Href != "" {
					t.Errorf("the not-reported row is a link: term %q, href %q", fv.Term, fv.Href)
				}
				if fv.Count != hostile {
					t.Errorf("not-reported count = %d, want %d", fv.Count, hostile)
				}
			default:
				if want := "state:policy-fingerprint=" + hexFP("d"); fv.Term != want {
					t.Errorf("facet value %q has term %q, want %q", fv.Label, fv.Term, want)
				}
			}
		}
		if sum != g.Count {
			t.Errorf("group %q: facet counts sum to %d, want the group's %d Nodes", g.Key, sum, g.Count)
		}
	}
}

// snapshotFPFixture seeds a registry Node with no Hello-recorded Policy
// fingerprint but a daemon version (so the Node page marks its Policy panel
// "Not corroborated by a recorded Hello" and draws the snapshot's own
// fingerprint), caches snapshotFP as that Node's Policy snapshot fingerprint,
// and returns the Node page body fetched through a real ReadLane.
func snapshotFPFixture(t *testing.T, snapshotFP string) string {
	t.Helper()
	const nodeID = "node-snap"
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: nodeID, DaemonVersion: goodDaemonVersion}); err != nil {
		t.Fatalf("Upsert %s: %v", nodeID, err)
	}
	policy := policyview.New()
	policy.Set(nodeID, policyview.Snapshot{PolicyFingerprint: snapshotFP, AllowedOperations: []string{"system.facts"}})
	sink := auditsink.New(&recordingTrail{}, auditsink.WithClock(func() time.Time { return testNow }))
	svc := newCapService(capSeams{
		reg:        reg,
		audit:      sink,
		auditQ:     emptyAuditQuery{},
		jobQ:       emptyJobQuery{},
		policyView: policy,
	})
	d := renderableDeps()
	d.Queries = svc.ReadLane

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/"+nodeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the Node page = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestNode_SnapshotPolicyFingerprintThatFailsTheBoundIsNeverRendered covers
// the Node page's code title attribute, which draws the fingerprint a cached
// Policy snapshot carries. The value is Node-reported, so the read lane serves
// it as "" when it fails the Hello bound, and the page states the snapshot
// carries none rather than drawing it.
//
// MUTATION: returning the cached snapshot unbounded from DescribeNode turns
// this red.
func TestNode_SnapshotPolicyFingerprintThatFailsTheBoundIsNeverRendered(t *testing.T) {
	const uncorroborated = "Not corroborated by a recorded Hello"
	hostile := map[string]string{
		"bidi override":   "abcdefghij" + bidiRune + strings.Repeat("a", 51),
		"quote and angle": `"><script>alert(1)</script>` + strings.Repeat("a", 40),
		"sha256 prefix":   "sha256:" + hexFP("a")[:57],
		"oversized":       strings.Repeat("a", 1<<20),
	}
	for name, value := range hostile {
		t.Run(name, func(t *testing.T) {
			body := snapshotFPFixture(t, value)
			if !strings.Contains(body, uncorroborated) {
				t.Fatal("the Policy panel is not in its uncorroborated branch, so this test would pass vacuously")
			}
			if !strings.Contains(body, "This snapshot carries no Policy fingerprint of its own.") {
				t.Error("the page does not state the snapshot carries no fingerprint")
			}
			if strings.Contains(body, value) || strings.Contains(body, html.EscapeString(value)) {
				t.Error("the page draws the Node-reported snapshot fingerprint")
			}
			if strings.Contains(body, bidiRune) {
				t.Error("the page carries U+202E from a snapshot fingerprint")
			}
		})
	}

	// Positive control on the same fixture: a well-formed fingerprint is drawn,
	// in the code element's title attribute.
	body := snapshotFPFixture(t, hexFP("c"))
	if !strings.Contains(body, uncorroborated) || !strings.Contains(body, "This snapshot carries its own Policy fingerprint") {
		t.Fatal("a well-formed snapshot fingerprint is not drawn on the uncorroborated panel")
	}
	if !strings.Contains(body, `title="`+hexFP("c")+`"`) {
		t.Error("the code element's title attribute does not carry the well-formed fingerprint")
	}
}
