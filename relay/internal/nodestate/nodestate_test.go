package nodestate_test

import (
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

var testNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

// --- MarkerCertExpiring ---

func TestMarkers_CertExpiringFiresUnderTheWindow(t *testing.T) {
	in := nodestate.Input{
		Node:               registry.Node{NodeID: "n", CertNotAfter: testNow.Add(1 * time.Hour)},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	ls := nodestate.Markers(in)
	found := false
	for _, l := range ls {
		if l.Key == string(nodestate.MarkerCertExpiring) {
			found = true
			if !l.Attention {
				t.Error("state:cert-expiring did not carry Attention — it is an alarm")
			}
		}
	}
	if !found {
		t.Error("a certificate 1h from expiry inside a 2h window did not fire state:cert-expiring")
	}
}

func TestMarkers_CertExpiringQuietAboveTheWindow(t *testing.T) {
	in := nodestate.Input{
		Node:               registry.Node{NodeID: "n", CertNotAfter: testNow.Add(10 * time.Hour)},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerCertExpiring) {
			t.Error("a certificate 10h from expiry inside a 2h window fired state:cert-expiring")
		}
	}
}

func TestMarkers_CertExpiringQuietWhenProvenanceUnknown(t *testing.T) {
	// Zero CertNotAfter must never read as an expiry in 1970: a Node with no
	// recorded provenance is quiet, not alarming.
	in := nodestate.Input{
		Node:               registry.Node{NodeID: "n"},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerCertExpiring) {
			t.Error("a Node with no recorded certificate provenance fired state:cert-expiring")
		}
	}
}

func TestMarkers_CertExpiringQuietWhenWindowIsZero(t *testing.T) {
	// A zero CertExpiringWithin means the marker never fires — the composition
	// root always sets a real one; this is what makes "no window configured"
	// distinguishable from "no threat".
	in := nodestate.Input{
		Node: registry.Node{NodeID: "n", CertNotAfter: testNow.Add(-1 * time.Hour)},
		Now:  testNow,
	}
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerCertExpiring) {
			t.Error("a zero CertExpiringWithin still fired state:cert-expiring")
		}
	}
}

func TestMarkers_CertExpiringFiresWhenAlreadyLapsed(t *testing.T) {
	// An alarm, not a countdown: a certificate that already lapsed still fires.
	in := nodestate.Input{
		Node:               registry.Node{NodeID: "n", CertNotAfter: testNow.Add(-1 * time.Hour)},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	found := false
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerCertExpiring) {
			found = true
		}
	}
	if !found {
		t.Error("an already-lapsed certificate did not fire state:cert-expiring")
	}
}

// --- LabelSet ---

func TestLabelSet_IsLabelsReduced(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:                 "n",
			DaemonVersion:          "1.4.2",
			PolicyFingerprint:      "abc123",
			TemplateSetFingerprint: "def456",
		},
		Now: testNow,
	}
	labels := nodestate.Labels(in)
	set := nodestate.LabelSet(in)

	if len(set) != len(labels) {
		t.Fatalf("LabelSet has %d entries, Labels has %d — they must be the same shape", len(set), len(labels))
	}
	for _, l := range labels {
		v, ok := set[l.Key]
		if !ok {
			t.Errorf("LabelSet is missing key %q, present in Labels", l.Key)
			continue
		}
		if v != l.Value {
			t.Errorf("LabelSet[%q] = %q, want %q (from Labels)", l.Key, v, l.Value)
		}
	}
}

// --- KeyKind closure ---

func TestKeyKind_Closure(t *testing.T) {
	markers := []string{"offline", "outdated", "cert-expiring", "template-unloadable"}
	for _, k := range markers {
		if got := nodestate.KeyKind(k); got != nodestate.KindMarker {
			t.Errorf("KeyKind(%q) = %v, want KindMarker", k, got)
		}
	}

	facts := []string{"daemon-version", "policy-fingerprint", "template-fingerprint"}
	for _, k := range facts {
		if got := nodestate.KeyKind(k); got != nodestate.KindFact {
			t.Errorf("KeyKind(%q) = %v, want KindFact", k, got)
		}
	}

	unknown := []string{"foo", "offline=", "", "daemon_version"}
	for _, k := range unknown {
		if got := nodestate.KeyKind(k); got != nodestate.KindUnknown {
			t.Errorf("KeyKind(%q) = %v, want KindUnknown", k, got)
		}
	}
}

func TestMarkerKeysAndFactKeys_MatchKeyKind(t *testing.T) {
	for _, k := range nodestate.MarkerKeys() {
		if nodestate.KeyKind(k) != nodestate.KindMarker {
			t.Errorf("MarkerKeys() returned %q, which KeyKind does not classify as a marker", k)
		}
	}
	for _, k := range nodestate.FactKeys() {
		if nodestate.KeyKind(k) != nodestate.KindFact {
			t.Errorf("FactKeys() returned %q, which KeyKind does not classify as a fact", k)
		}
	}
}

// --- Node-locality (acceptance 3) ---

func TestLabels_AreIndependentOfOtherNodes(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("upsert node-a: %v", err)
	}
	a, _ := reg.Get("node-a")
	inBefore := nodestate.Input{Node: a, Now: testNow, CertExpiringWithin: time.Hour}
	before := nodestate.Labels(inBefore)

	// A second Node, in a very different state (offline, outdated has no
	// minimum here so left alone, but distinctly unloadable), must not change
	// anything about the first.
	if _, err := reg.Upsert(registry.Report{NodeID: "node-b", TemplateSetFingerprint: nodestate.TemplateUnloadable}); err != nil {
		t.Fatalf("upsert node-b: %v", err)
	}
	a2, _ := reg.Get("node-a")
	inAfter := nodestate.Input{Node: a2, Now: testNow, CertExpiringWithin: time.Hour}
	after := nodestate.Labels(inAfter)

	if len(before) != len(after) {
		t.Fatalf("node-a's Labels changed when node-b was added: before=%+v after=%+v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("node-a's Labels[%d] changed when node-b was added: before=%+v after=%+v", i, before[i], after[i])
		}
	}
}

// --- state:outdated sourced only from n.Outdated ---

func TestMarkers_OutdatedComesOnlyFromNodeOutdated(t *testing.T) {
	reg := registry.NewInMemory(registry.WithMinDaemonVersion("1.4.0"))
	if _, err := reg.Upsert(registry.Report{NodeID: "old", DaemonVersion: "1.0.0"}); err != nil {
		t.Fatalf("upsert old: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "current", DaemonVersion: "1.5.0"}); err != nil {
		t.Fatalf("upsert current: %v", err)
	}

	old, _ := reg.Get("old")
	if !old.Outdated {
		t.Fatal("test setup: the registry did not derive Outdated for the old Node")
	}
	current, _ := reg.Get("current")
	if current.Outdated {
		t.Fatal("test setup: the registry derived Outdated for the current Node")
	}

	oldMarkers := nodestate.Markers(nodestate.Input{Node: old, Now: testNow})
	foundOutdated := false
	for _, l := range oldMarkers {
		if l.Key == string(nodestate.MarkerOutdated) {
			foundOutdated = true
		}
	}
	if !foundOutdated {
		t.Error("state:outdated did not fire for a Node the registry derived as Outdated")
	}

	currentMarkers := nodestate.Markers(nodestate.Input{Node: current, Now: testNow})
	for _, l := range currentMarkers {
		if l.Key == string(nodestate.MarkerOutdated) {
			t.Error("state:outdated fired for a Node the registry derived as current")
		}
	}
}

// --- Facts closes the vocabulary on the value side too (security review F1) ---

// TestFacts_HostileDaemonVersionCannotInjectASelectorTerm drives a hostile
// Hello.daemon_version — exactly what a compromised Node can send over the
// wire, with no validation at the tunnel.go ingress — through registry.Report
// (mirroring tunnel.go's Upsert), nodestate.Labels, and the rendered
// state_labels strings every surface (MCP, the Control API, the Console)
// exposes, and asserts the injected `tag:x=y` term never resolves to a
// second Predicate.
func TestFacts_HostileDaemonVersionCannotInjectASelectorTerm(t *testing.T) {
	const hostile = "1.4.2, tag:x=y"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "n", DaemonVersion: hostile}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	n, ok := reg.Get("n")
	if !ok {
		t.Fatal("test setup: node not found after upsert")
	}

	labels := nodestate.Labels(nodestate.Input{Node: n, Now: testNow})
	for _, l := range labels {
		if l.Key == string(nodestate.FactDaemonVersion) {
			t.Fatalf("state:daemon-version was rendered from a hostile value %q — "+
				"the closed vocabulary must be closed on the value side, not only the key side", l.Value)
		}
	}

	// Even reassembled exactly as list_nodes/describe_node hand it to a
	// caller — a comma-joined list of rendered state_labels strings fed
	// straight to ParseSelector, precisely what MCP's tool description
	// invites an AI-agent to do — the hostile value must not resolve to a
	// second predicate.
	rendered := make([]string, 0, len(labels))
	for _, l := range labels {
		rendered = append(rendered, l.String())
	}
	joined := strings.Join(rendered, ", ")
	sel, err := capability.ParseSelector(joined)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", joined, err)
	}
	for _, p := range sel.Predicates {
		if p.Namespace == capability.NamespaceTag {
			t.Fatalf("a hostile daemon-version injected a tag: predicate: %+v (rendered: %q)", p, joined)
		}
	}
}

func TestFacts_OmitsHostileValueShapes(t *testing.T) {
	hostile := []string{
		"1.4.2, tag:x=y",
		"1.4.2,tag:x=y",
		" 1.4.2",
		"1.4.2 ",
		"1.4.2\ttag:x=y",
		"\u00a01.4.2", // leading NBSP — pins the removed TrimSpace check
		"1.4.2\u00a0", // trailing NBSP — same
		"node:role=web",
		"relay:quarantine=on",
		"tag:x=y",
		"state:offline",
	}

	// All three Fact-producing fields share validFactValue, so the same
	// hostile shapes must be rejected identically from each.
	// TemplateSetFingerprint also carries the TemplateUnloadable sentinel
	// (nodestate.go:255), but none of the shapes above collide with it, so
	// this loop does not touch that disputed behaviour (see
	// TestMarkers_TemplateUnloadableFiresOnTheSentinelAndIsNotAmber).
	fields := []struct {
		name string
		key  nodestate.Fact
		node func(v string) registry.Node
	}{
		{"DaemonVersion", nodestate.FactDaemonVersion, func(v string) registry.Node {
			return registry.Node{NodeID: "n", DaemonVersion: v}
		}},
		{"PolicyFingerprint", nodestate.FactPolicyFingerprint, func(v string) registry.Node {
			return registry.Node{NodeID: "n", PolicyFingerprint: v}
		}},
		{"TemplateSetFingerprint", nodestate.FactTemplateFingerprint, func(v string) registry.Node {
			return registry.Node{NodeID: "n", TemplateSetFingerprint: v}
		}},
	}

	for _, f := range fields {
		for _, v := range hostile {
			in := nodestate.Input{Node: f.node(v), Now: testNow}
			for _, l := range nodestate.Facts(in) {
				if l.Key == string(f.key) {
					t.Errorf("%s: Facts emitted %s=%q from hostile value %q", f.name, f.key, l.Value, v)
				}
			}
		}
	}

	// Named Unicode White_Space cases, each in the issue's exact reproduction
	// shape ("aaaa<rune>tag:pci=yes") — the human-readable regression names;
	// TestFacts_NoWhiteSpaceRuneReachesASelectorTerm below is the guarantee
	// over the whole table. The last two repeat the leading/trailing pin
	// above against that reproduction shape specifically.
	namedWhitespace := []struct {
		name string
		v    string
	}{
		{"NBSP embedded", "aaaa\u00a0tag:pci=yes"},
		{"NEL embedded", "aaaa\u0085tag:pci=yes"},
		{"OGHAM SPACE MARK embedded", "aaaa\u1680tag:pci=yes"},
		{"LINE SEPARATOR embedded", "aaaa\u2028tag:pci=yes"},
		{"PARAGRAPH SEPARATOR embedded", "aaaa\u2029tag:pci=yes"},
		{"NARROW NO-BREAK SPACE embedded", "aaaa\u202ftag:pci=yes"},
		{"MEDIUM MATHEMATICAL SPACE embedded", "aaaa\u205ftag:pci=yes"},
		{"IDEOGRAPHIC SPACE embedded", "aaaa\u3000tag:pci=yes"},
		{"NBSP leading", "\u00a0aaaatag:pci=yes"},
		{"NBSP trailing", "aaaatag:pci=yes\u00a0"},
	}
	for _, c := range namedWhitespace {
		t.Run(c.name, func(t *testing.T) {
			in := nodestate.Input{Node: registry.Node{NodeID: "n", DaemonVersion: c.v}, Now: testNow}
			for _, l := range nodestate.Facts(in) {
				if l.Key == string(nodestate.FactDaemonVersion) {
					t.Errorf("Facts emitted state:daemon-version=%q from hostile value %q", l.Value, c.v)
				}
			}
		})
	}

	clean := []string{"1.4.2", "abc123def456", "unloadable-ish-but-not-quite"}
	for _, v := range clean {
		in := nodestate.Input{Node: registry.Node{NodeID: "n", DaemonVersion: v}, Now: testNow}
		found := false
		for _, l := range nodestate.Facts(in) {
			if l.Key == string(nodestate.FactDaemonVersion) {
				found = true
				if l.Value != v {
					t.Errorf("Facts emitted state:daemon-version=%q, want %q", l.Value, v)
				}
			}
		}
		if !found {
			t.Errorf("Facts omitted well-formed daemon-version %q", v)
		}
	}
}

// TestFacts_NoWhiteSpaceRuneReachesASelectorTerm walks the REAL
// unicode.White_Space table — stride-aware, since its R16 ranges are not
// contiguous runs (an entry spanning U+00A0..U+1680 strides by 5600, not 1,
// so a naive lo..hi loop would wrongly sweep in most of Latin-1) — and
// asserts Facts omits the daemon-version fact for a value carrying each rune
// embedded, leading and trailing. This pins the PROPERTY validFactValue is
// meant to hold rather than a hand-picked set: it fails automatically if
// Go's Unicode tables grow and the rewritten predicate stops agreeing with
// them. The leading and trailing arms are what pin the removal of the
// TrimSpace check — a value invalid ONLY because of a leading or trailing
// rune must still be rejected now that TrimSpace is gone.
func TestFacts_NoWhiteSpaceRuneReachesASelectorTerm(t *testing.T) {
	runes := whiteSpaceRunes(t)
	if len(runes) == 0 {
		t.Fatal("test setup: enumerated zero White_Space runes")
	}

	for _, r := range runes {
		s := string(r)
		shapes := map[string]string{
			"embedded": "aaaa" + s + "bbbb",
			"leading":  s + "aaaabbbb",
			"trailing": "aaaabbbb" + s,
		}
		for shape, v := range shapes {
			in := nodestate.Input{Node: registry.Node{NodeID: "n", DaemonVersion: v}, Now: testNow}
			for _, l := range nodestate.Facts(in) {
				if l.Key == string(nodestate.FactDaemonVersion) {
					t.Errorf("rune U+%04X, %s: Facts emitted state:daemon-version=%q", r, shape, l.Value)
				}
			}
		}
	}
}

// whiteSpaceRunes enumerates every rune unicode.White_Space contains, one at
// a time. A RangeTable's R16/R32 entries are (Lo, Hi, Stride) triples, not
// contiguous runs, so walking Lo..Hi by 1 would overcount; walking by Stride
// is what makes this an exact enumeration.
func whiteSpaceRunes(t *testing.T) []rune {
	t.Helper()
	var out []rune
	for _, r16 := range unicode.White_Space.R16 {
		stride := int(r16.Stride)
		if stride == 0 {
			stride = 1
		}
		for c := int(r16.Lo); c <= int(r16.Hi); c += stride {
			out = append(out, rune(c))
		}
	}
	for _, r32 := range unicode.White_Space.R32 {
		stride := int(r32.Stride)
		if stride == 0 {
			stride = 1
		}
		for c := int(r32.Lo); c <= int(r32.Hi); c += stride {
			out = append(out, rune(c))
		}
	}
	return out
}

// TestFacts_UnicodeWhitespaceCannotInjectASelectorTerm mirrors
// TestFacts_HostileDaemonVersionCannotInjectASelectorTerm but drives a
// different fact key — PolicyFingerprint, not DaemonVersion — through a
// non-ASCII LINE SEPARATOR rather than an ASCII comma-space, through the
// real registry ingress path (Report -> Upsert -> Get), exactly as
// tunnel.go feeds a Node's Hello.
func TestFacts_UnicodeWhitespaceCannotInjectASelectorTerm(t *testing.T) {
	const hostile = "aaaa\u2028tag:pci=yes"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "n", PolicyFingerprint: hostile}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	n, ok := reg.Get("n")
	if !ok {
		t.Fatal("test setup: node not found after upsert")
	}

	labels := nodestate.Labels(nodestate.Input{Node: n, Now: testNow})
	for _, l := range labels {
		if l.Key == string(nodestate.FactPolicyFingerprint) {
			t.Fatalf("state:policy-fingerprint was rendered from a hostile value %q — "+
				"the closed vocabulary must be closed on the value side, not only the key side", l.Value)
		}
	}

	rendered := make([]string, 0, len(labels))
	for _, l := range labels {
		rendered = append(rendered, l.String())
	}
	joined := strings.Join(rendered, ", ")
	sel, err := capability.ParseSelector(joined)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", joined, err)
	}
	if len(sel.Predicates) == 0 {
		t.Fatal("ParseSelector produced zero predicates — the NamespaceTag check below would " +
			"pass vacuously; it needs at least one real predicate (e.g. state:offline) to be meaningful")
	}
	for _, p := range sel.Predicates {
		if p.Namespace == capability.NamespaceTag {
			t.Fatalf("a hostile policy-fingerprint injected a tag: predicate: %+v (rendered: %q)", p, joined)
		}
	}
}

// TestFacts_ZeroWidthSpaceIsAcceptedKnownGap pins CURRENT behaviour, not a
// desired property. validFactValue rejects the Unicode `White_Space` set,
// and U+200B ZWSP is not a member of it (category Cf, `White_Space=No`), so
// it is accepted today — but that is NOT evidence the acceptance is
// correct. It is the narrow, genuinely-invisible case of a wider,
// ACKNOWLEDGED gap: runes outside `White_Space` can still render as a
// visible blank next to a comma and reproduce the same "reads as two terms"
// hazard this predicate exists to close (confirmed live for U+2800 BRAILLE
// PATTERN BLANK and U+3164 HANGUL FILLER, neither of which is category Cf or
// `White_Space`). See validFactValue's doc comment for the full gap and the
// allowlist follow-up that would close it structurally. If a future change
// tightens validFactValue to reject ZWSP too, update or delete this test —
// its failure would not be a regression.
func TestFacts_ZeroWidthSpaceIsAcceptedKnownGap(t *testing.T) {
	const v = "aaaa\u200bbbbb"
	in := nodestate.Input{Node: registry.Node{NodeID: "n", PolicyFingerprint: v}, Now: testNow}
	found := false
	for _, l := range nodestate.Facts(in) {
		if l.Key == string(nodestate.FactPolicyFingerprint) {
			found = true
			if l.Value != v {
				t.Errorf("Facts emitted state:policy-fingerprint=%q, want %q", l.Value, v)
			}
		}
	}
	if !found {
		t.Error("Facts omitted a value containing only U+200B ZWSP — if validFactValue was " +
			"tightened to close this gap, update this test rather than treating the failure as a regression")
	}
}

// --- MarkerOffline ---

func TestMarkers_OfflineComesFromConnectedness(t *testing.T) {
	in := nodestate.Input{Node: registry.Node{NodeID: "n", Connected: false}, Now: testNow}
	found := false
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerOffline) {
			found = true
			if !l.Attention {
				t.Error("state:offline did not carry Attention — it is an alarm")
			}
		}
	}
	if !found {
		t.Error("Connected: false did not fire state:offline")
	}

	connected := nodestate.Input{Node: registry.Node{NodeID: "n", Connected: true}, Now: testNow}
	for _, l := range nodestate.Markers(connected) {
		if l.Key == string(nodestate.MarkerOffline) {
			t.Error("Connected: true fired state:offline")
		}
	}
}

// --- MarkerTemplateUnloadable ---

func TestMarkers_TemplateUnloadableFiresOnTheSentinelAndIsNotAmber(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{NodeID: "n", Connected: true, TemplateSetFingerprint: nodestate.TemplateUnloadable},
		Now:  testNow,
	}
	found := false
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerTemplateUnloadable) {
			found = true
			if l.Attention {
				t.Error("state:template-unloadable carried Attention — an empty template vocabulary is inertness, not an alarm")
			}
		}
	}
	if !found {
		t.Fatal("the unloadable sentinel did not fire state:template-unloadable")
	}

	// A real fingerprint, and an empty one (no templates installed at all),
	// must both be quiet — only the literal sentinel fires the marker.
	for _, v := range []string{"abc123def456", ""} {
		clean := nodestate.Input{Node: registry.Node{NodeID: "n", Connected: true, TemplateSetFingerprint: v}, Now: testNow}
		for _, l := range nodestate.Markers(clean) {
			if l.Key == string(nodestate.MarkerTemplateUnloadable) {
				t.Errorf("TemplateSetFingerprint=%q fired state:template-unloadable", v)
			}
		}
	}
}

// --- Marker ordering ---

func TestMarkers_AreOrderedBySeverity(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:                 "n",
			Connected:              false,
			Outdated:               true,
			CertNotAfter:           testNow.Add(1 * time.Hour),
			TemplateSetFingerprint: nodestate.TemplateUnloadable,
		},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	markers := nodestate.Markers(in)
	want := []string{
		string(nodestate.MarkerOffline),
		string(nodestate.MarkerOutdated),
		string(nodestate.MarkerCertExpiring),
		string(nodestate.MarkerTemplateUnloadable),
	}
	if len(markers) != len(want) {
		t.Fatalf("Markers(in) = %+v, want %d markers in order %v", markers, len(want), want)
	}
	for i, k := range want {
		if markers[i].Key != k {
			t.Errorf("Markers(in)[%d].Key = %q, want %q", i, markers[i].Key, k)
		}
	}
}

func TestMarkers_ACalmNodeHasNone(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:                 "n",
			Connected:              true,
			Outdated:               false,
			CertNotAfter:           testNow.Add(1000 * time.Hour),
			TemplateSetFingerprint: "abc123def456",
		},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	if markers := nodestate.Markers(in); len(markers) != 0 {
		t.Errorf("Markers(in) = %+v, want none — a calm Node's empty slice is the calmest and most common answer", markers)
	}
}

// --- Attention ---

func TestAttention_IsTheAmberRollup(t *testing.T) {
	cases := []struct {
		name string
		node registry.Node
		want bool
	}{
		{"offline alone", registry.Node{NodeID: "n", Connected: false}, true},
		{"outdated alone", registry.Node{NodeID: "n", Connected: true, Outdated: true}, true},
		{"cert-expiring alone", registry.Node{NodeID: "n", Connected: true, CertNotAfter: testNow.Add(1 * time.Hour)}, true},
		{"template-unloadable alone", registry.Node{NodeID: "n", Connected: true, TemplateSetFingerprint: nodestate.TemplateUnloadable}, false},
		{"a calm Node", registry.Node{NodeID: "n", Connected: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := nodestate.Input{Node: c.node, Now: testNow, CertExpiringWithin: 2 * time.Hour}
			if got := nodestate.Attention(in); got != c.want {
				t.Errorf("Attention(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// --- Facts omission ---

func TestFacts_OmitsAnEmptyValue(t *testing.T) {
	cases := []struct {
		name       string
		node       registry.Node
		absentKey  string
		wantOthers []string
	}{
		{
			name:       "DaemonVersion empty",
			node:       registry.Node{NodeID: "n", PolicyFingerprint: "abc123", TemplateSetFingerprint: "def456"},
			absentKey:  string(nodestate.FactDaemonVersion),
			wantOthers: []string{string(nodestate.FactPolicyFingerprint), string(nodestate.FactTemplateFingerprint)},
		},
		{
			name:       "PolicyFingerprint empty",
			node:       registry.Node{NodeID: "n", DaemonVersion: "1.4.2", TemplateSetFingerprint: "def456"},
			absentKey:  string(nodestate.FactPolicyFingerprint),
			wantOthers: []string{string(nodestate.FactDaemonVersion), string(nodestate.FactTemplateFingerprint)},
		},
		{
			name:       "TemplateSetFingerprint empty",
			node:       registry.Node{NodeID: "n", DaemonVersion: "1.4.2", PolicyFingerprint: "abc123"},
			absentKey:  string(nodestate.FactTemplateFingerprint),
			wantOthers: []string{string(nodestate.FactDaemonVersion), string(nodestate.FactPolicyFingerprint)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := nodestate.Facts(nodestate.Input{Node: c.node, Now: testNow})
			for _, l := range facts {
				if l.Key == c.absentKey {
					t.Errorf("Facts emitted %q for a field left empty", l.Key)
				}
			}
			for _, want := range c.wantOthers {
				found := false
				for _, l := range facts {
					if l.Key == want {
						found = true
					}
				}
				if !found {
					t.Errorf("Facts omitted %q, which was well-formed", want)
				}
			}
		})
	}
}

// Whether nodestate.Facts (nodestate.go:255) renders the unloadable sentinel
// as state:template-fingerprint=unloadable is deliberately untested here:
// ADR-0034 (line 50) says that key carries "the template-set fingerprint, or
// the literal `unloadable`", but Facts today excludes the sentinel. That is a
// disagreement between the code and the ADR, not settled behaviour, and it is
// escalated on issue #470 for a human to resolve — this package neither
// enforces nor contradicts either side.

func TestFacts_EmitsAllThreeWhenWellFormed(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:                 "n",
			DaemonVersion:          "1.4.2",
			PolicyFingerprint:      "abc123",
			TemplateSetFingerprint: "def456",
		},
		Now: testNow,
	}
	facts := nodestate.Facts(in)
	wantKeys := []string{string(nodestate.FactDaemonVersion), string(nodestate.FactPolicyFingerprint), string(nodestate.FactTemplateFingerprint)}
	wantValues := []string{"1.4.2", "abc123", "def456"}
	if len(facts) != len(wantKeys) {
		t.Fatalf("Facts(in) = %+v, want %d facts", facts, len(wantKeys))
	}
	for i := range wantKeys {
		if facts[i].Key != wantKeys[i] {
			t.Errorf("Facts(in)[%d].Key = %q, want %q", i, facts[i].Key, wantKeys[i])
		}
		if facts[i].Value != wantValues[i] {
			t.Errorf("Facts(in)[%d].Value = %q, want %q", i, facts[i].Value, wantValues[i])
		}
	}
}

// --- Labels composition ---

func TestLabels_AreMarkersThenFacts(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:            "n",
			Connected:         false,
			DaemonVersion:     "1.4.2",
			PolicyFingerprint: "abc123",
		},
		Now: testNow,
	}
	labels := nodestate.Labels(in)
	want := append(nodestate.Markers(in), nodestate.Facts(in)...)
	if len(labels) != len(want) {
		t.Fatalf("Labels(in) has %d entries, want %d (Markers then Facts)", len(labels), len(want))
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Errorf("Labels(in)[%d] = %+v, want %+v", i, labels[i], want[i])
		}
	}
}

// --- Label.String ---

func TestLabel_StringRendersSelectorSyntax(t *testing.T) {
	marker := nodestate.Label{Key: string(nodestate.MarkerOffline)}
	if got, want := marker.String(), "state:offline"; got != want {
		t.Errorf("marker.String() = %q, want %q", got, want)
	}
	fact := nodestate.Label{Key: string(nodestate.FactPolicyFingerprint), Value: "4b18c02"}
	if got, want := fact.String(), "state:policy-fingerprint=4b18c02"; got != want {
		t.Errorf("fact.String() = %q, want %q", got, want)
	}
}

// --- CertExpiringWindow ---

// TestCertExpiringWindow_IsAFractionOfTheLifetime names ADR-0034's threshold:
// 25% of a 336h leaf lifetime is an 84h warning window. This package never
// imports internal/ca (see the package doc's import note), so the lifetime is
// a literal here rather than a reference to ca.LeafValidity.
func TestCertExpiringWindow_IsAFractionOfTheLifetime(t *testing.T) {
	const leafValidity = 336 * time.Hour
	got := nodestate.CertExpiringWindow(leafValidity, nodestate.DefaultCertExpiringFraction)
	if want := 84 * time.Hour; got != want {
		t.Errorf("CertExpiringWindow(336h, DefaultCertExpiringFraction) = %v, want %v", got, want)
	}
}

// --- CertExpiryKnown ---

func TestCertExpiryKnown_FollowsTheRecordedProvenance(t *testing.T) {
	if nodestate.CertExpiryKnown(registry.Node{NodeID: "n"}) {
		t.Error("CertExpiryKnown was true for a zero CertNotAfter")
	}
	if !nodestate.CertExpiryKnown(registry.Node{NodeID: "n", CertNotAfter: testNow}) {
		t.Error("CertExpiryKnown was false once CertNotAfter was recorded")
	}
}

// --- Quarantined ---

func TestQuarantined_NeedsTheKeyAndTheValue(t *testing.T) {
	on := registry.Node{NodeID: "n", RelayLabels: map[string]string{registry.QuarantineKey: registry.QuarantineOn}}
	if !nodestate.Quarantined(on) {
		t.Error("Quarantined was false for relay:quarantine=on")
	}
	off := registry.Node{NodeID: "n", RelayLabels: map[string]string{registry.QuarantineKey: "off"}}
	if nodestate.Quarantined(off) {
		t.Error("Quarantined was true for relay:quarantine=off")
	}
	absent := registry.Node{NodeID: "n"}
	if nodestate.Quarantined(absent) {
		t.Error("Quarantined was true with no relay:quarantine label at all")
	}

	// This only proves what Labels(in) actually returns: no Label carries the
	// key registry.QuarantineKey ("quarantine"). It does not claim that no
	// quarantine state: Label may ever exist — GLOSSARY.md:285 describes
	// `state:quarantined` as Relay-derived and read-only, which disagrees
	// with nodestate.go's Quarantined doc comment (nodestate.go:444-461)
	// here. That disagreement is escalated to a human (AGENTS.md, "When
	// documents and the code disagree") and is not settled by this test in
	// either direction.
	in := nodestate.Input{Node: on, Now: testNow}
	for _, l := range nodestate.Labels(in) {
		if l.Key == registry.QuarantineKey {
			t.Errorf("Labels(in) carried a %q key", l.Key)
		}
	}
}

// --- LabelSet ---

// TestLabelSet_CarriesEveryMarkerAndFact is TestLabelSet_IsLabelsReduced's
// sibling, pinning the exact shape rather than only the reduction property.
//
// TemplateSetFingerprint drives both MarkerTemplateUnloadable and
// FactTemplateFingerprint from the SAME field (nodestate.go:205, :255), so
// this Node's sentinel value exercises the field that couples them. Whether
// the sentinel also renders as a state:template-fingerprint fact is disputed
// (see the comment above TestFacts_EmitsAllThreeWhenWellFormed) — this test
// asserts the four markers and the two undisputed facts (daemon-version,
// policy-fingerprint) are present, not an exact entry count, and takes no
// position on that fact's presence either way.
func TestLabelSet_CarriesEveryMarkerAndFact(t *testing.T) {
	in := nodestate.Input{
		Node: registry.Node{
			NodeID:                 "n",
			Connected:              false,
			Outdated:               true,
			CertNotAfter:           testNow.Add(1 * time.Hour),
			TemplateSetFingerprint: nodestate.TemplateUnloadable,
			DaemonVersion:          "1.4.2",
			PolicyFingerprint:      "abc123",
		},
		Now:                testNow,
		CertExpiringWithin: 2 * time.Hour,
	}
	labels := nodestate.Labels(in)
	set := nodestate.LabelSet(in)
	if len(set) != len(labels) {
		t.Fatalf("LabelSet has %d entries, Labels has %d — they must be the same shape", len(set), len(labels))
	}
	for _, l := range labels {
		v, ok := set[l.Key]
		if !ok {
			t.Errorf("LabelSet is missing key %q, present in Labels", l.Key)
			continue
		}
		if v != l.Value {
			t.Errorf("LabelSet[%q] = %q, want %q (from Labels)", l.Key, v, l.Value)
		}
	}

	wantPresent := map[string]string{
		string(nodestate.MarkerOffline):            "",
		string(nodestate.MarkerOutdated):           "",
		string(nodestate.MarkerCertExpiring):       "",
		string(nodestate.MarkerTemplateUnloadable): "",
		string(nodestate.FactDaemonVersion):        "1.4.2",
		string(nodestate.FactPolicyFingerprint):    "abc123",
	}
	for k, want := range wantPresent {
		v, ok := set[k]
		if !ok {
			t.Errorf("LabelSet is missing key %q", k)
			continue
		}
		if v != want {
			t.Errorf("LabelSet[%q] = %q, want %q", k, v, want)
		}
	}
}

// Since (nodestate.go:466) and Until (nodestate.go:492) are the package's
// only other exported functions, and neither has a test in this file,
// deliberately: they are duration-rendering helpers, not state markers or
// facts, and they are already exercised through the Console's fleet and
// compare screens.
