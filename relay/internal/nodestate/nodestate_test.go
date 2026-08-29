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
	for _, v := range hostile {
		in := nodestate.Input{Node: registry.Node{NodeID: "n", DaemonVersion: v}, Now: testNow}
		for _, l := range nodestate.Facts(in) {
			if l.Key == string(nodestate.FactDaemonVersion) {
				t.Errorf("Facts emitted state:daemon-version=%q from hostile value %q", l.Value, v)
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
