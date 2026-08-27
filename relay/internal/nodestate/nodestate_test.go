package nodestate_test

import (
	"strings"
	"testing"
	"time"

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
