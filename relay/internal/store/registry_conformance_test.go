package store

import (
	"maps"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry/registrytest"
)

// TestSQLiteRegistryConformance runs the shared registry.Repository
// conformance suite against sqliteRegistry — the same suite
// registry.TestRepositoryConformance runs against InMemory, proving the
// production store and the fake every other package tests against behave
// alike.
func TestSQLiteRegistryConformance(t *testing.T) {
	registrytest.RunRepositoryConformance(t, func(t *testing.T, cfg registrytest.Config) registry.Repository {
		st, _ := openTestStore(t, WithMaxNodes(cfg.MaxNodes), WithMinDaemonVersion(cfg.MinDaemonVersion))
		return st.Registry()
	})
}

// TestRegistryNodeLabelConformance is the node-space-label half of the shared
// conformance suite, run against BOTH implementations from here rather than
// from registrytest: those cases need a Report carrying node labels, and the
// only way to build one is Report.WithNodeLabels, which
// protoconv.TestReportNodeLabelsHasTwoWriters forbids in any non-test file
// beyond its two production writers (#504). A _test.go file is where the
// guard expects test-only callers, and this package is the one place that
// can construct both implementations.
func TestRegistryNodeLabelConformance(t *testing.T) {
	impls := []struct {
		name string
		new  func(t *testing.T) registry.Repository
	}{
		{"InMemory", func(t *testing.T) registry.Repository { return registry.NewInMemory() }},
		{"SQLite", func(t *testing.T) registry.Repository {
			st, _ := openTestStore(t)
			return st.Registry()
		}},
	}

	labelled := func(nodeID string, labels map[string]string) registry.Report {
		return registry.Report{NodeID: nodeID, CertFingerprint: "fp-" + nodeID}.WithNodeLabels(labels)
	}
	upsert := func(t *testing.T, r registry.Repository, rep registry.Report) registry.Node {
		t.Helper()
		n, err := r.Upsert(rep)
		if err != nil {
			t.Fatalf("Upsert %q: %v", rep.NodeID, err)
		}
		return n
	}
	get := func(t *testing.T, r registry.Repository, id string) registry.Node {
		t.Helper()
		n, ok := r.Get(id)
		if !ok {
			t.Fatalf("Get %q: not found", id)
		}
		return n
	}
	setRelay := func(t *testing.T, r registry.Repository, id string, labels map[string]string) {
		t.Helper()
		if err := r.SetRelayLabels(id, labels); err != nil {
			t.Fatalf("SetRelayLabels %q: %v", id, err)
		}
	}

	for _, impl := range impls {
		t.Run(impl.name, func(t *testing.T) {
			t.Run("InsertStoresTheReportedSet", func(t *testing.T) {
				r := impl.new(t)
				n := upsert(t, r, labelled("node-a", map[string]string{"role": "web", "env": "staging"}))
				want := map[string]string{"role": "web", "env": "staging"}
				if !maps.Equal(n.NodeLabels, want) || !maps.Equal(get(t, r, "node-a").NodeLabels, want) {
					t.Errorf("NodeLabels = %v (Upsert) / %v (Get), want %v", n.NodeLabels, get(t, r, "node-a").NodeLabels, want)
				}
			})

			t.Run("UpdateReplacesTheSetWholesale", func(t *testing.T) {
				r := impl.new(t)
				upsert(t, r, labelled("node-a", map[string]string{"role": "web", "env": "staging"}))
				n := upsert(t, r, labelled("node-a", map[string]string{"env": "prod"}))
				want := map[string]string{"env": "prod"}
				if !maps.Equal(n.NodeLabels, want) || !maps.Equal(get(t, r, "node-a").NodeLabels, want) {
					t.Errorf("NodeLabels after update = %v, want %v — a report replaces, never merges", n.NodeLabels, want)
				}
				// A report with no labels clears the set to an empty map.
				n = upsert(t, r, registry.Report{NodeID: "node-a"})
				if n.NodeLabels == nil || len(n.NodeLabels) != 0 {
					t.Errorf("NodeLabels after an unlabelled update = %#v, want a non-nil empty map", n.NodeLabels)
				}
			})

			t.Run("RelayLabelsSurviveTheNodesReport", func(t *testing.T) {
				// The Node reports a node: label under the same bare key as a
				// relay: label. The two namespaces are disjoint maps; neither
				// may reach the other (invariant 7).
				r := impl.new(t)
				upsert(t, r, labelled("node-a", map[string]string{"role": "web"}))
				setRelay(t, r, "node-a", map[string]string{"role": "relay-owned", registry.QuarantineKey: registry.QuarantineOn})
				n := upsert(t, r, labelled("node-a", map[string]string{"role": "db", registry.QuarantineKey: "off"}))
				if n.NodeLabels["role"] != "db" || n.RelayLabels["role"] != "relay-owned" || !n.Quarantined() {
					t.Errorf("after the Node's report: node:%v relay:%v, want node role=db and relay role=relay-owned, quarantined",
						n.NodeLabels, n.RelayLabels)
				}
			})

			t.Run("NodeLabelsSurviveARelaySet", func(t *testing.T) {
				r := impl.new(t)
				upsert(t, r, labelled("node-a", map[string]string{"role": "web"}))
				setRelay(t, r, "node-a", map[string]string{"role": "relay-owned"})
				setRelay(t, r, "node-a", nil)
				if got := get(t, r, "node-a").NodeLabels; !maps.Equal(got, map[string]string{"role": "web"}) {
					t.Errorf("NodeLabels = %v, want {role:web} untouched by SetRelayLabels", got)
				}
			})

			t.Run("AreIndependentAcrossNodes", func(t *testing.T) {
				r := impl.new(t)
				upsert(t, r, labelled("node-a", map[string]string{"role": "web"}))
				upsert(t, r, labelled("node-b", map[string]string{"role": "db"}))
				upsert(t, r, labelled("node-a", map[string]string{"role": "cache"}))
				if got := get(t, r, "node-b").NodeLabels; !maps.Equal(got, map[string]string{"role": "db"}) {
					t.Errorf("node-b NodeLabels = %v, want {role:db} — a report from node-a leaked", got)
				}
			})

			t.Run("InputAndOutputMapsAreNotShared", func(t *testing.T) {
				r := impl.new(t)
				in := map[string]string{"role": "web"}
				upsert(t, r, labelled("node-a", in))
				in["role"] = "mutated"
				out := get(t, r, "node-a")
				out.NodeLabels["role"] = "mutated-out"
				for _, l := range r.List() {
					l.NodeLabels["injected"] = "x"
				}
				if got := get(t, r, "node-a").NodeLabels; !maps.Equal(got, map[string]string{"role": "web"}) {
					t.Errorf("NodeLabels = %v — a caller mutated stored node labels through an input or returned map", got)
				}
			})

			t.Run("MalformedStoredLabelIsDeclinedOnEveryRead", func(t *testing.T) {
				// The node-space half of registrytest's relay-space case:
				// "decline to serve, never write" (#504). WithNodeLabels
				// documents that its input must already be well-formed, so
				// this is input no production caller sends — it stands for a
				// row written before #504's ingress gate existed.
				r := impl.new(t)
				const bad = "web, relay:quarantine=on" // fails registry.WellFormedLabel
				upserted := upsert(t, r, labelled("node-a", map[string]string{"role": bad, "ok": "fine"}))
				var listed registry.Node
				if l := r.List(); len(l) == 1 {
					listed = l[0]
				} else {
					t.Fatalf("List returned %d Nodes, want 1", len(l))
				}
				for _, n := range []struct {
					via string
					n   registry.Node
				}{{"Get", get(t, r, "node-a")}, {"List", listed}, {"Upsert", upserted}} {
					if v, served := n.n.NodeLabels["role"]; served {
						t.Errorf("%s: malformed node:role=%q was served; a label WellFormedLabel refuses is declined on read", n.via, v)
					}
					// Declining is per pair, never per Node.
					if n.n.NodeLabels["ok"] != "fine" {
						t.Errorf("%s: a well-formed label beside a malformed one was not served: %v", n.via, n.n.NodeLabels)
					}
				}
			})
		})
	}
}

// The two halves below need a store reopen, which the shared suite cannot
// express through registry.Repository: they are what "persisted" and "never
// persisted" mean for the provenance and connectedness the suite covers.

// TestSQLiteRegistry_ProvenanceSurvivesARestart — certificate provenance is
// Relay-knowledge with no other source: a restart that lost it would turn
// every Node's expiry into "not recorded" until its next renewal, blinding
// state:cert-expiring for up to a leaf lifetime.
func TestSQLiteRegistry_ProvenanceSurvivesARestart(t *testing.T) {
	st, path := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", CertFingerprint: "fp-1", EnrollingTokenID: "tok-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	joined := time.Date(2026, 1, 1, 9, 0, 0, 123456789, time.UTC)
	renewed := joined.Add(10 * 24 * time.Hour)
	notAfter := renewed.Add(14 * 24 * time.Hour)
	if err := reg.RecordEnrollment("node-a", registry.Certificate{NotAfter: joined.Add(time.Hour)}, joined); err != nil {
		t.Fatalf("RecordEnrollment: %v", err)
	}
	if err := reg.RecordRenewal("node-a", registry.Certificate{NotAfter: notAfter}, renewed); err != nil {
		t.Fatalf("RecordRenewal: %v", err)
	}

	n, ok := reopenStore(t, st, path).Registry().Get("node-a")
	if !ok {
		t.Fatal("Get after reopen: not found")
	}
	if !n.EnrolledAt.Equal(joined) || !n.CertNotAfter.Equal(notAfter) ||
		n.RenewalCount != 1 || !n.LastRenewedAt.Equal(renewed) || n.EnrollingTokenID != "tok-1" {
		t.Errorf("provenance after reopen = EnrolledAt %v, CertNotAfter %v, RenewalCount %d, LastRenewedAt %v, token %q; "+
			"want %v, %v, 1, %v, tok-1", n.EnrolledAt, n.CertNotAfter, n.RenewalCount, n.LastRenewedAt,
			n.EnrollingTokenID, joined, notAfter, renewed)
	}
}

// TestSQLiteRegistry_ConnectedDoesNotSurviveARestart — connectedness must not
// outlive the process that observed it. A `connected = true` that survived a
// Relay crash would render as a green dot for a Node nothing can reach; after
// a restart the honest answer is "nothing is connected" until each Node dials
// back in (registry.Node.Connected, migration 0020).
func TestSQLiteRegistry_ConnectedDoesNotSurviveARestart(t *testing.T) {
	st, path := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	reg.SetConnected("node-a", true)
	if n, _ := reg.Get("node-a"); !n.Connected {
		t.Fatal("precondition: Node does not read as connected before the restart")
	}

	n, ok := reopenStore(t, st, path).Registry().Get("node-a")
	if !ok {
		t.Fatal("Get after reopen: not found")
	}
	if n.Connected {
		t.Error("a Node reads as connected after a Relay restart — connectedness was persisted")
	}
}

// reopenStore closes st and opens a fresh Store over the same path — a Relay
// restart, as far as the registry can tell.
func reopenStore(t *testing.T, st *Store, path string) *Store {
	t.Helper()
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	re, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { re.Close() }) //nolint:errcheck
	return re
}
