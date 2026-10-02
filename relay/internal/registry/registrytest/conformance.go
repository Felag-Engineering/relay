// Package registrytest holds the shared conformance suite for
// registry.Repository, run against both the registry package's own InMemory
// implementation and internal/store's sqliteRegistry.
//
// It exists because the two are written by hand to the same contract — the
// store's doc says it mirrors InMemory "exactly" — and every package that
// tests against the in-memory fake is trusting that claim on the production
// store's behalf. A case added here is proven against both at once, so the
// fake cannot quietly drift from what the Relay actually runs.
//
// It is a regular package, not a _test.go file, on the accountstest
// precedent: sqliteRegistry is unexported and reachable only through
// store.Open, so the harness has to live where both test packages can import
// it, taking a fresh registry.Repository from each caller rather than
// constructing one itself.
//
// Out of scope here, deliberately: how either implementation behaves when its
// backing store FAILS. That is the store's own concern and is tested there.
// Every case below drives the Repository only through its interface.
//
// Also not here: any case that needs a Report CARRYING node-space labels.
// Being a regular package, this file is inside the tree that
// protoconv.TestReportNodeLabelsHasTwoWriters walks, and that guard pins
// exactly two non-test callers of Report.WithNodeLabels (#504). This package
// does not become a third, and does not route around the guard either: the
// node-label cases run against both implementations from
// store.TestRegistryNodeLabelConformance, a _test.go file, which is where the
// guard expects test-only writers to be.
package registrytest

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Config is what a Factory builds a fresh Repository with. Each field mirrors
// an option both implementations accept (registry.WithMaxNodes /
// store.WithMaxNodes, and the WithMinDaemonVersion pair).
type Config struct {
	// MaxNodes caps INSERTs; 0 means unlimited.
	MaxNodes int
	// MinDaemonVersion is the ADR-0014 gate; "" means off.
	MinDaemonVersion string
}

// Factory returns a fresh, empty Repository built with cfg. It is called once
// per subtest; any cleanup belongs on t.
type Factory func(t *testing.T, cfg Config) registry.Repository

// Divergences declares, per implementation, the behaviours on which the two
// implementations are KNOWN to disagree. The suite does not paper over a
// disagreement: each field selects which side of a named subtest's assertion
// this implementation is held to, so both behaviours stay pinned and a change
// on either side fails here until somebody decides which one is right.
//
// A field here is a record of an open question, not a licence. Removing one
// is the goal; adding one needs the same escalation its doc names.
type Divergences struct {
	// ServesMalformedStoredLabels is true when a label that fails
	// registry.WellFormedLabel, once stored, is served back on read.
	//
	// sqliteRegistry declines to serve it (store.wellFormedLabels, #504/#555:
	// "decline to serve, never write"); InMemory stores and serves whatever it
	// was given. selectors-and-labels.md ("Labels the store declines to serve")
	// states the declining behaviour as intended, but that spec is still
	// aspirational, so it does not yet bind either implementation.
	ServesMalformedStoredLabels bool
}

// RunRepositoryConformance exercises the registry.Repository contract against
// a fresh Repository per subtest, built by newRepo. div declares the known
// divergences of the implementation under test (see Divergences).
func RunRepositoryConformance(t *testing.T, newRepo Factory, div Divergences) {
	t.Helper()

	fresh := func(t *testing.T) registry.Repository {
		t.Helper()
		return newRepo(t, Config{})
	}

	// ----------------------------------------------------------------
	// Upsert
	// ----------------------------------------------------------------

	t.Run("Upsert_EmptyNodeIDIsRefused", func(t *testing.T) {
		r := fresh(t)
		if _, err := r.Upsert(registry.Report{CertFingerprint: "fp"}); !errors.Is(err, registry.ErrEmptyNodeID) {
			t.Fatalf("Upsert with empty NodeID: err = %v, want ErrEmptyNodeID", err)
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("a refused Upsert left %d Nodes behind", len(got))
		}
	})

	t.Run("Upsert_InsertStoresEveryReportField", func(t *testing.T) {
		r := fresh(t)
		before := time.Now()
		n, err := r.Upsert(fullReport("node-a"))
		after := time.Now()
		if err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		checkFullReport(t, "Upsert result", n)
		if n.LastSeen.Before(before) || n.LastSeen.After(after) {
			t.Errorf("LastSeen = %v, want the insert time (between %v and %v)", n.LastSeen, before, after)
		}
		if n.RelayLabels == nil || len(n.RelayLabels) != 0 {
			t.Errorf("RelayLabels = %#v, want a non-nil empty map — a Report cannot carry relay: labels", n.RelayLabels)
		}
		if !n.RevokedAt.IsZero() || n.Connected || n.Outdated {
			t.Errorf("fresh Node: RevokedAt=%v Connected=%v Outdated=%v, want zero/false/false",
				n.RevokedAt, n.Connected, n.Outdated)
		}
		if n.CertProvenanceKnown() || !n.EnrolledAt.IsZero() || n.RenewalCount != 0 || !n.LastRenewedAt.IsZero() {
			t.Errorf("fresh Node carries certificate provenance it was never given: %+v", n)
		}

		got, ok := r.Get("node-a")
		if !ok {
			t.Fatal("Get after insert: not found")
		}
		checkFullReport(t, "Get", got)
		if !got.LastSeen.Equal(n.LastSeen) {
			t.Errorf("Get LastSeen = %v, Upsert returned %v — the result must be what was stored", got.LastSeen, n.LastSeen)
		}
	})

	t.Run("Upsert_UpdateOverwritesNodeRootedFields", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))

		n, err := r.Upsert(registry.Report{
			NodeID:                 "node-a",
			CertFingerprint:        "fp-new",
			Facts:                  registry.Facts{Hostname: "host-new", OS: "linux", Kernel: "6.9", Arch: "arm64"},
			EnrollingTokenID:       "tok-ignored",
			PolicyFingerprint:      "policy-new",
			DaemonVersion:          "2.0.0",
			TemplateSetFingerprint: "tmpl-new",
		})
		if err != nil {
			t.Fatalf("update Upsert: %v", err)
		}
		for _, got := range []registry.Node{n, mustGet(t, r, "node-a")} {
			if got.CertFingerprint != "fp-new" || got.PolicyFingerprint != "policy-new" ||
				got.DaemonVersion != "2.0.0" || got.TemplateSetFingerprint != "tmpl-new" {
				t.Errorf("update did not refresh the reported fields: %+v", got)
			}
			wantFacts := registry.Facts{Hostname: "host-new", OS: "linux", Kernel: "6.9", Arch: "arm64"}
			if !factsEqual(got.Facts, wantFacts) {
				t.Errorf("Facts = %+v, want a full replace to %+v", got.Facts, wantFacts)
			}
		}
		if got := r.List(); len(got) != 1 {
			t.Errorf("an update Upsert produced %d Nodes, want 1", len(got))
		}
	})

	t.Run("Upsert_UpdatePreservesRelayKnowledge", func(t *testing.T) {
		// Everything here is Relay-set and Node-immutable: a reconnecting
		// Hello must not be able to rewrite provenance, lift a revocation,
		// overwrite relay: labels, or reset certificate history.
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))
		revokedAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
		enrolledAt := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
		renewedAt := enrolledAt.Add(10 * 24 * time.Hour)
		notAfter := renewedAt.Add(14 * 24 * time.Hour)
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{registry.QuarantineKey: registry.QuarantineOn}))
		mustNil(t, "SetRevoked", r.SetRevoked("node-a", revokedAt))
		mustNil(t, "RecordEnrollment", r.RecordEnrollment("node-a", registry.Certificate{NotAfter: enrolledAt.Add(time.Hour)}, enrolledAt))
		mustNil(t, "RecordRenewal", r.RecordRenewal("node-a", registry.Certificate{NotAfter: notAfter}, renewedAt))

		n, err := r.Upsert(registry.Report{NodeID: "node-a", CertFingerprint: "fp-2", EnrollingTokenID: "tok-forged"})
		if err != nil {
			t.Fatalf("update Upsert: %v", err)
		}
		for _, got := range []registry.Node{n, mustGet(t, r, "node-a")} {
			if got.EnrollingTokenID != "tok-1" {
				t.Errorf("EnrollingTokenID = %q, want tok-1 — provenance is set once, at first enrollment", got.EnrollingTokenID)
			}
			if !got.Quarantined() || len(got.RelayLabels) != 1 {
				t.Errorf("RelayLabels = %v, want the quarantine to survive the Node's own report", got.RelayLabels)
			}
			if !got.RevokedAt.Equal(revokedAt) {
				t.Errorf("RevokedAt = %v, want %v — a Hello must not un-revoke", got.RevokedAt, revokedAt)
			}
			if !got.EnrolledAt.Equal(enrolledAt) || !got.CertNotAfter.Equal(notAfter) ||
				got.RenewalCount != 1 || !got.LastRenewedAt.Equal(renewedAt) {
				t.Errorf("certificate provenance changed under a Hello: %+v", got)
			}
		}
	})

	t.Run("Upsert_NilNodeLabelsReadBackAsEmptyMap", func(t *testing.T) {
		r := fresh(t)
		n := mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		if n.NodeLabels == nil || len(n.NodeLabels) != 0 {
			t.Errorf("insert NodeLabels = %#v, want a non-nil empty map", n.NodeLabels)
		}
		n = mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		if n.NodeLabels == nil || len(n.NodeLabels) != 0 {
			t.Errorf("update NodeLabels = %#v, want a non-nil empty map", n.NodeLabels)
		}
		if got := mustGet(t, r, "node-a"); got.NodeLabels == nil || len(got.NodeLabels) != 0 {
			t.Errorf("Get NodeLabels = %#v, want a non-nil empty map", got.NodeLabels)
		}
	})

	t.Run("Upsert_IPAddressesKeepNilVersusEmpty", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "nil-ips"})
		mustUpsert(t, r, registry.Report{NodeID: "empty-ips", Facts: registry.Facts{IPAddresses: []string{}}})
		if got := mustGet(t, r, "nil-ips").Facts.IPAddresses; got != nil {
			t.Errorf("nil IPAddresses read back as %#v, want nil", got)
		}
		if got := mustGet(t, r, "empty-ips").Facts.IPAddresses; got == nil || len(got) != 0 {
			t.Errorf("empty IPAddresses read back as %#v, want a non-nil empty slice", got)
		}
	})

	t.Run("Upsert_AtCapacityRefusesInsertsButNeverUpdates", func(t *testing.T) {
		r := newRepo(t, Config{MaxNodes: 2})
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		mustUpsert(t, r, registry.Report{NodeID: "node-b"})

		if _, err := r.Upsert(registry.Report{NodeID: "node-c"}); !errors.Is(err, registry.ErrAtCapacity) {
			t.Fatalf("third insert: err = %v, want ErrAtCapacity", err)
		}
		if _, ok := r.Get("node-c"); ok {
			t.Error("a refused insert left a Node behind")
		}
		// Reconnects and Hello Upserts must never be throttled by the cap.
		n, err := r.Upsert(registry.Report{NodeID: "node-a", CertFingerprint: "fp-reconnect"})
		if err != nil {
			t.Fatalf("update at capacity: %v", err)
		}
		if n.CertFingerprint != "fp-reconnect" {
			t.Errorf("update at capacity: CertFingerprint = %q, want fp-reconnect", n.CertFingerprint)
		}
		if total, _, err := r.Count(); err != nil || total != 2 {
			t.Errorf("Count = %d, %v; want 2, nil", total, err)
		}
	})

	t.Run("Upsert_ZeroMaxNodesIsUnbounded", func(t *testing.T) {
		r := fresh(t)
		for _, id := range []string{"n1", "n2", "n3", "n4", "n5"} {
			mustUpsert(t, r, registry.Report{NodeID: id})
		}
		if got := len(r.List()); got != 5 {
			t.Errorf("List has %d Nodes, want 5", got)
		}
	})

	// ----------------------------------------------------------------
	// UpdateLastSeen
	// ----------------------------------------------------------------

	t.Run("UpdateLastSeen_RoundTripsAndTouchesNothingElse", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))
		at := time.Date(2026, 5, 4, 3, 2, 1, 123456789, time.UTC)
		mustNil(t, "UpdateLastSeen", r.UpdateLastSeen("node-a", at))

		got := mustGet(t, r, "node-a")
		if !got.LastSeen.Equal(at) {
			t.Errorf("LastSeen = %v, want %v (nanoseconds included)", got.LastSeen, at)
		}
		checkFullReport(t, "after UpdateLastSeen", got)
	})

	t.Run("UpdateLastSeen_NonUTCInstantIsTheSameInstant", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		at := time.Date(2026, 5, 4, 3, 2, 1, 0, time.FixedZone("UTC+5", 5*60*60))
		mustNil(t, "UpdateLastSeen", r.UpdateLastSeen("node-a", at))
		if got := mustGet(t, r, "node-a").LastSeen; !got.Equal(at) {
			t.Errorf("LastSeen = %v, want the same instant as %v", got, at)
		}
	})

	t.Run("UpdateLastSeen_UnknownNodeIsNotFound", func(t *testing.T) {
		r := fresh(t)
		if err := r.UpdateLastSeen("ghost", time.Now()); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		if _, ok := r.Get("ghost"); ok {
			t.Error("UpdateLastSeen on an unknown Node created it")
		}
	})

	// ----------------------------------------------------------------
	// SetRelayLabels and the label-authority boundary (invariant 7)
	// ----------------------------------------------------------------

	t.Run("SetRelayLabels_ReplacesNeverMerges", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"zone": "eu", "tier": "gold"}))
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"zone": "us"}))
		if got := mustGet(t, r, "node-a").RelayLabels; !maps.Equal(got, map[string]string{"zone": "us"}) {
			t.Errorf("RelayLabels = %v, want exactly {zone:us} — a partial set must replace, not merge", got)
		}
		for _, empty := range []map[string]string{{}, nil} {
			mustNil(t, "SetRelayLabels(empty)", r.SetRelayLabels("node-a", empty))
			got := mustGet(t, r, "node-a").RelayLabels
			if got == nil || len(got) != 0 {
				t.Errorf("after SetRelayLabels(%#v): RelayLabels = %#v, want a non-nil empty map", empty, got)
			}
		}
	})

	t.Run("SetRelayLabels_UnknownNodeIsNotFound", func(t *testing.T) {
		r := fresh(t)
		if err := r.SetRelayLabels("ghost", map[string]string{"a": "b"}); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		if _, ok := r.Get("ghost"); ok {
			t.Error("SetRelayLabels on an unknown Node created it")
		}
	})

	// Cases that need a Node to REPORT node-space labels are not here: they
	// live in the store package's test file (see the package doc).

	t.Run("LabelAuthority_RelaySetLeavesNodeRootedFieldsAlone", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"role": "relay-owned", "env": "x"}))
		checkFullReport(t, "after SetRelayLabels", mustGet(t, r, "node-a"))
	})

	t.Run("RelayLabels_AreIndependentAcrossNodes", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		mustUpsert(t, r, registry.Report{NodeID: "node-b"})
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"zone": "eu"}))

		if b := mustGet(t, r, "node-b"); b.RelayLabels == nil || len(b.RelayLabels) != 0 {
			t.Errorf("node-b relay labels = %#v, want an empty map — a write to node-a leaked", b.RelayLabels)
		}
	})

	t.Run("Divergence_MalformedStoredRelayLabelReadBack", func(t *testing.T) {
		// The two implementations disagree here; see
		// Divergences.ServesMalformedStoredLabels. Both sides are pinned so
		// neither can move silently. The node-space half of this case is in
		// the store package's test file.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		// "pci/1" fails registry.WellFormedLabel; "eu" passes.
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"tier": "pci/1", "zone": "eu"}))

		for _, n := range []struct {
			via string
			n   registry.Node
		}{{"Get", mustGet(t, r, "node-a")}, {"List", onlyNode(t, r.List())}} {
			if _, served := n.n.RelayLabels["tier"]; served != div.ServesMalformedStoredLabels {
				t.Errorf("%s: malformed relay:tier served=%v; this implementation declares ServesMalformedStoredLabels=%v",
					n.via, served, div.ServesMalformedStoredLabels)
			}
			// Either way, the well-formed neighbour is served: declining is
			// per pair, never per Node.
			if n.n.RelayLabels["zone"] != "eu" {
				t.Errorf("%s: a well-formed label beside a malformed one was not served: %v", n.via, n.n.RelayLabels)
			}
		}
	})

	// ----------------------------------------------------------------
	// Get and List
	// ----------------------------------------------------------------

	t.Run("Get_UnknownNodeIsNotFound", func(t *testing.T) {
		r := fresh(t)
		n, ok := r.Get("ghost")
		if ok {
			t.Fatal("Get on an empty registry reported found")
		}
		if n.NodeID != "" || n.NodeLabels != nil || n.RelayLabels != nil {
			t.Errorf("Get miss returned %+v, want the zero Node", n)
		}
	})

	t.Run("Get_ReturnsACopy", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, fullReport("node-a"))
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", map[string]string{"zone": "eu"}))

		n := mustGet(t, r, "node-a")
		n.NodeLabels["role"] = "mutated"
		n.RelayLabels[registry.QuarantineKey] = registry.QuarantineOn
		n.Facts.IPAddresses[0] = "6.6.6.6"
		for _, l := range r.List() {
			l.NodeLabels["injected"] = "x"
			l.RelayLabels["injected"] = "x"
		}

		again := mustGet(t, r, "node-a")
		checkFullReport(t, "after mutating returned copies", again)
		if !maps.Equal(again.RelayLabels, map[string]string{"zone": "eu"}) {
			t.Errorf("RelayLabels = %v — a caller mutated stored relay: labels through a returned value", again.RelayLabels)
		}
	})

	t.Run("SetRelayLabels_InputMapIsNotRetained", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		rl := map[string]string{"zone": "eu"}
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-a", rl))
		rl["zone"] = "mutated"
		rl[registry.QuarantineKey] = registry.QuarantineOn
		if got := mustGet(t, r, "node-a").RelayLabels; !maps.Equal(got, map[string]string{"zone": "eu"}) {
			t.Errorf("stored relay labels changed when the caller's input map did: %v", got)
		}
	})

	t.Run("List_EmptyRegistry", func(t *testing.T) {
		if got := fresh(t).List(); len(got) != 0 {
			t.Errorf("List on an empty registry = %v, want none", got)
		}
	})

	t.Run("List_ReturnsEveryNodeAndAgreesWithGet", func(t *testing.T) {
		// Ordering is unspecified by the interface, so compared as a set.
		r := fresh(t)
		ids := []string{"node-c", "node-a", "node-b"}
		for _, id := range ids {
			mustUpsert(t, r, fullReport(id))
		}
		mustNil(t, "SetRelayLabels", r.SetRelayLabels("node-b", map[string]string{"zone": "eu"}))
		r.SetConnected("node-c", true)

		list := r.List()
		var got []string
		for _, n := range list {
			got = append(got, n.NodeID)
			g := mustGet(t, r, n.NodeID)
			if !nodesEqual(n, g) {
				t.Errorf("List and Get disagree about %s:\nList %+v\nGet  %+v", n.NodeID, n, g)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, []string{"node-a", "node-b", "node-c"}) {
			t.Errorf("List IDs = %v, want node-a, node-b, node-c", got)
		}
	})

	// ----------------------------------------------------------------
	// Revocation
	// ----------------------------------------------------------------

	t.Run("SetRevoked_UnknownNodeIsNotFound", func(t *testing.T) {
		r := fresh(t)
		if err := r.SetRevoked("ghost", time.Now()); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		if ids, err := r.RevokedNodeIDs(); err != nil || len(ids) != 0 {
			t.Errorf("RevokedNodeIDs = %v, %v; want none", ids, err)
		}
	})

	t.Run("SetRevoked_RoundTripsAndFeedsRevokedNodeIDs", func(t *testing.T) {
		r := fresh(t)
		for _, id := range []string{"node-c", "node-a", "node-b"} {
			mustUpsert(t, r, fullReport(id))
		}
		if ids, err := r.RevokedNodeIDs(); err != nil || len(ids) != 0 {
			t.Fatalf("RevokedNodeIDs before any revoke = %v, %v; want none", ids, err)
		}
		at := time.Date(2026, 2, 3, 4, 5, 6, 7, time.UTC)
		mustNil(t, "SetRevoked c", r.SetRevoked("node-c", at))
		mustNil(t, "SetRevoked a", r.SetRevoked("node-a", at))

		ids, err := r.RevokedNodeIDs()
		if err != nil {
			t.Fatalf("RevokedNodeIDs: %v", err)
		}
		slices.Sort(ids)
		if !slices.Equal(ids, []string{"node-a", "node-c"}) {
			t.Errorf("RevokedNodeIDs = %v, want node-a, node-c", ids)
		}
		got := mustGet(t, r, "node-a")
		if !got.RevokedAt.Equal(at) {
			t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, at)
		}
		checkFullReport(t, "after SetRevoked", got)
		if b := mustGet(t, r, "node-b"); !b.RevokedAt.IsZero() {
			t.Errorf("node-b RevokedAt = %v — revoking one Node touched another", b.RevokedAt)
		}
	})

	t.Run("SetRevokedAll_WritesEveryPresentNodeAndReportsMissing", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		mustUpsert(t, r, registry.Report{NodeID: "node-b"})
		mustUpsert(t, r, registry.Report{NodeID: "node-untouched"})
		at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

		missing, err := r.SetRevokedAll([]string{"node-a", "ghost-1", "node-b", "ghost-2"}, at)
		if err != nil {
			t.Fatalf("SetRevokedAll: %v", err)
		}
		if !slices.Equal(missing, []string{"ghost-1", "ghost-2"}) {
			t.Errorf("missing = %v, want ghost-1, ghost-2 in input order", missing)
		}
		for _, id := range []string{"node-a", "node-b"} {
			if got := mustGet(t, r, id).RevokedAt; !got.Equal(at) {
				t.Errorf("%s RevokedAt = %v, want %v", id, got, at)
			}
		}
		if got := mustGet(t, r, "node-untouched").RevokedAt; !got.IsZero() {
			t.Errorf("a Node outside the batch was revoked at %v", got)
		}
		for _, ghost := range []string{"ghost-1", "ghost-2"} {
			if _, ok := r.Get(ghost); ok {
				t.Errorf("SetRevokedAll created a record for missing id %s", ghost)
			}
		}
	})

	t.Run("SetRevokedAll_NoneMissingIsNil", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		missing, err := r.SetRevokedAll([]string{"node-a"}, time.Now())
		if err != nil || missing != nil {
			t.Errorf("SetRevokedAll = %v, %v; want nil, nil", missing, err)
		}
	})

	t.Run("SetRevokedAll_EmptyIsANoOp", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		for _, ids := range [][]string{nil, {}} {
			missing, err := r.SetRevokedAll(ids, time.Now())
			if err != nil || missing != nil {
				t.Errorf("SetRevokedAll(%#v) = %v, %v; want nil, nil", ids, missing, err)
			}
		}
		if _, revoked, _ := r.Count(); revoked != 0 {
			t.Errorf("an empty batch revoked %d Nodes", revoked)
		}
	})

	t.Run("SetRevokedAll_BorrowsNodeIDsReadOnly", func(t *testing.T) {
		// nodeIDs is a read-only borrow, and missing never aliases it.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		backing := make([]string, 3, 8)
		copy(backing, []string{"ghost-1", "node-a", "ghost-2"})
		spare := backing[:cap(backing)]
		for i := 3; i < len(spare); i++ {
			spare[i] = "sentinel"
		}

		missing, err := r.SetRevokedAll(backing, time.Now())
		if err != nil {
			t.Fatalf("SetRevokedAll: %v", err)
		}
		if !slices.Equal(backing, []string{"ghost-1", "node-a", "ghost-2"}) {
			t.Errorf("nodeIDs modified in place: %v", backing)
		}
		for i := 3; i < len(spare); i++ {
			if spare[i] != "sentinel" {
				t.Errorf("nodeIDs' spare capacity written at %d: %q", i, spare[i])
			}
		}
		if len(missing) > 0 {
			missing[0] = "overwritten"
			if backing[0] != "ghost-1" {
				t.Error("missing aliases nodeIDs")
			}
		}
	})

	t.Run("SetRevoked_AndSetRevokedAllAgree", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "single"})
		mustUpsert(t, r, registry.Report{NodeID: "batched"})
		at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
		mustNil(t, "SetRevoked", r.SetRevoked("single", at))
		if _, err := r.SetRevokedAll([]string{"batched"}, at); err != nil {
			t.Fatalf("SetRevokedAll: %v", err)
		}
		s, b := mustGet(t, r, "single"), mustGet(t, r, "batched")
		if !s.RevokedAt.Equal(b.RevokedAt) || !s.RevokedAt.Equal(at) {
			t.Errorf("SetRevoked wrote %v, SetRevokedAll wrote %v; want both %v", s.RevokedAt, b.RevokedAt, at)
		}
	})

	t.Run("Count_TotalsAndRevoked", func(t *testing.T) {
		r := fresh(t)
		if total, revoked, err := r.Count(); err != nil || total != 0 || revoked != 0 {
			t.Fatalf("empty Count = %d, %d, %v; want 0, 0, nil", total, revoked, err)
		}
		for _, id := range []string{"a", "b", "c"} {
			mustUpsert(t, r, registry.Report{NodeID: id})
		}
		mustNil(t, "SetRevoked", r.SetRevoked("b", time.Now()))
		r.SetConnected("a", true) // connectedness is not a Node, and not counted as one
		if total, revoked, err := r.Count(); err != nil || total != 3 || revoked != 1 {
			t.Errorf("Count = %d, %d, %v; want 3, 1, nil", total, revoked, err)
		}
	})

	// ----------------------------------------------------------------
	// Outdated (ADR-0014): derived on read, never stored
	// ----------------------------------------------------------------

	t.Run("Outdated_NoMinimumIsNeverOutdated", func(t *testing.T) {
		r := fresh(t)
		for id, v := range map[string]string{"empty": "", "garbage": "not-a-version", "old": "0.0.1"} {
			if n := mustUpsert(t, r, registry.Report{NodeID: id, DaemonVersion: v}); n.Outdated {
				t.Errorf("%s (%q): Outdated with no minimum configured", id, v)
			}
		}
		for _, n := range r.List() {
			if n.Outdated {
				t.Errorf("List: %s Outdated with no minimum configured", n.NodeID)
			}
		}
	})

	t.Run("Outdated_DerivedAgainstTheConfiguredMinimum", func(t *testing.T) {
		r := newRepo(t, Config{MinDaemonVersion: "1.2.0"})
		cases := map[string]struct {
			version string
			want    bool
		}{
			"below":     {"1.1.9", true},
			"equal":     {"1.2.0", false},
			"above":     {"1.3.0", false},
			"v-prefix":  {"v1.2.0", false},
			"empty":     {"", true}, // fail closed
			"malformed": {"not-a-version", true},
		}
		for id, c := range cases {
			n := mustUpsert(t, r, registry.Report{NodeID: id, DaemonVersion: c.version})
			if n.Outdated != c.want {
				t.Errorf("Upsert %s (%q): Outdated = %v, want %v", id, c.version, n.Outdated, c.want)
			}
		}
		for _, n := range r.List() {
			if want := cases[n.NodeID].want; n.Outdated != want {
				t.Errorf("List %s: Outdated = %v, want %v", n.NodeID, n.Outdated, want)
			}
			if g := mustGet(t, r, n.NodeID); g.Outdated != cases[n.NodeID].want {
				t.Errorf("Get %s: Outdated = %v, want %v", n.NodeID, g.Outdated, cases[n.NodeID].want)
			}
		}

		// A reconnect reporting a new version re-derives on the next read.
		if n := mustUpsert(t, r, registry.Report{NodeID: "below", DaemonVersion: "1.2.1"}); n.Outdated {
			t.Error("an upgraded Node still reads as Outdated after its Hello")
		}
	})

	// ----------------------------------------------------------------
	// Certificate provenance (#440, ADR-0034)
	// ----------------------------------------------------------------

	t.Run("Provenance_EnrolledAtSurvivesEveryRenewal", func(t *testing.T) {
		// #440's central acceptance criterion, and the reason RecordEnrollment
		// and RecordRenewal are two methods rather than one with a flag.
		//
		// Renewal is certificate-authenticated and preserves node_id, so a
		// Node's join date anchors an unbroken chain back to the Enrollment
		// Token it joined with. A renewal that rewrote it would erase the
		// provenance the record exists for — and would do it silently, since
		// the value would still look perfectly plausible.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a", CertFingerprint: "fp-1"})

		joined := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
		firstExpiry := joined.Add(14 * 24 * time.Hour)
		if err := r.RecordEnrollment("node-a", registry.Certificate{Fingerprint: "fp-1", NotAfter: firstExpiry}, joined); err != nil {
			t.Fatalf("RecordEnrollment: %v", err)
		}

		n := mustGet(t, r, "node-a")
		if !n.EnrolledAt.Equal(joined) {
			t.Fatalf("EnrolledAt = %v, want %v", n.EnrolledAt, joined)
		}
		if !n.CertNotAfter.Equal(firstExpiry) {
			t.Errorf("CertNotAfter = %v, want %v", n.CertNotAfter, firstExpiry)
		}
		if n.RenewalCount != 0 {
			t.Errorf("a fresh enrollment has renewal count %d, want 0", n.RenewalCount)
		}
		if !n.LastRenewedAt.IsZero() {
			t.Errorf("a fresh enrollment has a renewal time %v — it has never renewed", n.LastRenewedAt)
		}

		for i := 1; i <= 3; i++ {
			at := joined.Add(time.Duration(i) * 10 * 24 * time.Hour)
			exp := at.Add(14 * 24 * time.Hour)
			if err := r.RecordRenewal("node-a", registry.Certificate{Fingerprint: "fp-1", NotAfter: exp}, at); err != nil {
				t.Fatalf("RecordRenewal %d: %v", i, err)
			}

			n := mustGet(t, r, "node-a")
			if !n.EnrolledAt.Equal(joined) {
				t.Fatalf("after renewal %d, EnrolledAt = %v, want the original %v — provenance did not survive",
					i, n.EnrolledAt, joined)
			}
			if n.RenewalCount != i {
				t.Errorf("after renewal %d, count = %d", i, n.RenewalCount)
			}
			if !n.LastRenewedAt.Equal(at) {
				t.Errorf("after renewal %d, LastRenewedAt = %v, want %v", i, n.LastRenewedAt, at)
			}
			if !n.CertNotAfter.Equal(exp) {
				t.Errorf("after renewal %d, CertNotAfter = %v, want %v", i, n.CertNotAfter, exp)
			}
		}
	})

	t.Run("Provenance_ReEnrollmentDoesNotResetTheJoinDate", func(t *testing.T) {
		// A daemon reinstall that re-enrolls an existing node_id has not joined
		// the fleet a second time — but the certificate it now holds is new.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a", CertFingerprint: "fp-1"})

		joined := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
		later := joined.Add(90 * 24 * time.Hour)
		mustNil(t, "first RecordEnrollment", r.RecordEnrollment("node-a", registry.Certificate{NotAfter: joined.Add(time.Hour)}, joined))
		mustNil(t, "second RecordEnrollment", r.RecordEnrollment("node-a", registry.Certificate{NotAfter: later.Add(time.Hour)}, later))

		n := mustGet(t, r, "node-a")
		if !n.EnrolledAt.Equal(joined) {
			t.Errorf("EnrolledAt = %v, want the first join %v", n.EnrolledAt, joined)
		}
		if !n.CertNotAfter.Equal(later.Add(time.Hour)) {
			t.Errorf("CertNotAfter = %v, want the re-enrolled certificate's %v", n.CertNotAfter, later.Add(time.Hour))
		}
		if n.RenewalCount != 0 || !n.LastRenewedAt.IsZero() {
			t.Errorf("re-enrollment counted as a renewal: count=%d at=%v", n.RenewalCount, n.LastRenewedAt)
		}
	})

	t.Run("Provenance_RenewalBeforeEnrollmentLeavesJoinDateUnrecorded", func(t *testing.T) {
		// A Node enrolled before provenance existed gets its first record on
		// renewal. Renewal has no way to write EnrolledAt, so the join date
		// stays honestly unknown rather than being guessed from the renewal.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-legacy"})
		at := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
		mustNil(t, "RecordRenewal", r.RecordRenewal("node-legacy", registry.Certificate{NotAfter: at.Add(time.Hour)}, at))

		n := mustGet(t, r, "node-legacy")
		if !n.EnrolledAt.IsZero() {
			t.Errorf("EnrolledAt = %v — renewal wrote the join date", n.EnrolledAt)
		}
		if !n.CertProvenanceKnown() || n.RenewalCount != 1 || !n.LastRenewedAt.Equal(at) {
			t.Errorf("renewal of a legacy Node: %+v", n)
		}
	})

	t.Run("Provenance_ZeroMeansNotRecordedNotTheEpoch", func(t *testing.T) {
		// A Node enrolled before provenance landed carries none until its next
		// renewal. Every surface must be able to tell that apart from an
		// identity that expired in 1970, which would render as catastrophically
		// overdue on the one screen that warns before a Node silently leaves
		// the fleet.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-legacy"})

		n := mustGet(t, r, "node-legacy")
		if n.CertProvenanceKnown() {
			t.Fatal("a Node with no recorded provenance reports it as known")
		}
		if !n.CertNotAfter.IsZero() {
			t.Errorf("CertNotAfter = %v, want the zero time", n.CertNotAfter)
		}

		mustNil(t, "RecordEnrollment", r.RecordEnrollment("node-legacy", registry.Certificate{NotAfter: time.Now().Add(time.Hour)}, time.Now()))
		if n := mustGet(t, r, "node-legacy"); !n.CertProvenanceKnown() {
			t.Error("provenance was recorded but does not report as known")
		}
	})

	t.Run("Provenance_RecordingAgainstAnUnknownNodeIsNotFound", func(t *testing.T) {
		// Silently succeeding would mean an enrollment race quietly dropped a
		// Node's expiry on the floor.
		r := fresh(t)
		cert := registry.Certificate{NotAfter: time.Now()}
		if err := r.RecordEnrollment("ghost", cert, time.Now()); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("RecordEnrollment on an unknown Node: err = %v, want ErrNotFound", err)
		}
		if err := r.RecordRenewal("ghost", cert, time.Now()); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("RecordRenewal on an unknown Node: err = %v, want ErrNotFound", err)
		}
		if _, ok := r.Get("ghost"); ok {
			t.Error("recording provenance created a Node")
		}
	})

	t.Run("Provenance_IsPerNode", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		mustUpsert(t, r, registry.Report{NodeID: "node-b"})
		at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		mustNil(t, "RecordEnrollment", r.RecordEnrollment("node-a", registry.Certificate{NotAfter: at.Add(time.Hour)}, at))
		mustNil(t, "RecordRenewal", r.RecordRenewal("node-a", registry.Certificate{NotAfter: at.Add(2 * time.Hour)}, at))
		if b := mustGet(t, r, "node-b"); b.CertProvenanceKnown() || !b.EnrolledAt.IsZero() || b.RenewalCount != 0 {
			t.Errorf("recording node-a's provenance touched node-b: %+v", b)
		}
	})

	// ----------------------------------------------------------------
	// Connected: derived from the live Tunnel set, never stored
	// ----------------------------------------------------------------

	t.Run("Connected_IsNotInferredFromLastSeen", func(t *testing.T) {
		// A Node that reported four seconds ago and then dropped its stream is
		// unreachable for dispatch NOW — ADR-0004 resolves such a Task
		// `unreachable` without sending it. A registry that guessed from
		// LastSeen would tell an operator the fleet is healthier than the
		// dispatcher believes it is.
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})

		mustNil(t, "UpdateLastSeen", r.UpdateLastSeen("node-a", time.Now()))
		if n := mustGet(t, r, "node-a"); n.Connected {
			t.Error("a Node that has never opened a Tunnel reports connected because it was seen recently")
		}

		r.SetConnected("node-a", true)
		if n := mustGet(t, r, "node-a"); !n.Connected {
			t.Error("a Node with an open Tunnel reports disconnected")
		}

		// A stream close flips the answer immediately — no timeout involved.
		r.SetConnected("node-a", false)
		if n := mustGet(t, r, "node-a"); n.Connected {
			t.Error("a closed stream did not flip connectedness; the fleet view would show a green dot for an unreachable Node")
		}
	})

	t.Run("Connected_GetListAndUpsertAgreeAndAHelloCannotClearIt", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		mustUpsert(t, r, registry.Report{NodeID: "node-b"})
		r.SetConnected("node-a", true)

		if n := mustGet(t, r, "node-a"); !n.Connected {
			t.Fatal("Get does not report connected")
		}
		for _, n := range r.List() {
			if want := n.NodeID == "node-a"; n.Connected != want {
				t.Errorf("List: %s Connected = %v, want %v", n.NodeID, n.Connected, want)
			}
		}

		// Report is the daemon's input. It has no way to claim connectedness,
		// and a Hello must not clear the transport's fact either.
		n := mustUpsert(t, r, registry.Report{NodeID: "node-a", CertFingerprint: "fp-2"})
		if !n.Connected {
			t.Error("the Upsert result for a connected Node reports disconnected")
		}
		if n := mustGet(t, r, "node-a"); !n.Connected {
			t.Error("a Hello Upsert cleared connectedness — it is the transport's fact, not the report's")
		}
	})

	t.Run("Connected_IsIdempotent", func(t *testing.T) {
		r := fresh(t)
		mustUpsert(t, r, registry.Report{NodeID: "node-a"})
		r.SetConnected("node-a", true)
		r.SetConnected("node-a", true)
		r.SetConnected("node-a", false)
		if mustGet(t, r, "node-a").Connected {
			t.Error("one close after two opens left the Node connected — the Tunnel set is a set, not a count")
		}
		r.SetConnected("node-a", false) // closing a closed Node is harmless
		if mustGet(t, r, "node-a").Connected {
			t.Error("a second close reconnected the Node")
		}
	})

	t.Run("Connected_UnknownNodeCreatesNoRecord", func(t *testing.T) {
		// "An unknown nodeID is ignored": SetConnected takes no error, and it
		// must not conjure a Node into the registry either.
		r := fresh(t)
		r.SetConnected("ghost", true)
		if _, ok := r.Get("ghost"); ok {
			t.Error("SetConnected created a registry record")
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("List after SetConnected on an unknown Node = %v, want none", got)
		}
		if total, _, err := r.Count(); err != nil || total != 0 {
			t.Errorf("Count = %d, %v; want 0, nil", total, err)
		}
		r.SetConnected("ghost", false)
	})
}

// fullReport returns a Report with every field this package may populate, so
// a test can tell a field that was preserved from one that was dropped. It
// carries no node-space labels: see the package doc for why those cases live
// in the store's test file instead.
func fullReport(nodeID string) registry.Report {
	return registry.Report{
		NodeID:          nodeID,
		CertFingerprint: "fp-" + nodeID,
		Facts: registry.Facts{
			Hostname:    "host-" + nodeID,
			OS:          "linux",
			Kernel:      "6.1.0",
			Arch:        "x86_64",
			IPAddresses: []string{"10.0.0.1", "fd00::1"},
		},
		EnrollingTokenID:       "tok-1",
		PolicyFingerprint:      "policy-1",
		DaemonVersion:          "1.0.0",
		TemplateSetFingerprint: "tmpl-1",
	}
}

// checkFullReport asserts n carries exactly what fullReport(n.NodeID) reported.
func checkFullReport(t *testing.T, what string, n registry.Node) {
	t.Helper()
	want := fullReport(n.NodeID)
	if n.CertFingerprint != want.CertFingerprint || n.EnrollingTokenID != want.EnrollingTokenID ||
		n.PolicyFingerprint != want.PolicyFingerprint || n.DaemonVersion != want.DaemonVersion ||
		n.TemplateSetFingerprint != want.TemplateSetFingerprint {
		t.Errorf("%s: reported fields = %+v, want those of %+v", what, n, want)
	}
	if !factsEqual(n.Facts, want.Facts) {
		t.Errorf("%s: Facts = %+v, want %+v", what, n.Facts, want.Facts)
	}
	if n.NodeLabels == nil || len(n.NodeLabels) != 0 {
		t.Errorf("%s: NodeLabels = %#v, want a non-nil empty map", what, n.NodeLabels)
	}
}

func factsEqual(a, b registry.Facts) bool {
	return a.Hostname == b.Hostname && a.OS == b.OS && a.Kernel == b.Kernel && a.Arch == b.Arch &&
		slices.Equal(a.IPAddresses, b.IPAddresses) && (a.IPAddresses == nil) == (b.IPAddresses == nil)
}

// nodesEqual compares every field of two Nodes, times by instant rather than
// by representation (one implementation may hand back a time in the zone it
// was given, the other in UTC — the same instant either way).
func nodesEqual(a, b registry.Node) bool {
	return a.NodeID == b.NodeID && a.CertFingerprint == b.CertFingerprint && factsEqual(a.Facts, b.Facts) &&
		maps.Equal(a.NodeLabels, b.NodeLabels) && maps.Equal(a.RelayLabels, b.RelayLabels) &&
		a.LastSeen.Equal(b.LastSeen) && a.EnrollingTokenID == b.EnrollingTokenID &&
		a.PolicyFingerprint == b.PolicyFingerprint && a.DaemonVersion == b.DaemonVersion &&
		a.TemplateSetFingerprint == b.TemplateSetFingerprint && a.RevokedAt.Equal(b.RevokedAt) &&
		a.CertNotAfter.Equal(b.CertNotAfter) && a.EnrolledAt.Equal(b.EnrolledAt) &&
		a.RenewalCount == b.RenewalCount && a.LastRenewedAt.Equal(b.LastRenewedAt) &&
		a.Connected == b.Connected && a.Outdated == b.Outdated
}

func mustUpsert(t *testing.T, r registry.Repository, rep registry.Report) registry.Node {
	t.Helper()
	n, err := r.Upsert(rep)
	if err != nil {
		t.Fatalf("Upsert %q: %v", rep.NodeID, err)
	}
	return n
}

func mustGet(t *testing.T, r registry.Repository, nodeID string) registry.Node {
	t.Helper()
	n, ok := r.Get(nodeID)
	if !ok {
		t.Fatalf("Get %q: not found", nodeID)
	}
	return n
}

func mustNil(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func onlyNode(t *testing.T, nodes []registry.Node) registry.Node {
	t.Helper()
	if len(nodes) != 1 {
		t.Fatalf("List returned %d Nodes, want 1", len(nodes))
	}
	return nodes[0]
}
