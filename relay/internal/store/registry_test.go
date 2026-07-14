package store

import (
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// TestSqliteRegistry_UpsertInsertUpdate ports registry.TestUpsert_RegisterGetList
// and the update-path assertions from registry.TestPolicyFingerprint_...:
// insert stores all report fields; a second Upsert overwrites node-rooted
// fields and PolicyFingerprint but preserves RelayLabels and EnrollingTokenID.
func TestSqliteRegistry_UpsertInsertUpdate(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	n1, err := reg.Upsert(registry.Report{
		NodeID:            "node-a",
		CertFingerprint:   "fp-a",
		Facts:             registry.Facts{Hostname: "host-a", OS: "linux", IPAddresses: []string{"10.0.0.1"}},
		NodeLabels:        map[string]string{"role": "web"},
		EnrollingTokenID:  "tok-1",
		PolicyFingerprint: "abc123",
		DaemonVersion:     "1.0.0",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n1.NodeID != "node-a" || n1.CertFingerprint != "fp-a" || n1.Facts.Hostname != "host-a" ||
		n1.NodeLabels["role"] != "web" || n1.PolicyFingerprint != "abc123" || n1.EnrollingTokenID != "tok-1" ||
		n1.DaemonVersion != "1.0.0" {
		t.Errorf("insert result: got %#v", n1)
	}
	if n1.RelayLabels == nil || len(n1.RelayLabels) != 0 {
		t.Errorf("insert RelayLabels: got %#v, want non-nil empty map", n1.RelayLabels)
	}
	if !n1.RevokedAt.IsZero() {
		t.Errorf("insert RevokedAt: got %v, want zero value", n1.RevokedAt)
	}

	if err := reg.SetRelayLabels("node-a", map[string]string{"quarantine": "true"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	// Update path: new fingerprint/facts/labels, different (ignored) token.
	n2, err := reg.Upsert(registry.Report{
		NodeID:            "node-a",
		CertFingerprint:   "fp-new",
		Facts:             registry.Facts{Hostname: "host-a-new", OS: "linux"},
		NodeLabels:        map[string]string{"role": "db"},
		EnrollingTokenID:  "tok-ignored",
		PolicyFingerprint: "def456",
		DaemonVersion:     "1.1.0",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if n2.CertFingerprint != "fp-new" {
		t.Errorf("update CertFingerprint: got %q, want fp-new", n2.CertFingerprint)
	}
	if n2.Facts.Hostname != "host-a-new" {
		t.Errorf("update Facts.Hostname: got %q, want host-a-new", n2.Facts.Hostname)
	}
	if n2.NodeLabels["role"] != "db" {
		t.Errorf("update NodeLabels[role]: got %q, want db", n2.NodeLabels["role"])
	}
	if n2.PolicyFingerprint != "def456" {
		t.Errorf("update PolicyFingerprint: got %q, want def456", n2.PolicyFingerprint)
	}
	if n2.DaemonVersion != "1.1.0" {
		t.Errorf("update DaemonVersion: got %q, want 1.1.0 (refreshed on reconnect)", n2.DaemonVersion)
	}
	if n2.EnrollingTokenID != "tok-1" {
		t.Errorf("update EnrollingTokenID: got %q, want tok-1 (provenance must be immutable)", n2.EnrollingTokenID)
	}
	if n2.RelayLabels["quarantine"] != "true" {
		t.Errorf("update RelayLabels[quarantine]: got %q, want true (relay labels must survive reconnect)", n2.RelayLabels["quarantine"])
	}

	got, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.CertFingerprint != "fp-new" || got.EnrollingTokenID != "tok-1" || got.RelayLabels["quarantine"] != "true" ||
		got.DaemonVersion != "1.1.0" {
		t.Errorf("Get after update: got %#v", got)
	}
}

// TestSqliteRegistry_Outdated ports registry.TestOutdated_* against the
// SQLite-backed registry: daemon_version is persisted on insert and
// refreshed on update, and Outdated is derived at read time from the
// store's WithMinDaemonVersion, exactly mirroring registry.InMemory.
func TestSqliteRegistry_Outdated(t *testing.T) {
	st, _ := openTestStore(t, WithMinDaemonVersion("1.2.0"))
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-old", DaemonVersion: "1.1.0"}); err != nil {
		t.Fatalf("upsert node-old: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-new", DaemonVersion: "1.3.0"}); err != nil {
		t.Fatalf("upsert node-new: %v", err)
	}

	old, ok := reg.Get("node-old")
	if !ok {
		t.Fatal("Get node-old: not found")
	}
	if old.DaemonVersion != "1.1.0" {
		t.Errorf("node-old DaemonVersion: got %q, want 1.1.0", old.DaemonVersion)
	}
	if !old.Outdated {
		t.Error("node-old Outdated: got false, want true (below minimum)")
	}

	current, ok := reg.Get("node-new")
	if !ok {
		t.Fatal("Get node-new: not found")
	}
	if current.Outdated {
		t.Error("node-new Outdated: got true, want false (above minimum)")
	}

	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("List len: got %d, want 2", len(list))
	}
	if list[0].Outdated { // node-new sorts before node-old
		t.Errorf("List[0] (node-new): Outdated got %v, want false", list[0].Outdated)
	}
	if !list[1].Outdated {
		t.Errorf("List[1] (node-old): Outdated got %v, want true", list[1].Outdated)
	}

	// Reconnect at the minimum: Outdated must flip to false and the stored
	// daemon_version must refresh.
	upserted, err := reg.Upsert(registry.Report{NodeID: "node-old", DaemonVersion: "1.2.0"})
	if err != nil {
		t.Fatalf("reconnect upsert: %v", err)
	}
	if upserted.Outdated {
		t.Error("reconnect Upsert result: Outdated got true, want false")
	}
	old, _ = reg.Get("node-old")
	if old.DaemonVersion != "1.2.0" || old.Outdated {
		t.Errorf("after reconnect: got DaemonVersion=%q Outdated=%v, want 1.2.0/false", old.DaemonVersion, old.Outdated)
	}
}

// TestSqliteRegistry_Outdated_NoMinimumConfigured mirrors
// registry.TestOutdated_NoMinimumConfigured: with no WithMinDaemonVersion,
// every Node is always non-outdated regardless of its reported version.
func TestSqliteRegistry_Outdated_NoMinimumConfigured(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	n, err := reg.Upsert(registry.Report{NodeID: "node-a", DaemonVersion: "0.0.1"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if n.Outdated {
		t.Error("Upsert result: Outdated true with no min_daemon_version configured, want false")
	}

	got, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Outdated {
		t.Error("Get: Outdated true with no min_daemon_version configured, want false")
	}

	list := reg.List()
	if len(list) != 1 || list[0].Outdated {
		t.Errorf("List: Outdated true with no min_daemon_version configured, want false (list=%+v)", list)
	}
}

func TestSqliteRegistry_EmptyNodeID(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	_, err := reg.Upsert(registry.Report{})
	if !errors.Is(err, registry.ErrEmptyNodeID) {
		t.Errorf("expected ErrEmptyNodeID, got %v", err)
	}
}

func TestSqliteRegistry_AtCapacity(t *testing.T) {
	st, _ := openTestStore(t, WithMaxNodes(2))
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("insert node-a: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-b"}); err != nil {
		t.Fatalf("insert node-b: %v", err)
	}

	if _, err := reg.Upsert(registry.Report{NodeID: "node-c"}); !errors.Is(err, registry.ErrAtCapacity) {
		t.Errorf("third insert: want ErrAtCapacity, got %v", err)
	}
	if got := len(reg.List()); got != 2 {
		t.Errorf("after rejected insert: List() len = %d, want 2", got)
	}

	// UPDATE path must succeed even at capacity.
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", CertFingerprint: "fp-new"}); err != nil {
		t.Errorf("update at capacity: %v", err)
	}
}

func TestSqliteRegistry_SetRelayLabels_NotFound(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	err := reg.SetRelayLabels("does-not-exist", map[string]string{"k": "v"})
	if !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSqliteRegistry_UpdateLastSeen(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if err := reg.UpdateLastSeen("does-not-exist", time.Now()); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("UpdateLastSeen not found: want ErrNotFound, got %v", err)
	}

	if _, err := reg.Upsert(registry.Report{NodeID: "node-ls"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	newTime := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := reg.UpdateLastSeen("node-ls", newTime); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	got, ok := reg.Get("node-ls")
	if !ok {
		t.Fatal("Get: not found")
	}
	if !got.LastSeen.Equal(newTime) {
		t.Errorf("LastSeen: got %v, want %v", got.LastSeen, newTime)
	}
}

func TestSqliteRegistry_SetRevoked(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if err := reg.SetRevoked("does-not-exist", time.Now()); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("SetRevoked not found: want ErrNotFound, got %v", err)
	}

	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	ids, err := reg.RevokedNodeIDs()
	if err != nil {
		t.Fatalf("RevokedNodeIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("RevokedNodeIDs before revoke: got %v, want empty", ids)
	}

	revokedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := reg.SetRevoked("node-a", revokedAt); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}

	got, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get: not found")
	}
	if !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt: got %v, want %v", got.RevokedAt, revokedAt)
	}

	gotB, ok := reg.Get("node-b")
	if !ok {
		t.Fatal("Get node-b: not found")
	}
	if !gotB.RevokedAt.IsZero() {
		t.Errorf("node-b RevokedAt: got %v, want zero (unrevoked)", gotB.RevokedAt)
	}

	ids, err = reg.RevokedNodeIDs()
	if err != nil {
		t.Fatalf("RevokedNodeIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "node-a" {
		t.Errorf("RevokedNodeIDs after revoke: got %v, want [node-a]", ids)
	}
}

func TestSqliteRegistry_Count(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	total, revoked, err := reg.Count()
	if err != nil {
		t.Fatalf("Count on empty registry: %v", err)
	}
	if total != 0 || revoked != 0 {
		t.Errorf("Count on empty registry = (%d, %d), want (0, 0)", total, revoked)
	}

	for _, id := range []string{"node-a", "node-b", "node-c"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	total, revoked, err = reg.Count()
	if err != nil {
		t.Fatalf("Count with 3 enrolled: %v", err)
	}
	if total != 3 || revoked != 0 {
		t.Errorf("Count with 3 enrolled, none revoked = (%d, %d), want (3, 0)", total, revoked)
	}

	if err := reg.SetRevoked("node-b", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}

	total, revoked, err = reg.Count()
	if err != nil {
		t.Fatalf("Count with one revoked: %v", err)
	}
	if total != 3 || revoked != 1 {
		t.Errorf("Count with 3 enrolled, 1 revoked = (%d, %d), want (3, 1)", total, revoked)
	}
}

func TestSqliteRegistry_ListSortedByNodeID(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	for _, id := range []string{"node-c", "node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	list := reg.List()
	if len(list) != 3 {
		t.Fatalf("List len: got %d, want 3", len(list))
	}
	if list[0].NodeID != "node-a" || list[1].NodeID != "node-b" || list[2].NodeID != "node-c" {
		t.Errorf("List order: got [%q, %q, %q], want [node-a, node-b, node-c]",
			list[0].NodeID, list[1].NodeID, list[2].NodeID)
	}
}
