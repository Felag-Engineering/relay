package store

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestSqliteRegistry_UpsertInsertUpdate ports registry.TestUpsert_RegisterGetList
// and the update-path assertions from registry.TestPolicyFingerprint_...:
// insert stores all report fields; a second Upsert overwrites node-rooted
// fields and PolicyFingerprint but preserves RelayLabels and EnrollingTokenID.
func TestSqliteRegistry_UpsertInsertUpdate(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	n1, err := reg.Upsert(registry.Report{
		NodeID:                 "node-a",
		CertFingerprint:        "fp-a",
		Facts:                  registry.Facts{Hostname: "host-a", OS: "linux", IPAddresses: []string{"10.0.0.1"}},
		EnrollingTokenID:       "tok-1",
		PolicyFingerprint:      "abc123",
		DaemonVersion:          "1.0.0",
		TemplateSetFingerprint: "tmpl-abc",
	}.WithNodeLabels(map[string]string{"role": "web"}))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n1.TemplateSetFingerprint != "tmpl-abc" {
		t.Errorf("insert TemplateSetFingerprint: got %q, want tmpl-abc", n1.TemplateSetFingerprint)
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
		NodeID:                 "node-a",
		CertFingerprint:        "fp-new",
		Facts:                  registry.Facts{Hostname: "host-a-new", OS: "linux"},
		EnrollingTokenID:       "tok-ignored",
		PolicyFingerprint:      "def456",
		DaemonVersion:          "1.1.0",
		TemplateSetFingerprint: "tmpl-def",
	}.WithNodeLabels(map[string]string{"role": "db"}))
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if n2.TemplateSetFingerprint != "tmpl-def" {
		t.Errorf("update TemplateSetFingerprint: got %q, want tmpl-def (refreshed on reconnect)",
			n2.TemplateSetFingerprint)
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

// TestSqliteRegistry_FactsReplacedOnReconnect ports
// registry.TestUpsert_FactsReplacedOnReconnect against the SQLite-backed
// registry: a reconnect Upsert fully replaces the stored Facts (kernel/IPs
// go from empty to populated), round-tripping through the persistent store,
// while RelayLabels/EnrollingTokenID/RevokedAt are untouched.
func TestSqliteRegistry_FactsReplacedOnReconnect(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	// INSERT: first connect with partial Facts (kernel/IPs not yet populated).
	_, err := reg.Upsert(registry.Report{
		NodeID:           "node-facts",
		EnrollingTokenID: "tok-facts",
		Facts:            registry.Facts{Hostname: "old-host", OS: "linux"},
	}.WithNodeLabels(map[string]string{"env": "prod"}))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := reg.SetRelayLabels("node-facts", map[string]string{"quarantine": "true"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	// UPDATE: node reconnects (daemon restart) with full Facts and new NodeLabels.
	_, err = reg.Upsert(registry.Report{
		NodeID:           "node-facts",
		EnrollingTokenID: "tok-ignored", // must not overwrite provenance
		Facts: registry.Facts{
			Hostname:    "new-host",
			OS:          "linux",
			Kernel:      "6.12.0",
			Arch:        "x86_64",
			IPAddresses: []string{"10.0.0.5"},
		},
	}.WithNodeLabels(map[string]string{"env": "staging"}))
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := reg.Get("node-facts")
	if !ok {
		t.Fatal("Get: not found")
	}

	// Facts must round-trip through the store fully replaced.
	if got.Facts.Hostname != "new-host" {
		t.Errorf("Facts.Hostname: got %q, want new-host", got.Facts.Hostname)
	}
	if got.Facts.Kernel != "6.12.0" {
		t.Errorf("Facts.Kernel: got %q, want 6.12.0", got.Facts.Kernel)
	}
	if got.Facts.Arch != "x86_64" {
		t.Errorf("Facts.Arch: got %q, want x86_64", got.Facts.Arch)
	}
	if len(got.Facts.IPAddresses) != 1 || got.Facts.IPAddresses[0] != "10.0.0.5" {
		t.Errorf("Facts.IPAddresses: got %v, want [10.0.0.5]", got.Facts.IPAddresses)
	}
	if got.NodeLabels["env"] != "staging" {
		t.Errorf("NodeLabels[env]: got %q, want staging", got.NodeLabels["env"])
	}

	// Relay-space state must survive the node-sent Facts refresh.
	if got.RelayLabels["quarantine"] != "true" {
		t.Errorf("RelayLabels[quarantine]: got %q, want true (relay labels must survive Facts refresh)", got.RelayLabels["quarantine"])
	}
	if got.EnrollingTokenID != "tok-facts" {
		t.Errorf("EnrollingTokenID: got %q, want tok-facts (provenance must be immutable)", got.EnrollingTokenID)
	}
	if !got.RevokedAt.IsZero() {
		t.Errorf("RevokedAt: got %v, want zero value (untouched by Facts refresh)", got.RevokedAt)
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

func TestSqliteRegistry_SetRevokedAll_OneTransactionOverTheWholeChunk(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	for _, id := range []string{"node-a", "node-b", "node-c"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	missing, err := reg.SetRevokedAll([]string{"node-a", "node-b", "node-c", "no-such"}, at)
	if err != nil {
		t.Fatalf("SetRevokedAll: %v", err)
	}
	if len(missing) != 1 || missing[0] != "no-such" {
		t.Errorf("missing: got %v, want [no-such]", missing)
	}

	for _, id := range []string{"node-a", "node-b", "node-c"} {
		got, ok := reg.Get(id)
		if !ok {
			t.Fatalf("Get %s: not found", id)
		}
		if !got.RevokedAt.Equal(at) {
			t.Errorf("%s RevokedAt: got %v, want %v", id, got.RevokedAt, at)
		}
	}

	ids, err := reg.RevokedNodeIDs()
	if err != nil {
		t.Fatalf("RevokedNodeIDs: %v", err)
	}
	if len(ids) != 3 || ids[0] != "node-a" || ids[1] != "node-b" || ids[2] != "node-c" {
		t.Errorf("RevokedNodeIDs: got %v, want [node-a node-b node-c]", ids)
	}
}

func TestSqliteRegistry_SetRevokedAll_EmptyTouchesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	missing, err := reg.SetRevokedAll(nil, time.Now())
	if err != nil || missing != nil {
		t.Errorf("SetRevokedAll(nil): got (%v, %v), want (nil, nil)", missing, err)
	}

	got, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get: not found")
	}
	if !got.RevokedAt.IsZero() {
		t.Errorf("node-a RevokedAt: got %v, want zero (nothing revoked)", got.RevokedAt)
	}
}

// TestSqliteRegistry_SetRevokedAll_MidBatchFailureRollsBackEarlierIds is the
// all-or-nothing proof, and it exercises the ROLLBACK itself, not merely a
// failed BeginTx: a trigger aborts the UPDATE for one sentinel row partway
// through the batch, and the assertion is that an EARLIER id's already-
// executed UPDATE was rolled back with the rest of the transaction. Closing
// the Store first would only prove "a failure before the first statement
// writes nothing" — it never reaches a rollback at all, because BeginTx
// itself fails before any statement runs.
func TestSqliteRegistry_SetRevokedAll_MidBatchFailureRollsBackEarlierIds(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	for _, id := range []string{"node-a", "node-boom", "node-c"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	if _, err := st.db.Exec(`
		CREATE TRIGGER boom BEFORE UPDATE ON nodes
		WHEN NEW.node_id = 'node-boom'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	defer func() {
		if _, err := st.db.Exec(`DROP TRIGGER boom`); err != nil {
			t.Errorf("drop trigger: %v", err)
		}
	}()

	missing, err := reg.SetRevokedAll([]string{"node-a", "node-boom", "node-c"}, time.Now())
	if err == nil {
		t.Fatal("SetRevokedAll: want error from the aborted trigger, got nil")
	}
	if missing != nil {
		t.Errorf("missing: got %v, want nil on a batch failure", missing)
	}

	ids, err := reg.RevokedNodeIDs()
	if err != nil {
		t.Fatalf("RevokedNodeIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("RevokedNodeIDs after a rolled-back batch: got %v, want empty (node-a's earlier UPDATE must have rolled back too)", ids)
	}
}

func TestSqliteRegistry_SetRevokedAll_FailureBeforeTheFirstStatementWritesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	missing, err := reg.SetRevokedAll([]string{"node-a"}, time.Now())
	if err == nil {
		t.Fatal("SetRevokedAll on a closed store: want error, got nil")
	}
	if missing != nil {
		t.Errorf("missing: got %v, want nil on error", missing)
	}
}

func TestSqliteRegistry_SetRevoked_And_SetRevokedAll_WriteTheSameColumn(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := reg.SetRevoked("node-a", at); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}
	if _, err := reg.SetRevokedAll([]string{"node-b"}, at); err != nil {
		t.Fatalf("SetRevokedAll: %v", err)
	}

	a, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get node-a: not found")
	}
	b, ok := reg.Get("node-b")
	if !ok {
		t.Fatal("Get node-b: not found")
	}
	if !a.RevokedAt.Equal(at) || !b.RevokedAt.Equal(at) || !a.RevokedAt.Equal(b.RevokedAt) {
		t.Errorf("RevokedAt via SetRevoked vs SetRevokedAll: got %v and %v, want both equal to %v", a.RevokedAt, b.RevokedAt, at)
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

// TestGetNode_DoesNotServeMalformedLegacyNodeLabel is the exception item 11
// exists for (#504): a row written BEFORE the ingress gate existed
// (protoconv.ParseNodeLabel) can carry a node_labels value the gate would
// have refused. getNode is the single load path behind both Get and List, so
// this one test covers every reader.
//
// The forged row is inserted STRAIGHT INTO node_labels via raw SQL,
// bypassing Upsert entirely — exactly as a pre-fix Relay would have written
// it — because Upsert itself now refuses to write what this test is
// checking the READ path filters.
func TestGetNode_DoesNotServeMalformedLegacyNodeLabel(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-legacy",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The measured payload (#504's evidence), inserted as a pre-fix Relay
	// would have stored it: no prefix stripping needed, node_labels already
	// holds bare keys.
	if _, err := st.db.Exec(
		`INSERT INTO node_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-legacy", "env", "prod, relay:quarantine=on",
	); err != nil {
		t.Fatalf("insert forged legacy row: %v", err)
	}

	got, ok := reg.Get("node-legacy")
	if !ok {
		t.Fatal("Get: not found")
	}
	if len(got.NodeLabels) != 1 || got.NodeLabels["role"] != "web" {
		t.Errorf("Get NodeLabels: got %#v, want only {role: web} — the forged legacy row must be declined, not served",
			got.NodeLabels)
	}
	if _, forged := got.NodeLabels["env"]; forged {
		t.Errorf("Get served the forged legacy env label: %q", got.NodeLabels["env"])
	}

	list := reg.List()
	if len(list) != 1 {
		t.Fatalf("List len: got %d, want 1", len(list))
	}
	if len(list[0].NodeLabels) != 1 || list[0].NodeLabels["role"] != "web" {
		t.Errorf("List NodeLabels: got %#v, want only {role: web}", list[0].NodeLabels)
	}

	// The counter must advance for the namespace this test forges (node) and
	// stay untouched for the other (relay) — one Get plus one List, each
	// declining the single forged pair once. Extended per #565 so the
	// counter cannot be unwired from node-space while relay-space stays
	// honest.
	if node, relay := st.LabelsDeclined(); node != 2 || relay != 0 {
		t.Errorf("LabelsDeclined() = (%d, %d), want (2, 0) after one Get and one List", node, relay)
	}

	// The Relay declines to SERVE the forged row; it must not have DELETED
	// or rewritten it (invariant 7: node-space storage is the Node's own
	// self-description, and the Relay never edits it — only the Node's next
	// Hello may replace the whole set).
	var stillThere string
	if err := st.db.QueryRow(
		`SELECT value FROM node_labels WHERE node_id = ? AND key = ?`, "node-legacy", "env",
	).Scan(&stillThere); err != nil {
		t.Fatalf("the forged row must still be in node_labels (declined, not deleted): %v", err)
	}
	if stillThere != "prod, relay:quarantine=on" {
		t.Errorf("the stored row must be unmodified: got %q", stillThere)
	}
}

// TestGetNode_DoesNotServeMalformedLegacyRelayLabel is
// TestGetNode_DoesNotServeMalformedLegacyNodeLabel's relay-space sibling
// (#555): a relay_labels row stamped by an enrollment that ran BEFORE the
// well-formedness gate existed (enroll.validateScope) can carry a value the
// gate would have refused. getNode is the single load path behind both Get
// and List, so this one test covers every reader.
//
// The forged row is inserted STRAIGHT INTO relay_labels via raw SQL,
// bypassing SetRelayLabels entirely — exactly as a pre-fix enrollment would
// have written it.
func TestGetNode_DoesNotServeMalformedLegacyRelayLabel(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-legacy-relay",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// #504's measured payload mirrored into relay-space: a comma smuggles a
	// second, cross-namespace term into the value.
	if _, err := st.db.Exec(
		`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-legacy-relay", "env", "prod, relay:quarantine=on",
	); err != nil {
		t.Fatalf("insert forged legacy row: %v", err)
	}
	if _, err := st.db.Exec(
		`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-legacy-relay", registry.QuarantineKey, registry.QuarantineOn,
	); err != nil {
		t.Fatalf("insert quarantine row: %v", err)
	}

	got, ok := reg.Get("node-legacy-relay")
	if !ok {
		t.Fatal("Get: not found")
	}
	// RED ON: not filtering relay_labels — the forged pair must be absent.
	if _, forged := got.RelayLabels["env"]; forged {
		t.Errorf("Get served the forged legacy relay label: %q", got.RelayLabels["env"])
	}
	// RED ON: filtering too broadly — the quarantine fence pair, entirely
	// inside the allowlist, must survive and still read as quarantined.
	if got.RelayLabels[registry.QuarantineKey] != registry.QuarantineOn {
		t.Errorf("RelayLabels[%s]: got %q, want %q", registry.QuarantineKey, got.RelayLabels[registry.QuarantineKey], registry.QuarantineOn)
	}
	if !got.Quarantined() {
		t.Error("got.Quarantined() = false, want true — the filter must never lift a quarantine")
	}

	list := reg.List()
	if len(list) != 1 {
		t.Fatalf("List len: got %d, want 1", len(list))
	}
	if _, forged := list[0].RelayLabels["env"]; forged {
		t.Errorf("List served the forged legacy relay label: %q", list[0].RelayLabels["env"])
	}

	// The counter must advance for the namespace this test forges (relay)
	// and stay untouched for the other (node) — one Get plus one List, each
	// declining the single forged pair once. Extended per #565 so the
	// counter cannot be unwired from relay-space while node-space stays
	// honest.
	if node, relay := st.LabelsDeclined(); node != 0 || relay != 2 {
		t.Errorf("LabelsDeclined() = (%d, %d), want (0, 2) after one Get and one List", node, relay)
	}

	// RED ON: "healing" the row by deleting or rewriting it instead of
	// declining to serve it (ADR-0017's forge-to-attract cell) — the Relay
	// declines to SERVE the forged row; it must not have DELETED or
	// rewritten it.
	var stillThere string
	if err := st.db.QueryRow(
		`SELECT value FROM relay_labels WHERE node_id = ? AND key = ?`, "node-legacy-relay", "env",
	).Scan(&stillThere); err != nil {
		t.Fatalf("the forged row must still be in relay_labels (declined, not deleted): %v", err)
	}
	if stillThere != "prod, relay:quarantine=on" {
		t.Errorf("the stored row must be unmodified: got %q", stillThere)
	}
}

// TestGetNode_CountsDeclinedLabels is #565's Seam 2: getNode's read-back
// filter must count every declined PAIR, per namespace, and nothing else —
// not per call, not per Node, and never a well-formed pair. The fixture's
// node-space and relay-space totals are DELIBERATELY UNEQUAL (one malformed
// row vs. two) so a namespace mix-up cannot pass by accident, and a second,
// entirely clean Node is read alongside the affected one so a scan-shaped
// bug (counting every Node touched, rather than every pair declined) shows
// up immediately.
func TestGetNode_CountsDeclinedLabels(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-affected",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("Upsert node-affected: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-clean",
	}.WithNodeLabels(map[string]string{"role": "db"})); err != nil {
		t.Fatalf("Upsert node-clean: %v", err)
	}
	if err := reg.SetRelayLabels("node-clean", map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("SetRelayLabels node-clean: %v", err)
	}

	// Forged straight into the tables, AFTER both Upserts above, so neither
	// Upsert's own internal read-back (registry.go:113) sees them and
	// perturbs the "before any read" baseline below. One malformed
	// node-space pair; two malformed relay-space pairs — deliberately
	// unequal counts.
	if _, err := st.db.Exec(
		`INSERT INTO node_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-affected", "env", "prod, relay:quarantine=on",
	); err != nil {
		t.Fatalf("insert forged node_labels row: %v", err)
	}
	if _, err := st.db.Exec(
		`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-affected", "tier", "pci/1",
	); err != nil {
		t.Fatalf("insert forged relay_labels row (tier): %v", err)
	}
	if _, err := st.db.Exec(
		`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-affected", "owner", "team@sec",
	); err != nil {
		t.Fatalf("insert forged relay_labels row (owner): %v", err)
	}

	if node, relay := st.LabelsDeclined(); node != 0 || relay != 0 {
		t.Fatalf("before any read: LabelsDeclined() = (%d, %d), want (0, 0)", node, relay)
	}

	if _, ok := reg.Get("node-affected"); !ok {
		t.Fatal("Get(node-affected): not found")
	}
	if node, relay := st.LabelsDeclined(); node != 1 || relay != 2 {
		t.Errorf("after Get(node-affected): LabelsDeclined() = (%d, %d), want (1, 2)", node, relay)
	}

	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("List len: got %d, want 2", len(list))
	}
	if node, relay := st.LabelsDeclined(); node != 2 || relay != 4 {
		t.Errorf("after List: LabelsDeclined() = (%d, %d), want (2, 4) — node-clean must contribute nothing", node, relay)
	}
}

// TestUpsert_ReadBackIsNeverRoutedThroughTheSharedHandle reads this package's
// own source, for the same reason audit's TestKinds_ListsEveryDeclaredKind
// does: the property is a shape the code must have, and no assertion over
// behaviour can observe it.
//
// THE HAZARD. store.Open calls db.SetMaxOpenConns(1). Upsert opens a
// transaction on that single connection and calls getNode(ctx, tx, ...) while
// still holding it, committing only after getNode returns. A getNode that
// reached for r.db instead of the tx it was handed would try to check out a
// SECOND connection from a pool of one that this very call already holds — so
// it would block until the commit, which is sequenced after the blocked call.
// That is a deadlock on every Hello, not a data bug.
//
// WHY THIS IS A SOURCE GUARD AND NOT A BEHAVIOURAL ONE. A probe that actually
// triggers the deadlock cannot report it. I tried: the blocked goroutine holds
// the only connection forever (Upsert hardcodes context.Background(), so
// nothing can cancel the query), so when the probe's own deadline fires and
// calls t.Fatal, the store's cleanup then blocks in db.Close() waiting for
// that transaction — and the test binary is killed by go test -timeout before
// the framework ever prints the failure. The observed output is a bare
// "panic: test timed out" with a goroutine dump and no diagnosis at all. So a
// behavioural test here does not turn a deadlock into a failing test; it turns
// it into a wedged binary that happens to exit non-zero. This guard fails in
// milliseconds and says which line is wrong.
//
// RED ON: passing r.db (or s.db, or anything but the tx in scope) to getNode
// inside Upsert, and on methodizing getNode such that it has a receiver to
// reach a shared handle through at all.
//
// WHAT IT DOES NOT CATCH, stated so nobody mistakes it for a fence. It checks
// two things: getNode has no receiver, and Upsert's second argument to it is
// the identifier `tx`. So it would miss wellFormedLabels being methodized, and
// it would miss a helper CALLED FROM getNode reaching a shared handle of its
// own. It also false-positives on a correctly-scoped transaction held in a
// variable named anything else. That narrowness is accepted: it fails in
// milliseconds and names the line, which is worth more than the coverage it
// gives up against a hazard whose only behavioural symptom is a hang that
// cannot be reported from inside the test binary.
func TestUpsert_ReadBackIsNeverRoutedThroughTheSharedHandle(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "registry.go", nil, 0)
	if err != nil {
		t.Fatalf("parse registry.go: %v", err)
	}

	// getNode must be a FREE function: a receiver is the thing that would make
	// r.db reachable from inside it in the first place.
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "getNode" {
			return true
		}
		found = true
		if fn.Recv != nil {
			t.Error("getNode has a receiver: it must stay a free function so there is no " +
				"shared *sql.DB reachable from inside it — see this test's doc for the deadlock")
		}
		return true
	})
	if !found {
		t.Fatal("getNode not found in registry.go: this guard has gone stale and is proving nothing")
	}

	// And Upsert must hand it the transaction, never a shared handle.
	var checked bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Upsert" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "getNode" || len(call.Args) < 2 {
				return true
			}
			checked = true
			arg, ok := call.Args[1].(*ast.Ident)
			if !ok || arg.Name != "tx" {
				t.Errorf("Upsert passes %s to getNode as its queryer, want the in-scope tx: "+
					"anything else deadlocks on the single connection Upsert is already holding",
					types.ExprString(call.Args[1]))
			}
			return true
		})
		return true
	})
	if !checked {
		t.Fatal("no getNode call found inside Upsert: this guard has gone stale and is proving nothing")
	}
}

// TestUpsert_ReadBackDeclinesAndCountsInsideItsOwnTransaction is the
// behavioural half that CAN be asserted: with a forged relay_labels row
// already present, a Hello's own read-back declines it and the counter
// advances. It deliberately does not probe the deadlock — see
// TestUpsert_ReadBackIsNeverRoutedThroughTheSharedHandle for why that cannot
// be observed from inside the test binary.
func TestUpsert_ReadBackDeclinesAndCountsInsideItsOwnTransaction(t *testing.T) {
	st, _ := openTestStore(t)
	reg := st.Registry()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-hello"}); err != nil {
		t.Fatalf("initial Upsert: %v", err)
	}

	// Forged AFTER the initial Upsert, exactly as a pre-#555 enrollment would
	// have stored it, so the SECOND Upsert below is the first read-back to see it.
	if _, err := st.db.Exec(
		`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`,
		"node-hello", "env", "prod, relay:quarantine=on",
	); err != nil {
		t.Fatalf("insert forged relay_labels row: %v", err)
	}

	node, err := reg.Upsert(registry.Report{
		NodeID: "node-hello",
		Facts:  registry.Facts{Hostname: "host-hello"},
	})
	if err != nil {
		t.Fatalf("Upsert (a Hello) with a forged relay_labels row present: %v", err)
	}
	if _, served := node.RelayLabels["env"]; served {
		t.Error("Upsert's read-back served the forged relay_labels pair")
	}
	if n, r := st.LabelsDeclined(); n != 0 || r != 1 {
		t.Errorf("LabelsDeclined() = (%d, %d), want (0, 1) after Upsert's own read-back declined the forged pair", n, r)
	}
}

// TestLabelNamespaceTable pins the namespace-to-table mapping, which invariant
// 7 rests on and which nothing else would catch.
//
// The two label namespaces are disjoint TABLES, and that disjointness is how
// "a Node can never set a relay: label" is structural rather than enforced.
// Since #565 both write sites and both read sites reach their table through
// labelNamespace.table() instead of a literal — so a symmetric edit to that one
// four-line function would route Node-reported labels into relay_labels and
// back out again, and EVERY round-trip test would still pass, because the reads
// flip with the writes. Only an assertion on the mapping itself sees it.
//
// *Fails if*: the two cases are swapped, or a table is renamed on one side only.
func TestLabelNamespaceTable(t *testing.T) {
	t.Parallel()

	if got := nsNode.table(); got != "node_labels" {
		t.Errorf("nsNode.table() = %q, want %q — node-reported labels must never reach relay_labels", got, "node_labels")
	}
	if got := nsRelay.table(); got != "relay_labels" {
		t.Errorf("nsRelay.table() = %q, want %q", got, "relay_labels")
	}
}
