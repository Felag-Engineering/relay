package registry

import (
	"errors"
	"testing"
	"time"
)

// fixedClock returns a WithClock option that always returns t.
func fixedClock(t time.Time) Option {
	return WithClock(func() time.Time { return t })
}

func TestUpsert_RegisterGetList(t *testing.T) {
	ts := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	reg := NewInMemory(fixedClock(ts))

	rep1 := Report{
		NodeID:           "node-a",
		CertFingerprint:  "fp-a",
		Facts:            Facts{Hostname: "host-a", OS: "linux", IPAddresses: []string{"10.0.0.1"}},
		NodeLabels:       map[string]string{"role": "web"},
		EnrollingTokenID: "tok-1",
	}
	rep2 := Report{
		NodeID:           "node-b",
		CertFingerprint:  "fp-b",
		Facts:            Facts{Hostname: "host-b", OS: "linux"},
		NodeLabels:       map[string]string{"role": "db"},
		EnrollingTokenID: "tok-2",
	}

	n1, err := reg.Upsert(rep1)
	if err != nil {
		t.Fatalf("upsert node-a: %v", err)
	}
	if n1.NodeID != "node-a" {
		t.Errorf("NodeID: got %q, want %q", n1.NodeID, "node-a")
	}
	if n1.CertFingerprint != "fp-a" {
		t.Errorf("CertFingerprint: got %q, want %q", n1.CertFingerprint, "fp-a")
	}
	if n1.Facts.Hostname != "host-a" {
		t.Errorf("Facts.Hostname: got %q, want %q", n1.Facts.Hostname, "host-a")
	}
	if n1.NodeLabels["role"] != "web" {
		t.Errorf("NodeLabels[role]: got %q, want %q", n1.NodeLabels["role"], "web")
	}
	if !n1.LastSeen.Equal(ts) {
		t.Errorf("LastSeen: got %v, want %v", n1.LastSeen, ts)
	}

	if _, err := reg.Upsert(rep2); err != nil {
		t.Fatalf("upsert node-b: %v", err)
	}

	got, ok := reg.Get("node-a")
	if !ok {
		t.Fatal("Get node-a: not found")
	}
	if got.NodeID != "node-a" {
		t.Errorf("Get NodeID: got %q, want %q", got.NodeID, "node-a")
	}

	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("List len: got %d, want 2", len(list))
	}
	// List must be sorted by NodeID.
	if list[0].NodeID != "node-a" || list[1].NodeID != "node-b" {
		t.Errorf("List order: got [%q, %q], want [node-a, node-b]",
			list[0].NodeID, list[1].NodeID)
	}
}

func TestUpsert_EmptyNodeID(t *testing.T) {
	reg := NewInMemory()
	_, err := reg.Upsert(Report{})
	if !errors.Is(err, ErrEmptyNodeID) {
		t.Errorf("expected ErrEmptyNodeID, got %v", err)
	}
}

func TestProvenance_StoredAndImmutable(t *testing.T) {
	reg := NewInMemory()

	// First enrollment: provenance set to tok-1.
	_, err := reg.Upsert(Report{NodeID: "node-x", EnrollingTokenID: "tok-1"})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	n, _ := reg.Get("node-x")
	if n.EnrollingTokenID != "tok-1" {
		t.Errorf("after first upsert: EnrollingTokenID got %q, want tok-1", n.EnrollingTokenID)
	}

	// Re-upsert with a different token ID — provenance must not change.
	_, err = reg.Upsert(Report{NodeID: "node-x", EnrollingTokenID: "tok-2"})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	n, _ = reg.Get("node-x")
	if n.EnrollingTokenID != "tok-1" {
		t.Errorf("after re-upsert: EnrollingTokenID got %q, want tok-1 (provenance must be immutable)", n.EnrollingTokenID)
	}
}

func TestImmutabilityBoundary_RelaySurvivesNodeReport(t *testing.T) {
	reg := NewInMemory()

	// Initial upsert with node labels A.
	_, err := reg.Upsert(Report{
		NodeID:     "node-q",
		NodeLabels: map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Relay sets a quarantine label.
	if err := reg.SetRelayLabels("node-q", map[string]string{"quarantine": "true"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	// Node re-upserts with updated node labels B — must not clear relay labels.
	_, err = reg.Upsert(Report{
		NodeID:     "node-q",
		NodeLabels: map[string]string{"env": "staging"},
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	n, _ := reg.Get("node-q")
	if n.RelayLabels["quarantine"] != "true" {
		t.Errorf("RelayLabels[quarantine]: got %q, want %q (node report must not clear relay labels)",
			n.RelayLabels["quarantine"], "true")
	}
	if n.NodeLabels["env"] != "staging" {
		t.Errorf("NodeLabels[env]: got %q, want %q", n.NodeLabels["env"], "staging")
	}
}

func TestImmutabilityBoundary_NodeSurvivesRelaySet(t *testing.T) {
	reg := NewInMemory()

	_, err := reg.Upsert(Report{
		NodeID:     "node-r",
		NodeLabels: map[string]string{"role": "api"},
		Facts:      Facts{Hostname: "host-r", OS: "linux"},
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := reg.SetRelayLabels("node-r", map[string]string{"tier": "critical"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	n, _ := reg.Get("node-r")

	// Node-space must be untouched.
	if n.NodeLabels["role"] != "api" {
		t.Errorf("NodeLabels[role]: got %q, want api", n.NodeLabels["role"])
	}
	if n.Facts.Hostname != "host-r" {
		t.Errorf("Facts.Hostname: got %q, want host-r", n.Facts.Hostname)
	}
	// Relay-space must be set.
	if n.RelayLabels["tier"] != "critical" {
		t.Errorf("RelayLabels[tier]: got %q, want critical", n.RelayLabels["tier"])
	}
}

func TestSetRelayLabels_NotFound(t *testing.T) {
	reg := NewInMemory()
	err := reg.SetRelayLabels("does-not-exist", map[string]string{"k": "v"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateLastSeen_NotFound(t *testing.T) {
	reg := NewInMemory()
	err := reg.UpdateLastSeen("does-not-exist", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateLastSeen(t *testing.T) {
	reg := NewInMemory()
	_, err := reg.Upsert(Report{NodeID: "node-ls"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	newTime := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := reg.UpdateLastSeen("node-ls", newTime); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}

	n, ok := reg.Get("node-ls")
	if !ok {
		t.Fatal("Get: not found")
	}
	if !n.LastSeen.Equal(newTime) {
		t.Errorf("LastSeen: got %v, want %v", n.LastSeen, newTime)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	reg := NewInMemory()

	_, err := reg.Upsert(Report{
		NodeID:     "node-copy",
		NodeLabels: map[string]string{"k": "v"},
		Facts:      Facts{IPAddresses: []string{"192.168.1.1"}},
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := reg.SetRelayLabels("node-copy", map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	got, _ := reg.Get("node-copy")

	// Mutate the returned value.
	got.NodeLabels["k"] = "mutated"
	got.RelayLabels["env"] = "mutated"
	got.Facts.IPAddresses[0] = "0.0.0.0"

	// Store must be unaffected.
	fresh, _ := reg.Get("node-copy")
	if fresh.NodeLabels["k"] != "v" {
		t.Errorf("store NodeLabels mutated: got %q, want v", fresh.NodeLabels["k"])
	}
	if fresh.RelayLabels["env"] != "prod" {
		t.Errorf("store RelayLabels mutated: got %q, want prod", fresh.RelayLabels["env"])
	}
	if fresh.Facts.IPAddresses[0] != "192.168.1.1" {
		t.Errorf("store Facts.IPAddresses mutated: got %q, want 192.168.1.1", fresh.Facts.IPAddresses[0])
	}
}

func TestUpsert_AtCapacity(t *testing.T) {
	// Cap of 2: node-a and node-b succeed; node-c is rejected.
	reg := NewInMemory(WithMaxNodes(2))

	if _, err := reg.Upsert(Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("insert node-a: %v", err)
	}
	if _, err := reg.Upsert(Report{NodeID: "node-b"}); err != nil {
		t.Fatalf("insert node-b: %v", err)
	}

	// Third insert must fail with ErrAtCapacity.
	_, err := reg.Upsert(Report{NodeID: "node-c"})
	if !errors.Is(err, ErrAtCapacity) {
		t.Errorf("third insert: want ErrAtCapacity, got %v", err)
	}
	// Registry must still contain exactly 2 nodes.
	if got := len(reg.List()); got != 2 {
		t.Errorf("after rejected insert: List() len = %d, want 2", got)
	}

	// UPDATE path (node-a already exists) must succeed even at capacity.
	if _, err := reg.Upsert(Report{NodeID: "node-a", CertFingerprint: "fp-new"}); err != nil {
		t.Errorf("update node-a at capacity: %v", err)
	}
	n, _ := reg.Get("node-a")
	if n.CertFingerprint != "fp-new" {
		t.Errorf("update at capacity: CertFingerprint = %q, want fp-new", n.CertFingerprint)
	}

	// Default (no WithMaxNodes) stays unbounded: a 3rd insert into an uncapped
	// registry must succeed.
	unbound := NewInMemory()
	if _, err := unbound.Upsert(Report{NodeID: "n1"}); err != nil {
		t.Fatalf("unbound insert 1: %v", err)
	}
	if _, err := unbound.Upsert(Report{NodeID: "n2"}); err != nil {
		t.Fatalf("unbound insert 2: %v", err)
	}
	if _, err := unbound.Upsert(Report{NodeID: "n3"}); err != nil {
		t.Errorf("unbound insert 3: %v", err)
	}
}

func TestUpsert_NilNodeLabels(t *testing.T) {
	reg := NewInMemory()

	// Upsert with nil NodeLabels — returned map must be non-nil (not panic-able).
	n, err := reg.Upsert(Report{NodeID: "node-nil"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if n.NodeLabels == nil {
		t.Error("NodeLabels must be non-nil on insert with nil report NodeLabels")
	}
	if n.RelayLabels == nil {
		t.Error("RelayLabels must be non-nil on insert")
	}

	// Write to returned maps must not panic.
	n.NodeLabels["x"] = "y"
	n.RelayLabels["x"] = "y"
}
