package registry_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// enrolled is a Node in the registry, ready to have provenance recorded.
func enrolled(t *testing.T, r registry.Repository, nodeID string) {
	t.Helper()
	if _, err := r.Upsert(registry.Report{NodeID: nodeID, CertFingerprint: "fp-1"}); err != nil {
		t.Fatalf("upsert %s: %v", nodeID, err)
	}
}

// TestProvenance_EnrolledAtSurvivesEveryRenewal is #440's central acceptance
// criterion, and the reason RecordEnrollment and RecordRenewal are two methods
// rather than one with a flag.
//
// Renewal is certificate-authenticated and preserves node_id, so a Node's join
// date anchors an unbroken chain back to the Enrollment Token it joined with. A
// renewal that rewrote it would erase the provenance the record exists for —
// and would do it silently, since the value would still look perfectly
// plausible.
func TestProvenance_EnrolledAtSurvivesEveryRenewal(t *testing.T) {
	r := registry.NewInMemory()
	enrolled(t, r, "node-a")

	joined := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	firstExpiry := joined.Add(14 * 24 * time.Hour)
	if err := r.RecordEnrollment("node-a", registry.Certificate{Fingerprint: "fp-1", NotAfter: firstExpiry}, joined); err != nil {
		t.Fatalf("RecordEnrollment: %v", err)
	}

	n, _ := r.Get("node-a")
	if !n.EnrolledAt.Equal(joined) {
		t.Fatalf("EnrolledAt = %v, want %v", n.EnrolledAt, joined)
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

		n, _ := r.Get("node-a")
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
}

// TestProvenance_ReEnrollmentDoesNotResetTheJoinDate — a daemon reinstall that
// re-enrolls an existing node_id has not joined the fleet a second time.
func TestProvenance_ReEnrollmentDoesNotResetTheJoinDate(t *testing.T) {
	r := registry.NewInMemory()
	enrolled(t, r, "node-a")

	joined := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	later := joined.Add(90 * 24 * time.Hour)
	cert := registry.Certificate{Fingerprint: "fp-1", NotAfter: later}

	_ = r.RecordEnrollment("node-a", cert, joined)
	_ = r.RecordEnrollment("node-a", cert, later)

	n, _ := r.Get("node-a")
	if !n.EnrolledAt.Equal(joined) {
		t.Errorf("EnrolledAt = %v, want the first join %v", n.EnrolledAt, joined)
	}
}

// TestProvenance_ZeroMeansNotRecordedNotTheEpoch.
//
// A Node enrolled before this landed carries no provenance until its next
// renewal. Every surface must be able to tell that apart from an identity that
// expired in 1970, which would render as catastrophically overdue on the one
// screen that warns before a Node silently leaves the fleet.
func TestProvenance_ZeroMeansNotRecordedNotTheEpoch(t *testing.T) {
	r := registry.NewInMemory()
	enrolled(t, r, "node-legacy")

	n, _ := r.Get("node-legacy")
	if n.CertProvenanceKnown() {
		t.Fatal("a Node with no recorded provenance reports it as known")
	}
	if !n.CertNotAfter.IsZero() {
		t.Errorf("CertNotAfter = %v, want the zero time", n.CertNotAfter)
	}

	_ = r.RecordEnrollment("node-legacy", registry.Certificate{NotAfter: time.Now().Add(time.Hour)}, time.Now())
	n, _ = r.Get("node-legacy")
	if !n.CertProvenanceKnown() {
		t.Error("provenance was recorded but does not report as known")
	}
}

// TestProvenance_RecordingAgainstAnUnknownNodeFails — silently succeeding would
// mean an enrollment race quietly dropped a Node's expiry on the floor.
func TestProvenance_RecordingAgainstAnUnknownNodeFails(t *testing.T) {
	r := registry.NewInMemory()
	cert := registry.Certificate{NotAfter: time.Now()}
	if err := r.RecordEnrollment("ghost", cert, time.Now()); err == nil {
		t.Error("RecordEnrollment on an unknown Node returned nil")
	}
	if err := r.RecordRenewal("ghost", cert, time.Now()); err == nil {
		t.Error("RecordRenewal on an unknown Node returned nil")
	}
}

// TestConnected_IsNotInferredFromLastSeen is the liveness half of #440.
//
// A Node that reported four seconds ago and then dropped its stream is
// unreachable for dispatch NOW — ADR-0004 resolves such a Task `unreachable`
// without sending it. A registry that guessed from LastSeen would tell an
// operator the fleet is healthier than the dispatcher believes it is.
func TestConnected_IsNotInferredFromLastSeen(t *testing.T) {
	r := registry.NewInMemory()
	enrolled(t, r, "node-a")

	if err := r.UpdateLastSeen("node-a", time.Now()); err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	n, _ := r.Get("node-a")
	if n.Connected {
		t.Error("a Node that has never opened a Tunnel reports connected because it was seen recently")
	}

	r.SetConnected("node-a", true)
	if n, _ := r.Get("node-a"); !n.Connected {
		t.Error("a Node with an open Tunnel reports disconnected")
	}

	// A stream close flips the answer immediately — no timeout involved.
	r.SetConnected("node-a", false)
	if n, _ := r.Get("node-a"); n.Connected {
		t.Error("a closed stream did not flip connectedness; the fleet view would show a green dot for an unreachable Node")
	}
}

// TestConnected_IsNeverStored — connectedness must not survive the process that
// observed it.
func TestConnected_IsNeverStored(t *testing.T) {
	r := registry.NewInMemory()
	enrolled(t, r, "node-a")
	r.SetConnected("node-a", true)

	// List and Get agree, and both derive rather than read a stored field.
	if n, _ := r.Get("node-a"); !n.Connected {
		t.Fatal("Get does not report connected")
	}
	for _, n := range r.List() {
		if n.NodeID == "node-a" && !n.Connected {
			t.Error("List and Get disagree about connectedness")
		}
	}

	// Report is the daemon's input. It must have no way to claim connectedness
	// — or anything else in this record.
	if _, err := r.Upsert(registry.Report{NodeID: "node-a", CertFingerprint: "fp-2"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if n, _ := r.Get("node-a"); !n.Connected {
		t.Error("a Hello Upsert cleared connectedness — it is the transport's fact, not the report's")
	}
}

// TestReport_CannotCarryRelayKnowledge is the structural half: registry.Report
// is the ONLY thing a daemon supplies, and none of #440's fields may appear on
// it. Mirrors the existing guarantee for RelayLabels and RevokedAt.
//
// The Relay minted the certificate. A daemon that could report its own expiry
// could claim an identity that never lapses.
func TestReport_CannotCarryRelayKnowledge(t *testing.T) {
	forbidden := []string{"CertNotAfter", "EnrolledAt", "RenewalCount", "LastRenewedAt", "Connected", "RevokedAt", "RelayLabels"}
	rt := reflect.TypeOf(registry.Report{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		for _, bad := range forbidden {
			if name == bad {
				t.Errorf("registry.Report has a %s field — a daemon must not be able to report Relay-knowledge", bad)
			}
		}
	}
}
