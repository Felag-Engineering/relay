package registry_test

import (
	"reflect"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// #440's behavioural tests — EnrolledAt surviving renewal, re-enrollment not
// resetting the join date, zero meaning "not recorded", recording against an
// unknown Node, and connectedness being derived rather than inferred from
// LastSeen — live in registrytest's conformance suite, so they run against
// both InMemory and the SQLite store (TestRepositoryConformance here,
// store.TestSQLiteRegistryConformance there). What stays here is the
// structural half, which is a property of the Report type, not of any
// implementation.

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
