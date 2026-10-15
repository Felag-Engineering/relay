package registry_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// statelabels_test.go is the structural assertion that NO ACCOUNT OF ANY
// ROLE can write a `state:` label (ADR-0034 decision 1). It mirrors
// TestReport_CannotCarryRelayKnowledge's (provenance_test.go) reflect-over-
// the-struct pattern, extended to the registry's write INTERFACE as well:
// there is nowhere to put a state label and no method that could set one, so
// "nobody can write one" is enforced by absence rather than a permission
// check.
//
// The complementary read-side assertion — a forged node:/relay: label can
// never satisfy a state: Selector term — lives in
// capability/selector_test.go (TestSelectorMatchesStateNeverReadsForgedLabels),
// beside the Selector code that would otherwise be tempted to read one. The
// security-lane assertion — state: is never a valid target for a relay:
// write — is explicitly NOT here; it lands on the write path in #430
// (ADR-0034, final Consequence).

// stateLabelFieldNames are the names a state-label field on Node or Report
// might plausibly have been given. None of them may exist.
var stateLabelFieldNames = []string{"StateLabels", "State", "StateLabel"}

func TestNode_HasNoStateLabelField(t *testing.T) {
	rt := reflect.TypeOf(registry.Node{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		for _, bad := range stateLabelFieldNames {
			if name == bad {
				t.Errorf("registry.Node has a %s field — state: labels are evaluated at Selector-resolution "+
					"time (ADR-0034) and must never be stored", name)
			}
		}
	}
}

func TestReport_HasNoStateLabelField(t *testing.T) {
	rt := reflect.TypeOf(registry.Report{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		for _, bad := range stateLabelFieldNames {
			if name == bad {
				t.Errorf("registry.Report has a %s field — a daemon must not be able to report a state: label "+
					"any more than it can report a relay: one", name)
			}
		}
	}
}

// TestRepository_HasNoStateLabelWriter reflects over the Repository
// INTERFACE and fails on any method whose name contains "State". The
// registry's write surface is the only way a Relay-side actor reaches a
// Node record; there is no SetStateLabels to authorize, so this is enforced
// by the absence of a method rather than a permission check.
func TestRepository_HasNoStateLabelWriter(t *testing.T) {
	rt := reflect.TypeOf((*registry.Repository)(nil)).Elem()
	for i := 0; i < rt.NumMethod(); i++ {
		name := rt.Method(i).Name
		if strings.Contains(name, "State") {
			t.Errorf("registry.Repository has a %s method — state: labels are derived, never written; "+
				"there must be no method through which any Account, of any role, could set one", name)
		}
	}
}
