package api

import (
	"reflect"
	"strings"
	"testing"
)

// TestDeps_HasNoConfigField is a structural guard for invariant 11: Deps
// must never grow a Relay Config, CA, blast-cap, or listener field. A route
// that could read cfg.ReadBlastCap/MutateBlastCap or the CA key would let
// the Control API raise its own limits or mutate configuration, which
// ADR-0010 forbids. This walks Deps's fields via reflection so the check
// fails the moment such a field is added, without needing to import
// cmd/relay.Config (which .golangci.yml's api-imports rule refuses).
// Proves RC-11.
func TestDeps_HasNoConfigField(t *testing.T) {
	typ := reflect.TypeOf(Deps{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "config") {
			t.Errorf("Deps field %q looks like a Relay Config field — invariant 11 forbids the Control API from touching Relay configuration", f.Name)
		}
		fieldTypeName := f.Type.String()
		if strings.Contains(strings.ToLower(fieldTypeName), "config") {
			t.Errorf("Deps field %q has type %q, which looks like a Relay Config type — invariant 11 forbids the Control API from touching Relay configuration", f.Name, fieldTypeName)
		}
	}
}
