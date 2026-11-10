package registry_test

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// TestConnectionObservationWriters_EachHasOnlyItsDefiningCallers pins who may
// call the writers of the connection observations on a Node record: the
// reported Raw Exec state, the first-connect marker and the clock skew. The
// first-connect marker and the skew are Relay-authored. The Raw Exec state is
// the Node's self-report, which the Relay only records as evidence. All three
// are kept apart from Report, so a Node's registration cannot set them
// (invariant 9), and this guard limits who writes them. The tunnel is the one
// production writer; eventsink is a pass-through that decides nothing (invariant 10), and
// registrytest is the shared conformance suite.
//
// MUTATION: call RecordHeartbeat, MarkConnected or RecordPolicySnapshot from
// any other non-test file and this test goes red. TestLabelWriters_Fixtures
// arms the scanner.
func TestConnectionObservationWriters_EachHasOnlyItsDefiningCallers(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// this file is relay/internal/registry/connection_writers_guard_test.go; the
	// module root ("relay/") is three directories up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	want := map[string][]string{
		"RecordHeartbeat": {
			"cmd/relay/tunnel.go",
			"internal/eventsink/eventsink.go",
			"internal/registry/registrytest/conformance.go",
		},
		"MarkConnected": {
			"cmd/relay/tunnel.go",
			"internal/eventsink/eventsink.go",
			"internal/registry/registrytest/conformance.go",
		},
		"RecordPolicySnapshot": {
			"cmd/relay/tunnel.go",
			"internal/eventsink/eventsink.go",
			"internal/registry/registrytest/conformance.go",
		},
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	got, err := selectorUses(root, names...)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, n := range names {
		if !reflect.DeepEqual(got[n], want[n]) {
			t.Errorf("%s callers: got %v, want %v", n, got[n], want[n])
		}
	}
}
