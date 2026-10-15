package revocation_test

import (
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

func TestDenylist_AddIsRevoked(t *testing.T) {
	d := revocation.NewDenylist()

	if d.IsRevoked("node-1") {
		t.Error("unknown node should not be revoked")
	}

	d.Add("node-1")
	if !d.IsRevoked("node-1") {
		t.Error("added node should be revoked")
	}
}

func TestDenylist_UnknownNodeID(t *testing.T) {
	d := revocation.NewDenylist()
	d.Add("node-1")
	if d.IsRevoked("node-2") {
		t.Error("node-2 was not added but is reported as revoked")
	}
}

func TestDenylist_EmptyNodeID(t *testing.T) {
	d := revocation.NewDenylist()
	d.Add("") // must be a no-op, not panic
	if d.IsRevoked("") {
		t.Error("empty node_id should never be revoked")
	}
}

// TestDenylist_ConcurrentAccess exercises the RWMutex under -race.
func TestDenylist_ConcurrentAccess(t *testing.T) {
	d := revocation.NewDenylist()
	const goroutines = 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.Add("node-race")
		}()
		go func() {
			defer wg.Done()
			d.IsRevoked("node-race")
		}()
	}
	wg.Wait()

	// After all concurrent Adds, the node must be denylisted.
	if !d.IsRevoked("node-race") {
		t.Error("node-race should be denylisted after concurrent Adds")
	}
}
