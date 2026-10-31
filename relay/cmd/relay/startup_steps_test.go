package main

import (
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

type fakeRevokedLister struct {
	ids []string
	err error
}

func (f fakeRevokedLister) RevokedNodeIDs() ([]string, error) { return f.ids, f.err }

func TestRehydrateDenylist_LoadsEveryPersistedRevocation(t *testing.T) {
	d := revocation.NewDenylist()
	if err := rehydrateDenylist(fakeRevokedLister{ids: []string{"n1", "n2"}}, d); err != nil {
		t.Fatalf("rehydrateDenylist: %v", err)
	}
	for _, id := range []string{"n1", "n2"} {
		if !d.IsRevoked(id) {
			t.Errorf("%s not on the denylist after rehydrate", id)
		}
	}
	if d.IsRevoked("n3") {
		t.Error("an unrevoked Node is on the denylist")
	}
}

func TestRehydrateDenylist_WrapsAndReturnsARegistryFailure(t *testing.T) {
	boom := errors.New("boom")
	err := rehydrateDenylist(fakeRevokedLister{err: boom}, revocation.NewDenylist())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the registry failure", err)
	}
}
