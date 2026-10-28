package capability

import (
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func TestResolveAPITokenTTL_HumanDefaultsToSevenDays(t *testing.T) {
	got, err := ResolveAPITokenTTL(accounts.KindHuman, DefaultAPITokenLifetime())
	if err != nil {
		t.Fatalf("ResolveAPITokenTTL: %v", err)
	}
	if got != 7*24*time.Hour {
		t.Errorf("ttl = %v, want 168h", got)
	}
}

func TestResolveAPITokenTTL_MachineHasNoDefault(t *testing.T) {
	for _, kind := range []accounts.Kind{accounts.KindMachine, ""} {
		if _, err := ResolveAPITokenTTL(kind, DefaultAPITokenLifetime()); !errors.Is(err, ErrAPITokenTTLRequired) {
			t.Errorf("kind %q: err = %v, want ErrAPITokenTTLRequired", kind, err)
		}
	}
}

func TestResolveAPITokenTTL_ExplicitIsKeptIncludingZero(t *testing.T) {
	for _, kind := range []accounts.Kind{accounts.KindHuman, accounts.KindMachine} {
		for _, ttl := range []time.Duration{0, time.Hour, -time.Second} {
			got, err := ResolveAPITokenTTL(kind, ExplicitAPITokenLifetime(ttl))
			if err != nil || got != ttl {
				t.Errorf("kind %q ttl %v: got %v, %v; want it unchanged", kind, ttl, got, err)
			}
		}
	}
}
