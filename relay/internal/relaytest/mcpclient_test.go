package relaytest

import "testing"

// TestElicitingClientOptions_AdvertisesElicitationAndDisablesAutoFulfil is a
// pure data assertion — no network. The wire behaviour (an input-required
// result reaching a client built this way unchanged) is proved by the
// cmd/relay smoke test (#721).
func TestElicitingClientOptions_AdvertisesElicitationAndDisablesAutoFulfil(t *testing.T) {
	opts := ElicitingClientOptions()

	if opts.Capabilities == nil || opts.Capabilities.Elicitation == nil || opts.Capabilities.Elicitation.Form == nil {
		t.Fatalf("ElicitingClientOptions().Capabilities = %+v, want a form elicitation capability advertised", opts.Capabilities)
	}
	if opts.MultiRoundTrip == nil || !opts.MultiRoundTrip.Disabled {
		t.Fatalf("ElicitingClientOptions().MultiRoundTrip = %+v, want Disabled=true so an input-required "+
			"result reaches the caller instead of being auto-fulfilled", opts.MultiRoundTrip)
	}

	// Two calls must return distinct pointers, so a caller mutating one (to
	// add URL elicitation or an ElicitationHandler) cannot affect another
	// test's client.
	other := ElicitingClientOptions()
	if opts == other {
		t.Fatal("ElicitingClientOptions() returned the same pointer twice, want a fresh value per call")
	}
	if opts.Capabilities == other.Capabilities {
		t.Fatal("ElicitingClientOptions() returned the same Capabilities pointer twice, want a fresh value per call")
	}
}
