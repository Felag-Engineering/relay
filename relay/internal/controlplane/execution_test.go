package controlplane

import "testing"

// TestResolveTimeoutSeconds_RejectsOutOfRange is RB6's concrete bound
// (plan review): timeout_seconds outside [0, MaxTimeoutSeconds] is a
// legible rejection, never a silent clamp/overflow on an RCE surface.
func TestResolveTimeoutSeconds_RejectsOutOfRange(t *testing.T) {
	if _, err := ResolveTimeoutSeconds(-1); err == nil {
		t.Error("ResolveTimeoutSeconds(-1) = nil error, want a rejection")
	}
	if _, err := ResolveTimeoutSeconds(MaxTimeoutSeconds + 1); err == nil {
		t.Error("ResolveTimeoutSeconds(max+1) = nil error, want a rejection")
	}
	if got, err := ResolveTimeoutSeconds(0); err != nil || got != 0 {
		t.Errorf("ResolveTimeoutSeconds(0) = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := ResolveTimeoutSeconds(MaxTimeoutSeconds); err != nil || got != MaxTimeoutSeconds {
		t.Errorf("ResolveTimeoutSeconds(max) = (%d, %v), want (%d, nil)", got, err, MaxTimeoutSeconds)
	}
}
