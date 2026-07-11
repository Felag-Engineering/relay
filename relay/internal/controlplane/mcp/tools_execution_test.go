package mcp

import (
	"context"
	"testing"
)

// TestRequirePrincipal_NoPrincipalInContextIsALegibleError is RB4's
// hardening (plan review): the execution tools must never fall through with
// a zero-value capability.Principal when PrincipalFromContext reports !ok.
func TestRequirePrincipal_NoPrincipalInContextIsALegibleError(t *testing.T) {
	if _, err := requirePrincipal(context.Background()); err == nil {
		t.Fatal("requirePrincipal(no principal in context) = nil error, want a legible error (RB4: never dispatch/cancel unattributed)")
	}
}

// TestResolveTimeoutSeconds_RejectsOutOfRange is RB6's concrete bound
// (plan review): timeout_seconds outside [0, maxTimeoutSeconds] is a
// legible rejection, never a silent clamp/overflow on an RCE surface.
func TestResolveTimeoutSeconds_RejectsOutOfRange(t *testing.T) {
	if _, err := resolveTimeoutSeconds(-1); err == nil {
		t.Error("resolveTimeoutSeconds(-1) = nil error, want a rejection")
	}
	if _, err := resolveTimeoutSeconds(maxTimeoutSeconds + 1); err == nil {
		t.Error("resolveTimeoutSeconds(max+1) = nil error, want a rejection")
	}
	if got, err := resolveTimeoutSeconds(0); err != nil || got != 0 {
		t.Errorf("resolveTimeoutSeconds(0) = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := resolveTimeoutSeconds(maxTimeoutSeconds); err != nil || got != maxTimeoutSeconds {
		t.Errorf("resolveTimeoutSeconds(max) = (%d, %v), want (%d, nil)", got, err, maxTimeoutSeconds)
	}
}
