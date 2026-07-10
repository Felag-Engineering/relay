package policyview

import "testing"

func TestCache_SetGet_RoundTrip(t *testing.T) {
	c := New()
	want := Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: "sha256:abc123",
	}

	c.Set("node-1", want)

	got, ok := c.Get("node-1")
	if !ok {
		t.Fatal("Get(node-1): ok = false, want true")
	}
	if got.RawExecEnabled != want.RawExecEnabled {
		t.Errorf("RawExecEnabled = %v, want %v", got.RawExecEnabled, want.RawExecEnabled)
	}
	if got.PolicyFingerprint != want.PolicyFingerprint {
		t.Errorf("PolicyFingerprint = %q, want %q", got.PolicyFingerprint, want.PolicyFingerprint)
	}
	if len(got.RawAllowPatterns) != 1 || got.RawAllowPatterns[0] != want.RawAllowPatterns[0] {
		t.Errorf("RawAllowPatterns = %v, want %v", got.RawAllowPatterns, want.RawAllowPatterns)
	}
	if len(got.RawDenyPatterns) != 1 || got.RawDenyPatterns[0] != want.RawDenyPatterns[0] {
		t.Errorf("RawDenyPatterns = %v, want %v", got.RawDenyPatterns, want.RawDenyPatterns)
	}
	if len(got.AllowedOperations) != 2 {
		t.Errorf("AllowedOperations = %v, want 2 entries", got.AllowedOperations)
	}
}

func TestCache_Get_MissingKey(t *testing.T) {
	c := New()

	got, ok := c.Get("no-such-node")
	if ok {
		t.Fatalf("Get(no-such-node): ok = true, want false; got %+v", got)
	}
	if got.PolicyFingerprint != "" || got.RawExecEnabled || len(got.RawAllowPatterns) != 0 ||
		len(got.RawDenyPatterns) != 0 || len(got.AllowedOperations) != 0 {
		t.Errorf("Get(no-such-node): got %+v, want zero value", got)
	}
}

// TestCache_Set_CopyIsolation proves Set deep-copies its input: mutating the
// caller's slice after Set must not reach the cached value.
func TestCache_Set_CopyIsolation(t *testing.T) {
	c := New()
	allow := []string{"pattern-a"}
	c.Set("node-1", Snapshot{RawAllowPatterns: allow})

	allow[0] = "mutated"

	got, ok := c.Get("node-1")
	if !ok {
		t.Fatal("Get(node-1): ok = false, want true")
	}
	if got.RawAllowPatterns[0] != "pattern-a" {
		t.Errorf("RawAllowPatterns[0] = %q, want %q (Set must copy, not alias)", got.RawAllowPatterns[0], "pattern-a")
	}
}

// TestCache_Get_CopyIsolation proves Get returns a copy: mutating the
// returned Snapshot's slices must not reach the cached value.
func TestCache_Get_CopyIsolation(t *testing.T) {
	c := New()
	c.Set("node-1", Snapshot{RawDenyPatterns: []string{"pattern-a"}})

	got, ok := c.Get("node-1")
	if !ok {
		t.Fatal("Get(node-1): ok = false, want true")
	}
	got.RawDenyPatterns[0] = "mutated"

	got2, ok := c.Get("node-1")
	if !ok {
		t.Fatal("second Get(node-1): ok = false, want true")
	}
	if got2.RawDenyPatterns[0] != "pattern-a" {
		t.Errorf("RawDenyPatterns[0] = %q, want %q (Get must copy, not alias)", got2.RawDenyPatterns[0], "pattern-a")
	}
}

func TestCache_Set_Overwrites(t *testing.T) {
	c := New()
	c.Set("node-1", Snapshot{PolicyFingerprint: "first"})
	c.Set("node-1", Snapshot{PolicyFingerprint: "second"})

	got, ok := c.Get("node-1")
	if !ok {
		t.Fatal("Get(node-1): ok = false, want true")
	}
	if got.PolicyFingerprint != "second" {
		t.Errorf("PolicyFingerprint = %q, want %q (Set must overwrite, not merge)", got.PolicyFingerprint, "second")
	}
}
