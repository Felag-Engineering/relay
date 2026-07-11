package opvocab

import (
	"sort"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestOperations_Membership pins the v1 vocabulary and each Operation's risk
// class against gleipnir.proto:142-145, so a drift between proto and this
// mirror fails a test rather than silently rendering the wrong risk class in
// list_operations.
func TestOperations_Membership(t *testing.T) {
	want := map[string]jobs.RiskClass{
		"system.facts":    jobs.RiskClassRead,
		"file.read":       jobs.RiskClassRead,
		"service.restart": jobs.RiskClassMutate,
		"pkg.install":     jobs.RiskClassMutate,
	}

	got := Operations()
	if len(got) != len(want) {
		t.Fatalf("Operations(): got %d entries, want %d: %+v", len(got), len(want), got)
	}

	seen := make(map[string]bool)
	for _, d := range got {
		if seen[d.Name] {
			t.Errorf("Operations(): duplicate entry %q", d.Name)
		}
		seen[d.Name] = true

		wantRisk, ok := want[d.Name]
		if !ok {
			t.Errorf("Operations(): unexpected entry %q (Raw Exec must never appear here — it is not an Operation)", d.Name)
			continue
		}
		if d.Risk != wantRisk {
			t.Errorf("Operations()[%q].Risk = %v, want %v", d.Name, d.Risk, wantRisk)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("Operations(): missing entry %q", name)
		}
	}
}

// TestOperations_RiskNeverUnspecified proves every Operation declares a real
// risk class — RiskClassUnspecified would silently defeat blast-radius
// control (ADR-0012).
func TestOperations_RiskNeverUnspecified(t *testing.T) {
	for _, d := range Operations() {
		if d.Risk != jobs.RiskClassRead && d.Risk != jobs.RiskClassMutate {
			t.Errorf("Operations()[%q].Risk = %v, want RiskClassRead or RiskClassMutate", d.Name, d.Risk)
		}
	}
}

// TestOperations_RawExecAbsent pins that Raw Exec never appears in the
// Operation vocabulary (it is not an Operation; ADR-0003/CONTEXT.md).
func TestOperations_RawExecAbsent(t *testing.T) {
	for _, d := range Operations() {
		if d.Name == "raw_exec" || d.Name == "" {
			t.Errorf("Operations() contains %q; Raw Exec must never be listed here", d.Name)
		}
	}
}

// TestOperations_Legible is the mechanical CI floor (#120 deliverable 4) at
// the source: every Descriptor must carry real model-facing legibility prose
// — a non-empty Purpose, a non-empty Example, a real risk class, a non-nil
// ArgConstraints map, and a non-empty constraint string for every documented
// arg — so a future Operation literally cannot compile-and-pass-CI while
// shipping illegible (ADR-0001's typed-path-by-default safety assumption
// depends on this text being present and honest).
//
// system.facts' ArgConstraints is an empty-but-non-nil map: that is
// INTENTIONAL (a zero-arg Operation has nothing to document), not "not yet
// filled" — TestOperations_DocumentedArgKeys separately pins the exact
// documented key set per Operation, so a future Operation with real
// arguments cannot read this test's tolerance of an empty map as license to
// skip documenting them.
func TestOperations_Legible(t *testing.T) {
	for _, d := range Operations() {
		if strings.TrimSpace(d.Purpose) == "" {
			t.Errorf("Operations()[%q].Purpose is empty, want a non-empty description", d.Name)
		}
		if d.Example == "" {
			t.Errorf("Operations()[%q].Example is empty, want a concrete usage example", d.Name)
		}
		if d.Risk != jobs.RiskClassRead && d.Risk != jobs.RiskClassMutate {
			t.Errorf("Operations()[%q].Risk = %v, want RiskClassRead or RiskClassMutate", d.Name, d.Risk)
		}
		if d.ArgConstraints == nil {
			t.Errorf("Operations()[%q].ArgConstraints is nil, want non-nil (empty map for a zero-arg Operation)", d.Name)
			continue
		}
		for arg, constraint := range d.ArgConstraints {
			if strings.TrimSpace(constraint) == "" {
				t.Errorf("Operations()[%q].ArgConstraints[%q] is empty, want documented constraint prose", d.Name, arg)
			}
		}
	}
}

// TestOperations_DocumentedArgKeys pins the exact documented arg-key set per
// Operation against daemon/src/dispatch.rs's OP_ARG_* constants (the keys the
// daemon actually reads out of Operation.args), so opvocab's ArgConstraints
// can never silently drift from what the daemon accepts — neither
// documenting a key the daemon ignores nor omitting one it reads.
func TestOperations_DocumentedArgKeys(t *testing.T) {
	// This exact key set is also asserted in
	// relay/internal/controlplane/mcp/mcp_test.go and mirrors the daemon's
	// OP_ARG_* constants — update all three together.
	want := map[string][]string{
		"system.facts":    {},
		"file.read":       {"path"},
		"service.restart": {"unit"},
		"pkg.install":     {"name", "version"},
	}

	for _, d := range Operations() {
		wantKeys, ok := want[d.Name]
		if !ok {
			t.Errorf("Operations(): unexpected entry %q", d.Name)
			continue
		}
		gotKeys := make([]string, 0, len(d.ArgConstraints))
		for k := range d.ArgConstraints {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(gotKeys)
		sort.Strings(wantKeys)
		if len(gotKeys) != len(wantKeys) {
			t.Errorf("Operations()[%q].ArgConstraints keys = %v, want %v", d.Name, gotKeys, wantKeys)
			continue
		}
		for i := range wantKeys {
			if gotKeys[i] != wantKeys[i] {
				t.Errorf("Operations()[%q].ArgConstraints keys = %v, want %v", d.Name, gotKeys, wantKeys)
				break
			}
		}
	}
}
