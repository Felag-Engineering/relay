package opvocab

import (
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

// TestOperations_ArgConstraintsPlaceholder pins that ArgConstraints is a
// non-nil empty placeholder this issue (#120 fills in real content), never
// nil (which would render as JSON null instead of {}).
func TestOperations_ArgConstraintsPlaceholder(t *testing.T) {
	for _, d := range Operations() {
		if d.ArgConstraints == nil {
			t.Errorf("Operations()[%q].ArgConstraints is nil, want non-nil empty map", d.Name)
		}
		if len(d.ArgConstraints) != 0 {
			t.Errorf("Operations()[%q].ArgConstraints = %v, want empty (this issue's placeholder)", d.Name, d.ArgConstraints)
		}
	}
}
