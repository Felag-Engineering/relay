package approval

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

func restart(svc string) jobs.Action {
	return jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "service.restart",
		OperationArgs: map[string]string{"service": svc},
		RiskClass:     jobs.RiskClassMutate,
	}
}

// TestHashPlanIsStableAcrossOrdering: the hash is a property of the Plan, not of
// map iteration or the registry's result ordering. Without this, an approval
// would spuriously stop matching its own dispatch and every Job would re-park.
func TestHashPlanIsStableAcrossOrdering(t *testing.T) {
	a := HashPlan(restart("nginx"), []string{"node-a", "node-b", "node-c"})
	b := HashPlan(restart("nginx"), []string{"node-c", "node-a", "node-b"})
	if a != b {
		t.Errorf("node ordering changed the plan hash:\n %s\n %s", a, b)
	}

	multi := jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "op",
		OperationArgs: map[string]string{"x": "1", "y": "2", "z": "3"},
	}
	first := HashPlan(multi, []string{"n"})
	for i := 0; i < 50; i++ {
		if got := HashPlan(multi, []string{"n"}); got != first {
			t.Fatalf("argument map iteration order changed the hash on attempt %d", i)
		}
	}
}

// TestHashPlanChangesWithFanOut is THE property the approval flow rests on.
// An approval binds to the resolved node set; if the fleet drifts between
// approval and dispatch, the hash must differ so the Job re-parks instead of
// silently landing on Nodes the approver never saw.
func TestHashPlanChangesWithFanOut(t *testing.T) {
	approved := HashPlan(restart("nginx"), []string{"node-a", "node-b", "node-c"})

	grew := HashPlan(restart("nginx"), []string{"node-a", "node-b", "node-c", "node-d"})
	if grew == approved {
		t.Error("a Node joining the fan-out must change the plan hash — otherwise an approval for 3 Nodes silently covers 4")
	}

	shrank := HashPlan(restart("nginx"), []string{"node-a", "node-b"})
	if shrank == approved {
		t.Error("a Node leaving the fan-out must change the plan hash")
	}

	swapped := HashPlan(restart("nginx"), []string{"node-a", "node-b", "node-z"})
	if swapped == approved {
		t.Error("substituting a Node must change the plan hash — same count is not the same blast radius")
	}
}

func TestHashPlanChangesWithAction(t *testing.T) {
	nodes := []string{"node-a"}
	base := HashPlan(restart("nginx"), nodes)

	if HashPlan(restart("sshd"), nodes) == base {
		t.Error("a different argument must change the plan hash")
	}

	other := restart("nginx")
	other.OperationName = "service.stop"
	if HashPlan(other, nodes) == base {
		t.Error("a different Operation must change the plan hash")
	}

	raw := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/systemctl", "restart", "nginx"}, RiskClass: jobs.RiskClassMutate}
	if HashPlan(raw, nodes) == base {
		t.Error("Raw Exec must not collide with a structured Operation")
	}
}

// TestHashPlanEncodingIsUnambiguous: arguments are caller-controlled, so an
// encoding that merely joined fields with a separator could let two different
// Plans hash identically by embedding the separator. The length-prefixed
// encoding is what rules that out.
func TestHashPlanEncodingIsUnambiguous(t *testing.T) {
	one := jobs.Action{Kind: jobs.ActionOperation, OperationName: "op", OperationArgs: map[string]string{"a": "x", "b": "y"}}
	two := jobs.Action{Kind: jobs.ActionOperation, OperationName: "op", OperationArgs: map[string]string{"a": "x\nb=y", "b": ""}}
	if HashPlan(one, []string{"n"}) == HashPlan(two, []string{"n"}) {
		t.Error("an argument containing the field separator must not be able to forge another Plan's hash")
	}

	// argv order is semantic and must never be normalized away.
	a := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"rm", "-rf", "/tmp/x"}}
	b := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"-rf", "rm", "/tmp/x"}}
	if HashPlan(a, []string{"n"}) == HashPlan(b, []string{"n"}) {
		t.Error("argv order is semantic — reordering must change the hash")
	}
}

// TestSummaryNeverUnderstatesBlastRadius: the sample is truncated for
// legibility, but the count is the truth and must always be present.
func TestSummaryNeverUnderstatesBlastRadius(t *testing.T) {
	nodes := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		nodes = append(nodes, string(rune('a'+i%26))+"-node")
	}
	s := Summarize(restart("nginx"), nodes)

	if s.NodeCount != 40 {
		t.Errorf("NodeCount = %d, want 40", s.NodeCount)
	}
	if len(s.SampleNodes) > SampleLimit {
		t.Errorf("SampleNodes = %d, want at most %d", len(s.SampleNodes), SampleLimit)
	}
	line := s.String()
	if !strings.Contains(line, "40 node(s)") {
		t.Errorf("summary %q must state the true node count", line)
	}
	if !strings.Contains(line, "and 30 more") {
		t.Errorf("summary %q must say the sample is truncated", line)
	}
	if !strings.Contains(line, "mutate") {
		t.Errorf("summary %q must state the risk class", line)
	}
	if !strings.Contains(line, "service.restart") {
		t.Errorf("summary %q must name the Operation", line)
	}
}
