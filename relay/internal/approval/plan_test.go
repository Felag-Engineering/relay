package approval

import (
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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

// TestHashPlanEncodingIsUnambiguous is #494's own test: no caller-controlled
// argument value, argument key, or node ID may forge a field boundary or a
// framing count in HashPlan's preimage.
//
// It uses an Operation name opvocab does not know (as shape_test.go's
// injection table does): that is the reachable case — a Template Operation's
// argument keys are exactly the ones neither ValidateArgNames call site
// constrains.
func TestHashPlanEncodingIsUnambiguous(t *testing.T) {
	tmpl := func(args map[string]string) jobs.Action {
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "site.deploy",
			OperationArgs: args, RiskClass: jobs.RiskClassMutate,
		}
	}

	argPairs := []struct {
		name string
		a, b map[string]string
	}{
		{
			// The issue's executed witness. Under the OLD encoding
			// (write("arg."+k, v), which folded the key into the field name)
			// both sides produced the byte-identical field arg.a=5:1=1:x\n
			// and therefore the same PlanHash. They must now hash differently.
			name: "the issue's executed witness",
			a:    map[string]string{"a": "1=1:x"},
			b:    map[string]string{"a=5:1": "x"},
		},
		{
			name: "an argument containing the field separator",
			a:    map[string]string{"a": "x", "b": "y"},
			b:    map[string]string{"a": "x\nb=y", "b": ""},
		},
		{
			name: "an = in the value versus in the key",
			a:    map[string]string{"a": "b=c"},
			b:    map[string]string{"a=b": "c"},
		},
		{
			name: "a value impersonating a second argument field",
			a:    map[string]string{"a": "1", "b": "2"},
			b:    map[string]string{"a": "1\narg.k=1:b\narg.v=1:2"},
		},
		{
			name: "a value impersonating the args count",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"a": "1\nargs=0"},
		},
	}
	for _, p := range argPairs {
		if HashPlan(tmpl(p.a), []string{"n"}) == HashPlan(tmpl(p.b), []string{"n"}) {
			t.Errorf("%s: %v and %v share a plan hash", p.name, p.a, p.b)
		}
	}

	// HashPlan additionally hashes the resolved fan-out — HashPlanShape does
	// not — so the node list gets its own pair of injection cases, mirroring
	// the argument ones above.
	nodePairs := []struct {
		name string
		a, b []string
	}{
		{
			name: "a node ID impersonating a second node field",
			a:    []string{"a", "b"},
			b:    []string{"a\nnode=1:b"},
		},
		{
			name: "a node ID impersonating the nodes count",
			a:    []string{"a"},
			b:    []string{"a\nnodes=0"},
		},
	}
	act := tmpl(map[string]string{"k": "v"})
	for _, p := range nodePairs {
		if HashPlan(act, p.a) == HashPlan(act, p.b) {
			t.Errorf("%s: %v and %v share a plan hash", p.name, p.a, p.b)
		}
	}

	// argv order is semantic and must never be normalized away.
	a := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"rm", "-rf", "/tmp/x"}}
	b := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"-rf", "rm", "/tmp/x"}}
	if HashPlan(a, []string{"n"}) == HashPlan(b, []string{"n"}) {
		t.Error("argv order is semantic — reordering must change the hash")
	}
}

// TestHashPlanIsInjectiveOverDistinctPlans is the injectivity property
// itself: a table of Actions differing only in a field HashPlan hashes —
// kind, risk class, Operation name, argument keys, argument values, argv
// contents, argv order, node set membership, and node set size — including
// adversarial keys, values, and node IDs containing =, :, \n, digits, and the
// empty string. No two entries may collide.
//
// TimeoutSeconds and off-branch fields (RawExecArgv set on an ActionOperation,
// or OperationName/OperationArgs set on an ActionRawExec) are deliberately not
// varied here: the doc comment on HashPlan already excludes the former, and
// the latter are dead by the time anything dispatches (dispatch.taskRequest,
// dispatch.policyQuery switch on Action.Kind with the same branch split), so
// two Actions that hash alike there dispatch identically — not a collision in
// any meaningful sense, and not this test's job to bless or refute.
func TestHashPlanIsInjectiveOverDistinctPlans(t *testing.T) {
	op := func(name string, args map[string]string, risk jobs.RiskClass) jobs.Action {
		return jobs.Action{Kind: jobs.ActionOperation, OperationName: name, OperationArgs: args, RiskClass: risk}
	}
	raw := func(argv []string, risk jobs.RiskClass) jobs.Action {
		return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: argv, RiskClass: risk}
	}
	baseArgs := map[string]string{"a": "1", "b": "2"}
	baseNodes := []string{"node-a", "node-b"}

	cases := map[string]struct {
		act   jobs.Action
		nodes []string
	}{
		"base":                        {op("site.deploy", baseArgs, jobs.RiskClassMutate), baseNodes},
		"different kind":              {raw([]string{"a", "1"}, jobs.RiskClassMutate), baseNodes},
		"different risk class":        {op("site.deploy", baseArgs, jobs.RiskClassRead), baseNodes},
		"different operation name":    {op("site.other", baseArgs, jobs.RiskClassMutate), baseNodes},
		"different argument key":      {op("site.deploy", map[string]string{"c": "1", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"different argument value":    {op("site.deploy", map[string]string{"a": "9", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"extra argument":              {op("site.deploy", map[string]string{"a": "1", "b": "2", "c": "3"}, jobs.RiskClassMutate), baseNodes},
		"empty argument key":          {op("site.deploy", map[string]string{"": "1", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"empty argument value":        {op("site.deploy", map[string]string{"a": "", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"argument key with = : \\n":   {op("site.deploy", map[string]string{"a=1:x\ny": "1", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"argument value with = : \\n": {op("site.deploy", map[string]string{"a": "1=1:x\ny", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"digit-heavy argument key":    {op("site.deploy", map[string]string{"12": "1", "b": "2"}, jobs.RiskClassMutate), baseNodes},
		"different argv contents":     {raw([]string{"a", "2"}, jobs.RiskClassMutate), baseNodes},
		"different argv order":        {raw([]string{"1", "a"}, jobs.RiskClassMutate), baseNodes},
		"argv split vs concatenated":  {raw([]string{"a1"}, jobs.RiskClassMutate), baseNodes},
		"empty argv element":          {raw([]string{"a", "1", ""}, jobs.RiskClassMutate), baseNodes},
		"argv element with = : \\n":   {raw([]string{"a=1:x\ny", "1"}, jobs.RiskClassMutate), baseNodes},
		"different node membership":   {op("site.deploy", baseArgs, jobs.RiskClassMutate), []string{"node-a", "node-z"}},
		"different node set size":     {op("site.deploy", baseArgs, jobs.RiskClassMutate), []string{"node-a", "node-b", "node-c"}},
		"empty node ID":               {op("site.deploy", baseArgs, jobs.RiskClassMutate), []string{"", "node-b"}},
		"node ID with = : \\n":        {op("site.deploy", baseArgs, jobs.RiskClassMutate), []string{"node=1:x\ny", "node-b"}},
	}

	seen := make(map[string]string, len(cases))
	for name, c := range cases {
		key := HashPlan(c.act, c.nodes)
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share a plan hash", name, other)
		}
		seen[key] = name
	}
}

// TestHashPlanIgnoresNilVersusEmptyOperationArgs makes explicit an edge a
// future reviewer could otherwise mistake for a bug in the injectivity table
// above: a nil OperationArgs map and a non-nil empty one describe the SAME
// Action — zero arguments, either way — and must hash IDENTICALLY. Both are
// deliberately absent from TestHashPlanIsInjectiveOverDistinctPlans's
// distinctness table, because asserting them there would assert the opposite
// of what is actually true.
func TestHashPlanIgnoresNilVersusEmptyOperationArgs(t *testing.T) {
	nilArgs := jobs.Action{Kind: jobs.ActionOperation, OperationName: "site.deploy", OperationArgs: nil, RiskClass: jobs.RiskClassMutate}
	emptyArgs := jobs.Action{Kind: jobs.ActionOperation, OperationName: "site.deploy", OperationArgs: map[string]string{}, RiskClass: jobs.RiskClassMutate}

	nodes := []string{"node-a"}
	if HashPlan(nilArgs, nodes) != HashPlan(emptyArgs, nodes) {
		t.Error("a nil OperationArgs map and a non-nil empty one hashed differently; they describe the same Action")
	}
}

// TestPlanHashAndScopeHashNeverCollide: HashPlan and HashScope both write into
// the same approval_requests.plan_hash column, and ByPlanHash
// (capability/approval.go) is the release lookup — a collision between the
// two spaces would let an approved GRANT REQUEST release an ordinary
// dispatch. Modeled on TestPlanAndGrantShapesNeverCollide (shape_test.go).
//
// The loop below sweeps a bounded range of jobs.ActionKind values, including
// a few out-of-range ones, but a bounded sweep can never be exhaustive over
// every int the Go type permits — a future `case jobs.ActionKind(7): return
// "grant"` outside this range would slip past it undetected. The real
// guarantee this test rests on is ActionKindName's default arm (plan.go):
// every kind this build does not explicitly recognize falls through to that
// arm, which returns the literal "unspecified", never "grant". That is what
// makes "grant" exclusively HashScope's own literal "kind" field value
// (grant.go), so the two preimage spaces diverge at byte zero for every
// ActionKind this build can produce or ever read back from storage. The
// second assertion below pins that default-arm literal directly, using a
// kind value chosen to be far outside any plausible named constant so it is
// guaranteed to hit default regardless of how many named cases exist by the
// time this test runs; the bounded sweep is defense in depth on top of it,
// not the guarantee itself.
func TestPlanHashAndScopeHashNeverCollide(t *testing.T) {
	for k := jobs.ActionKind(-2); k <= 5; k++ {
		if name := ActionKindName(k); name == "grant" {
			t.Errorf("ActionKindName(%d) = %q, want anything but \"grant\" — HashScope reserves that kind value", int(k), name)
		}
	}

	if name := ActionKindName(jobs.ActionKind(1 << 20)); name != "unspecified" {
		t.Errorf("ActionKindName(1<<20) = %q, want %q — this pins the switch's default arm, "+
			"which is the actual guarantee this test relies on, not the bounded sweep above", name, "unspecified")
	}

	// One sampled digest inequality on top of the structural proof above.
	planHash := HashPlan(restart("nginx"), []string{"node-a"})
	scopeHash := HashScope(Scope{
		Account: "acct", RiskClass: jobs.RiskClassMutate,
		Operations: []string{"service.restart"}, MaxFanOut: 10,
	}, t0, t0.Add(time.Hour), 5)
	if planHash == scopeHash {
		t.Error("a HashPlan digest collided with a HashScope digest")
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
