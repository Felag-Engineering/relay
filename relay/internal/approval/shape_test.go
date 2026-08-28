package approval

import (
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// shapeSel is a known, one-term Selector — the ordinary case these tests hold
// fixed while they vary the Action.
var shapeSel = SelectorShape{
	Known: true,
	Terms: []SelectorTerm{{Namespace: "node", Key: "role", Value: "web"}},
}

// known wraps terms as a Selector that was actually seen, so a test never
// accidentally compares against the "no Selector known" key.
func known(terms ...SelectorTerm) SelectorShape {
	return SelectorShape{Known: true, Terms: terms}
}

func restartUnit(unit string) jobs.Action {
	return jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "service.restart",
		OperationArgs: map[string]string{"unit": unit},
		RiskClass:     jobs.RiskClassMutate,
	}
}

// TestPlanShape_IgnoresFanOut is acceptance 1a: the shape key is the same
// action over one Node and over two thousand, while the PLAN hash — the thing
// that actually releases a dispatch — is not.
//
// Both hashes are computed here rather than read off a Request, because
// NewRequest takes its plan hash as a parameter: asserting on that would be
// asserting on the test's own arguments.
func TestPlanShape_IgnoresFanOut(t *testing.T) {
	act := restartUnit("nginx")

	one := []string{"node-a"}
	many := make([]string, 0, 2000)
	for i := range 2000 {
		many = append(many, "node-"+strconv.Itoa(i))
	}

	small := NewRequest("req-1", HashPlan(act, one), "acct", "mike", act, one, shapeSel, nil, req(1, true), t0)
	large := NewRequest("req-2", HashPlan(act, many), "acct", "mike", act, many, shapeSel, nil, req(1, true), t0)

	if small.ShapeKey != large.ShapeKey {
		t.Errorf("shape key changed with fan-out: %q vs %q", small.ShapeKey, large.ShapeKey)
	}
	if small.PlanHash == large.PlanHash {
		t.Error("plan hash did NOT change with fan-out — the release binding stopped covering the resolved Node set")
	}
}

// TestPlanShape_DistinguishesOperationRiskAndShapeArgs is acceptance 1b: two
// materially different actions never share a key.
func TestPlanShape_DistinguishesOperationRiskAndShapeArgs(t *testing.T) {
	rawExec := func(argv ...string) jobs.Action {
		return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: argv, RiskClass: jobs.RiskClassMutate}
	}
	read := func(path string) jobs.Action {
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "file.read",
			OperationArgs: map[string]string{"path": path}, RiskClass: jobs.RiskClassRead,
		}
	}

	keys := map[string]string{
		"restart nginx":     HashPlanShape(restartUnit("nginx"), shapeSel),
		"restart sshd":      HashPlanShape(restartUnit("sshd"), shapeSel),
		"read os-release":   HashPlanShape(read("/etc/os-release"), shapeSel),
		"read shadow":       HashPlanShape(read("/etc/shadow"), shapeSel),
		"raw exec restart":  HashPlanShape(rawExec("service.restart", "nginx"), shapeSel),
		"raw exec reversed": HashPlanShape(rawExec("nginx", "service.restart"), shapeSel),
		// Same Operation and arguments, different risk class: the class picks
		// the blast cap, so it is never cosmetic (invariant 13).
		"restart nginx as read": HashPlanShape(jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "service.restart",
			OperationArgs: map[string]string{"unit": "nginx"}, RiskClass: jobs.RiskClassRead,
		}, shapeSel),
	}

	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share a shape key", name, other)
		}
		seen[key] = name
	}
}

// TestPlanShape_IgnoresScaleArgs: pkg.install's version is declared SCALE
// (D10's canonical "argument expected to vary"), so a rollout's steps share a
// key and the diff can say "same as Tuesday, except 1.24.0 -> 1.25.0". The
// package name is shape and must not.
func TestPlanShape_IgnoresScaleArgs(t *testing.T) {
	install := func(name, version string) jobs.Action {
		args := map[string]string{"name": name}
		if version != "" {
			args["version"] = version
		}
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "pkg.install",
			OperationArgs: args, RiskClass: jobs.RiskClassMutate,
		}
	}

	if HashPlanShape(install("nginx", "1.24.0"), shapeSel) != HashPlanShape(install("nginx", "1.25.0"), shapeSel) {
		t.Error("pkg.install's version changed the shape key; it is declared scale")
	}
	if HashPlanShape(install("nginx", "1.24.0"), shapeSel) != HashPlanShape(install("nginx", ""), shapeSel) {
		t.Error("omitting a scale argument changed the shape key")
	}
	if HashPlanShape(install("nginx", "1.24.0"), shapeSel) == HashPlanShape(install("apache", "1.24.0"), shapeSel) {
		t.Error("two different packages share a shape key; the package name is shape")
	}
}

// TestPlanShape_UnknownOperationTreatsEveryArgAsShape: a Template Operation
// (ADR-0021) has declared nothing, so nothing may be dropped.
func TestPlanShape_UnknownOperationTreatsEveryArgAsShape(t *testing.T) {
	tmpl := func(args map[string]string) jobs.Action {
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "site.deploy",
			OperationArgs: args, RiskClass: jobs.RiskClassMutate,
		}
	}

	// "version" is scale for pkg.install; for an Operation this build does not
	// know, it is not classified at all and must stay in the key.
	a := HashPlanShape(tmpl(map[string]string{"name": "site", "version": "1.24.0"}), shapeSel)
	b := HashPlanShape(tmpl(map[string]string{"name": "site", "version": "1.25.0"}), shapeSel)
	if a == b {
		t.Error("an unclassified argument was dropped from an unknown Operation's shape key")
	}
}

// TestPlanShape_ArgumentSeparatorInjection is the encoding's whole point.
//
// The witness is a REAL collision in the older HashPlan construction, which
// writes the argument key inside the field name (write("arg."+k, v)):
//
//	{"a": "1=1:x"}  ->  arg.a=5:1=1:x\n
//	{"a=5:1": "x"}  ->  arg.a=5:1=1:x\n     byte-identical
//
// HashPlanShape writes the key and the value as SEPARATE length-prefixed
// fields, so no argument value can forge a key boundary. (The HashPlan
// collision itself is live on stored records and is escalated as #494; this
// test asserts only that the new encoding does not inherit it.)
func TestPlanShape_ArgumentSeparatorInjection(t *testing.T) {
	tmpl := func(args map[string]string) jobs.Action {
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "site.deploy",
			OperationArgs: args, RiskClass: jobs.RiskClassMutate,
		}
	}

	pairs := []struct {
		name string
		a, b map[string]string
	}{
		{
			name: "the HashPlan witness",
			a:    map[string]string{"a": "1=1:x"},
			b:    map[string]string{"a=5:1": "x"},
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

	for _, p := range pairs {
		if HashPlanShape(tmpl(p.a), shapeSel) == HashPlanShape(tmpl(p.b), shapeSel) {
			t.Errorf("%s: %v and %v share a shape key", p.name, p.a, p.b)
		}
	}
}

// TestPlanShape_SelectorTermInjection is invariant 7's half: no Selector text
// can forge a namespace boundary, because the namespace is its own field.
func TestPlanShape_SelectorTermInjection(t *testing.T) {
	act := restartUnit("nginx")

	twoTerms := known(
		SelectorTerm{Namespace: "node", Key: "a", Value: "b"},
		SelectorTerm{Namespace: "node", Key: "c", Value: "d"},
	)
	oneJoinedTerm := known(SelectorTerm{Namespace: "node", Key: "a", Value: "b,node:c=d"})
	if HashPlanShape(act, twoTerms) == HashPlanShape(act, oneJoinedTerm) {
		t.Error("two terms and one term spelling them as text share a shape key")
	}

	// The security-lane case: a tag: term whose KEY reads "relay:q" must never
	// collide with the relay: term it imitates (ADR-0006, ADR-0020, invariant
	// 7). Two Selectors that target different Nodes may not share a key.
	tagImitatingRelay := known(SelectorTerm{Namespace: "tag", Key: "relay:q", Value: "on"})
	realRelay := known(SelectorTerm{Namespace: "relay", Key: "q", Value: "on"})
	if HashPlanShape(act, tagImitatingRelay) == HashPlanShape(act, realRelay) {
		t.Error("a tag: term forged a relay: shape key — the security lane blurred")
	}

	// A namespace token spelled into a key or a value stays data.
	if HashPlanShape(act, known(SelectorTerm{Namespace: "node", Key: "a", Value: "b"})) ==
		HashPlanShape(act, known(SelectorTerm{Namespace: "node", Key: "a", Value: "b\nsel.ns=5:relay"})) {
		t.Error("a value impersonating a namespace field shares a shape key")
	}
}

// TestPlanShape_TermOrderWhitespaceAndDuplicates is acceptance 2's unit half.
func TestPlanShape_TermOrderWhitespaceAndDuplicates(t *testing.T) {
	act := restartUnit("nginx")
	a := SelectorTerm{Namespace: "node", Key: "role", Value: "web"}
	b := SelectorTerm{Namespace: "node", Key: "env", Value: "prod"}

	same := []SelectorShape{
		known(a, b),
		known(b, a),
		known(a, b, a),
		known(a, a, b, b),
	}
	want := HashPlanShape(act, same[0])
	for i, sel := range same {
		if got := HashPlanShape(act, sel); got != want {
			t.Errorf("terms %d (%v) hashed to %q, want %q", i, sel.Terms, got, want)
		}
	}

	// A known Selector with no terms is the FLEET-WIDE dispatch, and it must be
	// its own shape — neither the two-term one nor the "no Selector known" one.
	fleetWide := SelectorShape{Known: true}
	unknown := SelectorShape{}
	if HashPlanShape(act, fleetWide) == want {
		t.Error("the fleet-wide Selector shares a key with a two-term one")
	}
	if HashPlanShape(act, fleetWide) == HashPlanShape(act, unknown) {
		t.Error("a fleet-wide Selector and an unknown one share a key; the widest dispatch there is would group with a record nobody can describe")
	}
	if HashPlanShape(act, SelectorShape{Known: true, Terms: []SelectorTerm{}}) != HashPlanShape(act, fleetWide) {
		t.Error("a nil term slice and an empty one hash differently")
	}

	// Same namespace and key, DIFFERENT values: contradictory, matches nothing,
	// and never folded into one term. BOTH halves must be checked — the sort
	// puts "db" first, so a dedupe widened to key-only would collapse
	// {web, db} to {db} and pass a comparison against {web} alone.
	contradictory := known(a, SelectorTerm{Namespace: "node", Key: "role", Value: "db"})
	if HashPlanShape(act, contradictory) == HashPlanShape(act, known(a)) {
		t.Error("node:role=web,node:role=db collapsed to node:role=web")
	}
	if HashPlanShape(act, contradictory) == HashPlanShape(act, known(SelectorTerm{Namespace: "node", Key: "role", Value: "db"})) {
		t.Error("node:role=web,node:role=db collapsed to node:role=db")
	}

	// An empty value is a real, distinct value (node:role= parses cleanly, and
	// a state: marker carries none).
	if HashPlanShape(act, known(SelectorTerm{Namespace: "node", Key: "role"})) == HashPlanShape(act, known(a)) {
		t.Error("an empty term value shares a key with a non-empty one")
	}
}

// TestPlanShape_DoesNotMutateItsInput pins that hashing leaves the caller's
// term slice in source order — Selector.String and the audit trail read it
// after checkApproval has hashed it.
func TestPlanShape_DoesNotMutateItsInput(t *testing.T) {
	sel := known(
		SelectorTerm{Namespace: "node", Key: "role", Value: "web"},
		SelectorTerm{Namespace: "node", Key: "env", Value: "prod"},
	)
	HashPlanShape(restartUnit("nginx"), sel)
	if sel.Terms[0].Key != "role" || sel.Terms[1].Key != "env" {
		t.Fatalf("HashPlanShape reordered its input: %v", sel.Terms)
	}
}

var hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestShapeKeyIsStableAcrossRuns: no map iteration order leaks into the key.
func TestShapeKeyIsStableAcrossRuns(t *testing.T) {
	build := func() jobs.Action {
		// Rebuilt with a different insertion order each time.
		args := map[string]string{}
		for _, k := range []string{"z", "a", "m", "b"} {
			args[k] = k + "-value"
		}
		return jobs.Action{
			Kind: jobs.ActionOperation, OperationName: "site.deploy",
			OperationArgs: args, RiskClass: jobs.RiskClassMutate,
		}
	}

	want := HashPlanShape(build(), shapeSel)
	if !hexKey.MatchString(want) {
		t.Fatalf("shape key %q is not 64 lower-case hex characters", want)
	}
	for i := range 50 {
		if got := HashPlanShape(build(), shapeSel); got != want {
			t.Fatalf("run %d produced %q, want %q", i, got, want)
		}
	}
}

func TestLegacyShapeKey(t *testing.T) {
	if LegacyShapePrefix != "legacy:" {
		t.Errorf("LegacyShapePrefix = %q, want %q", LegacyShapePrefix, "legacy:")
	}
	if got := LegacyShapeKey("req-1"); got != "legacy:req-1" {
		t.Errorf("LegacyShapeKey(%q) = %q", "req-1", got)
	}
	if !IsLegacyShapeKey(LegacyShapeKey("req-1")) {
		t.Error("IsLegacyShapeKey does not recognise its own key")
	}
	// A computed key is 64 hex characters and can never carry the prefix.
	if IsLegacyShapeKey(HashPlanShape(restartUnit("nginx"), shapeSel)) {
		t.Error("a computed shape key reads as legacy")
	}
	if IsLegacyShapeKey("") {
		t.Error("an empty key reads as legacy; the two are distinct states")
	}
}

// TestPlanAndGrantShapesNeverCollide: the domain tag separates the two spaces.
func TestPlanAndGrantShapesNeverCollide(t *testing.T) {
	planKey := HashPlanShape(jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate,
	}, SelectorShape{Known: true})
	grantKey := HashGrantShape(Scope{
		Account: "", RiskClass: jobs.RiskClassMutate, Operations: []string{"service.restart"},
	})
	if planKey == grantKey {
		t.Error("a Plan shape and a Grant shape collided; the domain tag is not doing its job")
	}
}

// TestGrantShapeIgnoresCeilingWindowAndUses is the half of the Grant key that
// the anti-fatigue diff callout depends on, pinned directly rather than through
// a consumer.
//
// A ceiling IS fan-out, and D10 excludes fan-out from every shape key: "same
// scope, ceiling grew 10 -> 500" is exactly the sentence the callout exists to
// shout, and it can only be rendered if the two Grants share a key in the first
// place. The window and the use limit are scale for the same reason. HashScope
// — the Grant's actual approval binding — still covers all three, so none of
// them can move without invalidating the approval itself.
func TestGrantShapeIgnoresCeilingWindowAndUses(t *testing.T) {
	scope := Scope{
		Account: "gleipnir-prod", RiskClass: jobs.RiskClassMutate,
		MaxFanOut: 10, Operations: []string{"service.restart"},
	}
	wider := scope
	wider.MaxFanOut = 500

	if HashGrantShape(scope) != HashGrantShape(wider) {
		t.Error("widening the fan-out ceiling changed the Grant shape key — the callout can no longer " +
			"find the prior Grant, which is the one comparison it exists to make")
	}

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	short := Grant{Scope: scope, StartsAt: now, ExpiresAt: now.Add(time.Hour), MaxUses: 5}
	long := Grant{Scope: wider, StartsAt: now, ExpiresAt: now.Add(8 * time.Hour), MaxUses: 200}
	if short.ShapeKey() != long.ShapeKey() {
		t.Error("the window or the use limit reached the Grant shape key; both are scale, not shape")
	}

	// The other direction, so this does not pass by hashing nothing at all.
	other := scope
	other.Operations = []string{"pkg.install"}
	if HashGrantShape(scope) == HashGrantShape(other) {
		t.Error("two Grants over different Operations share a shape key")
	}
}
