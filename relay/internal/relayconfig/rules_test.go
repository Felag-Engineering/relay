package relayconfig

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// twoRules is minimal plus two valid gate rules: the second rule's header is on
// line 11, so a field appended to it is on line 13.
const twoRules = minimal + `[[approval.rules]]
name = "first"
ttl = "30m"

[[approval.rules]]
name = "second"
`

// secondRuleField is twoRules with line appended inside the second rule.
func secondRuleField(line string) string { return twoRules + line + "\n" }

func notContains(t *testing.T, got string, forbidden ...string) {
	t.Helper()
	for _, f := range forbidden {
		if strings.Contains(got, f) {
			t.Errorf("error %q must not contain %q", got, f)
		}
	}
}

// A rule names what it matches and its ttl, and nothing else: each field that
// used to say who may decide, or how, is refused at load, by name and line.
//
// Proves AP-81.
func TestLoad_RuleFieldNamingADecisionTermRefusedNamingField(t *testing.T) {
	forms := []struct {
		name string
		line func(field string) string
	}{
		{"as a field of the rule", func(f string) string { return f + ` = "CANARY"` }},
		{"as an array", func(f string) string { return f + ` = ["CANARY"]` }},
		{"as a sub-table", func(f string) string { return "[approval.rules." + f + "]\nx = \"CANARY\"" }},
		{"as a dotted key", func(f string) string { return f + `.x = "CANARY"` }},
	}
	for _, field := range []string{"count", "audience", "requester_allowed", "channel"} {
		for _, form := range forms {
			t.Run(field+" "+form.name, func(t *testing.T) {
				got := loadErr(t, secondRuleField(form.line(field)))
				want := "approval.rules." + field + " (line 13)"
				if !strings.Contains(got, want) {
					t.Fatalf("error %q does not contain %q", got, want)
				}
				notContains(t, got, "CANARY", "unrecognised")
			})
		}
	}

	t.Run("an unknown rule field is unrecognised, not echoed", func(t *testing.T) {
		got := loadErr(t, secondRuleField(`CANARYFIELD = 1`))
		if !strings.Contains(got, "an unrecognised key in [approval.rules]") {
			t.Fatalf("error %q does not name the unrecognised key", got)
		}
		notContains(t, got, "CANARY")
	})
}

// Gate rules are [[approval.rules]] sections and nothing else: an inline array,
// a value written at the key, a dotted field outside a rule section and the
// single-bracket table are each refused before decoding, in fixed text.
//
// Proves AP-89, RC-37.
func TestLoad_GateRulesOnlyAsArrayTables(t *testing.T) {
	const want = "approval.rules (line %d): must be written as [[approval.rules]] sections"
	cases := []struct {
		name string
		src  string
		line int
	}{
		{"inline array", minimal + "[approval]\nrules = [{name = \"CANARY\", ttl = \"1h\"}]\n", 8},
		{"multi-line inline array with a removed field", minimal + "[approval]\nrules = [\n  {name = \"a\"},\n  {name = \"b\", channel = \"CANARY\"},\n]\n", 8},
		{"dotted from the root", "approval.rules = [{name = \"CANARY\"}]\n" + minimal, 1},
		{"inline table at the root", "approval = { rules = [{name = \"CANARY\"}] }\n" + minimal, 1},
		{"single-bracket table", minimal + "[approval.rules]\nname = \"CANARY\"\n", 7},
		{"single-bracket table with a bad value", minimal + "[approval.rules]\nttl = \"CANARY\"\n", 7},
		{"dotted field under [approval]", minimal + "[approval]\nrules.ttl = \"CANARY\"\n", 8},
		{"a sub-table with no rule section before it", minimal + "[approval.rules.name]\nx = \"CANARY\"\n", 7},
		{"a scalar written at the key", minimal + "[approval]\nrules = \"CANARY\"\n", 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, tc.src)
			if w := strings.Replace(want, "%d", strconv.Itoa(tc.line), 1); !strings.Contains(got, w) {
				t.Fatalf("error %q does not contain %q", got, w)
			}
			notContains(t, got, "CANARY")
		})
	}
}

// Proves RC-37.
func TestLoad_GateRulesPathRefusedNamingKey(t *testing.T) {
	got := loadErr(t, minimal+"[approval]\ngate_rules_path = \"/etc/relay/CANARY.json\"\n")
	if !strings.Contains(got, "approval.gate_rules_path (line 8)") || !strings.Contains(got, "[[approval.rules]]") {
		t.Fatalf("error %q does not name the key, its line and where the rules went", got)
	}
	notContains(t, got, "CANARY")
}

func TestLoad_RepeatedRuleTablesAreNotSetTwice(t *testing.T) {
	cfg := mustLoad(t, twoRules)
	if len(cfg.Approval.Rules) != 2 {
		t.Fatalf("rules = %d, want 2: a second [[approval.rules]] is a new rule, not a key set twice", len(cfg.Approval.Rules))
	}

	got := loadErr(t, minimal+"[[approval.rules]]\nname = \"a\"\nttl = \"1h\"\nttl = \"2h\"\n")
	if !strings.Contains(got, "approval.rules.ttl (line 10): is set twice") {
		t.Fatalf("error %q: a key set twice inside one rule is reported as such", got)
	}

	got = loadErr(t, minimal+"[[approval.rules]]\nname = \"first\"\n\n[[approval.rules]]\nname = 7\n")
	if !strings.Contains(got, "approval.rules.name (line 11): is malformed or has the wrong type") {
		t.Fatalf("error %q: a type error in the second rule is malformed, not set twice", got)
	}
	notContains(t, got, "set twice")

	got = loadErr(t, secondRuleField(`min_fan_out = "two"`))
	if !strings.Contains(got, "approval.rules.min_fan_out (line 13): is malformed or has the wrong type") {
		t.Fatalf("error %q does not name the field", got)
	}
}

func TestElemLine_OutOfRangeFallsBack(t *testing.T) {
	idx := keyLines([]byte(twoRules))
	cases := []struct {
		name  string
		key   string
		i     int
		field string
		want  int
	}{
		{"a field of the first rule", "approval.rules", 0, "ttl", 9},
		{"the second rule's header for an unwritten field", "approval.rules", 1, "ttl", 11},
		{"past the last element falls back to the key", "approval.rules", 2, "ttl", 7},
		{"a negative index falls back to the key", "approval.rules", -1, "ttl", 7},
		{"an unrecorded key is line 0", "approval.nothing", 3, "x", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := idx.elemLine(tc.key, tc.i, tc.field); got != tc.want {
				t.Errorf("elemLine(%q, %d, %q) = %d, want %d", tc.key, tc.i, tc.field, got, tc.want)
			}
		})
	}
	if got := (lineIndex{}).elemLine("approval.rules", 4, "name"); got != 0 {
		t.Errorf("elemLine on an empty index = %d, want 0", got)
	}
}

// Proves AP-89.
func TestApprovalRulesLoadFromTheConfigurationFile(t *testing.T) {
	if got := mustLoad(t, minimal).Approval.Rules; len(got) != 0 {
		t.Fatalf("a configuration with no [[approval.rules]] has rules %v; it gates nothing", got)
	}

	cfg := mustLoad(t, minimal+`[[approval.rules]]
name = "fleet-wide-mutates"
risk_class = "mutate"
min_fan_out = 2
selector_namespace = "relay"
ttl = "1h"

[[approval.rules]]
name = "raw-exec-by-bot"
account = "gleipnir-prod"
raw_exec = true

[[approval.rules]]
name = "restarts"
operation = "service.restart"
`)
	want := []approval.Rule{
		{
			Name:    "fleet-wide-mutates",
			Match:   approval.Match{RiskClass: jobs.RiskClassMutate, MinFanOut: 2, SelectorNamespace: "relay"},
			Require: approval.Requirement{TTL: time.Hour},
		},
		{Name: "raw-exec-by-bot", Match: approval.Match{Account: "gleipnir-prod", RawExec: true}},
		{Name: "restarts", Match: approval.Match{Operation: "service.restart"}},
	}
	if len(cfg.Approval.Rules) != len(want) {
		t.Fatalf("rules = %+v, want %+v", cfg.Approval.Rules, want)
	}
	for i := range want {
		if cfg.Approval.Rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, cfg.Approval.Rules[i], want[i])
		}
	}

	gate, err := approval.NewGate(cfg.Approval.Rules)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	cases := []struct {
		name  string
		d     approval.Dispatch
		ttl   time.Duration
		gated bool
	}{
		{"fleet-wide mutate in the relay namespace", approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 2, Namespaces: []string{"relay"}}, time.Hour, true},
		{"single-Node mutate", approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, Namespaces: []string{"relay"}}, 0, false},
		{"fleet-wide read", approval.Dispatch{RiskClass: jobs.RiskClassRead, FanOut: 9, Namespaces: []string{"relay"}}, 0, false},
		{"Raw Exec by the named Account", approval.Dispatch{RawExec: true, Account: "gleipnir-prod"}, approval.DefaultTTL, true},
		{"Raw Exec by another Account", approval.Dispatch{RawExec: true, Account: "someone"}, 0, false},
		{"the named Operation", approval.Dispatch{Operation: "service.restart"}, approval.DefaultTTL, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _, gated := gate.Evaluate(tc.d)
			if gated != tc.gated || (gated && req.TTL != tc.ttl) {
				t.Errorf("gated = %v ttl = %v, want gated = %v ttl = %v", gated, req.TTL, tc.gated, tc.ttl)
			}
		})
	}
}

// Every value a rule can get wrong is refused naming approval.rules.<field> and
// the field's own line, never the value (RC-18).
//
// Proves AP-81, AP-6, RC-37.
func TestValidate_GateRuleValuesRefusedNamingField(t *testing.T) {
	cases := []struct {
		name   string
		second string // the body of the second rule
		want   string
	}{
		{"a missing name", `ttl = "1h"`, "approval.rules.name (line 10)"},
		{"an empty name", `name = ""`, "approval.rules.name (line 11)"},
		{"a repeated name, case-insensitively", `name = "FIRST"`, "approval.rules.name (line 11)"},
		{"a bad risk class", "name = \"s\"\nrisk_class = \"CANARY\"", "approval.rules.risk_class (line 12)"},
		{"a negative fan-out", "name = \"s\"\nmin_fan_out = -1", "approval.rules.min_fan_out (line 12)"},
		{"an unknown namespace", "name = \"s\"\nselector_namespace = \"CANARY\"", "approval.rules.selector_namespace (line 12)"},
		{"an empty account", "name = \"s\"\naccount = \"\"", "approval.rules.account (line 12)"},
		{"an empty operation", "name = \"s\"\noperation = \"\"", "approval.rules.operation (line 12)"},
		{"an unparsable ttl", "name = \"s\"\nttl = \"CANARY\"", "approval.rules.ttl (line 12)"},
		{"a zero ttl", "name = \"s\"\nttl = \"0s\"", "approval.rules.ttl (line 12)"},
		{"a negative ttl", "name = \"s\"\nttl = \"-1h\"", "approval.rules.ttl (line 12)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := minimal + "[[approval.rules]]\nname = \"first\"\n\n[[approval.rules]]\n" + tc.second + "\n"
			got := loadErr(t, src)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("error %q does not contain %q", got, tc.want)
			}
			notContains(t, got, "CANARY", "first", "FIRST")
		})
	}
}

// Proves AP-89.
func TestDiff_GateRulesChangeAppliedByReload(t *testing.T) {
	base := mustLoad(t, twoRules)
	next := mustLoad(t, strings.Replace(twoRules, `ttl = "30m"`, `ttl = "45m"`, 1))
	cs := Diff(base, next)
	if len(cs) != 1 || cs[0].Key != "approval.rules" || cs[0].RestartRequired || cs[0].Secret {
		t.Fatalf("Diff = %+v, want one reloadable approval.rules change", cs)
	}
	if cs := Diff(base, mustLoad(t, twoRules)); len(cs) != 0 {
		t.Errorf("unchanged rules differ: %+v", cs)
	}
	if !IsSettingKey("approval.rules") {
		t.Error("approval.rules is not a setting key, so a reload audit could not name it")
	}
}

// Odd spellings of the rules section never panic the loader on start or on
// reload: each either loads or is refused, and a refusal never echoes a value.
func TestLoad_OddGateRuleSpellingsNeverPanic(t *testing.T) {
	for _, src := range []string{
		minimal + "[[approval.rules]]\nname = \"a\"\n[approval.rules.name]\nx = \"CANARY\"\n",
		minimal + "[[approval.rules]]\nname = \"a\"\n[[approval.rules.count]]\nx = \"CANARY\"\n",
		minimal + "[[approval.rules]]\n[[approval.rules]]\n[[approval.rules]]\nname = \"CANARY\"\n",
		minimal + "[approval]\nrules = []\n",
		minimal + "[[approval.rules]]\nname = { x = \"CANARY\" }\n",
		minimal + "[[approval.rules]]\nname = [\"CANARY\"]\n",
		minimal + "[[approval.rules]]\nrules = 1\nname = \"CANARY\"\n",
		minimal + "[approval.rules.name]\n",
		minimal + "[[approval.rules]\n",
		"[[approval.rules]]\n" + minimal,
	} {
		_, _, err := Load([]byte(src))
		if err != nil {
			notContains(t, err.Error(), "CANARY")
		}
	}
}
