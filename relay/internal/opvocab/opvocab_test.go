package opvocab

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestOperations_Membership pins the v1 vocabulary and each Operation's risk
// class against relay.proto:142-145, so a drift between proto and this
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
// Operation vocabulary (it is not an Operation; ADR-0003/GLOSSARY.md).
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
// filled" — TestOperations_MatchesGoldenSchema separately pins the exact
// documented key set per Operation against the daemon's golden schema, so a
// future Operation with real arguments cannot read this test's tolerance of
// an empty map as license to skip documenting them.
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

// ---------------------------------------------------------------------------
// Golden Operation schema cross-check (ADR-0015)
//
// The daemon (daemon/src/operations/schema.rs) is the single source of truth
// for what it actually enforces. Its offline `dump-operation-schema`
// subcommand emits a canonical JSON schema, committed at
// testdata/operations.schema.json ("make gen-opschema"; regenerated and
// diffed by the opschema-drift CI step). goldenSchema below //go:embeds that
// exact file — go:embed cannot reach above its own package tree, which is
// WHY the golden lives inside relay/internal/opvocab/testdata/, not at the
// repo root.
//
// TestOperations_MatchesGoldenSchema is trip-wire (c) of the three
// independent trip-wires ADR-0015 describes: it reads the golden and asserts
// opvocab.Operations() agrees on names, risk classes, arg keys, and — for
// every documented arg — that the prose contains the golden's charset token
// plus its anchor phrases. It retires the hand-copied `want`/`wantArgKeys`
// maps that used to live in this file (and in mcp_test.go, #163 S3): those
// were "kept in sync by hand with no guard", precisely the failure mode
// ADR-0015 exists to close.
// ---------------------------------------------------------------------------

//go:embed testdata/operations.schema.json
var goldenSchemaJSON []byte

type goldenArg struct {
	Key            string  `json:"key"`
	Charset        *string `json:"charset"`
	FirstLastAlnum bool    `json:"first_last_alnum"`
	NoLeadingDash  bool    `json:"no_leading_dash"`
	Kind           string  `json:"kind"`
}

type goldenOp struct {
	Name string      `json:"name"`
	Risk string      `json:"risk"`
	Args []goldenArg `json:"args"`
}

type goldenDoc struct {
	Operations []goldenOp `json:"operations"`
}

func loadGoldenSchema(t *testing.T) goldenDoc {
	t.Helper()
	var doc goldenDoc
	if err := json.Unmarshal(goldenSchemaJSON, &doc); err != nil {
		t.Fatalf("failed to parse testdata/operations.schema.json: %v", err)
	}
	return doc
}

func riskString(r jobs.RiskClass) string {
	switch r {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// charsetTokenRe extracts the exact bracket-notation charset token following
// the word "charset" in ArgConstraints prose (case-insensitive: pkg.install's
// "version" arg capitalizes it — "Charset [...]" — while the others don't).
var charsetTokenRe = regexp.MustCompile(`(?i)charset\s+(\[[^\]]*\])`)

// extractCharsetToken pulls the literal `[...]` charset token out of prose,
// e.g. "charset [A-Za-z0-9@._-], no leading '-'" -> "[A-Za-z0-9@._-]".
func extractCharsetToken(prose string) (string, bool) {
	m := charsetTokenRe.FindStringSubmatch(prose)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func TestOperations_MatchesGoldenSchema(t *testing.T) {
	golden := loadGoldenSchema(t)
	byName := make(map[string]goldenOp, len(golden.Operations))
	for _, op := range golden.Operations {
		byName[op.Name] = op
	}

	got := Operations()
	if len(got) != len(golden.Operations) {
		t.Fatalf("Operations(): got %d entries, want %d (golden): %+v", len(got), len(golden.Operations), got)
	}

	for _, d := range got {
		op, ok := byName[d.Name]
		if !ok {
			t.Errorf("Operations(): entry %q has no matching golden schema entry", d.Name)
			continue
		}

		if gotRisk := riskString(d.Risk); gotRisk != op.Risk {
			t.Errorf("Operations()[%q].Risk = %q, want %q (golden)", d.Name, gotRisk, op.Risk)
		}

		wantKeys := make([]string, 0, len(op.Args))
		for _, arg := range op.Args {
			wantKeys = append(wantKeys, arg.Key)
		}
		gotKeys := make([]string, 0, len(d.ArgConstraints))
		for k := range d.ArgConstraints {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(wantKeys)
		sort.Strings(gotKeys)
		if len(gotKeys) != len(wantKeys) {
			t.Errorf("Operations()[%q].ArgConstraints keys = %v, want %v (golden)", d.Name, gotKeys, wantKeys)
			continue
		}
		for i := range wantKeys {
			if gotKeys[i] != wantKeys[i] {
				t.Errorf("Operations()[%q].ArgConstraints keys = %v, want %v (golden)", d.Name, gotKeys, wantKeys)
				break
			}
		}

		for _, arg := range op.Args {
			prose := d.ArgConstraints[arg.Key]
			if arg.Charset != nil {
				// Extract the EXACT "charset [...]" token from prose and
				// require it to equal the golden's token verbatim, rather
				// than merely checking substring containment: a plain
				// strings.Contains(prose, *arg.Charset) check only proves
				// the golden's characters appear SOMEWHERE in prose, which
				// would still pass if prose additionally (wrongly) claimed
				// extra characters outside that exact bracket. Equality on
				// the extracted token proves prose advertises the EXACT
				// charset the golden — itself now proven byte-for-byte equal
				// to the real validator (schema.rs's
				// display_matches_declared_predicate_byte_space) — declares.
				got, ok := extractCharsetToken(prose)
				if !ok {
					t.Errorf("Operations()[%q].ArgConstraints[%q] = %q, want a \"charset [...]\" token",
						d.Name, arg.Key, prose)
				} else if got != *arg.Charset {
					t.Errorf("Operations()[%q].ArgConstraints[%q] charset token = %q, want exactly %q (golden)",
						d.Name, arg.Key, got, *arg.Charset)
				}
			}
			if arg.FirstLastAlnum && !strings.Contains(prose, "start and end alphanumeric") {
				t.Errorf("Operations()[%q].ArgConstraints[%q] = %q, want it to contain %q (golden first_last_alnum=true)",
					d.Name, arg.Key, prose, "start and end alphanumeric")
			}
			if arg.NoLeadingDash && !strings.Contains(prose, "no leading '-'") {
				t.Errorf("Operations()[%q].ArgConstraints[%q] = %q, want it to contain %q (golden no_leading_dash=true)",
					d.Name, arg.Key, prose, "no leading '-'")
			}
		}
	}
}

// --- ArgClasses / ShapeArgs (the approval shape key's declaration, #415) ---

// TestArgClasses_CoverEveryDocumentedArg is the hole D10 names: an argument
// added to an Operation without deciding whether it is shape or scale would
// otherwise land on the zero value and quietly change what "the same shape"
// means.
//
// It is deliberately an EQUALITY on the key sets, not a subset check in either
// direction: a class declared for an argument that no longer exists is stale
// documentation of a decision nobody can act on.
func TestArgClasses_CoverEveryDocumentedArg(t *testing.T) {
	for _, d := range Operations() {
		if d.ArgClasses == nil {
			t.Errorf("Operations()[%q].ArgClasses is nil; a zero-arg Operation declares an empty map", d.Name)
			continue
		}
		for k := range d.ArgConstraints {
			if _, ok := d.ArgClasses[k]; !ok {
				t.Errorf("Operations()[%q].ArgClasses has no entry for documented argument %q", d.Name, k)
			}
		}
		for k := range d.ArgClasses {
			if _, ok := d.ArgConstraints[k]; !ok {
				t.Errorf("Operations()[%q].ArgClasses classifies %q, which is not a documented argument", d.Name, k)
			}
		}
	}
}

// TestArgClasses_AreNeverUnspecified refuses the zero value, so "I added the
// key but never picked a class" is a test failure rather than a silent shape.
func TestArgClasses_AreNeverUnspecified(t *testing.T) {
	for _, d := range Operations() {
		for k, c := range d.ArgClasses {
			if c != ArgClassShape && c != ArgClassScale {
				t.Errorf("Operations()[%q].ArgClasses[%q] = %v, want ArgClassShape or ArgClassScale", d.Name, k, c)
			}
		}
	}
}

// TestArgClasses_MatchGoldenSchema ties the classification to the DAEMON's own
// Operation schema (ADR-0015), which is what makes "declared in the golden
// schema" true: an argument the daemon grows and opvocab classifies nothing
// for fails here, exactly as an unclassified ArgConstraints entry fails above.
func TestArgClasses_MatchGoldenSchema(t *testing.T) {
	golden := loadGoldenSchema(t)
	byName := make(map[string]goldenOp, len(golden.Operations))
	for _, op := range golden.Operations {
		byName[op.Name] = op
	}

	for _, d := range Operations() {
		op, ok := byName[d.Name]
		if !ok {
			t.Errorf("Operations(): entry %q has no matching golden schema entry", d.Name)
			continue
		}
		wantKeys := make([]string, 0, len(op.Args))
		for _, arg := range op.Args {
			wantKeys = append(wantKeys, arg.Key)
		}
		gotKeys := make([]string, 0, len(d.ArgClasses))
		for k := range d.ArgClasses {
			gotKeys = append(gotKeys, k)
		}
		sort.Strings(wantKeys)
		sort.Strings(gotKeys)
		if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
			t.Errorf("Operations()[%q].ArgClasses keys = %v, want %v (golden)", d.Name, gotKeys, wantKeys)
		}
	}
}

func TestShapeArgs(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		args      map[string]string
		want      map[string]string
	}{
		{
			name:      "pkg.install drops the version, keeps the package",
			operation: "pkg.install",
			args:      map[string]string{"name": "nginx", "version": "1.24.0"},
			want:      map[string]string{"name": "nginx"},
		},
		{
			name:      "service.restart keeps the unit",
			operation: "service.restart",
			args:      map[string]string{"unit": "nginx"},
			want:      map[string]string{"unit": "nginx"},
		},
		{
			name:      "file.read keeps the path",
			operation: "file.read",
			args:      map[string]string{"path": "/etc/shadow"},
			want:      map[string]string{"path": "/etc/shadow"},
		},
		{
			// A Template Operation (ADR-0021) has declared nothing, so nothing
			// may be dropped.
			name:      "an unknown operation keeps every argument",
			operation: "site.deploy",
			args:      map[string]string{"name": "nginx", "version": "1.24.0", "anything": "x"},
			want:      map[string]string{"name": "nginx", "version": "1.24.0", "anything": "x"},
		},
		{
			name:      "no arguments",
			operation: "system.facts",
			args:      nil,
			want:      map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShapeArgs(tt.operation, tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("ShapeArgs(%q, %v) = %v, want %v", tt.operation, tt.args, got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("ShapeArgs(%q)[%q] = %q, want %q", tt.operation, k, got[k], v)
				}
			}
		})
	}
}

// TestShapeArgs_DoesNotMutateItsInput pins that the caller's Action arguments
// survive hashing untouched — the map handed in is the one that will be
// dispatched.
func TestShapeArgs_DoesNotMutateItsInput(t *testing.T) {
	args := map[string]string{"name": "nginx", "version": "1.24.0"}
	ShapeArgs("pkg.install", args)
	if len(args) != 2 || args["version"] != "1.24.0" {
		t.Fatalf("ShapeArgs mutated its input: %v", args)
	}
}

// --- Lookup / ValidateArgNames (shared by every control surface) ----------

// TestArgConstraintsAreClassifiable guards the marker convention argIsRequired
// depends on: every published ArgConstraints value must contain exactly one of
// ", required" or ", optional", so a reword can never silently flip a required
// argument to "not required" and reopen #345 on every surface at once.
func TestArgConstraintsAreClassifiable(t *testing.T) {
	for _, d := range Operations() {
		for arg, constraint := range d.ArgConstraints {
			req := strings.Contains(constraint, ", required")
			opt := strings.Contains(constraint, ", optional")
			if req == opt { // both false, or (impossibly) both true
				t.Errorf("%s arg %q constraint %q must contain exactly one of \", required\" / \", optional\" (argIsRequired depends on it)",
					d.Name, arg, constraint)
			}
		}
	}
}

func TestLookup(t *testing.T) {
	d, ok := Lookup("service.restart")
	if !ok {
		t.Fatal(`Lookup("service.restart") ok = false, want true`)
	}
	if d.Name != "service.restart" || d.Risk != jobs.RiskClassMutate {
		t.Errorf("Lookup(service.restart) = {%q %v}, want {service.restart mutate}", d.Name, d.Risk)
	}
	if _, ok := Lookup("nope.notreal"); ok {
		t.Error(`Lookup("nope.notreal") ok = true, want false`)
	}
	// A Template Operation is per-Node, never native: Lookup must not claim it.
	if _, ok := Lookup("disk.usage"); ok {
		t.Error(`Lookup("disk.usage") ok = true — a template name must not resolve as native`)
	}
}

// TestValidateArgNames is the shared half of #345's guarantee: the same
// misspelled/unknown/missing cases must be refused for every surface that
// calls it, so a malformed call never reaches dispatch and comes back as
// denied_by_policy.
func TestValidateArgNames(t *testing.T) {
	mustLookup := func(name string) Descriptor {
		d, ok := Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q): not found", name)
		}
		return d
	}

	t.Run("misspelled required name is unknown", func(t *testing.T) {
		err := ValidateArgNames(mustLookup("service.restart"), map[string]string{"unitt": "nginx"})
		if err == nil {
			t.Fatal("ValidateArgNames({unitt}) = nil, want an unknown-argument error")
		}
		for _, want := range []string{"unitt", "unit"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must mention %q", err, want)
			}
		}
	})

	t.Run("unknown extra name on an otherwise valid call", func(t *testing.T) {
		err := ValidateArgNames(mustLookup("file.read"), map[string]string{"path": "/etc/os-release", "bogus": "x"})
		if err == nil || !strings.Contains(err.Error(), "bogus") {
			t.Fatalf("ValidateArgNames({path,bogus}) = %v, want an error naming 'bogus' (never silently dropped)", err)
		}
	})

	t.Run("zero-arg operation refuses any argument", func(t *testing.T) {
		if err := ValidateArgNames(mustLookup("system.facts"), map[string]string{"x": "y"}); err == nil {
			t.Fatal("ValidateArgNames(system.facts, {x}) = nil, want an error")
		}
	})

	t.Run("missing required name", func(t *testing.T) {
		err := ValidateArgNames(mustLookup("service.restart"), map[string]string{})
		if err == nil || !strings.Contains(err.Error(), "unit") {
			t.Fatalf("ValidateArgNames(service.restart, {}) = %v, want an error naming the missing 'unit'", err)
		}
	})

	t.Run("valid names pass, including an omitted optional", func(t *testing.T) {
		cases := []struct {
			op   string
			args map[string]string
		}{
			{"system.facts", map[string]string{}},
			{"file.read", map[string]string{"path": "/etc/os-release"}},
			{"service.restart", map[string]string{"unit": "nginx"}},
			{"pkg.install", map[string]string{"name": "nginx"}}, // version is optional
			{"pkg.install", map[string]string{"name": "nginx", "version": "1.24.0"}},
		}
		for _, c := range cases {
			if err := ValidateArgNames(mustLookup(c.op), c.args); err != nil {
				t.Errorf("ValidateArgNames(%s, %v) = %v, want nil", c.op, c.args, err)
			}
		}
	})
}
