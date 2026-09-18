package dispatch

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// This file locks #632's fix in place with three guards of decreasing
// strength, in a deliberate hierarchy — stated here AND in the PR body:
//
//   - G2 (TestEveryWireOutcomeIsClassified) is LOAD-BEARING. It iterates the
//     GENERATED enum (relayv1.Outcome_value) and fails on any value that is
//     not classified, whatever any comment says: no edit to /proto's prose
//     can defeat it, because Outcome_value comes from declarations, not
//     comments.
//   - G1 (TestProtoRelayOnlySetMatchesWireBoundary) is a CROSS-CHECK that
//     /proto's prose and the Go mirror (relayOnlyOutcomes, convert.go) still
//     agree. It catches the likelier, friendlier mistake — a value marked
//     Relay-only in the contract and not mirrored in the code — and says so
//     in the contract's own words. G1 is NOT the contract and must never be
//     trusted as one: it reads comments, the softest artifact in the repo.
//     A comment block placed above two or more consecutive values is
//     structurally ambiguous — which value does it describe? — so the
//     parser refuses it outright rather than silently attaching it to the
//     first and leaving the second unmarked (fixture 10 in
//     TestParseOutcomeEnum_Fixtures pins this as a parse error).
//   - G4 (TestOnlyDispatchConvertsWireOutcomes) is CONTAINMENT. It proves G1
//     and G2 still guard the only place the conversion happens, for every
//     mechanism that names the wire Outcome type, calls the generated
//     GetOutcome accessor, or reads the generated Outcome field directly.
//
// Shared harness: repoRoot mirrors registry/daemon_version_contract_test.go.
// A read failure is t.Fatalf, never t.Skip — proto/relay/v1/relay.proto is
// committed, and a moved or renamed contract is precisely the event this
// guard exists to notice (the registry precedent's t.Skip is for optional
// tools — bash, git — not committed files).
const repoRoot = "../../.."

// daemonEmittable is G2's hand-declared partition of the values a
// relay-daemon may legitimately report today. Kept in the test, deliberately
// not exported from convert.go: it exists only to drive this guard's
// exhaustiveness check, not as production logic.
var daemonEmittable = map[string]bool{
	"OUTCOME_SUCCESS":          true,
	"OUTCOME_FAILURE":          true,
	"OUTCOME_TIMEOUT":          true,
	"OUTCOME_DENIED_BY_POLICY": true,
	"OUTCOME_CANCELLED":        true,
	"OUTCOME_UNSUPPORTED":      true,
}

// unresolvedOutcomes is G2's third partition: the wire enum's own "not yet
// resolved" zero value. Hand-declared here, like daemonEmittable — result()
// inlines this single-value comparison directly
// (relayv1.Outcome_OUTCOME_UNSPECIFIED), so no production symbol of this
// name exists.
var unresolvedOutcomes = map[string]bool{
	"OUTCOME_UNSPECIFIED": true,
}

// relayOnlyOutcomeNames derives the name set of the production
// relayOnlyOutcomes map (convert.go) from relayv1.Outcome_name, so G1/G2
// compare against the actual wire boundary rather than a second hand-copy of
// it.
func relayOnlyOutcomeNames() map[string]bool {
	names := make(map[string]bool, len(relayOnlyOutcomes))
	for o := range relayOnlyOutcomes {
		names[relayv1.Outcome_name[int32(o)]] = true
	}
	return names
}

// classifyOutcome reports which of G2's three sets name belongs to, or
// ok=false if it belongs to none — the state a new /proto Outcome value
// lands in before anyone classifies it.
func classifyOutcome(name string) (class string, ok bool) {
	switch {
	case daemonEmittable[name]:
		return "daemonEmittable", true
	case relayOnlyOutcomeNames()[name]:
		return "relayOnly", true
	case unresolvedOutcomes[name]:
		return "unresolved", true
	default:
		return "", false
	}
}

// membershipCount reports how many of G2's three sets — daemonEmittable,
// relayOnlyOutcomeNames(), unresolvedOutcomes — claim name, so the "exactly
// one" partition claim below is a counted fact rather than an artifact of
// classifyOutcome's first-match switch (which would silently pick one set
// and never report a name claimed by two).
func membershipCount(name string) int {
	n := 0
	if daemonEmittable[name] {
		n++
	}
	if relayOnlyOutcomeNames()[name] {
		n++
	}
	if unresolvedOutcomes[name] {
		n++
	}
	return n
}

// TestEveryWireOutcomeIsClassified is G2, the load-bearing guard: every name
// in the GENERATED relayv1.Outcome_value must land in exactly one of
// daemonEmittable, relayOnlyOutcomes (convert.go), or unresolvedOutcomes —
// checked by membershipCount, not inferred from classifyOutcome's first-match
// switch — and, behaviourally, result() must treat each set the way its
// classification promises.
func TestEveryWireOutcomeIsClassified(t *testing.T) {
	// Secondary message only — per #633's lesson, the iteration below is the
	// real guard, not this count.
	if got := len(relayv1.Outcome_value); got != 9 {
		t.Logf("relayv1.Outcome_value has %d entries, today's enum has 9 — not a failure by itself, the classification loop below is what must catch a new value", got)
	}

	for name, number := range relayv1.Outcome_value {
		if n := membershipCount(name); n > 1 {
			t.Errorf("%s is claimed by %d classification sets, want exactly 1 — classifyOutcome's "+
				"first-match switch would silently pick one and hide this", name, n)
		}

		class, ok := classifyOutcome(name)
		if !ok {
			// Errorf + continue, not Fatalf: this loop covers every generated
			// enum value in one run, and the first unclassified name must not
			// hide whatever the rest of the loop would have found (code
			// review, cycle 2).
			t.Errorf("%s is in no classification set. Do NOT simply add it to daemonEmittable. Read its "+
				"comment in proto/relay/v1/relay.proto: if it says the Relay synthesizes it and a daemon "+
				"never emits this, mirror it into relayOnlyOutcomes in convert.go so the wire boundary "+
				"refuses it (#632). Only a value a relay-daemon may genuinely report belongs in "+
				"daemonEmittable.", name)
			continue
		}

		wire := relayv1.Outcome(number)
		res, v := result(&relayv1.TaskResult{TaskId: "t", Outcome: wire})

		switch class {
		case "daemonEmittable":
			if v.Violated() {
				t.Errorf("%s is classified daemonEmittable but result() reported a protocol violation: %+v", name, v)
			}
		case "relayOnly", "unresolved":
			if !v.Violated() {
				t.Errorf("%s is classified %s but result() reported no violation", name, class)
				continue
			}
			if res.Outcome != jobs.OutcomeFailure {
				t.Errorf("%s: Result.Outcome = %v, want jobs.OutcomeFailure", name, res.Outcome)
			}
			if res.ExitCode != -1 {
				t.Errorf("%s: Result.ExitCode = %d, want -1", name, res.ExitCode)
			}
			if string(res.Stderr) != v.Explanation() {
				t.Errorf("%s: Result.Stderr = %q, want v.Explanation()", name, res.Stderr)
			}
			// A future third ViolationRule with no Explanation() case would
			// make this "" == "" and pass silently, producing exactly the
			// empty-stderr failure this PR exists to prevent (code review,
			// cycle 2) — assert non-empty directly rather than only equal.
			if len(res.Stderr) == 0 {
				t.Errorf("%s: Result.Stderr is empty for a refused outcome — indistinguishable from an "+
					"ordinary non-zero exit with no message", name)
			}
			wantRule := jobs.ViolationRelayOnlyOutcome
			if class == "unresolved" {
				wantRule = jobs.ViolationUnresolvedOutcome
			}
			if v.Rule != wantRule {
				t.Errorf("%s: violation Rule = %v, want %v", name, v.Rule, wantRule)
			}
			if v.ReportedOutcome != name {
				t.Errorf("%s: violation ReportedOutcome = %q, want %q", name, v.ReportedOutcome, name)
			}
		}
	}
}

// TestClassifyOutcome_UnknownName exercises G2's failure path directly,
// rather than only reasoning about it: a name in none of the three sets must
// be reported as unclassified, never silently accepted into one. This is
// the state a hypothetical tenth /proto Outcome value would be in before
// anyone classifies it.
func TestClassifyOutcome_UnknownName(t *testing.T) {
	if _, ok := classifyOutcome("OUTCOME_FUTURE"); ok {
		t.Error(`classifyOutcome("OUTCOME_FUTURE") = ok, want unclassified`)
	}
}

// ---------------------------------------------------------------------------
// G1 — /proto's prose and the Go mirror agree (cross-check, not the contract)
// ---------------------------------------------------------------------------

// outcomeValue is one enum Outcome value, as parsed from /proto's source
// text: its name, its number, and its joined leading+trailing comment text
// (used only to test the canonical/loose marker regexes below).
type outcomeValue struct {
	Name    string
	Number  int32
	Comment string
}

// canonicalRelayOnlyMarker is the exact phrase /proto uses to mark a value
// Relay-synthesized: "Relay-synthesized: ... a daemon never emits this",
// possibly spanning a preceding two-line comment block (hence (?s), so "."
// matches the newline between them).
var canonicalRelayOnlyMarker = regexp.MustCompile(`(?is)relay-synthesized:.*?a daemon never emits this`)

// looseRelayOnlyMarker is deliberately broader than the canonical form: any
// near-miss wording (a different spelling, a lone half of the phrase, a
// marker in the wrong comment style) still trips this scan, so it can be
// reported as an error rather than silently doing nothing.
var looseRelayOnlyMarker = regexp.MustCompile(`(?i)relay[- ]synthesi[sz]ed|never emits|relay-only|synthesi[sz]ed by the relay`)

// valueLineRe matches an enum value declaration's CODE half (everything
// before any comment): NAME = NUMBER;
var valueLineRe = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*)\s*=\s*(-?\d+)\s*;`)

// parseOutcomeEnum extracts every value of "enum Outcome { ... }" from src
// (a /proto source file, or a synthetic fixture of the same shape) and marks
// which ones carry the canonical Relay-only marker. It is a CROSS-CHECK
// parser, not the contract: comments are the softest artifact in the repo,
// so this function fails loud on anything it cannot attribute unambiguously
// rather than guessing — including a comment block that precedes two or
// more consecutive values (TestParseOutcomeEnum_Fixtures, row 10): such a
// block attaches to the first value only, which is ambiguous rather than
// benign, so it is refused rather than silently accepted. G1 is still a
// cross-check, never the contract, because comments remain the softest
// artifact in the repo; G2 (the generated-enum partition) is the guard that
// cannot be fooled by any comment shape at all.
func parseOutcomeEnum(src string) (all []outcomeValue, relayOnly []outcomeValue, err error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")

	const marker = "enum Outcome"
	idx := strings.Index(src, marker)
	if idx < 0 {
		return nil, nil, fmt.Errorf("parseOutcomeEnum: no %q found", marker)
	}
	braceIdx := strings.IndexByte(src[idx:], '{')
	if braceIdx < 0 {
		return nil, nil, fmt.Errorf("parseOutcomeEnum: %q has no opening brace", marker)
	}
	braceIdx += idx

	depth := 1
	end := -1
	for i := braceIdx + 1; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, nil, fmt.Errorf("parseOutcomeEnum: unterminated enum Outcome block")
	}
	body := src[braceIdx+1 : end]
	lines := strings.Split(body, "\n")

	values := make([]outcomeValue, 0, len(lines))
	valueIndexByName := map[string]int{}
	owner := map[int]string{}       // line index -> owning value name
	declLineIdx := map[string]int{} // value name -> line index of its declaration
	hadLeadingBlock := map[string]bool{}
	var pendingText []string
	var pendingIdx []int

	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)

		switch {
		case trimmed == "":
			pendingText, pendingIdx = nil, nil
			continue

		case strings.HasPrefix(trimmed, "//"):
			commentText := strings.TrimSpace(strings.TrimPrefix(trimmed, "//"))
			if valueLineRe.MatchString(commentText) {
				return nil, nil, fmt.Errorf(
					"parseOutcomeEnum: line %d looks like a commented-out enum value (%q) — "+
						"ambiguous whether it is declared; declare it or delete it, don't leave a "+
						"marker attributed to something that may not exist", i+1, commentText)
			}
			pendingText = append(pendingText, commentText)
			pendingIdx = append(pendingIdx, i)
			continue

		case strings.HasPrefix(trimmed, "/*"), strings.HasPrefix(trimmed, "option"), strings.HasPrefix(trimmed, "reserved"):
			// Breaks attachment: a block-comment marker line, an
			// allow_alias/other option, or a reserved statement can never be
			// a value's leading comment.
			pendingText, pendingIdx = nil, nil
			continue
		}

		codePart := raw
		trailing := ""
		if ci := strings.Index(raw, "//"); ci >= 0 {
			codePart = raw[:ci]
			trailing = strings.TrimSpace(raw[ci+2:])
		}

		m := valueLineRe.FindStringSubmatch(codePart)
		if m == nil {
			// Some other line this parser does not recognize: breaks
			// attachment rather than guessing.
			pendingText, pendingIdx = nil, nil
			continue
		}

		name := m[1]
		number, convErr := strconv.ParseInt(m[2], 10, 32)
		if convErr != nil {
			return nil, nil, fmt.Errorf("parseOutcomeEnum: line %d: %s = %q is not a valid number", i+1, name, m[2])
		}

		comment := strings.Join(pendingText, "\n")
		if trailing != "" {
			if comment != "" {
				comment += "\n"
			}
			comment += trailing
		}

		values = append(values, outcomeValue{Name: name, Number: int32(number), Comment: comment})
		valueIndexByName[name] = len(values) - 1
		declLineIdx[name] = i
		hadLeadingBlock[name] = len(pendingText) > 0

		for _, pi := range pendingIdx {
			owner[pi] = name
		}
		owner[i] = name
		pendingText, pendingIdx = nil, nil
	}

	if len(values) == 0 {
		return nil, nil, fmt.Errorf("parseOutcomeEnum: parsed zero values — the parser is matching nothing, not the contract")
	}

	// A leading comment block is consumed by the very next value line (see
	// the loop above: pendingText is cleared the moment a value line reads
	// it), so a block placed above a run of two or more consecutive values
	// attaches to the first only — silently, with no error anywhere, and the
	// second value is exactly as unmarked as if it had never been commented
	// at all. That shape is ambiguous, not benign, so refuse it outright
	// rather than let the first value's block quietly stand in for the
	// second's too.
	for _, v := range values {
		if !hadLeadingBlock[v.Name] {
			continue
		}
		nextIdx := declLineIdx[v.Name] + 1
		if nextIdx >= len(lines) {
			continue
		}
		nextTrimmed := strings.TrimSpace(lines[nextIdx])
		if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "//") || strings.HasPrefix(nextTrimmed, "/*") {
			// A blank line, or the next value's own leading comment, means
			// this value's block does not sit directly above another value.
			continue
		}
		nextCode := lines[nextIdx]
		if ci := strings.Index(nextCode, "//"); ci >= 0 {
			nextCode = nextCode[:ci]
		}
		if m := valueLineRe.FindStringSubmatch(nextCode); m != nil {
			return nil, nil, fmt.Errorf(
				"parseOutcomeEnum: the comment block above %s sits directly above %s's declaration too, "+
					"with nothing in between — a shared block attaches to %s only and %s would be left "+
					"unmarked with no error; give %s its own comment, or move %s so the block precedes "+
					"only the single value it describes", v.Name, m[1], v.Name, m[1], m[1], v.Name)
		}
	}

	// Mark canonical Relay-only values.
	isCanonical := make([]bool, len(values))
	for i, v := range values {
		isCanonical[i] = canonicalRelayOnlyMarker.MatchString(v.Comment)
	}

	// Loose scan: every line in the block, resolved to its owner (if any).
	for i, raw := range lines {
		if !looseRelayOnlyMarker.MatchString(raw) {
			continue
		}
		name, ok := owner[i]
		if !ok || name == "" {
			return nil, nil, fmt.Errorf(
				"parseOutcomeEnum: line %d carries a Relay-only marker (%q) that belongs to no enum "+
					"value — attach it to the value it describes, in a form G1 can parse", i+1, strings.TrimSpace(raw))
		}
		vi := valueIndexByName[name]
		if !isCanonical[vi] {
			return nil, nil, fmt.Errorf(
				"parseOutcomeEnum: %s carries a Relay-only-ish marker but not the canonical form — "+
					"write exactly %q in its comment (matched case-insensitively, may span a preceding "+
					"comment block, but must be plain \"//\" comment text, not \"/* */\")",
				name, "Relay-synthesized: ... a daemon never emits this")
		}
	}

	for i, v := range values {
		if isCanonical[i] {
			relayOnly = append(relayOnly, v)
		}
	}
	return values, relayOnly, nil
}

// TestProtoRelayOnlySetMatchesWireBoundary is G1: parses the REAL
// proto/relay/v1/relay.proto and cross-checks it against convert.go's
// relayOnlyOutcomes, in both directions, plus a name->number PAIR check
// against the generated relayv1.Outcome_value (not just names — a /proto
// edit that renumbers a value without regenerating would leave a name-only
// comparison green while the Go mirror refuses the wrong integer).
func TestProtoRelayOnlySetMatchesWireBoundary(t *testing.T) {
	path := filepath.Join(repoRoot, "proto", "relay", "v1", "relay.proto")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — this file is committed; a moved or renamed contract must not silently skip this guard", path, err)
	}

	all, relayOnly, err := parseOutcomeEnum(string(raw))
	if err != nil {
		t.Fatalf("parseOutcomeEnum(%s): %v", path, err)
	}

	parsedNames := make(map[string]bool, len(relayOnly))
	for _, v := range relayOnly {
		parsedNames[v.Name] = true
	}
	mirrorNames := relayOnlyOutcomeNames()

	for name := range parsedNames {
		if !mirrorNames[name] {
			t.Errorf("/proto marks %s Relay-synthesized (\"a daemon never emits this\"), but convert.go's "+
				"relayOnlyOutcomes does not refuse it at the wire boundary — mirror it in (#632)", name)
		}
	}
	for name := range mirrorNames {
		if !parsedNames[name] {
			t.Errorf("convert.go's relayOnlyOutcomes refuses %s, but proto/relay/v1/relay.proto's enum "+
				"Outcome comment no longer marks it Relay-synthesized — either the mirror is stale or "+
				"the contract's prose regressed", name)
		}
	}

	if len(all) == 0 {
		t.Fatal("parseOutcomeEnum parsed zero values from the real relay.proto — it is matching nothing, not the contract")
	}
	for _, v := range all {
		got, ok := relayv1.Outcome_value[v.Name]
		if !ok {
			t.Errorf("/proto declares %s but relayv1.Outcome_value (generated code) has no such name — run make proto", v.Name)
			continue
		}
		if got != v.Number {
			t.Errorf("/proto declares %s = %d but the generated mirror has %s = %d — /proto was edited without regenerating (make proto)", v.Name, v.Number, v.Name, got)
		}
	}
	for name, number := range relayv1.Outcome_value {
		found := false
		for _, v := range all {
			if v.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("generated relayv1.Outcome_value has %s = %d but proto/relay/v1/relay.proto's enum Outcome declares no such name — the generated code is stale (make proto)", name, number)
		}
	}
}

// TestParseOutcomeEnum_Fixtures is G1b: parseOutcomeEnum proven against ten
// synthetic shapes, not just today's real contract. Rows 7-10 "fail loud",
// which is the right outcome for a shape this parser cannot attribute
// unambiguously; each is fixtured because an unfixtured edge invites a later
// implementer to "fix" it into silence. Rows 1-3 additionally assert that
// comparing the parsed set against today's two-entry relayOnlyOutcomes
// produces a MISMATCH — what makes "a hypothetical third Relay-only value
// added without being refused" a committed automated failure rather than a
// manual promise, in every comment shape that works.
func TestParseOutcomeEnum_Fixtures(t *testing.T) {
	wrap := func(body string) string {
		return "syntax = \"proto3\";\n\nenum Outcome {\n" + body + "}\n"
	}

	trailingCommentBody := "  OUTCOME_UNSPECIFIED = 0;\n" +
		"  OUTCOME_SUCCESS = 1;\n" +
		"  OUTCOME_UNREACHABLE = 6; // Relay-synthesized: the Node was offline; a daemon never emits this\n" +
		"  OUTCOME_VERSION_REFUSED = 7; // Relay-synthesized: version too old; a daemon never emits this\n" +
		"  OUTCOME_NEWTHING = 9; // Relay-synthesized: something new; a daemon never emits this\n"

	precedingBlockBody := "  OUTCOME_UNSPECIFIED = 0;\n" +
		"  OUTCOME_SUCCESS = 1;\n" +
		"  // Relay-synthesized: the Node was offline\n" +
		"  // a daemon never emits this\n" +
		"  OUTCOME_UNREACHABLE = 6;\n" +
		"  // Relay-synthesized: version too old\n" +
		"  // a daemon never emits this\n" +
		"  OUTCOME_VERSION_REFUSED = 7;\n" +
		"  // Relay-synthesized: something new\n" +
		"  // a daemon never emits this\n" +
		"  OUTCOME_NEWTHING = 9;\n"

	threeRelayOnly := []string{"OUTCOME_UNREACHABLE", "OUTCOME_VERSION_REFUSED", "OUTCOME_NEWTHING"}

	cases := []struct {
		name          string
		src           string
		wantErr       bool
		wantErrSubstr string
		wantRelayOnly []string
		checkMismatch bool
	}{
		{
			name:          "1_third_value_trailing_comment",
			src:           wrap(trailingCommentBody),
			wantRelayOnly: threeRelayOnly,
			checkMismatch: true,
		},
		{
			name:          "2_third_value_preceding_block",
			src:           wrap(precedingBlockBody),
			wantRelayOnly: threeRelayOnly,
			checkMismatch: true,
		},
		{
			name:          "3_preceding_block_crlf",
			src:           strings.ReplaceAll(wrap(precedingBlockBody), "\n", "\r\n"),
			wantRelayOnly: threeRelayOnly,
			checkMismatch: true,
		},
		{
			name: "4_commented_out_value",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  // OUTCOME_HIDDEN = 9; // Relay-synthesized: hidden; a daemon never emits this\n" +
				"  OUTCOME_UNREACHABLE = 6; // Relay-synthesized: offline; a daemon never emits this\n"),
			wantErr:       true,
			wantErrSubstr: "commented-out",
		},
		{
			name: "5_floating_marker",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  // Relay-synthesized: this marker belongs to nothing\n" +
				"  // a daemon never emits this\n" +
				"  option allow_alias = true;\n" +
				"  OUTCOME_UNREACHABLE = 6;\n"),
			wantErr:       true,
			wantErrSubstr: "belongs to no enum value",
		},
		{
			name: "6_near_miss_wording",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  OUTCOME_UNREACHABLE = 6; // Relay-synthesised: offline, never used by a daemon\n"),
			wantErr:       true,
			wantErrSubstr: "OUTCOME_UNREACHABLE",
		},
		{
			name: "7_block_comment_above_value",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  /* Relay-synthesized: offline; a daemon never emits this */\n" +
				"  OUTCOME_UNREACHABLE = 6;\n"),
			wantErr:       true,
			wantErrSubstr: "belongs to no enum value",
		},
		{
			name: "8_marker_separated_by_blank_line",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  // Relay-synthesized: offline\n" +
				"  // a daemon never emits this\n" +
				"\n" +
				"  OUTCOME_UNREACHABLE = 6;\n"),
			wantErr:       true,
			wantErrSubstr: "belongs to no enum value",
		},
		{
			name: "9_same_line_block_comment_after_value",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  OUTCOME_UNREACHABLE = 6; /* Relay-synthesized: offline; a daemon never emits this */\n"),
			wantErr:       true,
			wantErrSubstr: "OUTCOME_UNREACHABLE",
		},
		{
			name: "10_shared_block_above_two_consecutive_values",
			src: wrap("  OUTCOME_UNSPECIFIED = 0;\n" +
				"  OUTCOME_SUCCESS = 1;\n" +
				"  // Relay-synthesized: shared marker\n" +
				"  // a daemon never emits this\n" +
				"  OUTCOME_ALPHA = 6;\n" +
				"  OUTCOME_BETA = 7;\n"),
			wantErr:       true,
			wantErrSubstr: "sits directly above OUTCOME_BETA's declaration",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, relayOnly, err := parseOutcomeEnum(tt.src)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseOutcomeEnum: got no error, want one containing %q", tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("parseOutcomeEnum error = %q, want it to contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOutcomeEnum: %v", err)
			}

			gotNames := make([]string, 0, len(relayOnly))
			for _, v := range relayOnly {
				gotNames = append(gotNames, v.Name)
			}
			sort.Strings(gotNames)
			want := append([]string(nil), tt.wantRelayOnly...)
			sort.Strings(want)
			if !reflect.DeepEqual(gotNames, want) {
				t.Errorf("relay-only names = %v, want %v", gotNames, want)
			}

			if tt.checkMismatch {
				mirror := relayOnlyOutcomeNames()
				mismatch := len(mirror) != len(gotNames)
				if !mismatch {
					for _, n := range gotNames {
						if !mirror[n] {
							mismatch = true
							break
						}
					}
				}
				if !mismatch {
					t.Errorf("expected the parsed relay-only set %v to MISMATCH today's production "+
						"relayOnlyOutcomes (derived from %v) — a third Relay-only value must be a "+
						"detectable drift, not silently absorbed", gotNames, mirror)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// G4 — the wire Outcome is converted in ONE place (AST containment)
// ---------------------------------------------------------------------------

// relayV1ImportPath is the wire Outcome type's import path. G4 keys on this
// path under ANY local name (including a dot or blank import), never on a
// hardcoded package identifier — a renamed import cannot evade it. This is
// why the #629 type-alias concession is DELETED, not reworded: an
// import-path-keyed walk sees `type wireOutcome = relayv1.Outcome` as
// ordinary selectors like any other.
const relayV1ImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"

// findWireOutcomeSelectors returns one finding string per line in file for
// every mechanism this walk can see:
//
//	(i)   a dot-import or blank import of relayV1ImportPath, reported in its
//	      own right — a dot-import makes every selector-free reference
//	      invisible to (ii);
//	(ii)  any *ast.SelectorExpr whose X is an ident bound to relayV1ImportPath
//	      (under any local name) and whose Sel is "Outcome" or has the
//	      "Outcome_" prefix;
//	(iii) any *ast.SelectorExpr whose Sel is "GetOutcome", on ANY receiver —
//	      the C3 widening: without it the walk is blind to a converter that
//	      never names the Outcome type at all (a renamed import plus
//	      tr.GetOutcome() switched on numeric literals). This rule is
//	      receiver-blind by design: an unrelated future GetOutcome() method
//	      anywhere in relay/ trips this guard too, and with no allowlist the
//	      remedy is a rename or an explicit reviewed decision, never a silent
//	      exemption. mcp/tasks.go already declares an unrelated TaskResult
//	      type with no GetOutcome method today — the plausible future
//	      collision this rule is written to catch if one is ever added.
//	(iv)  any *ast.SelectorExpr whose Sel is "Outcome" on a receiver OTHER
//	      than the relayV1ImportPath import identifier, in a file that
//	      imports relayV1ImportPath under any name — the plain-field-access
//	      widening (code review, cycle 2): a converter can reach the wire
//	      Outcome as a generated struct field (tr.Outcome) without ever
//	      calling GetOutcome() or naming the Outcome type via the import
//	      identifier, and (ii)/(iii) alone are blind to that. This rule is
//	      receiver-blind by the same reasoning as (iii): an unrelated
//	      "Outcome" field on some other struct, in a file that happens to
//	      import relayV1ImportPath for another reason, trips it too, and the
//	      remedy is the same — a rename or a reviewed decision, never a
//	      silent exemption.
//
// file must be parsed with comments OFF (parser.ParseFile mode 0): this is
// exactly why the two comment-prose mentions of relayv1.Outcome
// (jobs/jobs.go, capability/refusal.go) never trip this walk.
func findWireOutcomeSelectors(fset *token.FileSet, file *ast.File, _ string) []string {
	var findings []string

	localName := ""
	importsWire := false
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != relayV1ImportPath {
			continue
		}
		importsWire = true
		switch {
		case imp.Name == nil:
			localName = "relayv1"
		case imp.Name.Name == "_":
			findings = append(findings, fmt.Sprintf("%s: blank import of %s", fset.Position(imp.Pos()), relayV1ImportPath))
		case imp.Name.Name == ".":
			findings = append(findings, fmt.Sprintf("%s: dot-import of %s", fset.Position(imp.Pos()), relayV1ImportPath))
		default:
			localName = imp.Name.Name
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "GetOutcome" {
			findings = append(findings, fmt.Sprintf("%s: GetOutcome() call", fset.Position(sel.Pos())))
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && localName != "" && ident.Name == localName {
			if sel.Sel.Name == "Outcome" || strings.HasPrefix(sel.Sel.Name, "Outcome_") {
				findings = append(findings, fmt.Sprintf("%s: %s.%s", fset.Position(sel.Pos()), localName, sel.Sel.Name))
			}
			return true
		}
		if importsWire && sel.Sel.Name == "Outcome" {
			findings = append(findings, fmt.Sprintf("%s: .Outcome field access (file imports %s)", fset.Position(sel.Pos()), relayV1ImportPath))
		}
		return true
	})
	return findings
}

// TestOnlyDispatchConvertsWireOutcomes is G4. Its residual is smaller than it
// looks: m.GetTaskResult() (cmd/relay/tunnel.go:249) has exactly one
// production call site in the whole repo, and result( (convert.go:111) has
// exactly one production caller (router.go:228), so a hypothetical second
// converter would first have to acquire a *relayv1.TaskResult from the one
// place that yields one.
//
// SCOPE LIMIT — this comment claims no more than the walk performs. It
// covers the relay module's non-test, non-generated Go source. It finds a
// second converter that names the wire Outcome type under any import alias
// (via a selector on the import identifier, or a dot/blank import); that
// calls the generated GetOutcome accessor, on any receiver; or that reads
// the generated Outcome field directly (tr.Outcome), on any receiver, in
// any file that imports the wire package under any name. It does NOT find a
// converter that reaches the outcome through none of those: a cross-package
// type alias (a package that imports the wire package re-exports
// `type WireResult = relayv1.TaskResult`, and a second package that never
// imports the wire package reads `tr.Outcome` through the alias — the
// declaring file is silent too, because `relayv1.TaskResult` has
// `Sel == "TaskResult"`, matching none of these rules), struct embedding
// (`type Wrapped struct{ *relayv1.TaskResult }`, read as `w.Outcome` on the
// promoted field), protoreflect, reflection, or unmarshalling the message
// into a map — none of which types or selects "Outcome" as Go source in the
// file this walk inspects — and it does not cross module boundaries. Widening
// the walk to catch cross-package aliasing or embedding needs full type
// checking, a different tool than an AST walk; out of scope here. For
// everything it does find, internal/dispatch/convert.go is the only
// permitted home. G2 is the behavioural backstop for the converter that
// exists: it asserts result()'s refusal for every value in the generated
// enum. It is NOT a backstop against a hypothetical second converter that
// bypasses result() entirely; nothing in this PR is. That residual is
// contained by this guard for every mechanism that names the type, calls the
// accessor, or reads the field; by the fact a second converter must still
// acquire a *relayv1.TaskResult from the one call site that yields one; and
// by human review — relay/internal/dispatch/** is on the security surface
// and never merges unreviewed.
func TestOnlyDispatchConvertsWireOutcomes(t *testing.T) {
	root := filepath.Join(repoRoot, "relay")
	skipDir := filepath.Join(root, "internal", "relay", "v1")
	fset := token.NewFileSet()

	var findings []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == "testdata" || path == skipDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		findings = append(findings, findWireOutcomeSelectors(fset, file, path)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(findings) == 0 {
		t.Fatal("the walk found zero wire-Outcome selectors anywhere in relay/, including convert.go itself — it is not seeing what it thinks it is seeing")
	}
	for _, f := range findings {
		if !strings.Contains(f, filepath.FromSlash("internal/dispatch/convert.go")) {
			t.Errorf("wire Outcome conversion found outside internal/dispatch/convert.go — see this test's "+
				"header comment for what this walk does and does not see: %s", f)
		}
	}
}

// TestWireOutcomeSelectors_Fixture proves findWireOutcomeSelectors can
// actually FIRE, not merely that it is asserted to. Each case is a real Go
// file, parsed exactly as production code is.
func TestWireOutcomeSelectors_Fixture(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantLen int
	}{
		{
			// Never names the Outcome type at all — the C3 case the
			// unwidened walk (rev 2's rule set) found 0 in and the widened
			// one finds 1.
			name: "renamed_import_getoutcome_numeric_literal",
			src: `package fixture

import pb "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"

func sneak(tr *pb.TaskResult) {
	switch tr.GetOutcome() {
	case 7:
	}
}
`,
			wantLen: 1,
		},
		{
			name: "comment_only_mention",
			src: `package fixture

// This function's doc comment mentions relayv1.Outcome only in prose, never
// in code — mode-0 parsing discards comments, so this must stay silent.
func noop() {}
`,
			wantLen: 0,
		},
		{
			name: "dot_import",
			src: `package fixture

import . "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"

func noop() {}
`,
			wantLen: 1,
		},
		{
			name: "type_alias_behind_renamed_import",
			src: `package fixture

import wire "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"

type wireOutcome = wire.Outcome

func use() wireOutcome { return wire.Outcome_OUTCOME_SUCCESS }
`,
			wantLen: 2,
		},
		{
			// The code-review (cycle 2) case: reads the generated struct field
			// directly, no GetOutcome() call and no relayv1.Outcome selector —
			// this is what rule (ii)/(iii) alone left G4 blind to. Verbatim
			// shape of the reviewer's proof-of-concept converter.
			name: "plain_field_access_renamed_import",
			src: `package fixture

import pb "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"

func sneakyConvert2(tr *pb.TaskResult) int {
	switch tr.Outcome {
	case 7:
		return 1
	}
	return 0
}
`,
			wantLen: 1,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "fixture.go")
			if err := os.WriteFile(path, []byte(tt.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := findWireOutcomeSelectors(fset, file, path)
			if len(got) != tt.wantLen {
				t.Errorf("findWireOutcomeSelectors = %v (len %d), want len %d", got, len(got), tt.wantLen)
			}
		})
	}
}
