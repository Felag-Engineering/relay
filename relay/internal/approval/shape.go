package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
)

// shape.go is the SHAPE KEY (#415, D10): the content address of WHAT an
// approval is for, as opposed to how much of it. It exists so the approval
// object can answer "what did I approve last time that looked like this?" as a
// lookup rather than a scan, which is what the anti-fatigue diff on the
// approval screen needs ("same as Tuesday, except the fan-out grew 1,180 ->
// 2,214").
//
// Three rules govern everything below, and each is load-bearing:
//
//  1. THE SHAPE KEY IS NEVER AN AUTHORIZATION OR RELEASE LOOKUP. A dispatch
//     proceeds on a matching PlanHash or on a claimed Grant whose Scope covers
//     it (see capability.checkApproval), and on nothing else; HashScope is what
//     binds the Grant's own approval. The shape key deliberately excludes the
//     resolved fan-out, so a key match means "these look alike", never "this
//     was approved". A release path that consulted it would be an approval-gate
//     bypass, and capability's TestSameShapeDifferentPlanStillParks exists to
//     prove no such path appeared.
//
//  2. THE PREIMAGE IS FULLY LENGTH-PREFIXED WITH A FIXED FIELD SEQUENCE. Every
//     field name is a compile-time literal, every variable-length value is
//     written as its byte length, a colon, then its bytes, and every count is a
//     \n-terminated decimal — so the preimage decodes left-to-right
//     deterministically and no caller-controlled value can forge a field
//     boundary or a count. In particular an argument KEY and its VALUE are
//     SEPARATE fields; folding the key into the field name (as
//     `write("arg."+k, v)` would) makes the key/value split ambiguous and is
//     collidable.
//
//  3. THE KEY FOLDS EXACTLY WHAT THE MATCHER FOLDS, AND NOWHERE ELSE. Nothing
//     in HashPlanShape is case-folded, whitespace-trimmed, or Unicode-
//     normalised, because Selector.Matches is an exact map lookup and the
//     daemon compares argument values byte-for-byte: folding here would let two
//     Selectors that target DIFFERENT Nodes share a key. The single exception
//     is HashGrantShape's account and Operation names, which Grant.Covers
//     itself compares with strings.EqualFold.
//
// The writer helpers below deliberately REPEAT plan.go's rather than
// refactoring it: HashPlan and HashScope are live security bindings on stored
// records, and even a byte-identical refactor of them is risk with no upside.
//
// KNOWN, ESCALATED, NOT FIXED HERE: HashPlan's own encoding has a real
// collision, because it writes the argument key inside the field name. Issue
// #494 carries it; nothing in this file shares the weakness.

// ShapeKeyVersion is written as the first bytes of every shape preimage, so a
// future encoding change produces a visibly different key rather than silently
// re-pointing stored ones.
const ShapeKeyVersion = "v1"

// SelectorTerm is one normalised Selector term as the shape key sees it.
//
// Namespace is the lower-case token for one of the four label namespaces
// ("node", "relay", "tag", "state" — ADR-0006, ADR-0020, ADR-0034, invariant
// 7). It is a SEPARATE FIELD rather than a prefix on Key, and that is the
// structural reason a `tag:` term can never collide with a `relay:` one: the
// namespace is projected from the typed Predicate, so no key or value — however
// it is spelled — can forge a namespace boundary.
//
// Value may legitimately be empty: a `state:` marker term carries none, and
// `node:role=` parses to an empty value too. Both hash as a zero-length field,
// distinct from any non-empty one.
type SelectorTerm struct {
	Namespace string
	Key       string
	Value     string
}

// SelectorShape is the Selector half of a shape key: the normalised terms, and
// whether the Selector they were projected from was KNOWN at all.
//
// The two facts are separate because "no Selector" is not "a Selector with no
// terms". A Selector with no Predicates matches EVERY Node (Selector.Resolve),
// so empty Terms is the fleet-wide dispatch — the widest thing there is.
// Conflating the two would let a record parked with no Selector information
// group with a genuine fleet-wide dispatch of the same Action, and the approval
// screen would tell a human "you approved this on Tuesday" about something
// materially broader.
//
// The ZERO VALUE IS UNKNOWN, not fleet-wide, and that is the point: the easy
// default a future call site reaches for is the one that claims the least. Two
// unknown records still share a key with each other — they are equally
// uninformative — but never with a real Selector.
//
// [capability.Selector.Shape] is the only thing that sets Known.
type SelectorShape struct {
	Known bool
	Terms []SelectorTerm
}

// LegacyShapePrefix marks a shape key that could not be computed — a record
// written before #415, whose Selector was never stored (migration 0012) and so
// cannot be recovered. D10 rules out reconstructing one: "normalising a
// Selector after the fact is guesswork, and the approval trail is exactly the
// data you least want to guess about."
const LegacyShapePrefix = "legacy:"

// LegacyShapeKey is the per-record placeholder for a Request whose true shape
// is unknowable. It is unique per record, so a legacy record is its own shape
// and matches nothing but itself — the diff callout can never tell a human "you
// approved this Tuesday" about a record nobody can compare.
func LegacyShapeKey(requestID string) string { return LegacyShapePrefix + requestID }

// IsLegacyShapeKey reports whether k is a placeholder rather than a computed
// key. A real key is 64 hex characters and can never carry the prefix.
func IsLegacyShapeKey(k string) bool { return strings.HasPrefix(k, LegacyShapePrefix) }

// writeField writes one variable-length field as "name=<byte length>:<bytes>\n".
func writeField(h io.Writer, field, value string) {
	fmt.Fprintf(h, "%s=%d:%s\n", field, len(value), value)
}

// writeCount writes one framing count as "name=<n>\n".
func writeCount(h io.Writer, field string, n int) {
	fmt.Fprintf(h, "%s=%d\n", field, n)
}

// HashPlanShape hashes what act does over sel, excluding the resolved fan-out
// and every argument opvocab declares to be SCALE.
//
// Every field is ALWAYS written, in this exact order, with no conditional
// presence — an Operation Action writes an empty argv block and a Raw Exec
// Action writes an empty args block — so the preimage's structure never depends
// on its content.
//
// Also excluded, for the same reason HashPlan excludes them: the requester, who
// is bound separately on the Request, and Action.TimeoutSeconds, which does not
// change what runs where.
//
// The zero SelectorShape is a well-defined key — "no Selector was known" — and
// is deliberately NOT the same key as the empty (fleet-wide) Selector.
func HashPlanShape(act jobs.Action, sel SelectorShape) string {
	h := sha256.New()

	writeField(h, "shape", ShapeKeyVersion)
	writeField(h, "domain", "plan")
	writeField(h, "kind", ActionKindName(act.Kind))
	writeField(h, "risk", RiskClassName(act.RiskClass))
	writeField(h, "op", act.OperationName)

	// Only an Operation Action has arguments to classify. ShapeArgs is the ONE
	// place the shape-vs-scale declaration is applied.
	var args map[string]string
	if act.Kind == jobs.ActionOperation {
		args = opvocab.ShapeArgs(act.OperationName, act.OperationArgs)
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeCount(h, "args", len(keys))
	for _, k := range keys {
		writeField(h, "arg.k", k)
		writeField(h, "arg.v", args[k])
	}

	// EVERY argv element is shape. There is no declaration for the arbitrary-
	// command path, and guessing which element is "scale" is exactly the
	// inference this feature must not make — strictness is the right default
	// for the unclassifiable path.
	var argv []string
	if act.Kind == jobs.ActionRawExec {
		argv = act.RawExecArgv
	}
	// argv order is semantic — never sorted.
	writeCount(h, "argv", len(argv))
	for _, a := range argv {
		writeField(h, "argv.v", a)
	}

	// Written as its own field rather than inferred from len(terms): an unknown
	// Selector and a fleet-wide one are different facts, and neither may be
	// read out of the absence of the other.
	fmt.Fprintf(h, "sel.known=%t\n", sel.Known)
	terms := canonicalTerms(sel.Terms)
	writeCount(h, "sel", len(terms))
	for _, t := range terms {
		writeField(h, "sel.ns", t.Namespace)
		writeField(h, "sel.k", t.Key)
		writeField(h, "sel.v", t.Value)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// canonicalTerms sorts terms into a total order and drops EXACT duplicates.
//
// Sorting is by (Namespace, Key, Value) AS STRINGS rather than by a namespace
// enum ordinal, so a future renumbering of that enum cannot reorder — and so
// silently re-point — keys already stored.
//
// Dropping exact duplicates is safe because Selector.Matches is a conjunction
// of equality predicates: a repeated identical predicate cannot change the
// matched set. Terms sharing a namespace and key but differing in VALUE are NOT
// collapsed — "node:a=b, node:a=c" is contradictory, matches nothing, and is a
// different Selector from either half.
func canonicalTerms(sel []SelectorTerm) []SelectorTerm {
	terms := append([]SelectorTerm(nil), sel...)
	sort.Slice(terms, func(i, j int) bool {
		a, b := terms[i], terms[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Value < b.Value
	})

	out := terms[:0]
	for i, t := range terms {
		if i > 0 && t == terms[i-1] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// HashGrantShape hashes a Grant's Scope minus the bounds that are SCALE: the
// window, the use limit, and the fan-out ceiling.
//
// Excluding MaxFanOut is deliberate and is the most valuable half of the
// feature here. D10 excludes fan-out, and a ceiling is fan-out: "same scope,
// ceiling grew 10 -> 500" is precisely the diff the callout exists to shout,
// and it only renders if the two records share a key. HashScope — the Grant's
// actual approval binding — still covers all three, so none of them can move
// without invalidating the approval.
//
// Account and Operation names are lower-cased HERE AND ONLY HERE, because
// Grant.Covers compares both with strings.EqualFold. SelectorNamespace is NOT
// folded: Scope.Validate accepts it case-sensitively, so "Node" is not a
// namespace at all.
func HashGrantShape(s Scope) string {
	h := sha256.New()

	writeField(h, "shape", ShapeKeyVersion)
	writeField(h, "domain", "grant")
	writeField(h, "risk", RiskClassName(s.RiskClass))
	writeField(h, "account", strings.ToLower(s.Account))
	writeField(h, "namespace", s.SelectorNamespace)
	fmt.Fprintf(h, "raw_exec=%t\n", s.RawExec)

	ops := make([]string, 0, len(s.Operations))
	for _, op := range s.Operations {
		ops = append(ops, strings.ToLower(op))
	}
	sort.Strings(ops)
	// De-duplicated AFTER folding, so "NGINX" and "nginx" — which Covers treats
	// as one Operation — do not read as two.
	deduped := ops[:0]
	for i, op := range ops {
		if i > 0 && op == ops[i-1] {
			continue
		}
		deduped = append(deduped, op)
	}
	writeCount(h, "ops", len(deduped))
	for _, op := range deduped {
		writeField(h, "op", op)
	}

	return hex.EncodeToString(h.Sum(nil))
}
