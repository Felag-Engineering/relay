// Package nodestate derives the `state:` label namespace (ADR-0034,
// invariant 7) from a single Node's registry record.
//
// # Why this is a package and not a rendering helper
//
// `state:` is the one namespace nobody sets. `node:` labels are stamped by the
// machine's config management, `tag:` by an operator, `relay:` by the Relay at
// enrollment or by an admin with step-up — but a `state:` label has no writer
// at all. It is evaluated at read time from the registry and a clock, which is
// what makes "nobody can forge one" a structural property rather than a
// permission check: there is no method to call.
//
// That evaluation has two consumers — the Console's fleet view renders it, and
// capability.Selector resolution matches on it (LabelSet) — and they must
// agree exactly, or an operator will filter for `state:offline` and target a
// different set than the one they were shown. One package, one vocabulary,
// both callers.
//
// # Why this package never imports internal/ca
//
// MarkerCertExpiring needs a warning window, and ADR-0034 pins it to a
// fraction of ca.LeafValidity. capability and api are both guarded by import
// allowlists that keep internal/ca out — the capability layer must never
// reach the CA, and admitting this package to their allowlists is only safe
// because it does not either. So this package holds the fraction's DEFAULT
// and CertExpiringWindow, a pure `leafValidity * fraction` conversion; the
// composition root — which already imports ca — multiplies once at startup
// and hands every surface the resulting time.Duration.
//
// # Node-local and objective
//
// Every label here is computable from ONE Node's record with no reference to
// any other Node. That is the load-bearing constraint from
// docs/design/console/00-foundations.md, and it is not stylistic: the first
// draft of this vocabulary carried a "behind the fleet's mode" marker, which
// silently inverts its own meaning halfway through a rollout — the moment the
// new fingerprint becomes the majority, every Node that already upgraded stops
// being "behind" and every laggard starts. A fleet-relative label also smuggles
// a desired state into a system that must never hold one (invariant 9).
//
// Drift is therefore NOT a state. It is read off the fingerprint facet as a
// distribution, and it is targeted by naming the value you want —
// `state:policy-fingerprint=4b18…` — which is an observation, not a judgement.
//
// # The vocabulary is closed
//
// A caller may not invent a term. Marker and Fact below enumerate everything
// that exists, and Labels returns exactly those. A `state:` term outside this
// set does not match a Node; it is a malformed Selector.
package nodestate

import (
	"strings"
	"time"
	"unicode"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Namespace is the label prefix every term here carries.
const Namespace = "state"

// Marker is a boolean `state:` label — present or absent, with no value.
//
// The four markers are the four ways a Node can be visibly unable to do what
// the fleet expects of it, and each one maps to a question in the four
// questions (00-foundations.md): can I reach it, will it take work, what will
// it permit.
type Marker string

const (
	// MarkerOffline: the Node has no live Tunnel right now. Every Task
	// dispatched to it resolves `unreachable` without leaving the Relay
	// (ADR-0004's offline fail-fast).
	MarkerOffline Marker = "offline"

	// MarkerOutdated: the daemon is below the Relay's dispatch minimum
	// (ADR-0014), so every dispatch returns `version_refused`. Derived by the
	// registry from the Relay's current config, never persisted.
	MarkerOutdated Marker = "outdated"

	// MarkerTemplateUnloadable: the Node's local Template Operation set failed
	// to load, so its template vocabulary is empty and it fails closed
	// (ADR-0021). The registry stores the literal "unloadable" in the
	// fingerprint field for this, which is why it is a marker and not a
	// missing value — "no templates installed" and "templates broken" are
	// different facts and must not collapse.
	MarkerTemplateUnloadable Marker = "template-unloadable"

	// MarkerCertExpiring: the Node's identity certificate is inside the
	// renewal warning window and has not renewed. Ignored, the Node simply
	// drops off the fleet when it lapses — silently, which is why it is worth
	// a marker at all.
	//
	// The window is CertExpiringWithin on Input, a file-only fraction of
	// ca.LeafValidity the composition root computes once via
	// CertExpiringWindow and hands to every surface (invariant 11) — this
	// package never reads the fraction from anywhere itself, and never
	// imports internal/ca (see the package doc's import note). An already-
	// lapsed certificate fires too: it is an alarm that automation failed,
	// never a countdown a caller can be early for.
	MarkerCertExpiring Marker = "cert-expiring"
)

// Fact is a key=value `state:` label: an observation with a value to target.
//
// These exist so that acting on drift means naming the value you want rather
// than naming a comparison. "The ones that are behind" is not expressible and
// deliberately so; `state:policy-fingerprint=4b18…c02` is.
type Fact string

const (
	FactDaemonVersion       Fact = "daemon-version"
	FactPolicyFingerprint   Fact = "policy-fingerprint"
	FactTemplateFingerprint Fact = "template-fingerprint"
)

// TemplateUnloadable is the literal the daemon reports in place of a
// template-set fingerprint when its local set failed to load (ADR-0021).
const TemplateUnloadable = "unloadable"

// Label is one derived `state:` term.
type Label struct {
	Key string

	// Value is empty for a marker and set for a fact.
	Value string

	// Attention is true when this label is a reason an operator cannot act on
	// the Node right now. It drives the amber treatment in the Console and
	// nothing else — it is presentation, and no decision is taken from it.
	Attention bool
}

// String renders the label in Selector syntax: `state:offline`, or
// `state:policy-fingerprint=4b18…`.
func (l Label) String() string {
	s := Namespace + ":" + l.Key
	if l.Value != "" {
		s += "=" + l.Value
	}
	return s
}

// Input is everything the derivation reads. It is a struct rather than a
// parameter list because two of the three inputs come from outside the
// registry record, and a caller that forgets one would otherwise get a
// plausible wrong answer instead of a compile error.
type Input struct {
	// Node is the registry record. Node.Outdated is already derived by the
	// registry against the Relay's configured minimum; this package does not
	// re-derive it and must not — a second version comparison is a second place
	// for the dispatch gate and the fleet view to disagree.
	//
	// Node.Connected is likewise already derived, by BOTH registry
	// implementations, from the dispatch router's live Tunnel set — the same
	// lifecycle fact MCP and the Control API already report. There is
	// deliberately no separate Connected field on Input: reading it off the
	// Node record is what makes every marker here provably "a function of one
	// Node's record" (ADR-0034), rather than a second liveness source a
	// caller could feed a different answer through.
	Node registry.Node

	// Now is the instant this evaluation is happening at — needed to compare
	// against Node.CertNotAfter. A caller passes its own clock (never
	// time.Now() here) so a whole Selector resolution or a whole rendered page
	// is evaluated against ONE instant.
	Now time.Time

	// CertExpiringWithin is the warning window for MarkerCertExpiring: the
	// marker fires when less than this much of the certificate's remaining
	// lifetime is left. File-only configuration (invariant 11) computed once
	// by the composition root via CertExpiringWindow — this package never
	// reads it from anywhere itself. Zero means the marker never fires.
	CertExpiringWithin time.Duration
}

// Markers returns the boolean `state:` labels that hold for in, in a stable
// order (severity, not alphabetical — the order is what an operator's eye
// scans).
//
// A Node with no markers is normal, and most Nodes are normal. The empty slice
// is the calmest and most common answer.
func Markers(in Input) []Label {
	var out []Label
	if !in.Node.Connected {
		out = append(out, Label{Key: string(MarkerOffline), Attention: true})
	}
	if in.Node.Outdated {
		out = append(out, Label{Key: string(MarkerOutdated), Attention: true})
	}
	// A zero CertExpiringWithin means the marker never fires (Input's doc
	// comment) — the composition root always sets it, so the only way this
	// stays quiet in production is a genuinely healthy certificate. An
	// unrecorded provenance (CertProvenanceKnown false) must never read as an
	// expiry in 1970, which is exactly what comparing a zero CertNotAfter
	// against Now would do.
	if in.CertExpiringWithin > 0 && in.Node.CertProvenanceKnown() &&
		in.Node.CertNotAfter.Sub(in.Now) < in.CertExpiringWithin {
		// An already-lapsed certificate (negative remaining) fires too: this is
		// an alarm that renewal automation failed, never a countdown a caller
		// can be early for.
		out = append(out, Label{Key: string(MarkerCertExpiring), Attention: true})
	}
	if in.Node.TemplateSetFingerprint == TemplateUnloadable {
		// Grey, not amber: an empty template vocabulary is inertness, not an
		// alarm. The Node still takes native Operations.
		out = append(out, Label{Key: string(MarkerTemplateUnloadable)})
	}
	return out
}

// DefaultCertExpiringFraction is ADR-0034's warning threshold: 25% of
// ca.LeafValidity remaining (84h at the current 336h lifetime). The daemon
// renews at a jittered 50-75% of the lifetime (daemon/src/renew.rs), so a
// Node under a quarter remaining has missed its entire renewal window —
// MarkerCertExpiring is an alarm that automation failed, not a heads-up.
const DefaultCertExpiringFraction = 0.25

// CertExpiringWindow converts a fraction of a certificate's lifetime into the
// absolute Duration Input.CertExpiringWithin wants.
//
// This package does not import internal/ca (see the package doc): it holds
// the fraction's DEFAULT and this pure conversion, and the composition root —
// which already imports ca for LeafValidity — multiplies once at startup and
// hands every surface the same Duration (invariant 11).
func CertExpiringWindow(leafValidity time.Duration, fraction float64) time.Duration {
	return time.Duration(float64(leafValidity) * fraction)
}

// Facts returns the key=value `state:` labels for in.
//
// A fact with no value is omitted rather than emitted empty: a Node that has
// never reported a Policy fingerprint has no such fact, and rendering
// `state:policy-fingerprint=` would put a targetable term on screen that
// matches nothing.
//
// A fact whose value fails validFactValue is likewise omitted, never
// sanitised in place: DaemonVersion, PolicyFingerprint and
// TemplateSetFingerprint are self-reported by the Node (tunnel.go copies
// Hello straight into registry.Report with no validation at that ingress),
// and String renders them unescaped into Selector grammar that every surface
// then advertises as directly targetable. Silently truncating or escaping a
// hostile value would still let a Node choose what gets rendered; omitting it
// is what keeps the closed vocabulary closed on the value side, not only the
// key side (the key side was already closed by KeyKind).
func Facts(in Input) []Label {
	var out []Label
	if v := in.Node.DaemonVersion; v != "" && validFactValue(v) {
		out = append(out, Label{Key: string(FactDaemonVersion), Value: v})
	}
	if v := in.Node.PolicyFingerprint; v != "" && validFactValue(v) {
		out = append(out, Label{Key: string(FactPolicyFingerprint), Value: v})
	}
	if v := in.Node.TemplateSetFingerprint; v != "" && v != TemplateUnloadable && validFactValue(v) {
		out = append(out, Label{Key: string(FactTemplateFingerprint), Value: v})
	}
	return out
}

// factNamespacePrefixes mirrors the four Selector namespace prefixes
// (capability.NamespaceNode/Relay/Tag/State) that ParseSelector recognises.
// nodestate cannot import capability — capability already imports nodestate,
// and the cycle would go the wrong way — so the four literals are repeated
// here rather than shared; grep for "node:" if the namespace set ever grows.
var factNamespacePrefixes = []string{"node:", "relay:", "tag:", "state:"}

// validFactValue reports whether v is safe to render unescaped into Selector
// grammar (capability.ParseSelector). A Node's self-reported fact values
// arrive with no validation at the wire ingress, so this is the vocabulary's
// closure on the VALUE side: a Node sending
// `Hello.daemon_version = "1.4.2, tag:x=y"` must not be able to inject a
// second Selector term merely by being rendered as `state:daemon-version=…`.
//
// Rejected outright rather than escaped, because ParseSelector has no escape
// syntax to escape INTO:
//   - `,` is the term separator ParseSelector splits on — the injection this
//     finding demonstrates.
//   - any Unicode `White_Space` rune anywhere in the value — leading,
//     trailing or embedded — lets a value sit next to a hand-typed comma (a
//     Console facet href, an AI-agent's copy-pasted selector string) and
//     still read as two terms once joined. This is CONTEXT.md's "Canonical
//     form" whitespace notion, not the ASCII one: ADR-0019's Raw Exec split
//     (`argv.join(" ").split_whitespace()`) folds a tab or an NBSP exactly
//     like a space, using the same `White_Space` property Rust's
//     `char::is_whitespace` implements, and Go's `unicode.IsSpace` agrees
//     with `unicode.Is(unicode.White_Space, r)` over every rune in Go's
//     Unicode tables — one whitespace definition, both sides of the system.
//     Zero-width characters (U+200B ZWSP, U+FEFF, U+180E) are category Cf,
//     `White_Space=No`, and are deliberately NOT rejected here: they create
//     no visible gap next to a comma, which is the hazard this bullet closes,
//     and rejecting them would make the Relay's whitespace notion strictly
//     wider than the daemon's — the same inconsistency this predicate exists
//     to remove, just in the other direction.
//   - a value starting with one of the four namespace prefixes could pose as
//     a second term the moment it lands beside any comma downstream, even one
//     this package did not itself introduce.
//
// None of these ever appear in a legitimate report: DaemonVersion is semver
// over `[0-9A-Za-z.+-]` (daemon/src/version.rs `version()`, asserted by that
// module's tests and by registry/daemon_version_contract_test.go) stamped by
// scripts/build-version.sh, whose header documents its three fields as
// whitespace-free by pipeline contract — not a runtime check version()
// itself performs, so a hand-corrupted build is the same failure class as
// any other pipeline compromise, not a case this predicate needs to catch.
// PolicyFingerprint and TemplateSetFingerprint are lowercase SHA-256 hex
// (daemon/src/policy.rs `policy_fingerprint`, daemon/src/templates.rs
// `fingerprint_files`) or the literal `unloadable`. So this never rejects a
// well-behaved daemon's report.
func validFactValue(v string) bool {
	if strings.Contains(v, ",") {
		return false
	}
	// strings.TrimSpace trims exactly the runes unicode.IsSpace is true for
	// (its ASCII fast path agrees with unicode.IsSpace on all 128 ASCII code
	// points and falls back to unicode.IsSpace itself past ASCII), so "has a
	// leading or trailing space rune" is a strict subset of "has a space rune
	// anywhere" — a separate TrimSpace check here would be dead code.
	if strings.ContainsFunc(v, unicode.IsSpace) {
		return false
	}
	for _, p := range factNamespacePrefixes {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	return true
}

// Labels returns every `state:` label for in — markers first, then facts.
func Labels(in Input) []Label {
	return append(Markers(in), Facts(in)...)
}

// allMarkers and allFacts are the closed vocabulary, in the same order Labels
// renders them. KeyKind, MarkerKeys and FactKeys are the one place that
// vocabulary is enumerated for a caller that has not evaluated an Input yet —
// a Selector parser, in particular, has a bare key and nothing else.
var allMarkers = []Marker{MarkerOffline, MarkerOutdated, MarkerCertExpiring, MarkerTemplateUnloadable}
var allFacts = []Fact{FactDaemonVersion, FactPolicyFingerprint, FactTemplateFingerprint}

// Kind classifies a `state:` key by shape: a boolean marker (no value) or a
// key=value fact. KindUnknown is the zero value and everything outside the
// closed vocabulary — a Selector term for it is a parse error, never a term
// that silently matches nothing (ADR-0034).
type Kind int

const (
	KindUnknown Kind = iota
	KindMarker
	KindFact
)

// KeyKind classifies key against the closed vocabulary. It is the one place
// that classification happens, so a Selector parser and this package's own
// Labels/LabelSet can never disagree about what a `state:` key means.
func KeyKind(key string) Kind {
	for _, m := range allMarkers {
		if string(m) == key {
			return KindMarker
		}
	}
	for _, f := range allFacts {
		if string(f) == key {
			return KindFact
		}
	}
	return KindUnknown
}

// MarkerKeys returns every marker key, for error text that names the closed
// vocabulary rather than just rejecting the term.
func MarkerKeys() []string {
	out := make([]string, len(allMarkers))
	for i, m := range allMarkers {
		out[i] = string(m)
	}
	return out
}

// FactKeys is MarkerKeys' sibling for facts.
func FactKeys() []string {
	out := make([]string, len(allFacts))
	for i, f := range allFacts {
		out[i] = string(f)
	}
	return out
}

// LabelSet reduces Labels(in) to the key->value map a `state:` Predicate
// looks up — "" for a marker, the fact's value for a fact. It is built FROM
// Labels, never independently, so the rendered set (fleet view, list_nodes,
// describe_node) and the matched set (a Selector) cannot drift apart: an
// unknown key is simply absent from the map, which is closure by
// construction, fail closed, exactly like n.NodeLabels/n.RelayLabels.
func LabelSet(in Input) map[string]string {
	labels := Labels(in)
	out := make(map[string]string, len(labels))
	for _, l := range labels {
		out[l.Key] = l.Value
	}
	return out
}

// CertExpiryKnown reports whether the Relay records enough about a Node's
// certificate to say anything about its expiry.
//
// Until #440 this returned a constant false and every caller rendered "not
// recorded". It now delegates, so the panels that were honest about the gap
// became live by changing one function rather than by finding every screen that
// had guessed — which was the point of routing them all through here.
func CertExpiryKnown(n registry.Node) bool { return n.CertProvenanceKnown() }

// Attention reports whether any marker for in demands attention. It is the
// fleet view's rollup predicate.
func Attention(in Input) bool {
	for _, m := range Markers(in) {
		if m.Attention {
			return true
		}
	}
	return false
}

// Quarantined reports whether the Node carries the `relay:quarantine=on` fence —
// the first rung of the incident ladder (ADR-0020).
//
// It delegates to registry.Node.Quarantined so the reader and the v0.7.0 writer
// share one definition. It tested only for the KEY until 2026-08-26, which meant
// `relay:quarantine=off` rendered a Node as fenced while the Selector an
// operator would target it with (`relay:quarantine=on`, key AND value) matched
// nothing — the drawn set and the targetable set disagreeing, on the security
// lane.
//
// It lives here beside the derived states because the fleet view renders it in
// the same column, but it is emphatically NOT a `state:` label: quarantine is
// DECLARED by an admin with step-up, and the difference between "the Relay
// observed this" and "a human decided this" is the difference between an
// observation and an act. Rendering them in one column is a layout choice;
// deriving them in one function would be a category error, so this returns a
// bool and never a Label.
func Quarantined(n registry.Node) bool { return n.Quarantined() }

// Since renders how long ago t was, in the coarse units an operator reads at a
// glance. Not a duration formatter: "3d" is the answer to "is this Node worth
// looking at", and "72h13m4.2s" is not.
func Since(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + "h"
	default:
		return itoa(int(d.Hours()/24)) + "d"
	}
}

// Until renders how long remains before t, in the same coarse units Since uses
// for the past. "in 11d" is the answer to "should I care yet"; a duration to the
// nanosecond is not.
//
// A time already past reads as overdue rather than as a negative duration: a
// Node whose identity lapsed two days ago has a problem, not a negative eleven
// days of validity.
func Until(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	if !t.After(now) {
		return "expired " + Since(t, now) + " ago"
	}
	return "in " + Since(now.Add(-t.Sub(now)), now)
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
