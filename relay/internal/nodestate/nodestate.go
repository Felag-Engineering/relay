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
// Selector resolution (#414) will match on it — and they must agree exactly, or
// an operator will filter for `state:offline` and target a different set than
// the one they were shown. One package, one vocabulary, both callers.
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
	"time"

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
	// NOT YET DERIVABLE. registry.Node carries the certificate FINGERPRINT and
	// nothing else — no notAfter, no renewal count — so there is no honest way
	// to compute this today; issue #440 adds the fields. Labels therefore never
	// emits it, and CertExpiryKnown reports false so a caller renders "not
	// recorded" rather than "fine". A marker that silently reads as absent when
	// it is really unknown is the worst of the three possible answers.
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
	Node registry.Node

	// Connected is whether the Node has a live Tunnel right now, from the
	// dispatch router. It is NOT read from LastSeen: a Node that reported four
	// seconds ago and then dropped its connection is offline for dispatch
	// purposes this instant, and "recently seen" would render it green while
	// every Task to it resolved `unreachable`.
	Connected bool
}

// Markers returns the boolean `state:` labels that hold for in, in a stable
// order (severity, not alphabetical — the order is what an operator's eye
// scans).
//
// A Node with no markers is normal, and most Nodes are normal. The empty slice
// is the calmest and most common answer.
func Markers(in Input) []Label {
	var out []Label
	if !in.Connected {
		out = append(out, Label{Key: string(MarkerOffline), Attention: true})
	}
	if in.Node.Outdated {
		out = append(out, Label{Key: string(MarkerOutdated), Attention: true})
	}
	if in.Node.TemplateSetFingerprint == TemplateUnloadable {
		// Grey, not amber: an empty template vocabulary is inertness, not an
		// alarm. The Node still takes native Operations.
		out = append(out, Label{Key: string(MarkerTemplateUnloadable)})
	}
	// MarkerCertExpiring is deliberately not emitted — see its doc comment.
	return out
}

// Facts returns the key=value `state:` labels for in.
//
// A fact with no value is omitted rather than emitted empty: a Node that has
// never reported a Policy fingerprint has no such fact, and rendering
// `state:policy-fingerprint=` would put a targetable term on screen that
// matches nothing.
func Facts(in Input) []Label {
	var out []Label
	if v := in.Node.DaemonVersion; v != "" {
		out = append(out, Label{Key: string(FactDaemonVersion), Value: v})
	}
	if v := in.Node.PolicyFingerprint; v != "" {
		out = append(out, Label{Key: string(FactPolicyFingerprint), Value: v})
	}
	if v := in.Node.TemplateSetFingerprint; v != "" && v != TemplateUnloadable {
		out = append(out, Label{Key: string(FactTemplateFingerprint), Value: v})
	}
	return out
}

// Labels returns every `state:` label for in — markers first, then facts.
func Labels(in Input) []Label {
	return append(Markers(in), Facts(in)...)
}

// CertExpiryKnown reports whether the Relay records enough about a Node's
// certificate to say anything about its expiry.
//
// It is a function returning a constant false, which looks silly and is not:
// it gives every caller one place to ask, so when #440 lands the Console's
// "not recorded" panels become live by changing this file rather than by
// finding every screen that guessed. The alternative — screens that quietly
// omit the row — hides the gap instead of stating it.
func CertExpiryKnown(registry.Node) bool { return false }

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
