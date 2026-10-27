package registry

import "unicode/utf8"

// WellFormedLabel reports whether (key, value) is safe to store as a Label in
// EVERY stored namespace — safe meaning "renders as exactly one Selector
// term, forever" (capability.ParseSelector). The rule is Selector grammar,
// which does not know or care which namespace it is parsing, so it is the
// ONE predicate for the question, owned here rather than in protoconv, enroll
// or the renderer. It currently governs NINE seams — counted as one per
// place a value can be REFUSED or DECLINED, which is why the tag-space
// Enrollment Token side is two of them and the node-space write side is one:
//
//   - node-space write ingress: protoconv.ParseNodeLabel. One seam, two
//     callers — Hello (cmd/relay/tunnel.go) and Enroll's self_labels
//     (enroll/handler.go) — because both reach the same refusal.
//   - node-space read-back: store/registry.go's getNode, via
//     wellFormedLabels(nodeLabels) — closes legacy rows the gate never saw.
//   - relay-space enrollment: enroll.validateLegacyScope from
//     Service.Validate, refusing an ALREADY-STORED relay: scope that an earlier
//     release minted. A new mint carries no relay: label at all.
//   - relay-space read-back: store/registry.go's getNode, via
//     wellFormedLabels(relayLabels) — closes legacy rows the gate never saw.
//   - tag-space mint: ParseInitialTags from enroll.Service.Create, refusing
//     fresh initial tags before a token carrying them can exist.
//   - tag-space enrollment: ParseInitialTags from enroll.Service.Validate,
//     refusing ALREADY-STORED initial tags that no longer hold. A separate
//     seam, not a second caller of the first one: it refuses a value Create
//     never saw — see "Two write seams, one namespace" below.
//   - tag-space write ingress: capability.ParseTagLabel, from
//     TagWriter.WriteTag — refuses a tag before any change is built.
//   - tag-space store write: the store's AppendWithTagWrite and
//     InMemory.ApplyTagChanges, both via TagChange.Validate — refuses a change
//     built around the ingress.
//   - tag-space read-back: store/registry.go's getNode, via
//     wellFormedLabels(tagLabels) — declines a row written around the gate.
//
// There is a further CALL SITE of this predicate — store/labelscan.go's
// startup scan, plus the relay_labels_declined_total counter at the
// read-back seams above — but not a further SEAM: both are READERS of this
// predicate, reporting what it refuses or declines; neither one itself
// refuses or declines anything. The count above stays NINE.
//
// Why one predicate for every namespace, not one each: `registry` carries no proto
// dependency (registry.go's package doc), so a predicate that must be
// reachable from protoconv (node-space ingress), enroll (relay-space
// ingress) and internal/store (every namespace's SQLite read path, which
// re-derives domain values straight from rows with no proto involved) has to
// live somewhere none of those drag proto into another. registry is that
// place, and it must stay the ONLY place:
//
//   - it must NOT live in protoconv.ParseNodeLabel's callers, enroll's
//     validateScope callers, or the Console's renderer (console/fleet.go):
//     any of those would fork validation into a second predicate, which is
//     exactly the drift one predicate exists to prevent.
//   - it must NOT live in registry.Upsert or registry.SetRelayLabels: neither
//     write method has a way to express "refuse the whole request", so
//     moving validation there would force the enrollment path to silently
//     drop a malformed label instead of rejecting the request (see
//     enroll/handler.go's hard reject, for both namespaces).
//
// # The rule: an ASCII allowlist, not a blocklist
//
// The key must be non-empty. Every byte of the key and every byte of the
// value must be one of [A-Za-z0-9._-]. The empty value is accepted — see
// below.
//
// This is a BYTE loop, not a rune loop: any multi-byte UTF-8 sequence
// contains at least one byte >= 0x80, so every non-ASCII rune is rejected
// without decoding it. That is what closes the class nodestate.validFactValue's
// own doc records as an ACKNOWLEDGED GAP, NOT CLOSED: a blocklist on
// unicode.IsSpace or literal separator runes still admits U+2800 BRAILLE
// PATTERN BLANK, U+3164 HANGUL FILLER and U+200B ZERO WIDTH SPACE — none of
// which is whitespace or a control character, all of which render as an
// invisible or blank cell next to a hand-typed separator. "Closing this needs
// an allowlist, not a wider blocklist" is validFactValue's own conclusion;
// this predicate is what acts on it, in every stored namespace.
//
// # The four hazards this rules out, named
//
//   - `,` — capability.ParseSelector's term separator (strings.Split(s, ",")).
//     A `node:role` value of "web, relay:quarantine=on" renders as two
//     Selector terms, the second spelled in the relay: namespace. The key
//     carries it too: a scope entry `relay:env=prod,node:role=web` stores
//     relay-space key "env" with value "prod,node:role=web" — same hazard,
//     opposite namespace.
//   - whitespace, of any kind — a value with no comma of its own still reads
//     as two terms once it sits beside a hand-typed comma (a Console facet
//     href, a Selector string an AI-agent copy-pasted), and whitespace is
//     also the visually-blank-rune class the byte loop closes for free once
//     it is ASCII-only.
//   - `:` — subsumes "starts with node:/relay:/tag:/state:": a value
//     containing a colon can itself be read as introducing a second
//     namespaced term once concatenated the way console/fleet.go's
//     buildFacets does ("node:role=" + k).
//   - `=` in the KEY — a rendered `node:a=b=v` re-parses with the wrong
//     key/value split (ParseSelector cuts on the FIRST `=`), so the href
//     targets a different key/value pair than the one it was rendered from.
//     validFactValue's blocklist does not cover this hazard at all, because
//     it only ever validates a fact VALUE, never a key.
//
// # Why empty value is accepted
//
// Node-space provenance: relay-daemon's only source of node: labels is
// RELAY_NODE_LABELS, parsed by parse_node_labels (daemon/src/enroll.rs) as
// comma-and-`=`-split pairs; a bare `role` entry with no `=` yields
// ("role", ""). capability.ParseSelector agrees: "node:role=" parses to one
// Predicate with Key "role" and an empty Value.
//
// Relay-space provenance is the same shape from the other side: a scope
// entry written without `=` (`relay:marker`) is split by enroll/handler.go
// into bare key "marker" and value "", and ParseSelector reads
// "relay:marker=" as one Predicate with Key "marker" and an empty Value.
//
// Rejecting the empty value would refuse a legitimate, already-shipped
// spelling in either namespace for no grammar reason.
//
// # Why this alphabet, and why no length cap
//
// The legitimate alphabet was checked, not assumed, in BOTH namespaces.
// Node-space: every RELAY_NODE_LABELS example this repo ships —
// relay-daemon.env.example, the dev fleets' compose files, the enrollment and install
// docs, and the validation suites — uses only [A-Za-z0-9._-]. Relay-space:
// every shipped scope example — docs/api/openapi.yaml, docs/operations/
// enrollment.md, docs/dev-fleet.md, docker/dev-fleet-init.sh, the validation
// suites, every e2e test, and cmd/relay/devharness.go — uses the same
// alphabet. `/`, `+`, `@`, `:` and non-ASCII are deliberately excluded: none
// of them appears in a shipped example of either namespace, and admitting
// them later is backwards-compatible while excluding them later is not (an
// already-enrolled Node's label, or an already-minted token's scope, would
// start being refused). This predicate has no length cap: the hazard here is
// GRAMMAR, what a value can be misread as, not size. Length is a separate
// bound, MaxLabelKeyLen and MaxLabelValueLen, held per namespace by its own
// writer: WellFormedNodeLabel applies it to node: at the ingress and on
// read-back, and the tag: write and an Enrollment Token's initial tags apply
// it to tag:. A legacy relay: scope Label minted by a human is not held to it,
// so it is not in this predicate.
//
// # Two write seams, one namespace (an Enrollment Token's initial tags)
//
// Unlike node-space, which has exactly one write ingress (protoconv), an
// Enrollment Token's initial tags must be checked at TWO points against the
// SAME value: enroll.Service.Create (a fresh mint) and enroll.Service.Validate
// (an already-stored token — SQLite persists it across restarts and upgrades,
// and a stored row is not retroactively well-formed). Closing only Create
// leaves a stored row free to write a malformed tag on every Node it enrolls.
// A legacy relay: scope is checked the same second way, by
// enroll.validateLegacyScope. See ParseInitialTags and enroll.Service.Validate.
//
// # What this predicate does NOT cover
//
// `state:` is Relay-derived from a closed vocabulary at Selector-resolution
// time and is never stored (ADR-0034), so it never reaches this predicate.
// Tag-space is validated by this predicate and no other: a second one written
// to fit would be exactly the drift one predicate exists to prevent.
func WellFormedLabel(key, value string) bool {
	if key == "" {
		return false
	}
	return wellFormedLabelBytes(key) && wellFormedLabelBytes(value)
}

// wellFormedLabelBytes reports whether every byte of s is in [A-Za-z0-9._-].
// The same allowlist applies to both the key and the value: '=' is not in it
// either way, which is what closes the "=-in-the-key" hazard documented on
// WellFormedLabel without needing a side-specific rule. Deliberately a
// byte loop, not a rune loop — see that doc for why that is load-bearing
// rather than incidental.
func wellFormedLabelBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'A' && b <= 'Z':
		case b >= 'a' && b <= 'z':
		case b >= '0' && b <= '9':
		case b == '.' || b == '_' || b == '-':
		default:
			return false
		}
	}
	return true
}

// MaxLabelKeyLen and MaxLabelValueLen bound a Label's bare key and value in
// bytes (selectors-and-labels "Limits"). Within the safe alphabet a byte is a
// character, so bytes and the spec's characters agree. They are applied where a
// writer other than the Relay supplies a Label: node: through
// WellFormedNodeLabel, and the tag: write. WellFormedLabel does not apply
// them; see the length-cap note on its doc.
const (
	MaxLabelKeyLen   = 63
	MaxLabelValueLen = 255
)

// WellFormedNodeLabel reports whether a bare node: key and its value may be
// recorded or served: WellFormedLabel, with the key at most MaxLabelKeyLen and
// the value at most MaxLabelValueLen bytes. The node: ingress
// (protoconv.ParseNodeLabel) refuses a pair that fails, and the read-back of a
// stored node: Label declines one stored before the length bound existed.
func WellFormedNodeLabel(key, value string) bool {
	return len(key) <= MaxLabelKeyLen && len(value) <= MaxLabelValueLen &&
		WellFormedLabel(key, value)
}

// MaxLoggedLabelKeyBytes bounds a refused label key before it reaches a log or
// a report.
//
// A wire key is attacker-controlled up to gRPC's message limit, so quoting it
// is not enough: %q escapes control characters but preserves length, and a
// reconnect-looping Node could otherwise write megabytes per connect. 128
// bytes is far more than any legitimate key (the allowlist alphabet above is
// [A-Za-z0-9._-], and the shipped examples are under twenty characters) and
// still leaves a truncated key recognisable to the operator reading it.
const MaxLoggedLabelKeyBytes = 128

// BoundLogKey truncates k to MaxLoggedLabelKeyBytes ON A RUNE BOUNDARY, so a
// multi-byte sequence is never cut in half into a lone continuation byte, and
// reports whether it truncated.
//
// The rune backoff is the whole point and is easy to drop: a refused key is BY
// DEFINITION outside the ASCII allowlist WellFormedLabel enforces, so it may
// well end in a multi-byte sequence. A naive k[:128] of 127 ASCII bytes plus
// one U+2028 yields invalid UTF-8 ending in a bare 0xe2 — which the stdlib log
// handlers escape safely, but which a log shipper or index requiring valid
// UTF-8 may drop or mangle. Losing that record loses the finding for the most
// hostile key in the fleet, which is the one worth having.
//
// It lives HERE, beside the predicate that decides a key is refused, because
// there is one hazard and there must be one helper: both the Hello ingress
// (cmd/relay/tunnel.go) and the read-back scan (internal/store) bound the same
// attacker-influenced key for the same reason, and a second copy would drift.
// The tunnel also bounds the wire hello.node_id with it, the same hazard: an
// attacker-controlled string headed for a log.
func BoundLogKey(k string) (bounded string, truncated bool) {
	if len(k) <= MaxLoggedLabelKeyBytes {
		return k, false
	}
	cut := MaxLoggedLabelKeyBytes
	for cut > 0 && !utf8.RuneStart(k[cut]) {
		cut--
	}
	return k[:cut], true
}
