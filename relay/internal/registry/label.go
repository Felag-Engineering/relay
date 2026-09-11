package registry

// WellFormedLabel reports whether (key, value) is safe to store as a Label in
// EITHER stored namespace — safe meaning "renders as exactly one Selector
// term, forever" (capability.ParseSelector). The rule is Selector grammar,
// which does not know or care which namespace it is parsing, so it is the
// ONE predicate for the question, owned here rather than in protoconv, enroll
// or the renderer. It currently governs FIVE seams — counted as one per
// place a value can be REFUSED or DECLINED, which is why the relay-space
// write side is two of them and the node-space write side is one:
//
//   - node-space write ingress: protoconv.ParseNodeLabel. One seam, two
//     callers — Hello (cmd/relay/tunnel.go) and Enroll's self_labels
//     (enroll/handler.go) — because both reach the same refusal.
//   - node-space read-back: store/registry.go's getNode, via
//     wellFormedLabels(nodeLabels) — closes rows a pre-#504 Relay wrote.
//   - relay-space mint: enroll.validateScope from Service.Create, refusing a
//     fresh scope before a token carrying it can exist.
//   - relay-space enrollment: enroll.validateScope from Service.Validate,
//     refusing an ALREADY-STORED scope that predates this gate. A separate
//     seam, not a second caller of the first one: it refuses a value Create
//     never saw — see "Two write seams, one namespace" below.
//   - relay-space read-back: store/registry.go's getNode, via
//     wellFormedLabels(relayLabels) — closes rows a pre-#555 Relay wrote.
//
// #565 adds a sixth CALL SITE of this predicate — store/labelscan.go's
// startup scan, plus the relay_labels_declined_total counter at the
// read-back seams above — but not a sixth SEAM: both are READERS of this
// predicate, reporting what it refuses or declines; neither one itself
// refuses or declines anything. The count above stays FIVE.
//
// Why one predicate for two namespaces, not two: `registry` carries no proto
// dependency (registry.go's package doc), so a predicate that must be
// reachable from protoconv (node-space ingress), enroll (relay-space
// ingress) and internal/store (both namespaces' SQLite read path, which
// re-derives domain values straight from rows with no proto involved) has to
// live somewhere none of those drag proto into another. registry is that
// place, and it must stay the ONLY place:
//
//   - it must NOT live in protoconv.ParseNodeLabel's callers, enroll's
//     validateScope callers, or the Console's renderer (console/fleet.go):
//     any of those would fork validation into a second predicate, which is
//     exactly the drift #488 exists to remove.
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
// this predicate is what acts on it, in both stored namespaces.
//
// # The four hazards this rules out, named
//
//   - `,` — capability.ParseSelector's term separator (strings.Split(s, ",")).
//     This is #504's measured payload: a `node:role` value of
//     "web, relay:quarantine=on" renders as two Selector terms, the second
//     spelled in the relay: namespace. #555 mirrors it in the key: a scope
//     entry `relay:env=prod,node:role=web` stores relay-space key "env" with
//     value "prod,node:role=web" — same hazard, opposite namespace.
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
// relay-daemon.env.example, docker-compose.yml, the enrollment and install
// docs, and the validation suites — uses only [A-Za-z0-9._-]. Relay-space:
// every shipped scope example — docs/api/openapi.yaml, docs/operations/
// enrollment.md, docs/dev-fleet.md, docker/bootstrap.sh, the validation
// suites, every e2e test, and cmd/relay/devharness.go — uses the same
// alphabet. `/`, `+`, `@`, `:` and non-ASCII are deliberately excluded: none
// of them appears in a shipped example of either namespace, and admitting
// them later is backwards-compatible while excluding them later is not (an
// already-enrolled Node's label, or an already-minted token's scope, would
// start being refused). There is no length cap: the hazard here is GRAMMAR —
// what a value can be misread as — not size, and gRPC's own message-size
// limit already bounds how large a Hello, Enroll or mint request (and
// therefore this map) can be. Leaving it unbounded here is a decision, not
// an oversight.
//
// # Two write seams, one namespace (relay-space)
//
// Unlike node-space, which has exactly one write ingress (protoconv), the
// relay-space rule must be enforced at TWO points against the SAME scope
// value: enroll.Service.Create (a fresh mint) and enroll.Service.Validate
// (an already-stored token whose scope predates this gate — SQLite persists
// it across restarts and upgrades, and a token minted before the gate
// existed does not retroactively become well-formed). Closing only Create
// leaves every pre-gate token free to keep stamping a malformed relay-space
// label forever. See enroll.validateScope and enroll.Service.Validate.
//
// # What this predicate does NOT cover
//
// `state:` is Relay-derived from a closed vocabulary at Selector-resolution
// time and is never stored (ADR-0034), so it never reaches this predicate.
// `tag:` has no storage until #430; when it lands it must be validated by
// THIS predicate, never a new one written to fit — that fork is exactly what
// #488 exists to prevent.
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
