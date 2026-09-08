package registry

// WellFormedNodeLabel reports whether (key, value) is safe to store as a
// node-space label — safe meaning "renders as exactly one Selector term,
// forever" (capability.ParseSelector). This is the ONE predicate for that
// question, owned here rather than in protoconv or the renderer:
//
//   - registry carries no proto dependency (registry.go's package doc), so a
//     predicate that must be reachable from BOTH protoconv (the write
//     ingress, ADR-0006) and internal/store (the SQLite read path, which
//     re-derives domain values straight from rows with no proto involved —
//     see store/registry.go's getNode) has to live somewhere neither drags
//     proto into the other. registry is that place.
//   - it must NOT live in protoconv.ParseNodeLabel's caller (cmd/relay/tunnel.go,
//     internal/enroll/handler.go) or the Console's renderer (console/fleet.go):
//     either of those would fork validation into a second predicate, which is
//     exactly the drift #488 exists to remove.
//   - it must NOT live in registry.Upsert: Upsert has no way to express
//     "refuse the whole enrollment", so moving validation there would force
//     the enrollment path to silently drop a malformed label instead of
//     rejecting the request (see enroll/handler.go's hard reject).
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
// this predicate is what acts on it for node: labels.
//
// # The four hazards this rules out, named
//
//   - `,` — capability.ParseSelector's term separator (strings.Split(s, ",")).
//     This is the issue's measured payload: a `node:role` value of
//     "web, relay:quarantine=on" renders as two Selector terms, the second
//     spelled in the relay: namespace.
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
// relay-daemon's only source of node: labels is RELAY_NODE_LABELS, parsed by
// parse_node_labels (daemon/src/enroll.rs) as comma-and-`=`-split pairs; a
// bare `role` entry with no `=` yields ("role", ""). capability.ParseSelector
// agrees: "node:role=" parses to one Predicate with Key "role" and an empty
// Value. Rejecting the empty value would refuse a legitimate, already-shipped
// spelling for no grammar reason.
//
// # Why this alphabet, and why no length cap
//
// The legitimate alphabet was checked, not assumed: every RELAY_NODE_LABELS
// example this repo ships — relay-daemon.env.example, docker-compose.yml, the
// enrollment and install docs, and the validation suites — uses only
// [A-Za-z0-9._-]. `/`, `+`, `@`, `:` and non-ASCII are deliberately excluded:
// none of them appears in a shipped example, and admitting them later is
// backwards-compatible while excluding them later is not (an already-enrolled
// Node's label would start being refused on its next Hello). There is no
// length cap: the hazard here is GRAMMAR — what a value can be misread as —
// not size, and gRPC's own message-size limit already bounds how large a
// Hello or Enroll request (and therefore this map) can be. Leaving it
// unbounded here is a decision, not an oversight.
func WellFormedNodeLabel(key, value string) bool {
	if key == "" {
		return false
	}
	return wellFormedLabelBytes(key) && wellFormedLabelBytes(value)
}

// wellFormedLabelBytes reports whether every byte of s is in [A-Za-z0-9._-].
// The same allowlist applies to both the key and the value: '=' is not in it
// either way, which is what closes the "=-in-the-key" hazard documented on
// WellFormedNodeLabel without needing a side-specific rule. Deliberately a
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
