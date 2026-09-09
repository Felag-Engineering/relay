package capability

import (
	"errors"
	"fmt"
	"strings"
)

// MaxRevokeReasonBytes bounds a Node-revocation reason, measured in bytes
// after trimming.
//
// 512 bytes is room for a sentence naming an incident and a ticket, which is
// what a later reader reconstructing the incident actually needs, and far less
// than the 64 KiB decodeJSON already allows a request body. The bound exists
// because the reason is STORED and RENDERED: it lands in an audit row that
// Node detail and the Activity trail both display, and an unbounded free-text
// field on a screen is a layout problem in the ordinary case and a
// scroll-the-trail-away problem in the adversarial one.
//
// Note the asymmetry this introduces, deliberately rather than by oversight:
// the Freeze release reason (ADR-0013) is required but NOT length-bounded, so
// it is capped only by the request-body limit. Bounding that one too is a
// separate change to a separate ADR's field and is not smuggled in here.
const MaxRevokeReasonBytes = 512

// ErrRevokeReasonRequired is returned by ValidateRevokeReason when the reason
// is empty or whitespace.
//
// Revoking a Node is the middle rung of ADR-0020's incident ladder and it is
// irreversible: the Node's certificate stops being trusted and it must
// re-enrol. The trail could already answer who revoked and when; without this
// it could not answer why, which is the half of attribution that matters
// (#487). The `relay:` lane exists so that security-sensitive actions are
// attributable, and an unattributed irreversible action is the gap.
//
// Defined in the capability layer, next to ErrFreezeReasonRequired and for the
// same stated reason: so a Console or a future CLI cannot revoke without one.
// See ValidateRevokeReason's doc for the limit of that guarantee here.
var ErrRevokeReasonRequired = errors.New("capability: revoking a Node requires a non-empty reason (ADR-0020, #487)")

// ErrRevokeReasonTooLong is returned by ValidateRevokeReason when the trimmed
// reason exceeds MaxRevokeReasonBytes.
var ErrRevokeReasonTooLong = fmt.Errorf("capability: a Node-revocation reason may not exceed %d bytes", MaxRevokeReasonBytes)

// ErrRevokeReasonMalformed is returned by ValidateRevokeReason when the reason
// is not valid UTF-8 or carries a C0 control character.
//
// Unlike #504's node-label gate, this is HYGIENE AND NOT DEFENCE, and the
// distinction is worth stating so a later reader does not mistake it for a
// trust boundary: a revocation reason is written by an authenticated `admin`,
// not by a Node, so there is no attacker on this input who is not already
// authorised to revoke. What the check buys is that a field which is persisted
// to SQLite, re-encoded as JSON, written to a CSV export and rendered on two
// screens is well-formed at the one place it enters the system, rather than at
// four places that each have to remember. A newline is refused for the same
// reason: a reason is one line, and a multi-line one misreads in every
// plaintext rendering of the trail.
var ErrRevokeReasonMalformed = errors.New("capability: a Node-revocation reason must be valid UTF-8 with no control characters")

// ValidateRevokeReason checks a raw, caller-supplied Node-revocation reason and
// returns the trimmed form to record. It is the single definition of what
// counts as a usable reason, so every surface that grows a revoke path records
// the same thing.
//
// THE LIMIT OF THE GUARANTEE, stated because the comment on
// ErrFreezeReasonRequired promises something stronger for Freeze and the
// difference is not obvious. ReleaseFreeze cannot be bypassed: the ACTION
// itself is a method on Service, so a surface that skips the check does not get
// to release the Freeze at all. Node revocation has no such method — the
// Control API calls revocation.Service.RevokeNode directly, and only
// authorization routes through the capability layer — so this is a validator a
// surface must remember to call, not a gate it cannot get past.
//
// What that buys, precisely: POST /api/v1/nodes/{node_id}/revoke cannot revoke
// unattributed. revocation.Service.RevokeToken cascade-revokes every Node an
// Enrollment Token enrolled, reached by DELETE /api/v1/enrollment-tokens/{id};
// the cascade now records one KindNodeRevoke per cascaded Node, attributed to
// the same Principal as the KindTokenRevoke row for the token itself, with a
// reason from CascadeRevokeReason (#557). revocation.Service still has no
// audit sink of its own — it imports neither internal/audit nor
// internal/capability (see revocation.RevocationRecorder) — so each record is
// written by a CALLER-supplied recorder, and its content is authored at the
// surface that authenticated the operator while the set of Nodes is decided
// inside the cascade's re-scan, the only place that knows it.
//
// enroll.Service also revokes a just-minted identity when enrollment fails
// partway (its own nodeDenylister, never this validator). That one is correct
// as it stands: it is the Relay cleaning up after itself, not an operator act,
// and there is no human whose reason could be demanded.
func ValidateRevokeReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if reason == "" {
		return "", ErrRevokeReasonRequired
	}
	if len(reason) > MaxRevokeReasonBytes {
		return "", ErrRevokeReasonTooLong
	}
	// One pass covers both malformed cases, and deliberately without importing
	// unicode/utf8: package capability keeps a deny-by-default import
	// allowlist (execution_test.go, the ADR-0009/0010 boundary), and widening
	// an architectural guard to save a function call is the wrong trade.
	// Ranging a string decodes UTF-8 natively and yields U+FFFD for each byte
	// of an invalid sequence, so the RuneError test below IS the validity
	// check. Its one false positive is a reason containing a literal U+FFFD,
	// which is not something an operator writes on purpose and is refused with
	// the same message either way.
	//
	// Trimming already removed the surrounding whitespace, so any control
	// character still here is interior and deliberate.
	for _, r := range reason {
		// C0 (below 0x20), DEL, and C1 (0x80-0x9f). C1 matters and is easy to
		// forget: U+0085 NEL is a line break in every plaintext rendering, so
		// omitting the range would let exactly the multi-line reason the
		// comment below rules out through under a different encoding.
		if r == '\uFFFD' || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", ErrRevokeReasonMalformed
		}
		// Bidi overrides and zero-width characters are refused for the same
		// reason #504 refused them in node labels: they make the rendered
		// string differ from the stored one. Here the stakes are a trust
		// screen — a U+202E inside the reason on Node detail visually reorders
		// the attribution text around it, so the next human reading the trail
		// sees something other than what was recorded. Not injection (the
		// Console escapes, the CSV export quotes), just a rendering the
		// operator did not write.
		if isBidiOrZeroWidth(r) {
			return "", ErrRevokeReasonMalformed
		}
	}
	return reason, nil
}

// CascadeRevokeReason renders the DERIVED reason for a Node revoked by an
// Enrollment Token cascade (#557): the operator authored no per-Node reason
// for a Node they never named and must not be asked for one after the fact,
// so this names the CAUSE instead — the token whose revocation swept the Node
// up.
//
// It is a renderer, not a validator: tokenID is caller-supplied path input
// (DELETE /api/v1/enrollment-tokens/{id}), so callers must still pass its
// output through ValidateRevokeReason before recording it, exactly as a
// human-authored reason would be.
func CascadeRevokeReason(tokenID string) string {
	return "cascade: enrollment token " + tokenID + " revoked"
}

// isBidiOrZeroWidth reports whether r reorders or hides surrounding text: the
// explicit bidirectional formatting and isolate controls, the zero-width
// space/joiners, and the byte-order mark in its U+FEFF word-joiner role.
//
// Listed explicitly rather than derived from a unicode range table, because
// package capability's import allowlist does not carry unicode and because an
// explicit list is the one a reader can check against the code points named in
// the comment above.
func isBidiOrZeroWidth(r rune) bool {
	switch r {
	case '\u200b', '\u200c', '\u200d', // zero-width space, non-joiner, joiner
		'\u200e', '\u200f', // LTR/RTL marks
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // embeddings and overrides
		'\u2060',                               // word joiner
		'\u2066', '\u2067', '\u2068', '\u2069', // isolates
		'\ufeff': // BOM / zero-width no-break space
		return true
	}
	return false
}
