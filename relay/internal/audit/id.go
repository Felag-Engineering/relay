package audit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// NewID mints a Record.ID: "audit-" followed by 16 lowercase hex digits of
// the mint time in Unix nanoseconds and 16 lowercase hex digits of 8
// crypto/rand bytes. 38 characters, the same shape as every id written
// before #656.
//
// Four properties, stated precisely because the trail's total order rests on
// them (#656):
//
//  1. SORTABLE. The time component is the zero-padded, fixed-width hex of a
//     NON-NEGATIVE int64, so lexicographic order over ids is numeric order
//     over mint times. This holds until 2262-04-11T23:47:16.854775807Z, the
//     last instant time.Time.UnixNano can represent — beyond it UnixNano
//     overflows int64 and the clamp in monotonicNanos.next takes over, at
//     which point a freshly minted id sorts BELOW every id already in the
//     table.
//
//  2. MONOTONIC WITHIN ONE PROCESS, and nowhere else. A mutex-guarded high
//     water mark means two ids from one process are strictly increasing even
//     if the clock stands still or an NTP step moves it backwards. No claim
//     is made across processes or across hosts: two Relays minting from two
//     clocks order by those clocks, exactly as their ts columns would.
//
//  3. UNIQUE. See NewIDGen for why 64 bits of entropy is the right amount
//     here rather than a compromise.
//
//  4. SHAPED LIKE ITS PREDECESSORS: "audit-" plus exactly 32 lowercase hex
//     digits, so every row ever written — before this change and after it —
//     is one shape to a reader, a length assumption, or a query.
//
// The time component is the generator's own clock at MINT time, not the
// Record's Timestamp. The reason is the auditsink fan-out: one dispatch
// builds a single base Record with one clock reading and copies that
// Timestamp onto every per-Node Record, so an id derived from the record's
// own ts would give every row in the fan-out an identical time component and
// hand the tie-break straight back to the random suffix — the exact defect
// #656 is fixing.
func NewID() (string, error) {
	return defaultGen()
}

// defaultGen is NewID's generator: the production clock and crypto/rand.
var defaultGen = NewIDGen("audit-", time.Now, rand.Reader)

// NewIDGen returns a generator with NewID's properties and both seams
// injectable, so a test can drive a stuck clock, a backwards clock, a
// pre-epoch clock, or a failing entropy source.
//
// Each returned generator carries its own high water mark, so two generators
// are independent — which is what lets a test compare ids minted at two
// instants without one bumping the other.
//
// Entropy is 64 bits per id, deliberately, and deliberately not more. Within
// one process a collision is structurally impossible rather than merely
// improbable: the 64-bit time prefix is strictly increasing, so two ids from
// one generator differ in the prefix whatever crypto/rand returns. Across
// processes there is no second minter — the Relay is the single writer of
// its database file — and audit_id is not a lookup key on any surface: no
// Repository method takes one, no route exposes one, so it is not a
// capability, a bearer token, or a guessing target. A collision would fail
// loudly on the audit table's PRIMARY KEY, never silently. Matching the
// 38-character shape every existing row carries is worth more than entropy
// this token has no use for.
//
// A failed entropy read returns an error and an EMPTY id, never a partial
// one: an id is the audit table's primary key, and a caller that wrote a
// degraded one would be recording a row it cannot trust.
func NewIDGen(prefix string, now func() time.Time, entropy io.Reader) func() (string, error) {
	var mono monotonicNanos
	return func() (string, error) {
		suffix := make([]byte, 8)
		if _, err := io.ReadFull(entropy, suffix); err != nil {
			return "", fmt.Errorf("audit: generate record id: %w", err)
		}
		return fmt.Sprintf("%s%016x%s", prefix, mono.next(now()), hex.EncodeToString(suffix)), nil
	}
}

// monotonicNanos turns a clock that may stand still or step backwards into a
// strictly increasing sequence of non-negative Unix-nanosecond values.
type monotonicNanos struct {
	mu   sync.Mutex
	last int64
}

// next returns the strictly-increasing, non-negative nanosecond value for a
// clock reading of now.
func (m *monotonicNanos) next(now time.Time) int64 {
	n := now.UnixNano()

	// THE FLOOR: n is never negative past this point. What it prevents is
	// not what it looks like. Go's %x on a SIGNED integer prints
	// sign-magnitude, so fmt.Sprintf("%016x", int64(-1)) is
	// "-000000000000001" — not "ffff…". That string breaks the id two ways at
	// once: "-" is 0x2D and sorts BELOW every hex digit ("0" is 0x30), so the
	// id would sort under every real id; and it is 17 characters with a
	// non-hex byte, so it fails the "audit-" plus 32 lowercase hex shape
	// every length assumption downstream rests on. Reachable from a pre-epoch
	// clock and from a post-2262 one, where UnixNano overflows int64.
	//
	// Stated plainly because it is easy to get wrong in both directions: this
	// line is REDUNDANT as the code stands. last starts at zero and next is
	// its only writer, so the bump below already floors n at last+1 >= 1 on
	// every path, including the first call. It is kept because the floor is
	// the property, the bump enforces it only incidentally, and seeding last
	// from anywhere other than zero would make this line the only thing
	// holding it. TestNewIDGen_ClampsAPreEpochClock asserts the PROPERTY, and
	// goes red only when both are gone — which is the honest statement of
	// what is guarded.
	if n < 0 {
		n = 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= m.last {
		n = m.last + 1
	}
	m.last = n
	return n
}
