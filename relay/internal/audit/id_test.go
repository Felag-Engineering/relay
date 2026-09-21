package audit

import (
	"crypto/rand"
	"errors"
	"regexp"
	"sort"
	"testing"
	"time"
)

// idShape is the shape every audit id has carried since the table existed:
// "audit-" plus 32 lowercase hex digits.
var idShape = regexp.MustCompile(`^audit-[0-9a-f]{32}$`)

// failingReader is an entropy source that always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy today") }

func TestNewIDGen_SortsInMintOrder(t *testing.T) {
	gen := NewIDGen("audit-", time.Now, rand.Reader)

	ids := make([]string, 1000)
	for i := range ids {
		id, err := gen()
		if err != nil {
			t.Fatalf("gen(): %v", err)
		}
		ids[i] = id
	}

	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("ids are not in mint order at index %d: %q >= %q — the (ts, audit_id) tie-break depends on audit_id sorting in append order (#656)", i, ids[i-1], ids[i])
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Error("1000 ids from the real generator are not sorted — lexicographic order over ids must be mint order (#656)")
	}
}

func TestNewIDGen_IsMonotonicUnderAStuckClock(t *testing.T) {
	stuck := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	gen := NewIDGen("audit-", func() time.Time { return stuck }, rand.Reader)

	prev := ""
	for i := 0; i < 100; i++ {
		id, err := gen()
		if err != nil {
			t.Fatalf("gen(): %v", err)
		}
		if prev != "" && id <= prev {
			t.Fatalf("a stuck clock produced a non-increasing id: %q then %q — the monotonic bump in monotonicNanos.next is not doing its job", prev, id)
		}
		prev = id
	}
}

func TestNewIDGen_IsMonotonicUnderABackwardsClock(t *testing.T) {
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	calls := 0
	// An NTP step: the clock runs forward, then jumps back a full second.
	gen := NewIDGen("audit-", func() time.Time {
		calls++
		if calls > 10 {
			return base.Add(time.Duration(calls)*time.Millisecond - time.Second)
		}
		return base.Add(time.Duration(calls) * time.Millisecond)
	}, rand.Reader)

	prev := ""
	for i := 0; i < 50; i++ {
		id, err := gen()
		if err != nil {
			t.Fatalf("gen(): %v", err)
		}
		if prev != "" && id <= prev {
			t.Fatalf("a 1s backwards clock step produced a non-increasing id: %q then %q — monotonicNanos.next must bump past last, not trust the clock", prev, id)
		}
		prev = id
	}
}

// TestNewIDGen_ClampsAPreEpochClock pins the FLOOR, not one line of it: a
// clock reading that UnixNano cannot represent must never reach the format
// verb. Go's %x on a signed int prints sign-magnitude, so an unfloored
// negative value produces "audit--00000003b9aca00…" — mis-shaped, and sorting
// below every real id because "-" is 0x2D.
//
// monotonicNanos.next enforces the floor twice over (the explicit n < 0 clamp,
// and the bump against a zero-initialised high water mark), so this goes red
// only when BOTH are gone. That is deliberate and is what the property is
// worth: it is the floor that must hold, not either mechanism.
func TestNewIDGen_ClampsAPreEpochClock(t *testing.T) {
	preEpoch := NewIDGen("audit-", func() time.Time { return time.Unix(-1, 0) }, rand.Reader)
	modern := NewIDGen("audit-", func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }, rand.Reader)

	old, err := preEpoch()
	if err != nil {
		t.Fatalf("pre-epoch gen(): %v", err)
	}
	now, err := modern()
	if err != nil {
		t.Fatalf("modern gen(): %v", err)
	}

	if !idShape.MatchString(old) {
		t.Errorf(`a pre-epoch clock minted %q — UnixNano is negative there and Go's %%x prints sign-magnitude ("-000000000000001"), whose leading "-" (0x2D) sorts below every hex digit and whose length breaks the 32-hex id shape; monotonicNanos.next must floor it at zero`, old)
	}
	if old >= now {
		t.Errorf("a pre-epoch id %q does not sort below a 2026 id %q — the clamp must map an unrepresentable clock to a tiny positive value, not leave it negative", old, now)
	}
}

func TestNewID_ShapeMatchesTheLegacyIDs(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID(): %v", err)
	}
	if len(id) != 38 || !idShape.MatchString(id) {
		t.Errorf(`audit.NewID returned %q (len %d) — audit ids are "audit-" plus 32 lowercase hex, the same shape rows written before #656 carry`, id, len(id))
	}
}

func TestNewIDGen_EntropyFailureIsAnError(t *testing.T) {
	gen := NewIDGen("audit-", time.Now, failingReader{})

	id, err := gen()
	if err == nil || id != "" {
		t.Errorf("entropy failure returned id %q, err %v — a failed crypto/rand read must return an error and no id, never a partial one", id, err)
	}
}
