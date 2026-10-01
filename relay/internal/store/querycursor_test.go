package store

import (
	"encoding/base64"
	"errors"
	"testing"
)

var errTestInvalid = errors.New("invalid")

func TestCursor3_RoundTrip(t *testing.T) {
	a, b, c, err := decodeCursor3(encodeCursor3("asc", "2026-08-20T00:00:01Z", "job-2"), errTestInvalid)
	if err != nil || a != "asc" || b != "2026-08-20T00:00:01Z" || c != "job-2" {
		t.Errorf("round trip = %q %q %q, %v", a, b, c, err)
	}
}

func TestCursor3_RefusesAnythingButThreeNonEmptyParts(t *testing.T) {
	raw := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, cursor := range map[string]string{
		"not base64":  "!!!",
		"two parts":   encodeCursor2("a", "b"),
		"four parts":  raw("a\x00b\x00c\x00d"),
		"empty first": raw("\x00b\x00c"),
		"empty last":  raw("a\x00b\x00"),
	} {
		if _, _, _, err := decodeCursor3(cursor, errTestInvalid); !errors.Is(err, errTestInvalid) {
			t.Errorf("%s: err = %v, want the invalid sentinel", name, err)
		}
	}
}

// decodeCursor2's contract is exactly two non-empty parts. strings.Cut alone
// accepts a third, which would let a three-part cursor from the oldest-first
// direction parse here as a (a, "b\x00c") pair.
func TestDecodeCursor2_RefusesAThirdPart(t *testing.T) {
	if _, _, err := decodeCursor2(encodeCursor3("a", "b", "c"), errTestInvalid); !errors.Is(err, errTestInvalid) {
		t.Errorf("a three-part cursor in decodeCursor2: err = %v, want the invalid sentinel", err)
	}
	if a, b, err := decodeCursor2(encodeCursor2("a", "b"), errTestInvalid); err != nil || a != "a" || b != "b" {
		t.Errorf("a two-part cursor = %q %q, %v; want it unchanged", a, b, err)
	}
}
