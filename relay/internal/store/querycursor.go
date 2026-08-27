package store

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// querycursor.go is the opaque keyset-pagination cursor shared by
// auditquery.go and jobquery.go (#441, D7): caller-controlled input on a path
// to SQL, so it is base64 -> split -> bound as parameters, and a malformed
// cursor is always a typed error, never a silent reset to page one (which
// would loop a paging client forever).

// encodeCursor2 is the opaque two-part cursor used for keyset pagination
// ordered by (a, b) — e.g. (ts, audit_id) or (created_at, job_id):
// base64url(a + "\x00" + b).
func encodeCursor2(a, b string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a + "\x00" + b))
}

// decodeCursor2 is encodeCursor2's inverse. invalid is returned (wrapped)
// when cursor does not decode to base64, or does not split into exactly two
// non-empty parts.
func decodeCursor2(cursor string, invalid error) (a, b string, err error) {
	raw, decErr := base64.RawURLEncoding.DecodeString(cursor)
	if decErr != nil {
		return "", "", fmt.Errorf("%w: %v", invalid, decErr)
	}
	a, b, ok := strings.Cut(string(raw), "\x00")
	if !ok || a == "" || b == "" {
		return "", "", invalid
	}
	return a, b, nil
}

// encodeCursor1 is the opaque single-value cursor used for keyset pagination
// ordered by one column — e.g. task_id.
func encodeCursor1(a string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a))
}

// decodeCursor1 is encodeCursor1's inverse.
func decodeCursor1(cursor string, invalid error) (a string, err error) {
	raw, decErr := base64.RawURLEncoding.DecodeString(cursor)
	if decErr != nil {
		return "", fmt.Errorf("%w: %v", invalid, decErr)
	}
	if len(raw) == 0 {
		return "", invalid
	}
	return string(raw), nil
}
