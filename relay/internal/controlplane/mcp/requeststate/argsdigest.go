package requeststate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// argsLabel domain-separates DigestArgs' digest from any other SHA-256 use in
// this package, followed by a NUL byte for the same reason macLabel is.
const argsLabel = "relay-requeststate-args-v1\x00"

// DigestArgs returns a canonical digest of raw, a JSON document (typically an
// MCP call's arguments). Canonicalisation re-marshals the parsed value:
// encoding/json sorts object keys at every depth, keeps json.Number literals
// verbatim, and preserves array order, so semantically-identical JSON that
// differs only in key order or whitespace digests identically.
//
// Both legs of a call — the emitted request and the answered decision — must
// digest the same byte source (the call's raw arguments, or json.Marshal of
// the same typed value re-marshalled the same way) or every answer refuses
// at the binding check. That is fail-closed, never a silent mismatch, but it
// is a functional bug if the two legs disagree on source.
//
// Canonicalisation has limits, all fail-closed (a refusal, never a false
// match): numerals spelled differently (1, 1.0, 1e0) digest differently
// because json.Number preserves the literal. A duplicate object key resolves
// last-wins, the same rule Go's own decode of the call arguments applies. A
// JSON string containing an escaped lone surrogate decodes to U+FFFD (the
// Unicode replacement rune) and digests as that rune — again, the same rule
// Go's decoder applies to the call itself, so both legs agree.
//
// Canonicalisation happens at the JSON map level (map[string]any), not
// against any Go struct: encoding/json's own decode into a typed struct
// matches object keys case-insensitively when no exact match exists, so two
// inputs that digest equal here — for example {"node":"a"} and
// {"Node":"a"} — can decode to different fields, or the same field by a
// different route, once a caller unmarshals the raw arguments into a typed
// value. This digest is a binding check on the call's bytes, not a
// guarantee about what a later typed decode of those bytes produces;
// execution safety rests on the plan hash re-derived from the call at
// decision time, not on this digest matching a particular struct shape.
// Callers that need the digest to track a typed decode should digest
// json.Marshal of the typed, re-marshalled input on both legs — the emitted
// request and the answered decision — rather than the raw wire bytes.
//
// Arguments are not subject to requeststate's field alphabet: only their
// fixed-size digest is ever sealed.
func DigestArgs(raw []byte) (Digest, error) {
	// Trim only JSON's own whitespace set (space, tab, CR, LF) — not
	// bytes.TrimSpace's Unicode notion, which also strips characters such as
	// NBSP (U+00A0). Trimming those would let otherwise-invalid JSON (e.g. a
	// lone NBSP) canonicalise as though it were empty.
	trimmed := bytes.Trim(raw, " \t\r\n")
	if !utf8.Valid(trimmed) {
		// The decoder would otherwise map distinct invalid byte sequences to
		// the same U+FFFD rune, which would let two different inputs collide
		// on the same digest.
		return Digest{}, fmt.Errorf("%w: invalid utf-8", ErrInvalidArgs)
	}
	if len(trimmed) == 0 {
		trimmed = []byte("null")
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return Digest{}, fmt.Errorf("%w: %v", ErrInvalidArgs, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Digest{}, fmt.Errorf("%w: trailing data", ErrInvalidArgs)
	}

	canonical, err := json.Marshal(v)
	if err != nil {
		return Digest{}, fmt.Errorf("%w: %v", ErrInvalidArgs, err)
	}

	h := sha256.New()
	h.Write([]byte(argsLabel))
	h.Write(canonical)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}
