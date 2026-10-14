package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// maxRequestBodyBytes bounds every request body decoded by decodeJSON. The
// Control API's lifecycle payloads (scope lists, a reason string) are small;
// this cap exists to stop an oversized body from being fully buffered.
const maxRequestBodyBytes = 64 * 1024 // 64 KiB

// problem is the RFC 7807 (application/problem+json) error body every
// non-2xx Control API response renders, so every route has one consistent
// error shape.
type problem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// writeProblem writes an RFC 7807 problem+json response. detail must never
// contain a secret (an Enrollment Token plaintext, a credential) — callers
// are responsible for only passing safe-to-disclose text.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Status: status, Title: title, Detail: detail})
}

// writeJSON writes a successful application/json response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonMediaType is the ONE media type this API accepts on a request body — the
// same one docs/api/openapi.yaml declares for every requestBody it publishes.
const jsonMediaType = "application/json"

// decodeJSON decodes r's body into dst, capped at maxRequestBodyBytes,
// requiring the body to be declared application/json, and rejecting unknown
// fields. Any error (an undeclared or wrong media type, malformed JSON, an
// oversized body, or an unknown field) is returned as-is; every caller in this
// package treats a non-nil error the same way: render a 400 problem response.
//
// # Why the media type is checked at all
//
// Without it, a body sent as text/plain still decoded — and text/plain is one
// of the three media types an HTML form can POST with no CORS preflight. That
// made every mutating route on this surface reachable by a cross-origin form
// submission that carried whatever ambient credential the browser held, which
// on an internal deployment is a sibling host away. DisallowUnknownFields
// raised the bar (the form field name has to be a real field) but did not
// close it: a form encodes as `name=value`, and for POST /api/v1/raw-exec the
// `=` simply parks inside an argv element that is still a valid command.
//
// Requiring the header is the fail-closed direction, and it is the shape of
// the hole that is closed rather than one credential's use of it — a request
// that cannot declare a media type cannot be a form post, whatever credential
// it presents.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if got := mediaType(r.Header.Get("Content-Type")); got != jsonMediaType {
		return fmt.Errorf("Content-Type must be %s, got %q", jsonMediaType, r.Header.Get("Content-Type"))
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// mediaType reduces a Content-Type header to its lower-cased type/subtype,
// dropping any parameters (`; charset=utf-8`).
//
// Hand-rolled rather than mime.ParseMediaType because package api's imports
// are allowlisted (api_imports_test.go) and an equality check on the
// type/subtype needs neither parameter parsing nor its error taxonomy: a
// header this cannot reduce to exactly "application/json" is refused, which is
// the direction a stricter parser would also take.
func mediaType(header string) string {
	if i := strings.IndexByte(header, ';'); i >= 0 {
		header = header[:i]
	}
	return strings.ToLower(strings.TrimSpace(header))
}
