package api

import (
	"encoding/json"
	"net/http"
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

// decodeJSON decodes r's body into dst, capped at maxRequestBodyBytes and
// rejecting unknown fields. Any error (malformed JSON, an oversized body, or
// an unknown field) is returned as-is; every caller in this package treats a
// non-nil error the same way: render a 400 problem response.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
