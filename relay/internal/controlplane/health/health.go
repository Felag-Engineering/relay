// Package health is the control plane's health answer: one bit, read without a
// credential. It imports nothing from the Relay, so it can reach no capability,
// store or Node (invariant 10).
package health

import (
	"net/http"
	"sync/atomic"
)

// Pattern is the route the control plane registers ahead of authentication. A
// GET pattern also matches HEAD.
const Pattern = "GET /healthz"

// Status is the health bit. The zero value is "not serving".
type Status struct {
	serving atomic.Bool
}

// SetServing records whether the control-plane listener is serving.
func (s *Status) SetServing(v bool) {
	s.serving.Store(v)
}

// ServeHTTP answers "serving" or "not serving" and nothing else: no version,
// no counts, no fleet content. It never reads the request.
func (s *Status) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if s.serving.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("serving\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not serving\n"))
}
