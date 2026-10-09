// Package logctx carries request-scoped log correlation — the calling
// principal, the Job id and the HTTP request id — in a context.Context, and
// provides a slog.Handler that adds those values to every record logged with
// that context.
//
// It imports only context and log/slog: it is observational and reaches
// nothing in the capability layer.
//
// Never slog.SetDefault a logger built on this handler wrapped around
// slog.Default().Handler(). When the default handler is Go's built-in one,
// that recurses through the log package. This is why the composition root
// injects the logger rather than setting the default.
package logctx

import (
	"context"
	"log/slog"
)

// Attribute keys the Handler adds. KeyRequestID is deliberately not
// "request_id": that already means an approval Request id in log lines and in
// the GLOSSARY.
const (
	KeyPrincipal = "principal"
	KeyJobID     = "job_id"
	KeyRequestID = "http_request_id"
)

type (
	principalKey struct{}
	jobIDKey     struct{}
	requestIDKey struct{}
)

// WithPrincipal returns ctx carrying the calling Account's attribution.
func WithPrincipal(ctx context.Context, attribution string) context.Context {
	return context.WithValue(ctx, principalKey{}, attribution)
}

// WithJobID returns ctx carrying a Job id.
func WithJobID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, jobIDKey{}, id)
}

// WithRequestID returns ctx carrying a Relay-minted HTTP request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func from(ctx context.Context, key any) (string, bool) {
	v, _ := ctx.Value(key).(string)
	return v, v != ""
}

// PrincipalFrom returns the attribution set by WithPrincipal. An empty value
// counts as absent.
func PrincipalFrom(ctx context.Context) (string, bool) { return from(ctx, principalKey{}) }

// JobIDFrom returns the id set by WithJobID. An empty value counts as absent.
func JobIDFrom(ctx context.Context) (string, bool) { return from(ctx, jobIDKey{}) }

// RequestIDFrom returns the id set by WithRequestID. An empty value counts as
// absent.
func RequestIDFrom(ctx context.Context) (string, bool) { return from(ctx, requestIDKey{}) }

// pair is one correlation attribute present in a context.
type pair struct{ key, value string }

func pairs(ctx context.Context) []pair {
	var out []pair
	if v, ok := PrincipalFrom(ctx); ok {
		out = append(out, pair{KeyPrincipal, v})
	}
	if v, ok := JobIDFrom(ctx); ok {
		out = append(out, pair{KeyJobID, v})
	}
	if v, ok := RequestIDFrom(ctx); ok {
		out = append(out, pair{KeyRequestID, v})
	}
	return out
}

// Attrs returns the correlation values present in ctx as key/value pairs, for
// code that holds a request but logs without a context.
func Attrs(ctx context.Context) []any {
	var out []any
	for _, p := range pairs(ctx) {
		out = append(out, p.key, p.value)
	}
	return out
}

// Or returns l, or slog.Default() — evaluated now, not at construction — when
// l is nil. A component given no logger therefore logs exactly as it did
// before loggers were injected.
func Or(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

// Handler wraps a slog.Handler and adds the correlation values found in the
// record's context. A key the call site, or a With call, already supplied is
// never duplicated.
//
// After WithGroup, the correlation attrs are added to the record and so nest
// inside the innermost open group, as every attr of a record after WithGroup
// does; the Handler does not hoist them, which would mean re-implementing the
// group bookkeeping that belongs to the wrapped handler. Keys preset before
// the group still suppress the context value.
type Handler struct {
	inner   slog.Handler
	preset  map[string]bool
	grouped bool
}

// NewHandler wraps inner. It panics if inner is nil.
func NewHandler(inner slog.Handler) *Handler {
	if inner == nil {
		panic("logctx: NewHandler requires a non-nil handler")
	}
	return &Handler{inner: inner}
}

// Enabled delegates to the wrapped handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle adds the context's correlation values, then delegates.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	ps := pairs(ctx)
	if len(ps) == 0 {
		return h.inner.Handle(ctx, r)
	}
	r = r.Clone()
	present := map[string]bool{}
	r.Attrs(func(a slog.Attr) bool {
		present[a.Key] = true
		return true
	})
	for _, p := range ps {
		if present[p.key] || h.preset[p.key] {
			continue
		}
		r.AddAttrs(slog.String(p.key, p.value))
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs records the keys so a later context value does not duplicate
// them, then delegates.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	preset := h.preset
	if !h.grouped && len(as) > 0 {
		preset = make(map[string]bool, len(h.preset)+len(as))
		for k := range h.preset {
			preset[k] = true
		}
		for _, a := range as {
			preset[a.Key] = true
		}
	}
	return &Handler{inner: h.inner.WithAttrs(as), preset: preset, grouped: h.grouped}
}

// WithGroup opens a group on the wrapped handler. An empty name is a no-op,
// per slog's rule.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &Handler{inner: h.inner.WithGroup(name), preset: h.preset, grouped: true}
}
