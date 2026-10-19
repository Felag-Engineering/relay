package main

// reload_log.go is the log handler a configuration reload replaces (RC-21).

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// swapHandler is a slog.Handler whose base handler a reload can replace while
// the loggers already derived from it (With, WithGroup) keep working. Each
// derived handler records its attribute and group operations and replays them
// on the current base, cached per generation, so a line costs one atomic load
// when nothing has reloaded.
type swapHandler struct {
	root *swapRoot
	ops  []swapOp

	cache atomic.Pointer[swapCached]
}

type swapRoot struct {
	cur atomic.Pointer[swapBase]
}

type swapBase struct {
	h slog.Handler
}

// swapOp is one WithAttrs or WithGroup call.
type swapOp struct {
	attrs []slog.Attr
	group string
}

type swapCached struct {
	base *swapBase
	h    slog.Handler
}

func newSwapHandler(h slog.Handler) *swapHandler {
	root := &swapRoot{}
	root.cur.Store(&swapBase{h: h})
	return &swapHandler{root: root}
}

// swap makes h the base every derived handler writes through from now on.
func (s *swapHandler) swap(h slog.Handler) { s.root.cur.Store(&swapBase{h: h}) }

// handler returns this handler's operations replayed on the current base.
func (s *swapHandler) handler() slog.Handler {
	base := s.root.cur.Load()
	if c := s.cache.Load(); c != nil && c.base == base {
		return c.h
	}
	h := base.h
	for _, op := range s.ops {
		if op.group != "" {
			h = h.WithGroup(op.group)
		} else {
			h = h.WithAttrs(op.attrs)
		}
	}
	s.cache.Store(&swapCached{base: base, h: h})
	return h
}

func (s *swapHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return s.handler().Enabled(ctx, l)
}

func (s *swapHandler) Handle(ctx context.Context, r slog.Record) error {
	return s.handler().Handle(ctx, r)
}

func (s *swapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return s
	}
	return s.derive(swapOp{attrs: attrs})
}

func (s *swapHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return s
	}
	return s.derive(swapOp{group: name})
}

func (s *swapHandler) derive(op swapOp) *swapHandler {
	ops := make([]swapOp, len(s.ops)+1)
	copy(ops, s.ops)
	ops[len(s.ops)] = op
	return &swapHandler{root: s.root, ops: ops}
}
