package jobs

import (
	"context"
	"testing"
	"time"
)

func TestSendWithheld(t *testing.T) {
	bg := context.Background()
	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"no guard", bg, false},
		{"nil guard", WithSendGuard(bg, nil), false},
		{"guard allows", WithSendGuard(bg, func() bool { return false }), false},
		{"guard withholds", WithSendGuard(bg, func() bool { return true }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SendWithheld(tt.ctx); got != tt.want {
				t.Errorf("SendWithheld = %v, want %v", got, tt.want)
			}
		})
	}
}

type unrelatedCtxKey struct{}

func TestWithSendGuard_NilReturnsCtxUnchanged(t *testing.T) {
	ctx := context.WithValue(context.Background(), unrelatedCtxKey{}, 1)
	if got := WithSendGuard(ctx, nil); got != ctx {
		t.Error("WithSendGuard(ctx, nil) must return ctx unchanged")
	}
}

func TestSendWithheld_SurvivesDerivedContexts(t *testing.T) {
	base := WithSendGuard(context.Background(), func() bool { return true })
	timed, cancel := context.WithTimeout(base, time.Minute)
	defer cancel()
	for name, ctx := range map[string]context.Context{
		"WithoutCancel": context.WithoutCancel(base),
		"WithTimeout":   timed,
	} {
		if !SendWithheld(ctx) {
			t.Errorf("%s: guard lost", name)
		}
	}
}
