package controlplane

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// elapsedAwaiting returns the time AwaitStartedJob held, on the fake clock of
// the enclosing synctest bubble.
func elapsedAwaiting(ctx context.Context, sj capability.StartedJob, wait time.Duration) time.Duration {
	start := time.Now()
	AwaitStartedJob(ctx, sj, wait)
	return time.Since(start)
}

func TestAwaitStartedJob_ReturnsWhenDoneCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			time.Sleep(2 * time.Second)
			close(done)
		}()
		got := elapsedAwaiting(context.Background(), capability.StartedJob{Done: done}, time.Hour)
		if got != 2*time.Second {
			t.Errorf("held %v, want 2s", got)
		}
	})
}

func TestAwaitStartedJob_ReturnsWhenTheWaitLapses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		got := elapsedAwaiting(context.Background(), capability.StartedJob{Done: done}, 5*time.Second)
		if got != 5*time.Second {
			t.Errorf("held %v, want 5s", got)
		}
		select {
		case <-done:
			t.Error("Done closed: the wait must never touch the Job")
		default:
		}
	})
}

func TestAwaitStartedJob_ReturnsWhenCtxEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			time.Sleep(3 * time.Second)
			cancel()
		}()
		got := elapsedAwaiting(ctx, capability.StartedJob{Done: make(chan struct{})}, time.Hour)
		if got != 3*time.Second {
			t.Errorf("held %v, want 3s", got)
		}
	})
}

func TestAwaitStartedJob_ReturnsAtOnce(t *testing.T) {
	cases := map[string]struct {
		sj   capability.StartedJob
		wait time.Duration
	}{
		"zero wait":  {capability.StartedJob{Done: make(chan struct{})}, 0},
		"reattached": {capability.StartedJob{Done: make(chan struct{}), Reattached: true}, time.Hour},
		"nil Done":   {capability.StartedJob{}, time.Hour},
		"negative":   {capability.StartedJob{Done: make(chan struct{})}, -time.Second},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if got := elapsedAwaiting(context.Background(), tc.sj, tc.wait); got != 0 {
					t.Errorf("held %v, want 0", got)
				}
			})
		})
	}
}
