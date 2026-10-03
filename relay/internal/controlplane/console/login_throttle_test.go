package console

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestThrottleSecondsRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		wait time.Duration
		want int
	}{
		{time.Millisecond, 1},
		{time.Second, 1},
		{time.Second + time.Millisecond, 2},
		{30 * time.Second, 30},
	} {
		if got := throttleSeconds(tc.wait); got != tc.want {
			t.Errorf("throttleSeconds(%v) = %d, want %d", tc.wait, got, tc.want)
		}
	}
}

func TestSetRetryAfterMatchesThrottleSeconds(t *testing.T) {
	rec := httptest.NewRecorder()
	setRetryAfter(rec, 2500*time.Millisecond)
	if got := rec.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want %q", got, "3")
	}
}
