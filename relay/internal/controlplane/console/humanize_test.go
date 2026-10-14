package console

import (
	"testing"
	"time"
)

func TestHumanizedDurations(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	cases := []struct {
		name      string
		got, want string
	}{
		{"since zero", timeSince(time.Time{}, now), "never"},
		{"since seconds", timeSince(ago(59*time.Second), now), "just now"},
		{"since future", timeSince(now.Add(time.Hour), now), "just now"},
		{"since minute", timeSince(ago(time.Minute), now), "1m ago"},
		{"since 59m", timeSince(ago(59*time.Minute), now), "59m ago"},
		{"since hour", timeSince(ago(time.Hour), now), "1h ago"},
		{"since 23h", timeSince(ago(23*time.Hour+59*time.Minute), now), "23h ago"},
		{"since day", timeSince(ago(24*time.Hour), now), "1d ago"},
		{"since 3d", timeSince(ago(80*time.Hour), now), "3d ago"},
		{"decision unrecorded", decisionAgo(time.Time{}, now), ""},
		{"decision recorded", decisionAgo(ago(2*time.Hour), now), "2h ago"},
		{"span zero", renderSpan(0), "none"},
		{"span negative", renderSpan(-time.Minute), "none"},
		{"span minutes", renderSpan(90 * time.Second), "1m"},
		{"span hours", renderSpan(5 * time.Hour), "5h"},
		{"ttl expired", renderTTL(0), "expired"},
		{"ttl seconds", renderTTL(45 * time.Second), "45s left"},
		{"ttl minutes", renderTTL(10 * time.Minute), "10m left"},
		{"ttl hours", renderTTL(3 * time.Hour), "3h left"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}
