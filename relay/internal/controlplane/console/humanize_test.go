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
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// renderedAgeCases is the table renderedAgo is held to, and the one
// assets/freshness.js is held to under node.
var renderedAgeCases = []struct {
	age   time.Duration
	text  string
	stale bool
}{
	{-5 * time.Second, "rendered just now", false},
	{0, "rendered just now", false},
	{999 * time.Millisecond, "rendered just now", false},
	{time.Second, "rendered 1s ago", false},
	{40 * time.Second, "rendered 40s ago", false},
	{59 * time.Second, "rendered 59s ago", false},
	{time.Minute, "rendered 1 min ago", false},
	{4*time.Minute + 59*time.Second, "rendered 4 min ago", false},
	{5 * time.Minute, "rendered 5 min ago, Refresh to re-read", true},
	{12 * time.Minute, "rendered 12 min ago, Refresh to re-read", true},
	{59*time.Minute + 59*time.Second, "rendered 59 min ago, Refresh to re-read", true},
	{time.Hour, "rendered 1 hr ago, Refresh to re-read", true},
	{23*time.Hour + 59*time.Minute, "rendered 23 hr ago, Refresh to re-read", true},
	{24 * time.Hour, "rendered 1 day ago, Refresh to re-read", true},
	{72 * time.Hour, "rendered 3 days ago, Refresh to re-read", true},
}

func TestRenderedAgo_Wording(t *testing.T) {
	for _, tc := range renderedAgeCases {
		text, stale := renderedAgo(tc.age)
		if text != tc.text || stale != tc.stale {
			t.Errorf("renderedAgo(%v) = %q, %v; want %q, %v", tc.age, text, stale, tc.text, tc.stale)
		}
	}
}

// A render instant ahead of the clock is a skew, not a page from the future.
func TestRenderedAgo_NegativeAgeReadsAsJustNow(t *testing.T) {
	text, stale := renderedAgo(-5 * time.Second)
	if text != "rendered just now" || stale {
		t.Errorf("renderedAgo(-5s) = %q, %v", text, stale)
	}
}
