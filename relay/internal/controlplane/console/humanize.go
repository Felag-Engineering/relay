package console

import (
	"strconv"
	"time"
)

// Human-readable counts and durations for Console prose. Every function here is
// pure, so the Console's wording of time stays testable without a Deps.

// countOf renders "1 one" or "N many".
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// minutesOrHours renders d to whole minutes under an hour and whole hours
// from there up: "5m", "3h".
func minutesOrHours(d time.Duration) string {
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	return strconv.Itoa(int(d.Hours())) + "h"
}

// timeSince renders how long before now t was: "never" for the zero time.
func timeSince(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	if d < time.Minute {
		return "just now"
	}
	if d < 24*time.Hour {
		return minutesOrHours(d) + " ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d ago"
}

// decisionAgo is timeSince, except that an unrecorded time renders as nothing
// rather than "never".
func decisionAgo(t time.Time, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timeSince(t, now)
}

// renderSpan renders a window length for a human.
func renderSpan(d time.Duration) string {
	if d <= 0 {
		return "none"
	}
	return minutesOrHours(d)
}

// renderTTL renders the time an approval has left.
func renderTTL(d time.Duration) string {
	switch {
	case d <= 0:
		return "expired"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s left"
	default:
		return minutesOrHours(d) + " left"
	}
}
