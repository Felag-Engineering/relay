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

// verifiedKind returns kind only for an actor drawn in the VERIFIED lane, and
// "" otherwise. A kind label qualifies the Account the Relay authenticated
// (00-foundations.md, "Kind label"); beside a dashed chip it would read as a
// fact about an identity nothing checked. Every place that draws a kind label
// passes through here, with the same verified test its chip uses.
func verifiedKind(verified bool, kind string) string {
	if !verified {
		return ""
	}
	return kind
}
