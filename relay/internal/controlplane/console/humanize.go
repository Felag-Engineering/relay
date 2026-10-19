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

// pageStaleAfter is the age past which a page says it is old and asks to be
// refreshed. A page is a snapshot of reachability, so it is old enough to say
// so well before an operator would notice; 00-foundations.md "How old a page
// is" brackets it with 40s (fresh) and 12 min (old).
const pageStaleAfter = 5 * time.Minute

// renderedAgo is how a page states its own age: "rendered 40s ago", and past
// pageStaleAfter "rendered 12 min ago, Refresh to re-read" (00-foundations.md
// "How old a page is"). assets/freshness.js produces the same words as the page
// ages; TestAssets_FreshnessAdvancesUnderADOM holds the two equal.
func renderedAgo(age time.Duration) (text string, stale bool) {
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Second:
		text = "rendered just now"
	case age < time.Minute:
		text = "rendered " + strconv.Itoa(int(age/time.Second)) + "s ago"
	case age < time.Hour:
		text = "rendered " + strconv.Itoa(int(age/time.Minute)) + " min ago"
	case age < 24*time.Hour:
		text = "rendered " + strconv.Itoa(int(age/time.Hour)) + " hr ago"
	default:
		text = "rendered " + countOf(int(age/(24*time.Hour)), "day", "days") + " ago"
	}
	stale = age >= pageStaleAfter
	if stale {
		text += ", Refresh to re-read"
	}
	return text, stale
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
