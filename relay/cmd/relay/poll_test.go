package main

import (
	"testing"
	"time"
)

// pollInterval is the pause between condition checks for waitUntil: short,
// because every condition it serves reads in-process state.
const pollInterval = 5 * time.Millisecond

// pollUntil calls done every interval until it returns true, and reports
// false once timeout has passed without that. done always runs at least once,
// and the call that gives up is the first one made after the deadline. It
// never fails the test itself, so each caller's failure message can name the
// state its last call observed.
//
// It runs done on the calling goroutine, so a condition that never holds
// cannot outlive the test the way a background polling goroutine would.
func pollUntil(timeout, interval time.Duration, done func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if done() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// waitUntil fails the test, naming what it waited for, unless cond holds
// within the given time. A caller whose failure message must report the
// observed state uses pollUntil instead.
func waitUntil(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	if !pollUntil(within, pollInterval, cond) {
		t.Fatalf("timeout waiting for %s", what)
	}
}
