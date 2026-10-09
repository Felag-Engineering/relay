package controlplane

import (
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// The execution surfaces — the Control API's routes and the MCP tools — adapt
// one capability layer (invariant 10), so a caller must not discover a
// different contract depending on which door it used. What they share lives
// here, once, rather than in two copies kept identical by hand.

// MaxTimeoutSeconds bounds timeout_seconds on every execution surface: 24h.
// A missing bound on a remote-execution surface must read as deliberate, not
// an oversight; the OpenAPI spec publishes it.
const MaxTimeoutSeconds = 24 * 60 * 60

// MaxRenderedOutputBytes caps how much of a Task's stdout/stderr a per-Node
// result carries inline. Beyond it the matching truncated flag is set rather
// than growing the response unbounded: a Raw Exec Task's output is otherwise
// unconstrained.
const MaxRenderedOutputBytes = 4096

// ResolveTimeoutSeconds validates timeout_seconds against [0, MaxTimeoutSeconds]
// (0 or omitted means "the daemon/engine default"). It never silently clamps an
// out-of-range value on an execution surface.
func ResolveTimeoutSeconds(timeoutSeconds int32) (int32, error) {
	if timeoutSeconds < 0 {
		return 0, fmt.Errorf("timeout_seconds must be >= 0, got %d", timeoutSeconds)
	}
	if timeoutSeconds > MaxTimeoutSeconds {
		return 0, fmt.Errorf("timeout_seconds must be <= %d (24h), got %d", MaxTimeoutSeconds, timeoutSeconds)
	}
	return timeoutSeconds, nil
}

// MaxWaitSeconds bounds wait_seconds on the MCP execution tools: ADR-0004's
// "short wait budget" for a call that blocks until its Job finishes. It equals
// the daemon's per-Task hard wall clock, so a single-wave Job always fits;
// beyond it, a caller polls get_job. A long hold is the lost-response window
// idempotency keys exist to make safe.
const MaxWaitSeconds = 300

// ResolveWaitSeconds validates wait_seconds against [0, MaxWaitSeconds] (0 or
// omitted means "return as soon as the Job is persisted"). It never silently
// clamps.
func ResolveWaitSeconds(s int32) (time.Duration, error) {
	if s < 0 {
		return 0, fmt.Errorf("wait_seconds must be >= 0, got %d", s)
	}
	if s > MaxWaitSeconds {
		return 0, fmt.Errorf("wait_seconds must be <= %d, got %d; poll get_job for longer waits", MaxWaitSeconds, s)
	}
	return time.Duration(s) * time.Second, nil
}

// VerdictName renders a capability.VerdictStatus as its lowercase wire name.
func VerdictName(v capability.VerdictStatus) string {
	switch v {
	case capability.VerdictAllow:
		return "allow"
	case capability.VerdictDeny:
		return "deny"
	case capability.VerdictUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// TruncateOutput caps b at MaxRenderedOutputBytes, reporting whether it did.
func TruncateOutput(b []byte) (string, bool) {
	if len(b) <= MaxRenderedOutputBytes {
		return string(b), false
	}
	return string(b[:MaxRenderedOutputBytes]), true
}

// RFC3339 renders t in UTC as RFC 3339, or "" for the zero time so a "never
// happened" timestamp is omitted from a response rather than rendered as year
// 1. Both execution surfaces render their timestamps through it, so the same
// instant reads identically whichever door the caller used.
func RFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
