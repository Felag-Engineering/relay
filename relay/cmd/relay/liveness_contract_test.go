package main

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/transport"
)

// The liveness numbers span two binaries: the daemon sends a heartbeat and
// pings on its own schedule, the Relay closes a stream on a deadline derived
// from them. This test reads the daemon's committed constants and holds the
// relations between the two sides, so a one-sided edit fails here.

// repoRootFromCmd is this package's directory walked back up to the repository
// root (relay/cmd/relay -> relay/cmd -> relay -> .).
const repoRootFromCmd = "../../.."

// detectionMargin covers a round trip and timer slack in the keepalive ordering.
const detectionMargin = 5 * time.Second

// rustConst extracts the value of `NAME: ... = <expr>;` from a Rust source
// file with an exact-form pattern. A miss fails the test: a refactor of the
// constant's form must update this test, never silently skip it.
func rustConst(t *testing.T, relPath, name, exprPattern string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootFromCmd, filepath.FromSlash(relPath)))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	re := regexp.MustCompile(`(?m)^(?:pub )?const ` + regexp.QuoteMeta(name) + `: [A-Za-z0-9]+ = ` + exprPattern + `;$`)
	m := re.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("%s: no `const %s` in the expected form %q; update this test with the constant's new form", relPath, name, exprPattern)
	}
	return m[1:]
}

func rustSeconds(t *testing.T, relPath, name string) time.Duration {
	t.Helper()
	m := rustConst(t, relPath, name, `Duration::from_secs\((\d+)\)`)
	secs, err := strconv.Atoi(m[0])
	if err != nil {
		t.Fatalf("%s %s: %v", relPath, name, err)
	}
	return time.Duration(secs) * time.Second
}

func TestLivenessConstants_AgreeWithTheDaemon(t *testing.T) {
	const mainRs = "daemon/src/main.rs"
	const tunnelRs = "daemon/crates/relay-transport/src/tunnel.rs"

	daemonInterval := rustSeconds(t, mainRs, "HEARTBEAT_INTERVAL")
	jitterRaw := rustConst(t, mainRs, "HEARTBEAT_JITTER_FRACTION", `(\d+\.\d+)`)
	jitter, err := strconv.ParseFloat(jitterRaw[0], 64)
	if err != nil {
		t.Fatalf("HEARTBEAT_JITTER_FRACTION: %v", err)
	}
	daemonKeepaliveInterval := rustSeconds(t, tunnelRs, "KEEPALIVE_INTERVAL")
	daemonKeepaliveTimeout := rustSeconds(t, tunnelRs, "KEEPALIVE_TIMEOUT")

	if heartbeatInterval != daemonInterval {
		t.Errorf("heartbeatInterval = %v, but the daemon's HEARTBEAT_INTERVAL = %v", heartbeatInterval, daemonInterval)
	}

	// A single late or lost heartbeat, at the top of the jitter band, must never
	// trip offline: the deadline spans at least two maximal intervals.
	maxInterval := time.Duration(math.Ceil(float64(daemonInterval) * (1 + jitter)))
	if got := (&tunnelServer{}).livenessDeadline(); got < 2*maxInterval {
		t.Errorf("liveness deadline %v < 2 x the daemon's longest heartbeat interval (%v)", got, 2*maxInterval)
	}

	// The daemon pings every KEEPALIVE_INTERVAL; the Relay answers a client that
	// pings faster than its enforcement minimum with GOAWAY too_many_pings.
	if daemonKeepaliveInterval < 2*transport.KeepaliveMinClientPingInterval {
		t.Errorf("daemon KEEPALIVE_INTERVAL %v < 2 x the Relay's ping-enforcement minimum %v",
			daemonKeepaliveInterval, transport.KeepaliveMinClientPingInterval)
	}

	// On a silent dead link the daemon's earliest timeout is about
	// T - RTT + KEEPALIVE_TIMEOUT, because hyper's last read is not moved by the
	// Relay's pings, while the Relay's latest close is T + Time + Timeout
	// (grpc-go keepalive()). Holding the first at least the second plus a margin
	// means the Relay closes its stream, and resolves the Node's in-flight Tasks,
	// before the daemon reconnects.
	relayLatest := transport.KeepaliveTime + transport.KeepaliveTimeout
	if daemonKeepaliveTimeout < relayLatest+detectionMargin {
		t.Errorf("daemon KEEPALIVE_TIMEOUT %v < the Relay's keepalive Time+Timeout %v + margin %v",
			daemonKeepaliveTimeout, relayLatest, detectionMargin)
	}
}
