//go:build integration

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestCrossBinary_EnrollsByIPAddressWithNoDNSName is ADR-0031 §2's acceptance:
// a relay-daemon dialling an address the server certificate names enrolls and
// runs a Task with no DNS name on its path and no RELAY_SERVER_NAME set, so it
// verifies the Relay by the IP address it dials. It runs under make
// test-crossbinary with the real relay and relay-daemon binaries.
func TestCrossBinary_EnrollsByIPAddressWithNoDNSName(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	t.Run("tls.hostname is an IPv4 address", func(t *testing.T) {
		listen, err := freeLoopbackAddr()
		if err != nil {
			t.Fatalf("allocate a loopback port: %v", err)
		}
		join := enrollByIP(t, relayBin, daemonBin, "127.0.0.1", listen, "")
		if host, _, err := net.SplitHostPort(join.RelayAddress()); err != nil || host != "127.0.0.1" {
			t.Errorf("join string address = %q, want host 127.0.0.1", join.RelayAddress())
		}
	})

	t.Run("loopback, with a hostname that does not resolve", func(t *testing.T) {
		listen, err := freeLoopbackAddr()
		if err != nil {
			t.Fatalf("allocate a loopback port: %v", err)
		}
		join := enrollByIP(t, relayBin, daemonBin, "relay.invalid", listen, listen)
		// The join string names the only DNS name the Relay holds, so that name
		// cannot be what the daemon reached.
		if host, _, err := net.SplitHostPort(join.RelayAddress()); err != nil || host != "relay.invalid" {
			t.Errorf("join string address = %q, want host relay.invalid", join.RelayAddress())
		}
	})

	t.Run("a detected interface address, with a hostname that does not resolve", func(t *testing.T) {
		ip := firstUsableIPv4(t)
		if ip == nil {
			const msg = "no non-loopback IPv4 address on this host"
			if os.Getenv(relaytest.E2ERequiredEnv) == "1" {
				t.Fatalf("%s — but %s=1 (set by make), so it is a failure, not a skip", msg, relaytest.E2ERequiredEnv)
			}
			t.Skip(msg)
		}
		lis, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			t.Fatalf("listen on %s: %v", ip, err)
		}
		listen := lis.Addr().String()
		lis.Close()
		enrollByIP(t, relayBin, daemonBin, "relay.invalid", listen, listen)
	})
}

// firstUsableIPv4 is the first IPv4 address, in interface order, that the
// server certificate is expected to name; nil when the host has none.
func firstUsableIPv4(t *testing.T) net.IP {
	t.Helper()
	ips := detectedIPv4s(t)
	if len(ips) == 0 {
		return nil
	}
	return ips[0]
}

// enrollByIP starts a Relay whose tls.hostname is relayHostname and which
// listens on listenAddr, enrolls a real relay-daemon against it with no
// RELAY_SERVER_NAME, and dispatches file.read to prove the Tunnel is up over an
// IP-verified mTLS channel. A non-empty override is the daemon's RELAY_ADDRESS,
// the address it dials in place of the join string's. It returns the decoded
// join string.
func enrollByIP(t *testing.T, relayBin, daemonBin, relayHostname, listenAddr, override string) enroll.JoinString {
	t.Helper()
	layout := relaytest.NewRelayLayout(t, crossbinaryGate)
	proc, _ := startRelaySubprocessWithHostname(t, layout, relayBin, listenAddr, relayHostname, "")
	t.Cleanup(func() {
		proc.Kill() //nolint:errcheck
		<-proc.Done()
	})
	sockPath := harnessSocketPath(layout)
	waitForSocket(t, sockPath, 5*time.Second)
	harness := dialHarness(t, sockPath)

	raw := createFleetJoinString(t, harness, "relay:env=test")
	join, err := enroll.DecodeJoinString(raw)
	if err != nil {
		t.Fatalf("mint response's join_string does not decode: %v", err)
	}

	daemonLog := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s\ndaemon log:\n%s", proc.Log(), daemonLog.String())
		}
	})
	stateDir := t.TempDir()
	cfg := relaytest.DaemonConfig{
		Bin:            daemonBin,
		JoinString:     raw,
		StateDir:       stateDir,
		PolicyPath:     relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy),
		Hostname:       "enroll-by-ip-node",
		LogWriter:      daemonLog,
		OmitServerName: true,
	}
	dialled := join.RelayAddress()
	if override != "" {
		cfg.Address = "https://" + override
		dialled = override
	}
	relaytest.StartDaemon(t, cfg)
	nodeID := waitForConnected(t, harness, 1)[0]

	persisted, err := os.ReadFile(filepath.Join(stateDir, "relay_addr"))
	if err != nil {
		t.Fatalf("read persisted relay_addr: %v", err)
	}
	if got, want := strings.TrimSpace(string(persisted)), "https://"+dialled; got != want {
		t.Errorf("persisted relay_addr = %q, want %q (the address the daemon dialled)", got, want)
	}

	content := relaytest.WriteTempFile(t, "content-*.txt", "hello over an IP-verified channel\n")
	resp := harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "enroll-by-ip-file-read-1",
		"operation":       "file.read",
		"args":            map[string]string{"path": content},
		"timeout_seconds": 15,
	})
	if outcome, _ := resp["outcome"].(string); outcome != "OUTCOME_SUCCESS" {
		t.Errorf("file.read outcome: got %v, want OUTCOME_SUCCESS; stderr=%v", resp["outcome"], resp["stderr"])
	}
	return join
}
