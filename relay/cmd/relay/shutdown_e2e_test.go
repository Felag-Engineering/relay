//go:build integration

package main

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

// A stop signal ends the shippable Relay through its shutdown path, with
// status 0. Without RELAY_SHIPPABLE_BIN it skips, like its neighbours.
func TestShutdown_StopSignalEndsTheRelayWithStatusZero(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGTERM": syscall.SIGTERM, "SIGINT": syscall.SIGINT} {
		t.Run(name, func(t *testing.T) {
			bin, layout := shippableLayout(t)
			cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), ""))
			proc := startShippable(t, layout, bin, "--config", cfg)
			waitForRelayLog(t, proc, "relay listening")

			if err := proc.Signal(sig); err != nil {
				t.Fatalf("signal %s: %v", name, err)
			}
			select {
			case <-proc.Done():
			case <-time.After(30 * time.Second):
				t.Fatalf("relay did not exit within 30s of %s\n%s", name, proc.Log())
			}
			if err := proc.Err(); err != nil {
				t.Fatalf("relay exited with %v, want status 0\n%s", err, proc.Log())
			}
			out := proc.Log()
			for _, want := range []string{"relay shutting down", "relay stopped"} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %q:\n%s", want, out)
				}
			}
		})
	}
}
