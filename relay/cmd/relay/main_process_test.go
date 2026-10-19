package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestMain re-executes the test binary as the Relay when RELAYTEST_RUN_MAIN
// is set, so a test can drive main() as a real process (exit codes, stderr,
// the environment) without a separate build.
func TestMain(m *testing.M) {
	if os.Getenv("RELAYTEST_RUN_MAIN") == "1" {
		os.Args = append([]string{"relay"}, os.Args[1:]...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// syncBuffer is a mutex-guarded bytes.Buffer: subprocess log captures are
// written to concurrently (by the OS pipe copy) and read concurrently (by the
// readiness poll and, on failure, dumpLogs).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// relayChildEnv is the one place a Relay child's environment is built. It
// carries the few variables a process needs and never copies os.Environ():
// the Relay refuses a retired RELAY_* name, so a developer's exported
// RELAY_ADDR would otherwise fail every test that starts one.
func relayChildEnv(extra ...string) []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "GOCOVERDIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

// writeRelayTOML writes body as a read-only relay.toml in a fresh directory.
func writeRelayTOML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write relay.toml: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod relay.toml: %v", err)
	}
	return path
}

// minimalTOML is the smallest file the Relay starts from: the listen address,
// and a CA directory and store inside the test's temp dir.
func minimalTOML(t *testing.T, addr string) string {
	t.Helper()
	return fmt.Sprintf("[node_plane]\nlisten_address = %q\n\n[ca]\ndir = %q\n\n[store]\npath = %q\n\n[tls]\nhostname = \"localhost\"\n",
		addr, t.TempDir(), filepath.Join(t.TempDir(), "relay.db"))
}

// runRelayMain starts the test binary as the Relay with args, in a filtered
// environment plus env.
func runRelayMain(t *testing.T, env []string, args ...string) (*exec.Cmd, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = relayChildEnv(append([]string{"RELAYTEST_RUN_MAIN=1"}, env...)...)
	cmd.Stdout = buf
	cmd.Stderr = buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	return cmd, buf
}

// exitCode runs cmd to completion and returns its exit code.
func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("wait: %v", err)
	}
	return ee.ExitCode()
}

// TestMain_DefaultConfigPathNamedWhenAbsent: with no --config the Relay reads the default path,
// and a missing file refuses start naming it. The file is never reached, so this runs as the
// test's own uid; every start that reads a file is on the separate-uid harness
// (start_e2e_test.go).
func TestMain_DefaultConfigPathNamedWhenAbsent(t *testing.T) {
	if _, err := os.Stat("/etc/relay/relay.toml"); err == nil {
		t.Skip("the host has /etc/relay/relay.toml")
	}
	cmd, buf := runRelayMain(t, nil)
	if code := exitCode(t, cmd); code == 0 {
		t.Fatalf("relay with no configuration file exited 0:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "/etc/relay/relay.toml") {
		t.Errorf("output does not name the default path:\n%s", buf.String())
	}
}

func TestMain_OtherFlagsRefused(t *testing.T) {
	path := writeRelayTOML(t, minimalTOML(t, "127.0.0.1:0"))
	for _, extra := range [][]string{
		{"--addr", ":7654"},
		{"--ca-dir", "/x"},
		{"-hostname", "x"},
		{"--store-path", "/x"},
		{"--control-enabled"},
		{"--approval-webhook-url=https://h.example/T0K3N"},
		{"serve"},
	} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			cmd, buf := runRelayMain(t, nil, append([]string{"--config", path}, extra...)...)
			if code := exitCode(t, cmd); code != 2 {
				t.Errorf("exit code = %d, want 2\n%s", code, buf.String())
			}
			out := buf.String()
			if strings.Contains(out, "relay listening") {
				t.Errorf("relay started with %v", extra)
			}
			if strings.Contains(out, "T0K3N") {
				t.Errorf("output echoes the value:\n%s", out)
			}
		})
	}

	t.Run("--help", func(t *testing.T) {
		cmd, buf := runRelayMain(t, nil, "--help")
		if code := exitCode(t, cmd); code != 0 {
			t.Errorf("exit code = %d, want 0\n%s", code, buf.String())
		}
		if !strings.Contains(buf.String(), "--config") {
			t.Errorf("help does not mention --config:\n%s", buf.String())
		}
	})
}

func TestMain_RetiredEnvNameRefusesNamingKey(t *testing.T) {
	path := writeRelayTOML(t, minimalTOML(t, "127.0.0.1:0"))

	t.Run("RELAY_HOSTNAME", func(t *testing.T) {
		cmd, buf := runRelayMain(t, []string{"RELAY_HOSTNAME=s3cr3t-host"}, "--config", path)
		if code := exitCode(t, cmd); code != 1 {
			t.Errorf("exit code = %d, want 1\n%s", code, buf.String())
		}
		out := buf.String()
		for _, want := range []string{"RELAY_HOSTNAME", "tls.hostname"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "s3cr3t-host") {
			t.Errorf("output echoes the value:\n%s", out)
		}
	})

	t.Run("RELAY_APPROVAL_WEBHOOK_URL", func(t *testing.T) {
		cmd, buf := runRelayMain(t, []string{"RELAY_APPROVAL_WEBHOOK_URL=https://h.example/T0K3N"}, "--config", path)
		if code := exitCode(t, cmd); code != 1 {
			t.Errorf("exit code = %d, want 1\n%s", code, buf.String())
		}
		out := buf.String()
		if !strings.Contains(out, "approval.webhook_url") {
			t.Errorf("output does not name the key:\n%s", out)
		}
		if strings.Contains(out, "T0K3N") {
			t.Errorf("output echoes the value:\n%s", out)
		}
	})

	t.Run("refused before the file is opened", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.toml")
		cmd, buf := runRelayMain(t, []string{"RELAY_CA_DIR=x"}, "--config", missing)
		if code := exitCode(t, cmd); code != 1 {
			t.Errorf("exit code = %d, want 1\n%s", code, buf.String())
		}
		out := buf.String()
		if !strings.Contains(out, "RELAY_CA_DIR") || !strings.Contains(out, "ca.dir") {
			t.Errorf("output does not name the retired name and its key:\n%s", out)
		}
		if strings.Contains(out, "does not exist") {
			t.Errorf("the file was opened before the environment was refused:\n%s", out)
		}
	})
}
