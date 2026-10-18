package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// freeLoopbackAddr binds 127.0.0.1:0, reads the OS-assigned port, and closes
// the listener, returning the address string for a subprocess to bind next.
// The window between close and the subprocess's bind is inherent and small;
// startRelaySubprocess retries on a fresh port to absorb it.
func freeLoopbackAddr() (string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer lis.Close()
	return lis.Addr().String(), nil
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

// waitListening blocks until the Relay logs "relay listening", failing if it
// exits first. The process is killed and reaped when the test ends.
func waitListening(t *testing.T, cmd *exec.Cmd, buf *syncBuffer) {
	t.Helper()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.After(10 * time.Second)
	for {
		if strings.Contains(buf.String(), "relay listening") {
			return
		}
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("relay exited before listening: %v\n%s", err, buf.String())
		case <-deadline:
			t.Fatalf("relay did not report listening within 10s\n%s", buf.String())
		case <-time.After(25 * time.Millisecond):
		}
	}
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

func TestMain_ConfigFlagHonoured(t *testing.T) {
	for _, form := range []string{"--config", "-config="} {
		t.Run(form, func(t *testing.T) {
			addr, err := freeLoopbackAddr()
			if err != nil {
				t.Fatal(err)
			}
			body := minimalTOML(t, addr)
			path := writeRelayTOML(t, body)
			args := []string{"--config", path}
			if strings.HasSuffix(form, "=") {
				args = []string{form + path}
			}
			cmd, buf := runRelayMain(t, nil, args...)
			waitListening(t, cmd, buf)

			caDir, storePath := tomlValue(body, "dir"), tomlValue(body, "path")
			if _, err := os.Stat(filepath.Join(caDir, "ca-cert.pem")); err != nil {
				t.Errorf("CA was not created under the file's ca.dir: %v", err)
			}
			if _, err := os.Stat(storePath); err != nil {
				t.Errorf("store was not created at the file's store.path: %v", err)
			}
		})
	}

	t.Run("default path", func(t *testing.T) {
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
	})
}

// tomlValue returns the quoted value of the first `key = "..."` line.
func tomlValue(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, key+" = "); ok {
			return strings.Trim(rest, `"`)
		}
	}
	return ""
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

func TestMain_CoherentButSuspectConfigStartsWithWarning(t *testing.T) {
	addr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	path := writeRelayTOML(t, minimalTOML(t, addr)+"\n[reach]\nread_blast_cap = 2\nmutate_blast_cap = 5\n")
	cmd, buf := runRelayMain(t, nil, "--config", path)
	waitListening(t, cmd, buf)

	out := buf.String()
	warnAt := -1
	offset := 0
	for _, line := range strings.SplitAfter(out, "\n") {
		if warnAt < 0 && strings.Contains(line, "level=WARN") && strings.Contains(line, "mutate_blast_cap") {
			warnAt = offset
		}
		offset += len(line)
	}
	if warnAt < 0 {
		t.Fatalf("no warning line naming mutate_blast_cap:\n%s", out)
	}
	if warnAt > strings.Index(out, "relay listening") {
		t.Errorf("the warning does not precede 'relay listening':\n%s", out)
	}
}
