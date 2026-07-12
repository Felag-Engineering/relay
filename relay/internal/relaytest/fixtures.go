package relaytest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ControlCredential is the plaintext control-plane bearer credential that
// WriteCredentialHashFile hashes into the credential-hash file it writes.
const ControlCredential = "test-control-plane-credential" //nolint:gosec // test fixture

// FixturePolicy is the TOML policy a daemon subprocess loads across the
// cmd/relay integration e2e suites. It allows file.read (wildcard, except
// /etc/shadow), service.restart for nginx only (sshd denied by default), and
// raw_exec for systemctl status/restart plus a bounded /bin/sleep (used by
// the cancel/concurrency e2e tests to get a measurable long-running,
// Policy-allowed Task).
const FixturePolicy = `
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[[operation]]
name = "system.facts"
allowed_args = []

[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$", "^/bin/sleep [0-9]+$"]
deny  = ["--force", "\\brm\\b"]
`

// WriteTempFile writes content to a new 0600 temp file under t.TempDir() and
// returns its path.
func WriteTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	if err := os.Chmod(f.Name(), 0600); err != nil {
		t.Fatalf("chmod temp file: %v", err)
	}
	return f.Name()
}

// WriteCredentialHashFile writes a well-formed "sha256:<hex>" credential
// hash file (hashing ControlCredential) under t.TempDir() and returns its
// path.
func WriteCredentialHashFile(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(ControlCredential))
	path := filepath.Join(t.TempDir(), "control-credential-hash")
	if err := os.WriteFile(path, []byte("sha256:"+hex.EncodeToString(sum[:])), 0o400); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}
