package relaytest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingLF records which of Logf and Fatalf requireSeparateUID called, without ending the
// real test.
type recordingLF struct {
	logged, fataled bool
	msg             string
}

func (r *recordingLF) Helper() {}
func (r *recordingLF) Logf(format string, args ...any) {
	r.logged = true
	r.msg = fmt.Sprintf(format, args...)
}
func (r *recordingLF) Fatalf(format string, args ...any) {
	r.fataled = true
	r.msg = fmt.Sprintf(format, args...)
}

// ledger points make verify's skip ledger at a fresh empty file and returns its path.
func ledger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "skips")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(verifySkipsEnv, path)
	return path
}

func readLedger(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Without the separate uid, under make verify, the run records a skip in the ledger — the line
// verify's last line reports as SKIPPED — and does not fail; it is never silently a pass.
func TestRequireSeparateUID_RecordsSkipNotPass(t *testing.T) {
	for _, v := range []string{"", "0", "true"} {
		t.Run(SudoRequiredEnv+"="+v, func(t *testing.T) {
			t.Setenv(SudoRequiredEnv, v)
			path := ledger(t)
			r := &recordingLF{}
			requireSeparateUID(r, "test-gate", "sudo is not installed")
			if r.fataled {
				t.Fatalf("failed (%q), want a recorded skip", r.msg)
			}
			got := readLedger(t, path)
			want := "test-gate: the Relay as a separate uid (sudo is not installed)\n"
			if got != want {
				t.Fatalf("ledger = %q, want %q", got, want)
			}
			// A suite starts many Relays; the ledger says once that the separate uid did not run.
			requireSeparateUID(&recordingLF{}, "test-gate", "sudo is not installed")
			if got := readLedger(t, path); got != want {
				t.Fatalf("ledger after a second start = %q, want the one line %q", got, want)
			}
		})
	}
}

// RELAY_E2E_SUDO_REQUIRED=1 (CI) turns the skip into a failure, and records nothing.
func TestRequireSeparateUID_RequiredFails(t *testing.T) {
	t.Setenv(SudoRequiredEnv, "1")
	path := ledger(t)
	r := &recordingLF{}
	requireSeparateUID(r, "test-gate", "sudo is not installed")
	if !r.fataled {
		t.Fatal("did not fail under RELAY_E2E_SUDO_REQUIRED=1")
	}
	if !strings.Contains(r.msg, "sudo is not installed") || !strings.Contains(r.msg, SudoRequiredEnv) {
		t.Fatalf("failure %q should name the reason and the switch", r.msg)
	}
	if got := readLedger(t, path); got != "" {
		t.Fatalf("ledger = %q, want nothing recorded for a failure", got)
	}
}

// Outside make verify there is no ledger: the skip is logged, and nothing is written anywhere.
func TestRequireSeparateUID_NoLedgerOutsideVerify(t *testing.T) {
	t.Setenv(SudoRequiredEnv, "")
	t.Setenv(verifySkipsEnv, "")
	r := &recordingLF{}
	requireSeparateUID(r, "test-gate", "setpriv is not installed")
	if r.fataled || !r.logged || !strings.Contains(r.msg, "SKIPPING") {
		t.Fatalf("fataled=%v logged=%v msg=%q, want a logged skip", r.fataled, r.logged, r.msg)
	}
}

// With no sudo on PATH the probe reports the separate uid unavailable, naming sudo.
func TestProbeSeparateUID_NoSudo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	sep, reason := probeSeparateUID()
	if sep != nil {
		t.Fatal("probe found a separate uid with no sudo on PATH")
	}
	if !strings.Contains(reason, "sudo") {
		t.Fatalf("reason %q does not name sudo", reason)
	}
}

// A sudo that refuses (asks for a password) is unavailable too, not an error.
func TestProbeSeparateUID_SudoNeedsPassword(t *testing.T) {
	dir := t.TempDir()
	stub := "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	sep, reason := probeSeparateUID()
	if sep != nil || !strings.Contains(reason, "passwordless") {
		t.Fatalf("sep=%v reason=%q, want unavailable naming passwordless sudo", sep, reason)
	}
}

// setpriv's argv is the harness's one drop to the test user: exactly the flags the design
// names, with --groups keeping relaytest-io as the only supplementary group.
func TestSetprivArgs(t *testing.T) {
	got := strings.Join(setprivArgs(), " ")
	want := "setpriv --reuid=relaytest --regid=relaytest --groups=relaytest-io --inh-caps=-all"
	if got != want {
		t.Fatalf("setprivArgs = %q, want %q", got, want)
	}
}

func TestProcPPid(t *testing.T) {
	ppid, ok := procPPid(os.Getpid())
	if !ok || ppid != os.Getppid() {
		t.Fatalf("procPPid(self) = %d, %v; want %d", ppid, ok, os.Getppid())
	}
	uids, err := procStatusInts(os.Getpid(), "Uid:")
	if err != nil || len(uids) != 4 || uids[0] != os.Getuid() {
		t.Fatalf("procStatusInts(self, Uid:) = %v, %v; want 4 uids starting %d", uids, err, os.Getuid())
	}
}
