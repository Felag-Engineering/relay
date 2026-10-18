//go:build integration

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestHarness_RelayRunsAsSeparateUid proves the separate-uid real-binary harness on the
// shippable binary: the Relay it starts runs as relaytest, not as the test, with relaytest-io
// as its one supplementary group and no capabilities, over a configuration only root can
// write, a state directory only the Relay can enter, and a group-shared IO directory that
// holds its log. Runs under make test-integration (RELAY_SHIPPABLE_BIN); without sudo or
// setpriv the harness records a skip in make verify's skip ledger, and under
// RELAY_E2E_SUDO_REQUIRED=1 it fails.
func TestHarness_RelayRunsAsSeparateUid(t *testing.T) {
	bin := os.Getenv("RELAY_SHIPPABLE_BIN")
	if bin == "" {
		relaytest.SkipMissingBin(t, "RELAY_SHIPPABLE_BIN not set; skipping the separate-uid harness test (run via make test-integration)")
	}
	layout := relaytest.NewRelayLayout(t, "test-integration")
	if !layout.Separate() {
		t.Skip("the separate uid is unavailable here; the skip is recorded in the skip ledger")
	}

	addr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	cfg := layout.WriteConfig(t, fmt.Sprintf(
		"[node_plane]\nlisten_address = %q\n\n[ca]\ndir = %q\n\n[store]\npath = %q\n\n[tls]\nhostname = \"localhost\"\n",
		addr, filepath.Join(layout.StateDir(), "ca"), filepath.Join(layout.StateDir(), "relay.db")))
	proc, err := layout.Start(t, layout.InstallBinary(t, bin), relaySubprocessEnv(layout), "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	waitForRelayLog(t, proc, "relay listening")

	uids, err := proc.UIDs()
	if err != nil {
		t.Fatal(err)
	}
	for i, uid := range uids {
		if uid != layout.RelayUID() {
			t.Errorf("relay uid[%d] (real, effective, saved, fs) = %d, want relaytest's %d", i, uid, layout.RelayUID())
		}
		if uid == os.Getuid() {
			t.Errorf("relay uid[%d] = %d is the test's own uid", i, uid)
		}
	}
	groups, err := proc.Groups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != layout.IOGID() {
		t.Errorf("relay supplementary groups = %v, want exactly relaytest-io (%d)", groups, layout.IOGID())
	}
	caps, err := proc.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range caps {
		if strings.Trim(v, "0") != "" {
			t.Errorf("relay %s = %s, want no capabilities", k, v)
		}
	}

	u, err := user.Lookup(relaytest.TestUser)
	if err != nil {
		t.Fatal(err)
	}
	relayGID, _ := strconv.Atoi(u.Gid)
	assertOwnerMode(t, cfg, 0, relayGID, 0o640)
	assertOwnerMode(t, layout.ConfigDir(), 0, relayGID, 0o750)
	assertOwnerMode(t, layout.StateDir(), layout.RelayUID(), relayGID, 0o700)
	assertOwnerMode(t, layout.IODir(), layout.RelayUID(), layout.IOGID(), fs.ModeSetgid|0o770)
	if relayGID == layout.IOGID() {
		t.Errorf("relaytest's own group is relaytest-io: an IO-group member could read the configuration")
	}

	// As anyone but root the test meets the same walls a group member does.
	if os.Geteuid() != 0 {
		if _, err := os.ReadFile(cfg); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("the test read the configuration (err=%v); only root and the Relay may", err)
		}
		if _, err := os.ReadDir(layout.StateDir()); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("the test listed the state directory (err=%v); only the Relay may", err)
		}
	}
}

// waitForRelayLog blocks until the Relay's log holds want, failing if it exits first.
func waitForRelayLog(t *testing.T, proc *relaytest.RelayProcess, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !strings.Contains(proc.Log(), want) {
		select {
		case <-proc.Done():
			t.Fatalf("relay exited before logging %q: %v\n%s", want, proc.Err(), proc.Log())
		case <-deadline:
			t.Fatalf("relay did not log %q within 10s\n%s", want, proc.Log())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// assertOwnerMode checks path's owner, group and permission bits (setgid included).
func assertOwnerMode(t *testing.T, path string, uid, gid int, mode fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s: no stat_t", path)
	}
	if int(st.Uid) != uid || int(st.Gid) != gid {
		t.Errorf("%s owner = %d:%d, want %d:%d", path, st.Uid, st.Gid, uid, gid)
	}
	if got := fi.Mode() & (fs.ModePerm | fs.ModeSetgid | fs.ModeSetuid | fs.ModeSticky); got != mode {
		t.Errorf("%s mode = %v, want %v", path, got, mode)
	}
}
