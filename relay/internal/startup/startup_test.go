package startup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/startup/internal/sealed"
)

// TestStartup_RefusedGateRefusesBeforeTheCA: a configured gate file that is absent, or that
// the file check refuses, refuses start before the CA directory is touched. In-process, every
// file a test can make is refused by the check itself (sticky /tmp, the test's own uid, or
// root), so a malformed gate reaching the parser is proven on the harness instead
// (TestStart_RefusesMalformedGateFile, RC-35).
func TestStartup_RefusedGateRefusesBeforeTheCA(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{"absent", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") }},
		{"refused by the file check", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "gates.json")
			if err := os.WriteFile(p, []byte(`{"rules": []}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caDir := filepath.Join(t.TempDir(), "ca")
			files, err := Open(tc.path(t), caDir, filepath.Join(t.TempDir(), "relay.db"))
			if err == nil {
				t.Fatal("Open accepted a gate file it could not load")
			}
			if !strings.Contains(err.Error(), "approval gate") {
				t.Errorf("err = %v, want it to name the approval gate", err)
			}
			if files.Valid() {
				t.Errorf("Open returned material alongside its refusal")
			}
			if _, err := os.Stat(caDir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the CA directory was touched before the gate refused (stat err = %v)", err)
			}
		})
	}
}

// The zero value — all that code outside the startup tree can make without Open — is not
// valid, and FromSealed refuses anything incomplete.
func TestFiles_ZeroAndIncompleteRefused(t *testing.T) {
	if (Files{}).Valid() {
		t.Error("the zero Files is valid")
	}
	if f, err := FromSealed(sealed.Files{}); err == nil || f.Valid() {
		t.Errorf("FromSealed(zero) = %v, %v; want a refusal", f, err)
	}
}
