package ca

import (
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
)

// plainFiles opens the CA directory and key without hostfile's check, which refuses every
// temporary directory a test can make (it is sticky or the test's own, and a test may run as
// root). The check's own clauses are hostfile's table test; the real binary meets it on the
// separate-uid harness.
type plainFiles struct{}

func (plainFiles) openDir(path string) (*os.File, error) { return os.Open(path) }
func (plainFiles) openKey(path string) (*os.File, error) { return os.Open(path) }

func openPlain(dir string) (*CA, error) { return open(dir, plainFiles{}) }

// decidingFiles hands each descriptor's real owner and mode to hostfile.Decide under the rule
// Open passes, as a non-root Relay that owns the file on a trusted filesystem, and records the
// rule. It stands in for hostfile's own fact-gatherer, whose process facts a test cannot choose.
type decidingFiles struct {
	dirRule, keyRule hostfile.Rule
}

const (
	fakeRelayID = 4242
	ext4Magic   = 0xEF53 // a filesystem hostfile trusts
)

func (d *decidingFiles) decide(path string, flags int, rule hostfile.Rule) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|flags, 0)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	kind := hostfile.KindRegular
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		kind = hostfile.KindDir
	}
	facts := hostfile.Facts{
		Process: hostfile.Process{
			UIDs:   [3]uint32{fakeRelayID, fakeRelayID, fakeRelayID},
			GIDs:   [3]uint32{fakeRelayID, fakeRelayID, fakeRelayID},
			Groups: []uint32{fakeRelayID},
		},
		Path: []hostfile.Node{
			{Name: "/", Kind: hostfile.KindDir, Mode: 0o755, FSType: ext4Magic},
			{Name: filepath.Base(path), Kind: kind, UID: fakeRelayID, GID: fakeRelayID,
				Mode: st.Mode & 0o7777, FSType: ext4Magic},
		},
	}
	if err := hostfile.Decide(facts, rule); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (d *decidingFiles) openDir(path string) (*os.File, error) {
	d.dirRule = hostfile.GeneratedDir
	return d.decide(path, syscall.O_DIRECTORY, d.dirRule)
}

func (d *decidingFiles) openKey(path string) (*os.File, error) {
	d.keyRule = hostfile.GeneratedFile
	return d.decide(path, 0, d.keyRule)
}

// TestCA_RefusesGroupReadableKeyOrDirectory is RC-17 at the CA: the directory and the private
// key are generated material, so either one granting any access to another account refuses
// the CA, and the key is checked on the descriptor it is read from.
func TestCA_RefusesGroupReadableKeyOrDirectory(t *testing.T) {
	healthy := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "ca")
		if _, err := openPlain(dir); err != nil {
			t.Fatalf("create CA: %v", err)
		}
		return dir
	}

	t.Run("owner-only directory and key are accepted", func(t *testing.T) {
		files := &decidingFiles{}
		if _, err := open(healthy(t), files); err != nil {
			t.Fatalf("open: %v", err)
		}
		if files.dirRule != hostfile.GeneratedDir || files.keyRule != hostfile.GeneratedFile {
			t.Errorf("rules = %v, %v; want GeneratedDir for the directory and GeneratedFile for the key",
				files.dirRule, files.keyRule)
		}
	})

	for _, tc := range []struct {
		name   string
		target func(dir string) string
		mode   os.FileMode
	}{
		{"group-readable directory", func(dir string) string { return dir }, 0o750},
		{"world-readable directory", func(dir string) string { return dir }, 0o705},
		{"group-readable key", func(dir string) string { return filepath.Join(dir, keyFileName) }, 0o640},
		{"world-readable key", func(dir string) string { return filepath.Join(dir, keyFileName) }, 0o604},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := healthy(t)
			if err := os.Chmod(tc.target(dir), tc.mode); err != nil {
				t.Fatal(err)
			}
			c, err := open(dir, &decidingFiles{})
			if c != nil || err == nil {
				t.Fatalf("open = %v, %v; want a refusal", c, err)
			}
			var r *hostfile.Refusal
			if !errors.As(err, &r) || r.Clause != hostfile.ClauseGeneratedAccessByOther {
				t.Fatalf("err = %v, want hostfile's generated-material refusal", err)
			}
		})
	}
}

// Generate is a CA that touches no file: usable, and distinct on every call.
func TestGenerate_InMemoryCA(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("two generated CAs share a certificate")
	}
	csr, _ := newTestCSR(t, "ignored", elliptic.P256())
	if _, err := a.SignCSR(csr, "node-1"); err != nil {
		t.Errorf("SignCSR on a generated CA: %v", err)
	}
}
