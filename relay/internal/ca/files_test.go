package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/ca/internal/material"
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

// A certificate that is not the key's is refused: the certificate is read relative to the
// checked directory, and must carry the key's public key.
func TestOpen_RefusesCertificateNotMatchingKey(t *testing.T) {
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	for _, dir := range []string{a, b} {
		if _, err := openPlain(dir); err != nil {
			t.Fatal(err)
		}
	}
	other, err := os.ReadFile(filepath.Join(b, certFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, certFileName), other, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := openPlain(a)
	if c != nil || err == nil || !strings.Contains(err.Error(), "does not match the CA private key") {
		t.Fatalf("open = %v, %v; want the does-not-match refusal", c, err)
	}
}

// A certificate that is a symbolic link is refused, even to the right certificate: it is
// opened relative to the checked directory without following one.
func TestOpen_RefusesSymlinkedCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := openPlain(dir); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), certFileName)
	if err := os.Rename(filepath.Join(dir, certFileName), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, filepath.Join(dir, certFileName)); err != nil {
		t.Fatal(err)
	}
	c, err := openPlain(dir)
	if c != nil || !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("open = %v, %v; want ELOOP", c, err)
	}
}

// swappingFiles opens the CA directory, then moves it aside and puts another complete CA
// directory at its path before anything else is read: what a path-based read after the check
// would then see.
type swappingFiles struct {
	plainFiles
	replacement string
}

func (s swappingFiles) openDir(path string) (*os.File, error) {
	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(path, path+".checked"); err != nil {
		return nil, err
	}
	if err := os.Rename(s.replacement, path); err != nil {
		return nil, err
	}
	return d, nil
}

// TestOpen_RefusesDirectorySwappedAfterCheck: the certificate comes from the directory that
// was checked, so a directory swapped in after the check cannot supply a matching pair. A
// certificate read by path would match the swapped-in key, and the CA would be accepted.
func TestOpen_RefusesDirectorySwappedAfterCheck(t *testing.T) {
	root := t.TempDir()
	dir, replacement := filepath.Join(root, "ca"), filepath.Join(root, "other")
	for _, d := range []string{dir, replacement} {
		if _, err := openPlain(d); err != nil {
			t.Fatal(err)
		}
	}
	c, err := open(dir, swappingFiles{replacement: replacement})
	if c != nil || err == nil || !strings.Contains(err.Error(), "does not match the CA private key") {
		t.Fatalf("open = %v, %v; want the does-not-match refusal", c, err)
	}
}

// FromMaterial refuses the zero value, the only Material code outside the ca tree can make.
func TestFromMaterial_RefusesZero(t *testing.T) {
	if c, err := FromMaterial(material.Material{}); c != nil || err == nil {
		t.Fatalf("FromMaterial(zero) = %v, %v; want a refusal", c, err)
	}
}

// TestValidCA_Refusals: the CA certificate must be the key's, self-signed, a CA allowed to sign
// certificates, and inside its validity window.
func TestValidCA_Refusals(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Relay CA"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}
	// issue makes a certificate for key's public key from tmpl, signed by signer, with parent
	// as its issuer.
	issue := func(tmpl, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	self := func(mutate func(*x509.Certificate)) *x509.Certificate {
		tmpl := good()
		mutate(tmpl)
		return issue(tmpl, tmpl, key)
	}

	if err := validCA(self(func(*x509.Certificate) {}), key); err != nil {
		t.Fatalf("a good CA certificate was refused: %v", err)
	}
	otherParent := good()
	otherParent.Subject = pkix.Name{CommonName: "Someone else"}
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
		want string
	}{
		{"another key's certificate", self(func(*x509.Certificate) {}), other, "does not match the CA private key"},
		{"not self-signed", issue(good(), otherParent, other), key, "not self-signed"},
		{"not a CA", self(func(c *x509.Certificate) { c.IsCA = false }), key, "not a certificate authority"},
		{"no certificate-signing usage", self(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), key, "not a certificate authority"},
		{"expired", self(func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour) }), key, "has expired"},
		{"not yet valid", self(func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour) }), key, "not yet valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validCA(tc.cert, tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validCA = %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}

// Proves RC-28: OpenExisting refuses an absent CA and creates nothing.
func TestOpenExisting_RefusesAnAbsentCAAndCreatesNothing(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "ca")
	if _, err := openCA(absent, plainFiles{}, false); !errors.Is(err, ErrAbsent) {
		t.Fatalf("an absent directory: err = %v, want ErrAbsent", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory exists afterwards: %v", err)
	}

	empty := t.TempDir()
	if _, err := openCA(empty, plainFiles{}, false); !errors.Is(err, ErrAbsent) {
		t.Fatalf("an empty directory: err = %v, want ErrAbsent", err)
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("the empty directory holds %d entries afterwards", len(entries))
	}
}

// Proves RC-28: OpenExisting loads the CA Open created, the same one.
func TestOpenExisting_LoadsTheCAOpenCreated(t *testing.T) {
	dir := t.TempDir()
	created, err := openPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := openCA(dir, plainFiles{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint() != created.Fingerprint() {
		t.Errorf("fingerprint = %s, want %s", loaded.Fingerprint(), created.Fingerprint())
	}
}
