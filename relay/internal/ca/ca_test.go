package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestCSR generates a fresh ECDSA key on curve and returns a PEM-encoded
// CERTIFICATE REQUEST and the private key. The CSR Subject CN is set to csrCN
// to prove that SignCSR overrides it with the nodeID argument.
func newTestCSR(t *testing.T, csrCN string, curve elliptic.Curve) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate test ECDSA key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: csrCN},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create test CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// newRSACSR generates an RSA key and returns a PEM-encoded CERTIFICATE REQUEST.
// Used for the non-ECDSA rejection test.
func newRSACSR(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-node"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create RSA test CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// corruptCSRSig decodes csrPEM, flips the last byte of the DER (which lies
// inside the ECDSA signature value), and re-encodes to PEM so that
// CheckSignature fails while the ASN.1 structure remains parseable.
func corruptCSRSig(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("corruptCSRSig: decode PEM")
	}
	der := make([]byte, len(block.Bytes))
	copy(der, block.Bytes)
	der[len(der)-1] ^= 0xff
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// assertModeWithin asserts that path carries no permission bit beyond declared,
// and none of the forbidden bits.
//
// The CA's declared modes are ceilings rather than exact values (see the perm
// constants in ca.go): the process umask may tighten what MkdirAll and
// OpenFile produce, and nothing may widen it. So these are the two properties
// that are actually load-bearing — a regression that WIDENS the store (a forced
// chmod, a dropped perm argument, a looser constant) fails under every umask,
// and the security-relevant bits are pinned clear outright.
//
// The second check is not redundant with the first: the ceiling is a caller
// argument and survives being edited, so the forbidden-bit floor is what still
// fails if someone widens the writer AND raises the ceiling here to match.
func assertModeWithin(t *testing.T, path string, declared, forbidden os.FileMode, what string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", what, err)
	}
	mode := info.Mode().Perm()

	if extra := mode &^ declared; extra != 0 {
		t.Errorf("%s perm = %04o, want no looser than %04o (the umask may tighten it, nothing may widen it); extra bits %04o",
			what, mode, declared, extra)
	}
	if bad := mode & forbidden; bad != 0 {
		t.Errorf("%s perm = %04o, want none of %04o set; got %04o", what, mode, forbidden, bad)
	}
}

func TestOpen_CreatesOnFirstRun(t *testing.T) {
	// Use a non-existent subdirectory so Open/MkdirAll creates it fresh with
	// the expected 0700 mode. t.TempDir() itself is created by the test runner
	// with its own (potentially different) mode.
	dir := filepath.Join(t.TempDir(), "ca-store")

	ca, err := openPlain(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ca == nil {
		t.Fatal("Open returned nil CA without error")
	}

	keyPath := filepath.Join(dir, keyFileName)
	certPath := filepath.Join(dir, certFileName)

	// The declared modes are written out as literals rather than read back
	// from ca.go's constants ON PURPOSE: a test that borrows the writer's own
	// constant as its ceiling raises that ceiling in lockstep with any change
	// to it, so the ceiling check could never fail. Stating the number here
	// makes it an independent claim about the CA store.
	//
	// ca-key.pem — the crown jewel: declared 0600, and never readable by group
	// or world under any umask.
	assertModeWithin(t, keyPath, 0o600, 0o077, "ca-key.pem")
	// ca-cert.pem — public material (the trust anchor Nodes pin), so the claim
	// is integrity rather than secrecy: declared 0644, and never writable by
	// group or world.
	assertModeWithin(t, certPath, 0o644, 0o022, "ca-cert.pem")
	// The store directory carries the strongest claim of the three — a CA
	// store is owner-only — and a umask cannot loosen 0700. Here the ceiling
	// and the floor meet: "no bit beyond 0700" and "none of 0077" say the same
	// thing from both sides, which is precisely the claim being made. Exact
	// equality would add only the ability to fail when a umask TIGHTENED the
	// directory, which is neither a regression nor reachable — a umask that
	// clears an owner bit makes Open itself fail before this line.
	assertModeWithin(t, dir, 0o700, 0o077, "ca store directory")

	// Bundle must decode to a CA certificate.
	bundle := ca.Bundle()
	block, _ := pem.Decode(bundle)
	if block == nil {
		t.Fatal("Bundle returned empty/invalid PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert from Bundle: %v", err)
	}
	if !parsed.IsCA {
		t.Error("CA cert IsCA = false, want true")
	}
}

func TestOpen_Idempotent(t *testing.T) {
	dir := t.TempDir()

	ca1, err := openPlain(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	ca2, err := openPlain(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}

	// Identical bundles mean the second call loaded rather than regenerated.
	if !bytes.Equal(ca1.Bundle(), ca2.Bundle()) {
		t.Error("Bundle changed between opens: CA was regenerated instead of loaded")
	}
}

func TestOpen_InconsistentState(t *testing.T) {
	cases := []struct {
		name      string
		writeFile string
	}{
		{"key_without_cert", keyFileName},
		{"cert_without_key", certFileName},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.writeFile), []byte("dummy"), 0o600); err != nil {
				t.Fatalf("setup: %v", err)
			}

			ca, err := openPlain(dir)
			if err == nil {
				t.Error("Open succeeded on inconsistent state, want error")
			}
			if ca != nil {
				t.Errorf("Open returned non-nil CA on inconsistent state")
			}
		})
	}
}

func TestOpen_CorruptFiles(t *testing.T) {
	// Build a valid CA in a reference dir to obtain well-formed file bytes.
	refDir := t.TempDir()
	if _, err := openPlain(refDir); err != nil {
		t.Fatalf("setup reference CA: %v", err)
	}
	validKey, err := os.ReadFile(filepath.Join(refDir, keyFileName))
	if err != nil {
		t.Fatalf("read reference key: %v", err)
	}
	validCert, err := os.ReadFile(filepath.Join(refDir, certFileName))
	if err != nil {
		t.Fatalf("read reference cert: %v", err)
	}

	// garbagePEM is a valid PEM frame with a valid-base64 body that decodes to
	// non-DER bytes, so ParseCertificate / ParsePKCS8PrivateKey will fail.
	// "dGhpcyBpcyBub3QgdmFsaWQgREVS" = base64("this is not valid DER")
	garbagePEM := func(blockType string) []byte {
		return []byte("-----BEGIN " + blockType + "-----\ndGhpcyBpcyBub3QgdmFsaWQgREVS\n-----END " + blockType + "-----\n")
	}

	cases := []struct {
		name         string
		keyContents  []byte
		certContents []byte
	}{
		{
			// cert file: garbled PEM body (invalid base64) → pem.Decode returns nil.
			name:         "garbage_pem_body_in_cert",
			keyContents:  validKey,
			certContents: []byte("-----BEGIN CERTIFICATE-----\nnot!valid!base64\n-----END CERTIFICATE-----\n"),
		},
		{
			// key file: valid PEM frame but garbage DER inside → ParsePKCS8PrivateKey fails.
			name:         "corrupt_der_in_key",
			keyContents:  garbagePEM("PRIVATE KEY"),
			certContents: validCert,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, keyFileName), tc.keyContents, 0o600); err != nil {
				t.Fatalf("write key: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, certFileName), tc.certContents, 0o644); err != nil {
				t.Fatalf("write cert: %v", err)
			}

			ca, err := openPlain(dir)
			if err == nil {
				t.Error("Open succeeded on corrupt files, want error")
			}
			if ca != nil {
				t.Errorf("Open returned non-nil CA on corrupt files")
			}
		})
	}
}

func TestSignCSR_Valid(t *testing.T) {
	ca, err := openPlain(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	nodeID := "node-abc-123"
	csrPEM, _ := newTestCSR(t, "ignored-cn", elliptic.P256())

	certPEM, err := ca.SignCSR(csrPEM, nodeID)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if certPEM == nil {
		t.Fatal("SignCSR returned nil certPEM without error")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("SignCSR did not return a CERTIFICATE PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	if leaf.Subject.CommonName != nodeID {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, nodeID)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", leaf.PublicKeyAlgorithm)
	}
	if leaf.IsCA {
		t.Error("leaf IsCA = true, want false")
	}

	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}

	// Verify the full chain using Bundle() as the trust anchor.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.Bundle())
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Errorf("leaf.Verify: %v", err)
	}
}

func TestSignCSR_CNOverridesCSR(t *testing.T) {
	ca, err := openPlain(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// The CSR deliberately carries a CN that must not appear in the issued cert.
	csrPEM, _ := newTestCSR(t, "evil", elliptic.P256())
	nodeID := "legitimate-node-id"

	certPEM, err := ca.SignCSR(csrPEM, nodeID)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	if leaf.Subject.CommonName != nodeID {
		t.Errorf("CN = %q, want nodeID %q (CSR CN must not bleed through)", leaf.Subject.CommonName, nodeID)
	}
}

func TestSignCSR_ExpiryBounds(t *testing.T) {
	ca, err := openPlain(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	before := time.Now()
	csrPEM, _ := newTestCSR(t, "n", elliptic.P256())
	certPEM, err := ca.SignCSR(csrPEM, "node-x")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	after := time.Now()

	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// NotAfter must be close to now + LeafValidity.
	slack := time.Minute
	if leaf.NotAfter.Before(before.Add(LeafValidity).Add(-slack)) {
		t.Errorf("NotAfter %v too early (want >= %v)", leaf.NotAfter, before.Add(LeafValidity).Add(-slack))
	}
	if leaf.NotAfter.After(after.Add(LeafValidity).Add(slack)) {
		t.Errorf("NotAfter %v too late (want <= %v)", leaf.NotAfter, after.Add(LeafValidity).Add(slack))
	}

	// Validity window must account for the NotBefore backdate (clockSkew).
	window := leaf.NotAfter.Sub(leaf.NotBefore)
	if window < LeafValidity {
		t.Errorf("validity window %v < LeafValidity %v", window, LeafValidity)
	}
	if window > LeafValidity+clockSkew+slack {
		t.Errorf("validity window %v > LeafValidity+clockSkew+slack %v", window, LeafValidity+clockSkew+slack)
	}
}

func TestSignCSR_Malformed(t *testing.T) {
	ca, err := openPlain(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	validP256CSR, _ := newTestCSR(t, "n", elliptic.P256())
	validP384CSR, _ := newTestCSR(t, "n", elliptic.P384())
	rsaCSR := newRSACSR(t)
	corruptedSigCSR := corruptCSRSig(t, validP256CSR)

	cases := []struct {
		name   string
		csr    []byte
		nodeID string
	}{
		{"garbage_bytes", []byte("not pem at all"), "node-1"},
		{"wrong_pem_type", []byte("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"), "node-1"},
		{"corrupted_csr_sig", corruptedSigCSR, "node-1"},
		{"empty_nodeID", validP256CSR, ""},
		{"rsa_keyed_csr", rsaCSR, "node-1"},
		{"p384_csr", validP384CSR, "node-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, err := ca.SignCSR(tc.csr, tc.nodeID)
			if err == nil {
				t.Error("SignCSR succeeded, want error")
			}
			if certPEM != nil {
				t.Error("SignCSR returned non-nil cert on error")
			}
		})
	}
}

func TestBundle_IsCAPEM(t *testing.T) {
	dir := t.TempDir()
	ca, err := openPlain(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	bundle := ca.Bundle()
	onDisk, err := os.ReadFile(filepath.Join(dir, certFileName))
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}

	if !bytes.Equal(bundle, onDisk) {
		t.Error("Bundle() bytes differ from on-disk ca-cert.pem")
	}

	// Must decode to exactly one CERTIFICATE block.
	block, rest := pem.Decode(bundle)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("Bundle did not contain a CERTIFICATE PEM block")
	}
	extra, _ := pem.Decode(rest)
	if extra != nil {
		t.Error("Bundle contains more than one PEM block")
	}
}

// TestFingerprint_IsTheCACertificateDigest: this is the number an operator
// compares a Node's configured trust root against, and the one ADR-0031 will
// have a daemon pin — so it must be the digest of the certificate the Bundle
// actually delivers, and it must be stable across reopens of the same CA
// directory.
func TestFingerprint_IsTheCACertificateDigest(t *testing.T) {
	dir := t.TempDir()
	c, err := openPlain(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	block, _ := pem.Decode(c.Bundle())
	if block == nil {
		t.Fatal("Bundle did not contain a PEM block")
	}
	want := fingerprint(block.Bytes)

	if got := c.Fingerprint(); got != want {
		t.Errorf("Fingerprint() = %q, want the digest of the bundled certificate %q", got, want)
	}
	if len(c.Fingerprint()) != 64 {
		t.Errorf("Fingerprint() = %q, want 64 hex characters (SHA-256, no colons)", c.Fingerprint())
	}

	reopened, err := openPlain(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Fingerprint(); got != want {
		t.Errorf("Fingerprint() after reopen = %q, want %q — a value daemons pin cannot move "+
			"when the process restarts", got, want)
	}
}
