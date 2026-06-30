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

func TestOpen_CreatesOnFirstRun(t *testing.T) {
	// Use a non-existent subdirectory so Open/MkdirAll creates it fresh with
	// the expected 0700 mode. t.TempDir() itself is created by the test runner
	// with its own (potentially different) mode.
	dir := filepath.Join(t.TempDir(), "ca-store")

	ca, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ca == nil {
		t.Fatal("Open returned nil CA without error")
	}

	keyPath := filepath.Join(dir, keyFileName)
	certPath := filepath.Join(dir, certFileName)

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert file: %v", err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	if got := keyInfo.Mode().Perm(); got != keyPerm {
		t.Errorf("key file perm = %04o, want %04o", got, keyPerm)
	}
	if got := certInfo.Mode().Perm(); got != certPerm {
		t.Errorf("cert file perm = %04o, want %04o", got, certPerm)
	}
	if got := dirInfo.Mode().Perm(); got != dirPerm {
		t.Errorf("dir perm = %04o, want %04o", got, dirPerm)
	}

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

	ca1, err := Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	ca2, err := Open(dir)
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

			ca, err := Open(dir)
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
	if _, err := Open(refDir); err != nil {
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

			ca, err := Open(dir)
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
	ca, err := Open(t.TempDir())
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
	ca, err := Open(t.TempDir())
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
	ca, err := Open(t.TempDir())
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
	ca, err := Open(t.TempDir())
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
	ca, err := Open(dir)
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
