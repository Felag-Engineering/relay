package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// FuzzSignCSR fuzzes CA.SignCSR — the only parser of attacker-controlled bytes
// reachable without a client cert, via the certless Enroll RPC
// (cmd/relay/main.go's certless allowlist -> enroll/handler.go -> SignCSR).
// Property: SignCSR must never panic or hang on any (csrPEM, nodeID) input; it
// returns either (cert, nil) or (nil, err).
func FuzzSignCSR(f *testing.F) {
	// Build the CA once, outside the fuzz loop: Open generates a keypair and
	// SignCSR only reads it, so a single shared CA is safe to reuse across
	// iterations and avoids per-iteration keygen cost.
	c, err := openPlain(f.TempDir())
	if err != nil {
		f.Fatalf("Open: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate seed ECDSA key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		f.Fatalf("create seed CSR: %v", err)
	}
	validCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	f.Add(validCSRPEM, "node-seed")
	f.Add([]byte("not pem at all"), "node-1")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"), "node-1")
	f.Add([]byte{}, "") // exercises the empty-nodeID and empty-CSR branches together

	f.Fuzz(func(t *testing.T, csrPEM []byte, nodeID string) {
		_, _ = c.SignCSR(csrPEM, nodeID)
	})
}
