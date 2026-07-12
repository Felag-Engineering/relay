package relaytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// NewCSR generates a fresh ECDSA P-256 key and returns a PEM-encoded
// CERTIFICATE REQUEST and the private key. The CN is deliberately a
// throwaway — the Relay's SignCSR ignores the CSR subject and sets CN
// authoritatively to the Relay-assigned node_id (ADR-0006).
func NewCSR(t *testing.T, cn string) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), k
}

// AssembleClientCert combines a PEM-encoded leaf certificate and its ECDSA
// private key into a tls.Certificate suitable for use as a relay-daemon
// client credential on an mTLS connection.
func AssembleClientCert(t *testing.T, certPEM []byte, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert
}

// CertPool builds an *x509.CertPool from the given PEM bundle.
func CertPool(t *testing.T, bundlePEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundlePEM) {
		t.Fatal("CertPool: AppendCertsFromPEM returned false — empty or invalid PEM")
	}
	return pool
}
