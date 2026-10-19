// Package material generates a CA private key and its self-signed certificate.
//
// It is internal to the ca tree, so only ca and its test-only constructor (catest) can import
// it, and Material carries a non-exported field, so no struct literal written elsewhere has
// its type (Go assigns an unnamed look-alike struct to a named one, so unnameable is not
// enough). That is what keeps ca.FromMaterial, which builds a CA that no file check decided
// on, callable from nowhere else with anything but a zero value, which it refuses.
package material

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

const (
	// Validity is the CA certificate's lifetime.
	Validity = 10 * 365 * 24 * time.Hour
	// ClockSkew backdates NotBefore so a peer whose clock is slightly behind accepts a fresh
	// certificate.
	ClockSkew = 5 * time.Minute
)

// Material is a CA private key and its self-signed certificate, DER-encoded.
type Material struct {
	Key     *ecdsa.PrivateKey
	CertDER []byte

	// A non-exported field: field names that are not exported are never the same across
	// packages, so a look-alike literal written outside this package has another type.
	_ struct{}
}

// New generates a fresh ECDSA P-256 CA key and its self-signed certificate.
func New() (Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("ca: generate key: %w", err)
	}

	serial, err := NewSerial()
	if err != nil {
		return Material{}, fmt.Errorf("ca: generate serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Relay CA"},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              now.Add(Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return Material{}, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	return Material{Key: key, CertDER: der}, nil
}

// NewSerial generates a random positive 128-bit serial number. It retries on
// the astronomically unlikely event that rand.Int returns zero, guaranteeing a
// non-zero value per RFC 5280 §4.1.2.2.
func NewSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		s, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if s.Sign() > 0 {
			return s, nil
		}
		// s == 0: retry (probability 1/2^128, included for correctness).
	}
}
