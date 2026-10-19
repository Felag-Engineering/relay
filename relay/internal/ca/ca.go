// Package ca implements the Relay-hosted ECDSA P-256 certificate authority used
// to mint Node identity certificates at enrollment (ADR-0006), and to issue the
// Relay's own TLS server certificate — which it re-issues before expiry
// (ServerCertificate, ADR-0031 §5).
//
// No logging is performed anywhere in this package; all errors are returned to
// the caller, and rotation is reported through an injected observer rather than
// a log line. Key material is never embedded in error strings.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Felag-Engineering/relay/relay/internal/ca/internal/material"
	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
)

const (
	keyFileName  = "ca-key.pem"
	certFileName = "ca-cert.pem"

	// The CA store's on-disk modes. These are CEILINGS, deliberately left
	// umask-masked: os.MkdirAll and os.OpenFile mask the requested mode with
	// the process umask, so a stricter umask lands a stricter store — the safe
	// direction for every one of these paths, and left alone on purpose.
	//
	// Do NOT "make the declared mode authoritative" with an os.Chmod after
	// creation. Forcing is only safe where the declared mode is the tightest
	// one: forcing dirPerm or keyPerm could only ever tighten, but forcing
	// certPerm would hand an operator running `umask 077` a world-readable
	// ca-cert.pem where they get 0600 today — looser than what they have, on
	// the fleet's trust anchor, produced by the CA itself (ADR-0036; the daemon's
	// identity files follow the same rule).
	//
	// The tests therefore assert the direction — no bit beyond the declared
	// mode, and the security-relevant bits clear outright — never exact
	// equality, which is what made the suite fail on any developer machine not
	// sitting at the default 0o022.
	dirPerm  os.FileMode = 0o700
	keyPerm  os.FileMode = 0o600
	certPerm os.FileMode = 0o644

	// maxPEMBytes bounds what is read from the key and certificate files.
	maxPEMBytes = 64 << 10

	// LeafValidity is the lifetime issued to Node identity certificates (~2 weeks).
	LeafValidity = 336 * time.Hour

	// ServerLeafValidity is the lifetime issued to the Relay's OWN TLS server
	// certificate. It is deliberately a separate constant from LeafValidity,
	// and deliberately far shorter.
	//
	// A Node identity certificate is renewed across the network by a daemon
	// that must survive being offline, so its lifetime is generous. The
	// Relay's server certificate is re-issued in-process from a CA key already
	// open in the same address space (see ServerCertificate, ADR-0031 §5), so
	// a short lifetime costs one function call and bounds the life of a server
	// key that is otherwise never rotated.
	//
	// The two must never share a constant again: borrowing LeafValidity for
	// the server leaf, with nothing renewing it, is exactly how a Relay up
	// longer than fourteen days came to serve an expired certificate and take
	// the whole fleet fail-closed off it.
	ServerLeafValidity = 24 * time.Hour

	clockSkew = 5 * time.Minute
)

// CA is a persistent ECDSA P-256 certificate authority. The zero value is not
// usable; obtain one through Open.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte // cached PEM of c.cert; returned (copied) by Bundle.
}

// Open creates a new CA in dir on the first call, or loads the existing one on
// subsequent calls (idempotent). The directory is created with mode 0700 if it
// does not already exist.
//
// The directory and the private key are the Relay's generated material
// (RC-17): each is opened through hostfile's generated-material rule, and Open
// refuses unless both are owned by the Relay's uid and grant nothing to any
// other account. The key is read from the descriptor that was checked.
//
// Open refuses to proceed when exactly one of the two CA files is present:
// silently regenerating would orphan already-issued Node certs by replacing
// their trust root.
func Open(dir string) (*CA, error) {
	return open(dir, checkedFiles{})
}

// generatedFiles opens the CA directory and its private key. Open's is
// hostfile's generated-material rule; this package's tests substitute their
// own, because the check refuses every temporary directory a test can make.
type generatedFiles interface {
	openDir(path string) (*os.File, error)
	openKey(path string) (*os.File, error)
}

type checkedFiles struct{}

func (checkedFiles) openDir(path string) (*os.File, error) {
	return hostfile.OpenDir(path, hostfile.GeneratedDir)
}

func (checkedFiles) openKey(path string) (*os.File, error) {
	return hostfile.Open(path, hostfile.GeneratedFile)
}

func open(dir string, files generatedFiles) (*CA, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("ca: create dir: %w", err)
	}
	// The checked directory's descriptor stays open: the certificate is opened relative to
	// it, so it comes from the directory that was decided on.
	d, err := files.openDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ca: CA directory: %w", err)
	}
	defer d.Close() //nolint:errcheck // read-only

	keyExists, err := entryExists(d, keyFileName)
	if err != nil {
		return nil, fmt.Errorf("ca: stat key file: %w", err)
	}
	certExists, err := entryExists(d, certFileName)
	if err != nil {
		return nil, fmt.Errorf("ca: stat cert file: %w", err)
	}

	switch {
	case keyExists && certExists:
		return load(d, dir, files)
	case !keyExists && !certExists:
		if err := create(dir); err != nil {
			return nil, err
		}
		return load(d, dir, files)
	case keyExists:
		return nil, errors.New("ca: inconsistent state: ca-key.pem present but ca-cert.pem missing")
	default:
		return nil, errors.New("ca: inconsistent state: ca-cert.pem present but ca-key.pem missing")
	}
}

// FromMaterial builds a CA held only in memory, read from no file and so
// decided on by no file check; the Relay itself always uses Open. Its
// parameter's type is internal to this package's tree, so only the test-only
// constructor (catest, kept out of production code by depguard) can pass it
// anything but a zero value, which is refused.
func FromMaterial(m material.Material) (*CA, error) {
	if m.Key == nil || len(m.CertDER) == 0 {
		return nil, errors.New("ca: no key material")
	}
	cert, err := x509.ParseCertificate(m.CertDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}
	if err := validCA(cert, m.Key); err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     m.Key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.CertDER}),
	}, nil
}

// Bundle returns a copy of the CA certificate PEM. Callers use this to build
// an *x509.CertPool for the mTLS server config or to deliver the trust anchor
// to daemons during enrollment.
func (c *CA) Bundle() []byte {
	cp := make([]byte, len(c.certPEM))
	copy(cp, c.certPEM)
	return cp
}

// Fingerprint returns the hex-encoded SHA-256 digest of the CA certificate's
// DER bytes — the number `openssl x509 -noout -fingerprint -sha256` prints,
// minus the colons.
//
// Public-certificate data only: this is a digest over the same bytes Bundle
// already hands to every enrolling daemon, and it involves no key material. It
// exists so an operator can compare the trust root a machine is about to pin
// against the one this Relay actually holds (ADR-0031) — the Console's day-one
// screen and the startup log line both render it.
//
// It reuses the same fingerprint helper the server-certificate rotation
// observer and the enrollment handler use, deliberately: this value is meant to
// be compared against numbers those paths report, and two implementations of
// one digest is a fleet-wide trust bug waiting to happen.
func (c *CA) Fingerprint() string {
	return fingerprint(c.cert.Raw)
}

// SignCSR verifies csrPEM (a "CERTIFICATE REQUEST" PEM block whose key must be
// ECDSA P-256), then issues a Node identity certificate chained to this CA.
//
// The only thing taken from the CSR is the public key. The Subject and any SANs
// in the CSR are ignored; CN is set authoritatively to nodeID per ADR-0006 so
// that a Node cannot choose its own identity.
//
// nodeID must not be empty.
func (c *CA) SignCSR(csrPEM []byte, nodeID string) ([]byte, error) {
	if nodeID == "" {
		return nil, errors.New("ca: nodeID must not be empty")
	}

	// pem.Decode's second return is the trailing remainder, not an error.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("ca: failed to decode PEM block from CSR")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("ca: expected PEM block type CERTIFICATE REQUEST, got %q", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature check: %w", err)
	}

	// Enforce algorithm first, then curve — ECDSA P-256 specifically.
	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("ca: CSR must use ECDSA, got %v", csr.PublicKeyAlgorithm)
	}
	pk, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("ca: CSR must use ECDSA P-256")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	now := time.Now()
	leaf := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID}, // authoritative; never copied from CSR
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, &leaf, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// IssueServerCertificate mints a server certificate chained to this CA, with
// ExtKeyUsageServerAuth, ServerLeafValidity, and the given DNS names and IP
// SANs. The certificate is signed by the CA so daemons can verify it against
// the ca_bundle they receive at enrollment (ADR-0006).
//
// A caller that serves TLS must NOT hold the result static: a certificate
// minted once at process start expires while the process is still running, and
// every daemon then fail-closes off the Relay. Serve through
// ServerCertificate.GetCertificate instead, which re-issues before expiry.
// This entry point remains for tests and one-shot issuance.
//
// The chain is the leaf followed by the CA certificate. A daemon that pins the
// CA by SHA-256 over its DER (ADR-0031) can check the pin only if the root
// comes over the wire; a verifier that already holds the CA ignores it.
func (c *CA) IssueServerCertificate(dnsNames []string, ipAddresses []net.IP) (tls.Certificate, error) {
	return c.issueServerCertificate(dnsNames, ipAddresses, time.Now(), ServerLeafValidity)
}

// issueServerCertificate is IssueServerCertificate with the issuing instant and
// the leaf lifetime supplied by the caller, so ServerCertificate can issue
// against an injected clock.
func (c *CA) issueServerCertificate(dnsNames []string, ipAddresses []net.IP, now time.Time, validity time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate server key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate serial: %w", err)
	}

	leaf := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Relay"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, &leaf, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: sign server certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: parse server certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        leafCert,
	}, nil
}

// create generates a fresh CA key and self-signed certificate, writing both to
// dir with restrictive permissions using O_CREATE|O_EXCL.
func create(dir string) error {
	m, err := material.New()
	if err != nil {
		return err
	}
	key, der := m.Key, m.CertDER

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("ca: marshal private key: %w", err)
	}

	keyPath := filepath.Join(dir, keyFileName)
	certPath := filepath.Join(dir, certFileName)

	if err := writeFileExcl(keyPath, "PRIVATE KEY", keyDER, keyPerm); err != nil {
		return err
	}
	if err := writeFileExcl(certPath, "CERTIFICATE", der, certPerm); err != nil {
		return err
	}

	return nil
}

// entryExists reports whether name is present in the directory d, without
// following a symbolic link.
func entryExists(d *os.File, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT):
		return false, nil
	}
	return false, err
}

// load reads the CA key and certificate from dir, whose checked descriptor is
// d, parses them, and returns a ready CA. All parse errors propagate
// (corrupt-file path). The key is read from the descriptor files.openKey
// checked; the certificate is public, and is opened relative to d without
// following a symbolic link. The certificate must certify the key, so a
// certificate swapped in beside the checked key is refused.
func load(d *os.File, dir string, files generatedFiles) (*CA, error) {
	keyPath := filepath.Join(dir, keyFileName)

	// The key is opened by path, walking from the root through hostfile, rather
	// than relative to d. That is safe because the certificate, which is read
	// relative to d, must carry this key's public key: a key from anywhere but
	// the checked directory does not match it, and is refused below.
	kf, err := files.openKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: key file: %w", err)
	}
	keyRaw, err := readBounded(kf)
	if err != nil {
		return nil, fmt.Errorf("ca: read key file: %w", err)
	}

	cfd, err := unix.Openat(int(d.Fd()), certFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ca: open cert file: %w", err)
	}
	cf := os.NewFile(uintptr(cfd), certFileName)
	info, err := cf.Stat()
	if err != nil {
		_ = cf.Close()
		return nil, fmt.Errorf("ca: stat cert file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = cf.Close()
		return nil, errors.New("ca: cert file is not a regular file")
	}
	certRaw, err := readBounded(cf)
	if err != nil {
		return nil, fmt.Errorf("ca: read cert file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyRaw)
	if keyBlock == nil {
		return nil, errors.New("ca: failed to decode PEM block from key file")
	}
	if keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("ca: expected PEM block type PRIVATE KEY in key file, got %q", keyBlock.Type)
	}

	certBlock, _ := pem.Decode(certRaw)
	if certBlock == nil {
		return nil, errors.New("ca: failed to decode PEM block from cert file")
	}
	if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: expected PEM block type CERTIFICATE in cert file, got %q", certBlock.Type)
	}

	privAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse private key: %w", err)
	}
	priv, ok := privAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ca: key file does not contain an ECDSA private key")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}
	if err := validCA(cert, priv); err != nil {
		return nil, err
	}

	return &CA{
		cert:    cert,
		key:     priv,
		certPEM: certRaw,
	}, nil
}

// validCA refuses a certificate that is not a usable, self-signed CA
// certificate for key.
func validCA(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if !key.PublicKey.Equal(cert.PublicKey) {
		return errors.New("ca: the CA certificate does not match the CA private key")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("ca: the CA certificate is not a certificate authority that may sign certificates")
	}
	// After the flags: CheckSignatureFrom also refuses a parent that is not a CA.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return errors.New("ca: the CA certificate is not self-signed by the CA private key")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("ca: the CA certificate is not yet valid")
	}
	if !now.Before(cert.NotAfter) {
		return errors.New("ca: the CA certificate has expired")
	}
	return nil
}

// readBounded reads f to its end, at most maxPEMBytes, and closes it.
func readBounded(f *os.File) ([]byte, error) {
	defer f.Close() //nolint:errcheck // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPEMBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxPEMBytes)
	}
	return data, nil
}

// newSerial generates a random positive 128-bit serial number.
func newSerial() (*big.Int, error) { return material.NewSerial() }

// writeFileExcl PEM-encodes der as blockType and writes it to path with perm,
// using O_CREATE|O_EXCL so a concurrent creator is detected and the file mode
// is applied atomically at creation time.
func writeFileExcl(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm) //nolint:gosec // G304: a path under the operator-set CA directory (invariant 11)
	if err != nil {
		return fmt.Errorf("ca: create %s: %w", filepath.Base(path), err)
	}
	encErr := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
	closeErr := f.Close()
	if encErr != nil {
		return fmt.Errorf("ca: write %s: %w", filepath.Base(path), encErr)
	}
	if closeErr != nil {
		return fmt.Errorf("ca: close %s: %w", filepath.Base(path), closeErr)
	}
	return nil
}
