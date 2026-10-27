package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// renewMinFraction and renewMaxFraction bound the fraction of
// ServerLeafValidity still remaining when the leaf is re-issued. The lead time
// is drawn uniformly from that range once per issuance — the "jittered
// fraction of expiry" ADR-0031 §5 asks for — so re-issuance never lands on a
// round multiple of the process start time.
//
// The lower bound is what matters for safety: at one third of the lifetime
// remaining (8h at ServerLeafValidity), there is a wide window in which any
// handshake triggers the re-issue, and a leaf that somehow reaches expiry
// anyway is still replaced on the next handshake rather than served expired.
const (
	renewMinFraction = 1.0 / 3.0
	renewMaxFraction = 1.0 / 2.0
)

// Rotation reports one re-issuance attempt to the observer supplied by the
// composition root. It is the seam that makes rotation visible without this
// package logging anything itself (see the package comment).
//
// A non-nil Err means the re-issue failed while the current certificate was
// still valid: the Relay kept serving the certificate it had, and the operator
// has until that leaf's NotAfter to notice. The other fields are zero in that
// case.
type Rotation struct {
	// NotAfter is the expiry of the newly issued leaf.
	NotAfter time.Time
	// RenewAt is when the newly issued leaf will itself be re-issued.
	RenewAt time.Time
	// Fingerprint is the SHA-256 digest over the new leaf's DER, hex-encoded —
	// the same shape as every other certificate fingerprint in the Relay. It
	// identifies a certificate; it is not a secret.
	Fingerprint string
	// Err is non-nil when the attempt failed and the previous certificate was
	// served instead.
	Err error
}

// ServerCertificate is the Relay's own TLS server certificate, re-issued from
// the in-process CA before it expires (ADR-0031 §5).
//
// It exists because a server certificate minted once at process start is a
// fleet-wide outage on a timer: when the leaf expires, every daemon's chain
// verification fails and the fleet — correctly — fail-closes off the Relay.
// Rotation here is not a network protocol and not an operator ritual;
// the Relay is its own CA, so it is a function call against a key already open
// in this address space.
//
// Serve it through GetCertificate, which crypto/tls calls on every handshake.
// That placement is what makes the guarantee unconditional: renewal is driven
// by handshakes rather than by a timer, so a Relay that sat idle past its
// leaf's expiry still re-issues on the next connection instead of presenting a
// dead certificate. Existing TLS sessions are undisturbed — they are not
// re-handshaked, so a rotation never interrupts a live Tunnel.
//
// A *ServerCertificate is safe for concurrent use. Readers take no lock; at
// most one re-issuance runs at a time, and a reader either sees the whole
// previous certificate or the whole new one, never a mixture.
type ServerCertificate struct {
	ca          *CA
	dnsNames    []string
	ipAddresses []net.IP
	validity    time.Duration
	now         func() time.Time
	observe     func(Rotation)

	// mu serialises re-issuance so a burst of simultaneous handshakes mints
	// one certificate, not one each.
	mu sync.Mutex
	// current is replaced wholesale, never mutated in place: an issued value,
	// once stored, is immutable. That is what lets readers run lock-free
	// without ever seeing a torn certificate.
	current atomic.Pointer[issued]
}

// issued is one certificate and the instant it should be replaced, published
// as a unit.
type issued struct {
	cert    tls.Certificate
	renewAt time.Time
}

// ServerCertOption configures a ServerCertificate.
type ServerCertOption func(*ServerCertificate)

// WithClock replaces the clock ServerCertificate reads, for tests that need to
// cross the renewal threshold without waiting for it.
func WithClock(now func() time.Time) ServerCertOption {
	return func(s *ServerCertificate) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRotationObserver registers fn to be called after each re-issuance
// attempt that follows the initial one. The composition root uses it for the
// log line and the metric; this package logs nothing itself.
//
// fn is called off the re-issuance lock but on the goroutine serving a TLS
// handshake, so it must not block.
func WithRotationObserver(fn func(Rotation)) ServerCertOption {
	return func(s *ServerCertificate) { s.observe = fn }
}

// NewServerCertificate issues the Relay's server certificate for the given DNS
// and IP SANs and returns the holder that re-issues it before expiry. The
// first certificate is minted eagerly, so a CA that cannot issue fails startup
// rather than the first handshake.
func (c *CA) NewServerCertificate(dnsNames []string, ipAddresses []net.IP, opts ...ServerCertOption) (*ServerCertificate, error) {
	s := &ServerCertificate{
		ca:          c,
		dnsNames:    slices.Clone(dnsNames),
		ipAddresses: slices.Clone(ipAddresses),
		validity:    ServerLeafValidity,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}

	if _, err := s.GetCertificate(nil); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate returns the certificate to present for this handshake,
// re-issuing first if the current leaf has reached its renewal instant. It has
// the signature of tls.Config.GetCertificate and is meant to be installed
// there; the argument is unused because the Relay presents one certificate to
// every caller on every listener.
func (s *ServerCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cur := s.current.Load(); cur != nil && s.now().Before(cur.renewAt) {
		return &cur.cert, nil
	}
	return s.reissue()
}

// reissue mints a replacement certificate under the lock, unless another
// handshake already did so while this one waited for it.
func (s *ServerCertificate) reissue() (*tls.Certificate, error) {
	s.mu.Lock()

	// Re-check: a concurrent handshake may have rotated while we waited.
	cur := s.current.Load()
	if cur != nil && s.now().Before(cur.renewAt) {
		s.mu.Unlock()
		return &cur.cert, nil
	}

	next, err := s.issue()
	if err != nil {
		s.mu.Unlock()
		// A still-valid certificate beats a failed handshake: issuance here
		// touches nothing but the process's own entropy source, so a failure
		// is both vanishingly unlikely and likely transient. Report it and
		// keep serving; the next handshake tries again.
		if cur != nil && s.now().Before(cur.cert.Leaf.NotAfter) {
			s.report(Rotation{Err: err})
			return &cur.cert, nil
		}
		return nil, err
	}

	s.current.Store(next)
	s.mu.Unlock()

	// The initial issuance is not a rotation; startup reports itself.
	if cur != nil {
		s.report(Rotation{
			NotAfter:    next.cert.Leaf.NotAfter,
			RenewAt:     next.renewAt,
			Fingerprint: fingerprint(next.cert.Leaf.Raw),
		})
	}
	return &next.cert, nil
}

// Fingerprint returns the hex-encoded SHA-256 digest of the leaf this holder
// is currently presenting, or "" before the first one is minted.
//
// It reads the published pointer and NEVER calls GetCertificate. That is the
// whole point of it existing separately: GetCertificate re-issues once the
// current leaf has reached its renewal instant, so routing a display read
// through it would let rendering a web page rotate the Relay's TLS identity.
// A reader wants to know what is being served, not to cause a new one.
//
// Lock-free for the reason the type doc gives: current is replaced wholesale
// and an issued value, once stored, is immutable.
func (s *ServerCertificate) Fingerprint() string {
	cur := s.current.Load()
	if cur == nil {
		return ""
	}
	return fingerprint(cur.cert.Leaf.Raw)
}

// NotAfter returns when the leaf this holder is currently presenting expires,
// or the zero time before the first one is minted.
//
// Like Fingerprint it reads the published pointer and NEVER calls
// GetCertificate or re-issues: a metrics scrape must not be able to rotate the
// Relay's TLS identity.
func (s *ServerCertificate) NotAfter() time.Time {
	cur := s.current.Load()
	if cur == nil {
		return time.Time{}
	}
	return cur.cert.Leaf.NotAfter
}

// issue mints one certificate and computes when it should be replaced. Each
// call generates a fresh key: rotating the certificate without rotating the
// key would leave the key's lifetime unbounded, which is half of what
// ADR-0031 §5 is for.
func (s *ServerCertificate) issue() (*issued, error) {
	cert, err := s.ca.issueServerCertificate(s.dnsNames, s.ipAddresses, s.now(), s.validity)
	if err != nil {
		return nil, err
	}
	renewAt, err := s.renewalTime(cert.Leaf.NotAfter)
	if err != nil {
		return nil, err
	}
	return &issued{cert: cert, renewAt: renewAt}, nil
}

// renewalTime returns when a leaf expiring at notAfter should be re-issued: a
// lead time drawn uniformly from [renewMinFraction, renewMaxFraction] of the
// leaf's validity.
func (s *ServerCertificate) renewalTime(notAfter time.Time) (time.Time, error) {
	minLead := time.Duration(float64(s.validity) * renewMinFraction)
	span := time.Duration(float64(s.validity)*renewMaxFraction) - minLead

	lead := minLead
	if span > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
		if err != nil {
			return time.Time{}, fmt.Errorf("ca: draw renewal jitter: %w", err)
		}
		lead += time.Duration(n.Int64())
	}
	return notAfter.Add(-lead), nil
}

// report hands r to the observer, if one was registered.
func (s *ServerCertificate) report(r Rotation) {
	if s.observe != nil {
		s.observe(r)
	}
}

// fingerprint returns the hex-encoded SHA-256 digest over a certificate's DER
// bytes — the number `openssl x509 -noout -fingerprint -sha256` prints, minus
// the colons, and the same value the enrollment handler and the transport
// package record for Node certificates.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
