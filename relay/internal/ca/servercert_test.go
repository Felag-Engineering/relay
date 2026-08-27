package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a hand-advanced clock. ServerCertificate reads it through
// WithClock, which is how these tests cross a renewal threshold that is
// otherwise hours away.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// newTestClock starts the fake clock at the real present. The CA certificate
// itself is minted against the real clock, so a fake clock anchored anywhere
// else would make chain verification meaningless — the leaf would be outside
// its issuer's own validity. Only the ADVANCES here are synthetic.
func newTestClock() *fakeClock { return &fakeClock{now: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recorder collects the rotations reported to the observer.
type recorder struct {
	mu   sync.Mutex
	seen []Rotation
}

func (r *recorder) observe(rot Rotation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, rot)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

func (r *recorder) last(t *testing.T) Rotation {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		t.Fatal("no rotation observed")
	}
	return r.seen[len(r.seen)-1]
}

// testServerCert opens a CA in a temp dir and returns a ServerCertificate for
// it driven by clk, plus the CA and the rotation recorder.
func testServerCert(t *testing.T, clk *fakeClock) (*CA, *ServerCertificate, *recorder) {
	t.Helper()
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rec := &recorder{}
	s, err := c.NewServerCertificate(
		[]string{"relay.example"},
		[]net.IP{net.IPv4(127, 0, 0, 1)},
		WithClock(clk.Now),
		WithRotationObserver(rec.observe),
	)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	return c, s, rec
}

// mustGet fetches the certificate the way a TLS handshake does.
func mustGet(t *testing.T, s *ServerCertificate) (*x509.Certificate, *ecdsa.PublicKey) {
	t.Helper()
	cert, err := s.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("GetCertificate returned a certificate with no parsed Leaf")
	}
	pub, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key is %T, want *ecdsa.PublicKey", cert.Leaf.PublicKey)
	}
	// The presented chain must match the private key travelling with it, or
	// the handshake fails in a way no expiry test would catch.
	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Error("presented leaf does not match the private key served with it")
	}
	return cert.Leaf, pub
}

// verifyAgainstCA checks that leaf chains to c and is valid for server
// authentication at the given instant — exactly what a daemon does with the CA
// bundle it received at enrollment (ADR-0006).
func verifyAgainstCA(t *testing.T, c *CA, leaf *x509.Certificate, at time.Time) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.Bundle()) {
		t.Fatal("AppendCertsFromPEM: empty pool")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "relay.example",
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against the Relay CA at %s: %v", at.Format(time.RFC3339), err)
	}
}

// TestServerCertificate_RotatesAtRenewalThreshold is the defect itself (#403):
// a leaf that crosses its renewal instant is replaced in-process, with no
// restart, and the replacement is a valid certificate under the same CA.
func TestServerCertificate_RotatesAtRenewalThreshold(t *testing.T) {
	clk := newTestClock()
	c, s, rec := testServerCert(t, clk)

	firstLeaf, firstPub := mustGet(t, s)
	firstSerial := firstLeaf.SerialNumber.String()
	firstNotAfter := firstLeaf.NotAfter
	verifyAgainstCA(t, c, firstLeaf, clk.Now())

	// Past the latest instant the jitter can put the threshold at
	// (renewMaxFraction of the lifetime before expiry), and still well short of
	// expiry: this is renewal, not resurrection.
	clk.Advance(ServerLeafValidity - time.Duration(float64(ServerLeafValidity)*renewMinFraction) + time.Hour)

	secondLeaf, secondPub := mustGet(t, s)
	if secondLeaf.SerialNumber.String() == firstSerial {
		t.Fatal("crossing the renewal threshold returned the same certificate; nothing rotated")
	}
	if !secondLeaf.NotAfter.After(firstNotAfter) {
		t.Errorf("rotated NotAfter = %s, want later than %s", secondLeaf.NotAfter, firstNotAfter)
	}
	if secondPub.Equal(firstPub) {
		t.Error("rotation reused the previous server key; the key's lifetime must be bounded too")
	}
	// Same trust anchor: a daemon holding the CA bundle from enrollment must
	// keep verifying without being told anything.
	if err := secondLeaf.CheckSignatureFrom(c.cert); err != nil {
		t.Errorf("rotated leaf is not signed by the same Relay CA: %v", err)
	}
	verifyAgainstCA(t, c, secondLeaf, clk.Now())

	if got := rec.count(); got != 1 {
		t.Fatalf("observed rotations = %d, want 1", got)
	}
	rot := rec.last(t)
	if rot.Err != nil {
		t.Errorf("rotation reported Err = %v, want nil", rot.Err)
	}
	if !rot.NotAfter.Equal(secondLeaf.NotAfter) {
		t.Errorf("rotation NotAfter = %s, want %s", rot.NotAfter, secondLeaf.NotAfter)
	}
	if rot.Fingerprint != fingerprint(secondLeaf.Raw) {
		t.Errorf("rotation fingerprint = %q, want the new leaf's", rot.Fingerprint)
	}
	if !rot.RenewAt.After(clk.Now()) || !rot.RenewAt.Before(secondLeaf.NotAfter) {
		t.Errorf("rotation RenewAt = %s, want between now and NotAfter (%s)", rot.RenewAt, secondLeaf.NotAfter)
	}
}

// TestServerCertificate_NeverServesAnExpiredLeaf is the acceptance criterion
// from E2a: advance past expiry, and a valid certificate comes back anyway.
// Renewal is driven by handshakes, not by a timer, so a Relay that sat idle
// through its leaf's whole lifetime still re-issues on the next connection.
func TestServerCertificate_NeverServesAnExpiredLeaf(t *testing.T) {
	clk := newTestClock()
	c, s, _ := testServerCert(t, clk)

	firstLeaf, _ := mustGet(t, s)

	// A Relay up for four times the leaf's lifetime — the shape of the bug,
	// which needed only fourteen days of uptime to disconnect a whole fleet.
	clk.Advance(4 * ServerLeafValidity)
	if !clk.Now().After(firstLeaf.NotAfter) {
		t.Fatal("test setup: clock did not advance past the first leaf's expiry")
	}

	leaf, _ := mustGet(t, s)
	if !leaf.NotAfter.After(clk.Now()) {
		t.Fatalf("served leaf expires at %s, which is not after now (%s): an expired certificate was served",
			leaf.NotAfter, clk.Now())
	}
	verifyAgainstCA(t, c, leaf, clk.Now())
}

// TestServerCertificate_StableBeforeThreshold guards the other direction: a
// certificate with plenty of life left is not re-minted on every handshake.
func TestServerCertificate_StableBeforeThreshold(t *testing.T) {
	clk := newTestClock()
	_, s, rec := testServerCert(t, clk)

	firstLeaf, _ := mustGet(t, s)

	// Short of the earliest instant the jitter can put the threshold at.
	clk.Advance(ServerLeafValidity - time.Duration(float64(ServerLeafValidity)*renewMaxFraction) - time.Hour)

	for i := range 3 {
		leaf, _ := mustGet(t, s)
		if leaf.SerialNumber.String() != firstLeaf.SerialNumber.String() {
			t.Fatalf("handshake %d re-issued before the renewal threshold", i)
		}
	}
	if got := rec.count(); got != 0 {
		t.Errorf("observed rotations = %d, want 0 before the threshold", got)
	}
}

// TestServerCertificate_RenewalIsJittered asserts the threshold is drawn, not
// fixed: it lands inside the documented band and differs between holders, so
// the two listeners do not rotate in lockstep.
func TestServerCertificate_RenewalIsJittered(t *testing.T) {
	clk := newTestClock()

	minLead := time.Duration(float64(ServerLeafValidity) * renewMinFraction)
	maxLead := time.Duration(float64(ServerLeafValidity) * renewMaxFraction)

	leads := make(map[time.Duration]struct{})
	for range 16 {
		_, s, _ := testServerCert(t, clk)
		cur := s.current.Load()
		if cur == nil {
			t.Fatal("no certificate issued at construction")
		}
		lead := cur.cert.Leaf.NotAfter.Sub(cur.renewAt)
		if lead < minLead || lead > maxLead {
			t.Fatalf("renewal lead = %s, want within [%s, %s]", lead, minLead, maxLead)
		}
		leads[lead] = struct{}{}
	}
	if len(leads) < 2 {
		t.Errorf("all %d renewal instants identical; the jitter is not being applied", len(leads))
	}
}

// TestServerCertificate_ConcurrentHandshakesRotateOnce covers the property a
// per-handshake callback makes easy to get wrong: a burst of simultaneous
// handshakes at the threshold must mint ONE certificate, and every one of them
// must come away with that same whole certificate — never a torn one, never a
// different one each. Run with -race.
func TestServerCertificate_ConcurrentHandshakesRotateOnce(t *testing.T) {
	clk := newTestClock()
	_, s, rec := testServerCert(t, clk)

	firstLeaf, _ := mustGet(t, s)
	clk.Advance(ServerLeafValidity - time.Duration(float64(ServerLeafValidity)*renewMinFraction) + time.Hour)

	const goroutines = 32
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		serials = make(map[string]struct{})
		fails   atomic.Int64
	)
	start2 := make(chan struct{})
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start2
			cert, err := s.GetCertificate(nil)
			if err != nil {
				fails.Add(1)
				return
			}
			mu.Lock()
			serials[cert.Leaf.SerialNumber.String()] = struct{}{}
			mu.Unlock()
		}()
	}
	close(start2)
	wg.Wait()

	if n := fails.Load(); n != 0 {
		t.Fatalf("%d concurrent handshakes failed to get a certificate", n)
	}
	if len(serials) != 1 {
		t.Fatalf("concurrent handshakes saw %d distinct certificates, want 1", len(serials))
	}
	if _, stale := serials[firstLeaf.SerialNumber.String()]; stale {
		t.Error("concurrent handshakes were served the pre-threshold certificate")
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("observed rotations = %d, want exactly 1 for a concurrent burst", got)
	}
}

// TestServerLeafValidity_IsNotNodeIdentityValidity is the second E2a
// acceptance criterion. The server leaf borrowing LeafValidity — the constant
// documented for Node identity certificates — is how it came to expire with
// nothing renewing it; the two must answer to separate reasoning forever.
func TestServerLeafValidity_IsNotNodeIdentityValidity(t *testing.T) {
	if ServerLeafValidity == LeafValidity {
		t.Fatalf("ServerLeafValidity == LeafValidity (%s): the Relay's server leaf must not share the Node identity constant (#403)", LeafValidity)
	}

	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	serverCert, err := c.IssueServerCertificate([]string{"relay.example"}, nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	serverLife := serverCert.Leaf.NotAfter.Sub(serverCert.Leaf.NotBefore)
	if want := ServerLeafValidity + clockSkew; serverLife != want {
		t.Errorf("server leaf lifetime = %s, want %s (ServerLeafValidity + clock skew)", serverLife, want)
	}

	csrPEM, _ := newTestCSR(t, "ignored", elliptic.P256())
	identityPEM, err := c.SignCSR(csrPEM, "node-alpha")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	block, _ := pem.Decode(identityPEM)
	if block == nil {
		t.Fatal("decode identity certificate PEM")
	}
	identity, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	identityLife := identity.NotAfter.Sub(identity.NotBefore)
	if want := LeafValidity + clockSkew; identityLife != want {
		t.Errorf("Node identity leaf lifetime = %s, want %s (LeafValidity + clock skew)", identityLife, want)
	}

	if serverLife == identityLife {
		t.Error("server leaf and Node identity leaf still have the same lifetime")
	}
}

// TestServerCertificate_FingerprintNeverRotates is the reason this method
// exists separately from GetCertificate.
//
// GetCertificate re-issues once the current leaf reaches its renewal instant.
// Fingerprint is read by a page render, so if it went through GetCertificate,
// displaying a screen could rotate the Relay's TLS identity. It reads the
// published pointer instead: past the threshold it still reports what is being
// served, and only a real handshake changes that.
func TestServerCertificate_FingerprintNeverRotates(t *testing.T) {
	clk := newTestClock()
	_, s, rec := testServerCert(t, clk)

	leaf, _ := mustGet(t, s)
	if got := s.Fingerprint(); got != fingerprint(leaf.Raw) {
		t.Errorf("Fingerprint() = %q, want the served leaf's digest %q", got, fingerprint(leaf.Raw))
	}

	// Past the renewal threshold, but with no handshake.
	clk.Advance(ServerLeafValidity - time.Duration(float64(ServerLeafValidity)*renewMinFraction) + time.Hour)

	if got := s.Fingerprint(); got != fingerprint(leaf.Raw) {
		t.Error("Fingerprint() rotated the certificate — a page render must never be able to " +
			"re-issue the Relay's server certificate")
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("observed rotations = %d, want 0 — reading a fingerprint issued a certificate", got)
	}

	// A handshake does rotate it, and the reported value follows.
	rotated, _ := mustGet(t, s)
	if got := s.Fingerprint(); got != fingerprint(rotated.Raw) {
		t.Errorf("Fingerprint() = %q after rotation, want the new leaf's %q", got, fingerprint(rotated.Raw))
	}
}

// TestServerCertificate_FingerprintBeforeFirstIssue: the zero value reports
// nothing rather than a digest of nothing. NewServerCertificate mints eagerly,
// so this is only reachable through the zero value, and "" is what the Console
// renders as "not wired" rather than as a fingerprint.
func TestServerCertificate_FingerprintBeforeFirstIssue(t *testing.T) {
	var s ServerCertificate
	if got := s.Fingerprint(); got != "" {
		t.Errorf("Fingerprint() with no certificate = %q, want empty", got)
	}
}
