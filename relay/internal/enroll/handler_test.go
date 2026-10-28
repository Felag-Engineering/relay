package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/ca/catest"
	"github.com/Felag-Engineering/relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// mintToken creates an Enrollment Token in svc, minted by a human Account, naming
// the given initial tags, with a 1-hour TTL. It returns the stored *Token (for
// tok.ID, used in Revoke tests) and the plaintext credential.
func mintToken(t *testing.T, svc *Service, tags []string) (*Token, string) {
	t.Helper()
	tok, plaintext, err := svc.Create(context.Background(), tags, time.Hour, asHuman)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	return tok, plaintext
}

// genCSR generates a fresh ECDSA P-256 CSR with the given CommonName.
// The CN is deliberately set to a value that must NOT appear in the issued cert,
// proving that SignCSR ignores the CSR subject (ADR-0006).
func genCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genCSR: generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("genCSR: create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// writtenTags is one WriteInitialTags call a fakeTagWriter saw.
type writtenTags struct {
	minter  MintedBy
	tokenID string
	nodeID  string
	tags    []string
}

// fakeTagWriter is an InitialTagWriter that records its calls, or fails.
type fakeTagWriter struct {
	calls []writtenTags
	err   error

	// checks counts CheckInitialTags calls; checkErr is what each returns.
	checks   int
	checkErr error
}

func (f *fakeTagWriter) CheckInitialTags(_ context.Context, _ MintedBy, _ []string) error {
	f.checks++
	return f.checkErr
}

func (f *fakeTagWriter) WriteInitialTags(_ context.Context, minter MintedBy, tokenID, nodeID string, tags []string) error {
	f.calls = append(f.calls, writtenTags{minter: minter, tokenID: tokenID, nodeID: nodeID, tags: slices.Clone(tags)})
	return f.err
}

// newEnrollServer is a test helper that wires up a Server with the provided Service.
func newEnrollServer(t *testing.T, svc *Service) (*Server, *registry.InMemory, *ca.CA) {
	t.Helper()
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	return NewServer(svc, realCA, reg), reg, realCA
}

// parseCert decodes a PEM certificate and returns the parsed *x509.Certificate.
func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("parseCert: invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parseCert: %v", err)
	}
	return cert
}

// TestEnroll_Success verifies the happy path: a valid token + valid CSR + node: self_labels
// produce a signed cert (CN == NodeId, not the CSR CN), the correct CA bundle, relay:node-id
// as the only relay: label stamped or assigned, the token's initial tags written as the
// minting Account's act, and a fully-populated registry entry.
//
// RED ON: stamping any other relay: label, or a token's tags written as
// anyone but the Account that minted it, or not written at all.
//
// Proves EN-41, EN-13.
func TestEnroll_Success(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	tags := &fakeTagWriter{}
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	srv := NewServer(svc, realCA, reg, WithInitialTagWriter(tags))

	tok, plaintext := mintToken(t, svc, []string{"tag:role=web", "tag:env=prod", "tag:marker="})

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-daemon-cn-must-be-ignored"),
		SelfLabels: []*relayv1.Label{
			{Key: "node:role", Value: "web"},
		},
		Facts: &relayv1.Facts{
			Hostname: "host-1",
			Os:       "linux",
		},
	}

	resp, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// NodeId must be non-empty and have the "node-" prefix.
	if resp.NodeId == "" {
		t.Error("NodeId must not be empty")
	}
	if !strings.HasPrefix(resp.NodeId, "node-") {
		t.Errorf("NodeId must have node- prefix, got %q", resp.NodeId)
	}

	// Certificate: parse and assert CN == NodeId (not the bogus CSR CN).
	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName != resp.NodeId {
		t.Errorf("cert CN: got %q, want NodeId %q (Relay must assign identity)", cert.Subject.CommonName, resp.NodeId)
	}

	// CaBundle must match the real CA.
	if string(resp.CaBundle) != string(realCA.Bundle()) {
		t.Error("CaBundle does not match CA bundle")
	}

	// AssignedLabels is exactly relay:node-id with the Node's ID: no tag is a relay: label.
	if len(resp.AssignedLabels) != 1 ||
		resp.AssignedLabels[0].Key != "relay:node-id" || resp.AssignedLabels[0].Value != resp.NodeId {
		t.Errorf("AssignedLabels = %v, want exactly relay:node-id=%s", resp.AssignedLabels, resp.NodeId)
	}

	// Registry entry: node: labels from self_labels (bare keys), relay:node-id alone.
	node, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatal("Node not found in registry")
	}
	if node.NodeLabels["role"] != "web" {
		t.Errorf("NodeLabels[role]: got %q, want web", node.NodeLabels["role"])
	}
	if len(node.RelayLabels) != 1 || node.RelayLabels[registry.NodeIDKey] != resp.NodeId {
		t.Errorf("RelayLabels = %v, want exactly node-id=%s", node.RelayLabels, resp.NodeId)
	}
	if node.EnrollingTokenID != tok.ID {
		t.Errorf("EnrollingTokenID: got %q, want %q", node.EnrollingTokenID, tok.ID)
	}
	// Facts mapping: prove the proto→domain mapping actually ran.
	if node.Facts.Hostname != "host-1" {
		t.Errorf("Facts.Hostname: got %q, want host-1", node.Facts.Hostname)
	}

	// The initial tags are written once, on this Node, as the minting Account.
	if len(tags.calls) != 1 {
		t.Fatalf("WriteInitialTags called %d times, want 1", len(tags.calls))
	}
	call := tags.calls[0]
	wantMinter := MintedBy{AccountID: "acct-alice", Account: "alice", Role: "admin", Human: true}
	if call.minter != wantMinter {
		t.Errorf("tags written as %+v, want the minting Account %+v", call.minter, wantMinter)
	}
	if call.nodeID != resp.NodeId {
		t.Errorf("tags written on %q, want %q", call.nodeID, resp.NodeId)
	}
	if call.tokenID != tok.ID {
		t.Errorf("tags written naming token %q, want %q", call.tokenID, tok.ID)
	}
	if tags.checks != 1 {
		t.Errorf("CheckInitialTags called %d times, want 1 (before the write)", tags.checks)
	}
	if !slices.Equal(call.tags, []string{"tag:role=web", "tag:env=prod", "tag:marker="}) {
		t.Errorf("tags written = %v", call.tags)
	}
}

// TestEnroll_NoInitialTagsWritesNone checks that a token naming no initial tag
// enrolls without a tag write, so a server with no writer wired still enrolls it.
//
// Proves EN-41.
func TestEnroll_NoInitialTagsWritesNone(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, nil)

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	node, _ := reg.Get(resp.NodeId)
	if len(node.RelayLabels) != 1 || node.RelayLabels[registry.NodeIDKey] != resp.NodeId {
		t.Errorf("RelayLabels = %v, want exactly node-id", node.RelayLabels)
	}
}

// TestEnroll_InitialTagWriteFailureFailsEnrollment checks that a tag write that
// fails fails the enrollment closed, with the same opaque error as any internal
// failure and no distinct detail on the wire.
//
// Proves EN-41.
func TestEnroll_InitialTagWriteFailureFailsEnrollment(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	failing := &fakeTagWriter{err: errors.New("store is on fire")}
	srv := NewServer(svc, realCA, registry.NewInMemory(), WithInitialTagWriter(failing))
	_, plaintext := mintToken(t, svc, []string{"tag:env=prod"})

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})
	if resp != nil || status.Code(err) != codes.Internal {
		t.Fatalf("Enroll = (%v, %v), want Internal", resp, err)
	}
	if strings.Contains(err.Error(), "fire") {
		t.Errorf("the writer's error reached the wire: %v", err)
	}
}

// TestEnroll_InitialTagWriteFailureDenylistsTheNode checks that when the tag
// write fails after the Node is recorded, the just-minted node_id is
// self-denylisted so the identity enrollment signed cannot dial a Tunnel, and
// the answer is the opaque Internal error.
//
// Proves EN-13.
func TestEnroll_InitialTagWriteFailureDenylistsTheNode(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	den := &fakeDenylister{}
	failing := &fakeTagWriter{err: errors.New("store is on fire")}
	srv := NewServer(svc, realCA, registry.NewInMemory(),
		WithPostEnrollRevocationCheck(svc, den), WithInitialTagWriter(failing))
	srv.newID = func() (string, error) { return "node-tagfail-1", nil }
	_, plaintext := mintToken(t, svc, []string{"tag:env=prod"})

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})
	if resp != nil || status.Code(err) != codes.Internal {
		t.Fatalf("Enroll = (%v, %v), want Internal", resp, err)
	}
	if len(den.revoked) != 1 || den.revoked[0] != "node-tagfail-1" {
		t.Errorf("denylisted = %v, want [node-tagfail-1]", den.revoked)
	}
}

// TestEnroll_InitialTagsWithoutWriterFailsClosed checks that a token naming
// initial tags never enrolls a Node on a server with no tag writer, rather than
// dropping the tags silently.
//
// Proves EN-41.
func TestEnroll_InitialTagsWithoutWriterFailsClosed(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, []string{"tag:env=prod"})

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Enroll: want Internal, got %v", err)
	}
}

// TestEnroll_RefusedMinterLeavesNoNodeAndBurnsNoUse checks that a token whose
// minter the capability layer refuses to let write tags is turned away before
// the use is counted, the CSR signed or the Node recorded: the wire answer is
// the one every token rejection returns, the registry stays empty, no tag is
// written, and the token still has every use.
//
// Proves EN-44.
func TestEnroll_RefusedMinterLeavesNoNodeAndBurnsNoUse(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	refusing := &fakeTagWriter{checkErr: errors.New("only a human Account writes tags")}
	srv := NewServer(svc, realCA, reg, WithInitialTagWriter(refusing))
	tok, plaintext := mintToken(t, svc, []string{"tag:env=prod"})

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})
	if resp != nil || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Enroll = (%v, %v), want PermissionDenied", resp, err)
	}
	if strings.Contains(err.Error(), "human") {
		t.Errorf("the refusal's reason reached the wire: %v", err)
	}
	if n := len(reg.List()); n != 0 {
		t.Errorf("registry has %d Nodes after a refused minter, want 0", n)
	}
	if len(refusing.calls) != 0 {
		t.Errorf("tags were written for a refused minter: %+v", refusing.calls)
	}
	stored, err := svc.repo.ByID(context.Background(), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Uses != 0 {
		t.Errorf("token Uses = %d after a refusal, want 0", stored.Uses)
	}
}

// TestEnroll_IdentityNotFromCSR proves that the issued cert CN is the Relay-assigned
// node_id and not the CN the daemon placed in the CSR (ADR-0006).
// Proves EN-41.
func TestEnroll_IdentityNotFromCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, nil)

	const csrCN = "daemon-wants-this-identity"
	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, csrCN),
	}

	resp, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName == csrCN {
		t.Errorf("cert CN must not match CSR CN %q; Relay must assign node identity", csrCN)
	}
}

// TestEnroll_InvalidToken verifies that a garbage credential returns PermissionDenied
// and leaves no registry entry.
// Proves EN-13.
func TestEnroll_InvalidToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	req := &relayv1.EnrollRequest{
		EnrollmentToken: "deadbeef.notavalidtoken",
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("invalid token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_ExpiredToken verifies that an expired token returns PermissionDenied
// and leaves no registry entry.
// Proves EN-26.
func TestEnroll_ExpiredToken(t *testing.T) {
	svc, clk := newTestService(t) // fakeNow defined in token_test.go
	srv, reg, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, nil)
	clk.advance(2 * time.Hour) // past the 1-hour TTL

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expired token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_RevokedToken verifies that a revoked token returns PermissionDenied
// and leaves no registry entry.
// Proves EN-26.
func TestEnroll_RevokedToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	tok, plaintext := mintToken(t, svc, nil)
	if err := svc.Revoke(context.Background(), tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("revoked token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_ExhaustedToken verifies that a single-use token can enroll exactly once.
// The second Enroll returns PermissionDenied and must not add a new registry entry.
// Proves EN-26.
func TestEnroll_ExhaustedToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	_, pt, err := svc.Create(context.Background(), nil, time.Hour, WithMaxUses(1))
	if err != nil {
		t.Fatalf("Create single-use: %v", err)
	}

	// First enrollment must succeed.
	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: pt,
		Csr:             genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if len(reg.List()) != 1 {
		t.Errorf("after first Enroll: want 1 registry entry, got %d", len(reg.List()))
	}

	// Second enrollment must be rejected — MaxUses exhausted.
	_, err = srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: pt,
		Csr:             genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("exhausted token: want PermissionDenied, got %v", err)
	}
	// Must still be exactly 1 entry — the second rejection must not add one.
	if len(reg.List()) != 1 {
		t.Errorf("after second (rejected) Enroll: want 1 registry entry, got %d", len(reg.List()))
	}
}

// TestEnroll_BadCSR verifies that a malformed CSR returns InvalidArgument
// and leaves no registry entry.
// Proves EN-25.
func TestEnroll_BadCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, nil)

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             []byte("this is not a valid CSR"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad CSR: want InvalidArgument, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after bad CSR, got %d entries", len(reg.List()))
	}
}

// TestEnroll_SelfReportedFactsAreBounded proves the Hello ingress bound on
// self-reported Facts also holds at Enroll (#1068): a hostname carrying U+202E
// does not fail the request and is not recorded.
func TestEnroll_SelfReportedFactsAreBounded(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, nil)

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		Facts:           &relayv1.Facts{Hostname: "web\u202e01", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	node, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatal("Node not found in registry")
	}
	if node.Facts.Hostname != "" {
		t.Errorf("Facts.Hostname = %q, want not recorded", node.Facts.Hostname)
	}
	if node.Facts.OS != "linux" {
		t.Errorf("Facts.OS = %q, want linux kept", node.Facts.OS)
	}
}

// TestEnroll_RefusedFactsAreLoggedByNameNeverByValue pins that Enroll, like the
// Hello ingress, emits one warning naming the Facts fields it refused and never
// the value (#1068).
func TestEnroll_RefusedFactsAreLoggedByNameNeverByValue(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	logs := &strings.Builder{}
	srv := NewServer(svc, realCA, registry.NewInMemory(),
		WithServerLogger(slog.New(slog.NewJSONHandler(logs, nil))))
	_, plaintext := mintToken(t, svc, nil)

	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		Facts:           &relayv1.Facts{Hostname: "web\u202e01", Os: "linux"},
	}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	var refusals int
	for _, line := range strings.Split(strings.TrimRight(logs.String(), "\n"), "\n") {
		if strings.Contains(line, "web") || strings.Contains(line, "\u202e") || strings.Contains(line, `\u202e`) {
			t.Errorf("a log line carries a refused wire value: %.200s", line)
		}
		var entry struct {
			Msg           string   `json:"msg"`
			RefusedFields []string `json:"refused_fields"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || !strings.HasPrefix(entry.Msg, "refused malformed Facts") {
			continue
		}
		refusals++
		if !slices.Equal(entry.RefusedFields, []string{protoconv.FieldHostname}) {
			t.Errorf("refused_fields = %v, want [%s]", entry.RefusedFields, protoconv.FieldHostname)
		}
	}
	if refusals != 1 {
		t.Errorf("got %d refusal records, want exactly 1; logs:\n%.1000s", refusals, logs.String())
	}
}

// TestEnroll_RefusedSelfLabelKeyIsBoundedInTheError pins that the key echoed in
// the InvalidArgument message is bounded, so a hostile megabyte key cannot
// inflate the response (#1068).
func TestEnroll_RefusedSelfLabelKeyIsBoundedInTheError(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, nil)

	huge := "node:" + strings.Repeat("k", 1<<20) + "="
	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      []*relayv1.Label{{Key: huge, Value: "web"}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	msg := status.Convert(err).Message()
	if len(msg) > 1024 {
		t.Errorf("refusal message is %d bytes, want it bounded", len(msg))
	}
	if !strings.Contains(msg, "node:kkkk") {
		t.Errorf("refusal message %.200q does not name the (truncated) offending key", msg)
	}
}

// TestEnroll_NonNodeSelfLabel verifies that self_labels without the "node:" prefix
// (or with an empty bare key), or with a key/value that fails the well-formedness
// gate (registry.WellFormedLabel, #504), are rejected with InvalidArgument,
// and the registry and relay space remain untouched (D2: enrollment REJECTS
// where Hello DROPS — the fail-closed property this test pins).
// Proves EN-11, EN-25.
func TestEnroll_NonNodeSelfLabel(t *testing.T) {
	cases := []struct {
		name  string
		label *relayv1.Label
	}{
		{"relay-prefix", &relayv1.Label{Key: "relay:env", Value: "prod"}},
		{"bare-key", &relayv1.Label{Key: "role", Value: "web"}},
		{"empty-bare-key", &relayv1.Label{Key: "node:", Value: ""}},
		{
			// The measured payload (#504's evidence): a value that would
			// render as a second, relay:-spelled Selector term.
			name:  "malformed-value",
			label: &relayv1.Label{Key: "node:role", Value: "web, relay:quarantine=on"},
		},
		{
			// The key-side split hazard: "=" in the KEY re-splits a
			// rendered "key=value" pair with the wrong boundary.
			name:  "malformed-key",
			label: &relayv1.Label{Key: "node:role=x", Value: "web"},
		},
		{
			// The selectors-and-labels Limits: a bare key is at most
			// registry.MaxLabelKeyLen bytes (#1068).
			name:  "over-long-key",
			label: &relayv1.Label{Key: "node:" + strings.Repeat("k", registry.MaxLabelKeyLen+1), Value: "web"},
		},
		{
			name:  "over-long-value",
			label: &relayv1.Label{Key: "node:role", Value: strings.Repeat("v", registry.MaxLabelValueLen+1)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(NewMemoryRepository())
			srv, reg, _ := newEnrollServer(t, svc)

			_, plaintext := mintToken(t, svc, nil)

			req := &relayv1.EnrollRequest{
				EnrollmentToken: plaintext,
				Csr:             genCSR(t, "cn"),
				SelfLabels:      []*relayv1.Label{tc.label},
			}

			_, err := srv.Enroll(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("non-node: label %q: want InvalidArgument, got %v", tc.label.Key, err)
			}
			// The refusal states the length limits beside the alphabet, so an
			// operator with an over-long label can see what to change.
			for _, want := range []string{
				strconv.Itoa(registry.MaxLabelKeyLen), strconv.Itoa(registry.MaxLabelValueLen),
			} {
				if msg := status.Convert(err).Message(); !strings.Contains(msg, want) {
					t.Errorf("refusal message %.200q does not state the limit %s", msg, want)
				}
			}
			if len(reg.List()) != 0 {
				t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
			}
		})
	}
}

// TestEnroll_SelfLabelAtTheLengthBoundsIsAccepted is the accepting side of
// EN-11's length limits: a key of exactly 63 characters with a value of
// exactly 255 enrolls, and is recorded as declared. TestEnroll_NonNodeSelfLabel
// is the refusing side, one character over either bound.
// Proves EN-11.
func TestEnroll_SelfLabelAtTheLengthBoundsIsAccepted(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, nil)

	key := strings.Repeat("k", registry.MaxLabelKeyLen)
	value := strings.Repeat("v", registry.MaxLabelValueLen)
	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      []*relayv1.Label{{Key: "node:" + key, Value: value}},
	})
	if err != nil {
		t.Fatalf("Enroll with a Label at the bounds: %v", err)
	}
	n, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatalf("Get %s: not found", resp.NodeId)
	}
	if n.NodeLabels[key] != value {
		t.Errorf("NodeLabels = %d entries, want the declared Label at the bounds recorded", len(n.NodeLabels))
	}
}

// nodeSelfLabels returns n distinct well-formed self_labels.
func nodeSelfLabels(n int) []*relayv1.Label {
	labels := make([]*relayv1.Label, n)
	for i := range labels {
		labels[i] = &relayv1.Label{Key: "node:label-" + strconv.Itoa(i), Value: "v" + strconv.Itoa(i)}
	}
	return labels
}

// TestEnroll_OverTheNodeLabelCapIsRefused pins the per-Node node: label count:
// more than registry.MaxNodeLabels refuses the whole request with
// InvalidArgument, leaves no registry row and consumes no token use, and is
// recorded as one malformed attempt. The message carries counts, never a key
// or value.
func TestEnroll_OverTheNodeLabelCapIsRefused(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, reg := newObservedEnrollServer(t, svc, obs)
	_, plaintext := mintToken(t, svc, nil)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      nodeSelfLabels(registry.MaxNodeLabels + 1),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, strconv.Itoa(registry.MaxNodeLabels)) || strings.Contains(msg, "label-") {
		t.Errorf("refusal message %.200q must state the limit and name no label", msg)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
	if events := obs.snapshot(); len(events) != 1 || events[0].Reason != AttemptMalformed {
		t.Fatalf("events = %+v, want exactly one AttemptMalformed", events)
	}

	// The refusal came before the token was spent: the same credential still
	// enrolls once the Node declares a set within the cap.
	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      nodeSelfLabels(1),
	}); err != nil {
		t.Errorf("Enroll with the same token after the refusal: %v", err)
	}
}

func TestEnroll_AtTheNodeLabelCapIsAccepted(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)
	_, plaintext := mintToken(t, svc, nil)

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      nodeSelfLabels(registry.MaxNodeLabels),
	})
	if err != nil {
		t.Fatalf("Enroll with %d labels: %v", registry.MaxNodeLabels, err)
	}
	n, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatalf("Get %s: not found", resp.NodeId)
	}
	if len(n.NodeLabels) != registry.MaxNodeLabels {
		t.Errorf("NodeLabels has %d entries, want all %d", len(n.NodeLabels), registry.MaxNodeLabels)
	}
}

// TestEnroll_OverTheIPAddressCapRecordsNoAddresses pins that an address list
// over registry.MaxReportedIPAddresses is refused as a field, as every other
// Facts bound is: the request proceeds, no address is recorded, and the log
// names the field and carries no address.
func TestEnroll_OverTheIPAddressCapRecordsNoAddresses(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	logs := &strings.Builder{}
	reg := registry.NewInMemory()
	srv := NewServer(svc, realCA, reg, WithServerLogger(slog.New(slog.NewJSONHandler(logs, nil))))
	_, plaintext := mintToken(t, svc, nil)

	addrs := make([]string, registry.MaxReportedIPAddresses+1)
	for i := range addrs {
		addrs[i] = "10.9." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256)
	}
	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		Facts:           &relayv1.Facts{Hostname: "web-01", IpAddresses: addrs},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	n, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatalf("Get %s: not found", resp.NodeId)
	}
	if n.Facts.IPAddresses != nil {
		t.Errorf("IPAddresses has %d entries, want none", len(n.Facts.IPAddresses))
	}
	if n.Facts.Hostname != "web-01" {
		t.Errorf("Hostname = %q, want the other Facts kept", n.Facts.Hostname)
	}
	if strings.Contains(logs.String(), "10.9.") {
		t.Errorf("a log line carries a reported address; logs:\n%.1000s", logs.String())
	}
	if !strings.Contains(logs.String(), protoconv.FieldIPAddresses) {
		t.Errorf("no log line names %s; logs:\n%.1000s", protoconv.FieldIPAddresses, logs.String())
	}
}

// fakeDenylister implements NodeDenylister and records every RevokeNode call for
// assertion in tests. It does not interact with any real denylist.
type fakeDenylister struct{ revoked []string }

func (f *fakeDenylister) RevokeNode(nodeID string) { f.revoked = append(f.revoked, nodeID) }

// buildRaceServer is a test helper that wires a Server with a real CA, registry,
// and the given token Service plus a fakeDenylister and WithPostEnrollRevocationCheck.
// It returns the server, the registry, and the denylister for assertions.
func buildRaceServer(t *testing.T, svc *Service) (*Server, *registry.InMemory, *fakeDenylister) {
	t.Helper()
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	den := &fakeDenylister{}
	srv := NewServer(svc, realCA, reg, WithPostEnrollRevocationCheck(svc, den))
	return srv, reg, den
}

// TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow is the primary DoD test for
// issue #57. It simulates the escape window: Validate succeeds (token valid), then
// the token is revoked before Upsert (mimicking a concurrent RevokeToken cascade
// completing its bounded re-scan), and the post-check must catch and close the gap.
//
// Assertions:
//   - Enroll returns codes.PermissionDenied (fail-closed).
//   - The fakeDenylister recorded a RevokeNode call for the minted node id
//     (self-denylist ran). Note: this is verified via the fake recorder, not the
//     real Denylist.
//   - The Node IS present in the registry (Upsert ran before the post-check),
//     confirming the bounded cascade scan would have missed it.
//
// Proves EN-15.
func TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, den := buildRaceServer(t, svc)

	tok, plaintext := mintToken(t, svc, nil)

	// Inject newID to simulate the race: revoke the token mid-enrollment (after
	// Validate succeeds, before Upsert) and return a deterministic node id.
	srv.newID = func() (string, error) {
		if err := svc.Revoke(context.Background(), tok.ID); err != nil {
			t.Errorf("race hook Revoke: %v", err)
		}
		return "node-race-1", nil
	}

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("race window: want PermissionDenied, got %v", err)
	}

	// The minted node must have been self-denylisted.
	if len(den.revoked) != 1 || den.revoked[0] != "node-race-1" {
		t.Errorf("denylist: want [node-race-1], got %v", den.revoked)
	}

	// The Node must be in the registry — Upsert ran; the cascade would have missed it.
	if _, ok := reg.Get("node-race-1"); !ok {
		t.Error("registry: node-race-1 must be present (Upsert ran before post-check)")
	}
}

// TestEnroll_PostUpsertRevocationCheck_AllowsCleanEnroll verifies no false positive:
// when the token is still valid at post-check time, Enroll succeeds and the
// denylister records no calls.
func TestEnroll_PostUpsertRevocationCheck_AllowsCleanEnroll(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, den := buildRaceServer(t, svc)

	_, plaintext := mintToken(t, svc, nil)

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Errorf("clean enroll: want nil error, got %v", err)
	}
	if len(den.revoked) != 0 {
		t.Errorf("clean enroll: denylist must be empty, got %v", den.revoked)
	}
}

// TestEnroll_NoPostCheck_BackwardCompatible verifies that NewServer without any
// option (revocationChecker == nil) still handles a happy-path enrollment
// correctly — the post-check is skipped entirely.
func TestEnroll_NoPostCheck_BackwardCompatible(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc) // plain NewServer, no option

	_, plaintext := mintToken(t, svc, nil)

	req := &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Errorf("backward compat: want nil error, got %v", err)
	}
}

// ctxFromIP wraps context.Background with a gRPC peer carrying the given IP
// on port 40000. All rate-limit tests must use this helper so they don't share
// the "unknown" bucket that peerIP returns when no peer is set.
func ctxFromIP(ip string) context.Context {
	ctx := context.Background()
	return peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000},
	})
}

// newLimitedServer wires a Server with a ratelimit.Limiter built from cfg plus a
// real CA and an optionally capped registry. Returns the server and the registry.
func newLimitedServer(t *testing.T, svc *Service, cfg ratelimit.Config, regOpts ...registry.Option) (*Server, *registry.InMemory) {
	t.Helper()
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory(regOpts...)
	srv := NewServer(svc, realCA, reg, WithRateLimiter(ratelimit.New(cfg)))
	return srv, reg
}

// TestEnroll_RateLimited_PerIP verifies that the per-IP gate fires independently:
// two enrolls from one IP succeed (burst=2), the third is denied, while a fresh
// IP is still allowed.
// Proves EN-10.
func TestEnroll_RateLimited_PerIP(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg := newLimitedServer(t, svc, ratelimit.Config{
		PerIPRatePerMin:  60,
		PerIPBurst:       2,
		GlobalRatePerMin: 6000,
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	})

	_, plaintext1 := mintToken(t, svc, nil)
	_, plaintext2 := mintToken(t, svc, nil)
	_, plaintext3 := mintToken(t, svc, nil)
	_, plaintext4 := mintToken(t, svc, nil)

	ctx1 := ctxFromIP("10.0.0.1")
	ctx2 := ctxFromIP("10.0.0.2")

	// First two calls from IP-1 succeed (burst=2).
	if _, err := srv.Enroll(ctx1, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext1, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Errorf("IP-1 call 1: want nil, got %v", err)
	}
	if _, err := srv.Enroll(ctx1, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext2, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Errorf("IP-1 call 2: want nil, got %v", err)
	}

	// Third call from IP-1 is denied.
	_, err := srv.Enroll(ctx1, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext3, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("IP-1 call 3: want ResourceExhausted, got %v", err)
	}

	// Fresh IP-2 is still allowed.
	if _, err := srv.Enroll(ctx2, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext4, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Errorf("IP-2 call 1: want nil, got %v", err)
	}

	// Registry should have 3 entries (2 from IP-1, 1 from IP-2; throttled call left no entry).
	if got := len(reg.List()); got != 3 {
		t.Errorf("registry len: got %d, want 3", got)
	}
}

// TestEnroll_RateLimited_NoTokenOracle verifies the no-oracle property: when the
// per-IP bucket is empty (PerIPBurst=0), BOTH a call with a valid Enrollment Token
// and a call with a garbage token return codes.ResourceExhausted with identical
// error codes. Neither should add a registry entry.
// Proves EN-10.
func TestEnroll_RateLimited_NoTokenOracle(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	// PerIPBurst=0: the very first call from any IP is denied — no drain phase needed.
	srv, reg := newLimitedServer(t, svc, ratelimit.Config{
		PerIPRatePerMin:  0,
		PerIPBurst:       0,
		GlobalRatePerMin: 6000,
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	})

	_, validPlaintext := mintToken(t, svc, nil)
	ctx := ctxFromIP("10.0.0.42")

	// Valid token — denied at the rate-limit gate before any token validation.
	_, err := srv.Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: validPlaintext,
		Csr:             genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("valid token: want ResourceExhausted, got %v", err)
	}

	// Garbage token — must produce identical ResourceExhausted (no validity oracle).
	_, err = srv.Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: "garbage.notvalid",
		Csr:             genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("garbage token: want ResourceExhausted, got %v", err)
	}

	// Neither call must have produced a registry entry.
	if got := len(reg.List()); got != 0 {
		t.Errorf("registry must be empty after rate-limited calls, got %d entries", got)
	}
}

// TestEnroll_RateLimited_Global verifies that the global gate fires independently
// of the per-IP gate: GlobalBurst=1 means the second enroll from a fresh IP is
// denied even though that IP's per-IP bucket is full.
// Proves EN-10.
func TestEnroll_RateLimited_Global(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _ := newLimitedServer(t, svc, ratelimit.Config{
		PerIPRatePerMin:  6000,
		PerIPBurst:       1000,
		GlobalRatePerMin: 60,
		GlobalBurst:      1, // only 1 global token
		MaxTrackedIPs:    100,
	})

	_, pt1 := mintToken(t, svc, nil)
	_, pt2 := mintToken(t, svc, nil)

	// First enroll (IP-a) consumes the sole global token.
	if _, err := srv.Enroll(ctxFromIP("10.0.0.1"), &relayv1.EnrollRequest{
		EnrollmentToken: pt1, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Errorf("IP-a: want nil, got %v", err)
	}

	// Second enroll (fresh IP-b) denied — global budget exhausted.
	_, err := srv.Enroll(ctxFromIP("10.0.0.2"), &relayv1.EnrollRequest{
		EnrollmentToken: pt2, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("IP-b: want ResourceExhausted, got %v", err)
	}
}

// TestEnroll_RegistryAtCapacity verifies that when the registry is full the
// handler returns codes.ResourceExhausted and the registry size stays unchanged.
// Proves EN-25.
func TestEnroll_RegistryAtCapacity(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	// Generous limiter so the rate-limit gate never fires.
	srv, reg := newLimitedServer(t, svc, ratelimit.Config{
		PerIPRatePerMin:  6000,
		PerIPBurst:       1000,
		GlobalRatePerMin: 6000,
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	}, registry.WithMaxNodes(1))

	_, pt1 := mintToken(t, svc, nil)
	_, pt2 := mintToken(t, svc, nil)
	ctx := ctxFromIP("10.0.0.1")

	// First enroll fills the cap.
	if _, err := srv.Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: pt1, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if got := len(reg.List()); got != 1 {
		t.Fatalf("after first enroll: want 1, got %d", got)
	}

	// Second enroll must be rejected with ResourceExhausted.
	_, err := srv.Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: pt2, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("at capacity: want ResourceExhausted, got %v", err)
	}
	if got := len(reg.List()); got != 1 {
		t.Errorf("after rejected enroll: want 1, got %d", got)
	}
}

// TestEnroll_EmptyTokenOrCSR verifies that missing token or CSR returns InvalidArgument.
// Proves EN-11, EN-25.
func TestEnroll_EmptyTokenOrCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	csrPEM := genCSR(t, "cn")

	cases := []struct {
		name string
		req  *relayv1.EnrollRequest
	}{
		{"empty-token", &relayv1.EnrollRequest{Csr: csrPEM}},
		{"empty-csr", &relayv1.EnrollRequest{EnrollmentToken: "some.token"}},
		{"both-empty", &relayv1.EnrollRequest{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.Enroll(context.Background(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("%s: want InvalidArgument, got %v", tc.name, err)
			}
		})
	}
}

// TestEnroll_LegacyMalformedScopeIsRefusedBeforeAnySideEffect pins that a Token
// whose legacy scope predates registry.WellFormedLabel can still be sitting in
// the Repository — an upgrade does not retroactively validate a stored row —
// and Enroll must refuse it exactly like any other rejected token, with no
// certificate signed and no registry row written.
//
// The legacy token is written straight into the Repository, bypassing Create.
// Proves EN-26.
func TestEnroll_LegacyMalformedScopeIsRefusedBeforeAnySideEffect(t *testing.T) {
	assertStoredTokenRefusedBeforeAnySideEffect(t, &Token{
		LegacyScope: []string{"relay:quarantine\u200b=on"},
	})
}

// TestEnroll_StoredMalformedInitialTagIsRefusedBeforeAnySideEffect pins the same
// for a stored token whose initial tags no longer hold (a row edited outside the
// mint): no certificate, no registry row, no tag written, the same opaque
// rejection as every other token.
//
// Proves EN-26, EN-40.
func TestEnroll_StoredMalformedInitialTagIsRefusedBeforeAnySideEffect(t *testing.T) {
	assertStoredTokenRefusedBeforeAnySideEffect(t, &Token{
		InitialTags:        []string{"tag:quarantine\u200b=on"},
		CreatedBy:          "alice:admin",
		CreatedByAccountID: "acct-alice",
		CreatedByHuman:     true,
	})
}

// assertStoredTokenRefusedBeforeAnySideEffect seeds stored (with a known secret
// and a live expiry) straight into a Repository and checks that Enroll refuses
// it as any rejected token is refused, with the dedicated attempt reason.
func assertStoredTokenRefusedBeforeAnySideEffect(t *testing.T, stored *Token) {
	t.Helper()
	repo := NewMemoryRepository()
	svc := NewService(repo)
	obs := &capturingAttemptObserver{}
	srv, reg := newObservedEnrollServer(t, svc, obs)

	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := sha256.Sum256([]byte(secret))
	stored.ID = "deadbeefdeadbeefdeadbeefdeadbeef"
	stored.SecretHash = hash[:]
	stored.ExpiresAt = time.Now().Add(time.Hour)
	if err := repo.Create(context.Background(), stored); err != nil {
		t.Fatalf("seeding stored token: %v", err)
	}
	plaintext := stored.ID + secretSep + secret

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	})

	// RED ON: giving the scope refusal its own code or message — compared
	// against a REVOKED token's rejection captured from a fresh Server in
	// this same test, never a hardcoded string, so a change to the shared
	// message cannot silently desynchronize the two assertions.
	if resp != nil {
		t.Errorf("resp = %+v, want nil", resp)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Enroll: want PermissionDenied, got %v", err)
	}

	revokedSvc := NewService(NewMemoryRepository())
	revokedSrv, _, _ := newEnrollServer(t, revokedSvc)
	revokedTok, revokedPlaintext := mintToken(t, revokedSvc, nil)
	if err := revokedSvc.Revoke(context.Background(), revokedTok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, revokedErr := revokedSrv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: revokedPlaintext,
		Csr:             genCSR(t, "cn"),
	})
	if err.Error() != revokedErr.Error() {
		t.Errorf("stored-token refusal message = %q, want identical to a revoked token's %q — a distinct message is an oracle", err.Error(), revokedErr.Error())
	}

	// RED ON: moving the gate to step (k), which runs after
	// Upsert/SignCSR/RecordEnrollment — the exact placement error #555 flags.
	if got := len(reg.List()); got != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", got)
	}

	// RED ON: reusing AttemptMalformed instead of the dedicated reason.
	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d AttemptEvents, want 1: %+v", len(events), events)
	}
	if events[0].Accepted {
		t.Errorf("event.Accepted = true, want false")
	}
	if events[0].Reason != AttemptInvalidScope {
		t.Errorf("event.Reason = %q, want %q", events[0].Reason, AttemptInvalidScope)
	}
}
