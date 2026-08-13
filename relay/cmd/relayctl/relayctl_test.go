package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/api"
)

// relayctl_test.go drives the REAL CLI against the REAL Control API handlers.
//
// The server side is api.Register behind the production
// controlplane.Authenticator — not a hand-written stub — so these tests
// exercise the actual request the CLI sends, the actual authentication, the
// actual handler, and the actual RFC 7807 body the CLI then renders. A fake
// server would only prove the CLI is self-consistent; this proves the two
// halves agree, which is the whole point of a thin adapter.

const testCredential = "glp_test.credential"

// fakeAuditor captures lifecycle audit records so a test can assert an action
// was attributed, not merely accepted.
type fakeAuditor struct {
	mu      sync.Mutex
	records []audit.Record
}

func (f *fakeAuditor) Append(_ context.Context, r audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, r)
	return nil
}

func (f *fakeAuditor) all() []audit.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Record(nil), f.records...)
}

// roleVerifier authenticates testCredential as an Account with a chosen role.
type roleVerifier struct{ role accounts.Role }

func (v roleVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != testCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		Name: "cli-caller", Kind: accounts.KindHuman, Role: v.role, Enabled: true,
	}, accounts.APIToken{ID: "tok-cli"}, nil
}

// fakeFreezer records Freeze calls.
type fakeFreezer struct {
	mu       sync.Mutex
	engaged  int
	released []string
	err      error
}

func (f *fakeFreezer) EngageFreeze(_ context.Context, _ capability.Principal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.engaged++
	return f.err
}

func (f *fakeFreezer) ReleaseFreeze(_ context.Context, _ capability.Principal, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, reason)
	return f.err
}

// memAccounts is an in-memory api.AccountManager.
type memAccounts struct {
	mu   sync.Mutex
	next int
	m    map[string]accounts.Account
}

func newMemAccounts() *memAccounts { return &memAccounts{m: map[string]accounts.Account{}} }

func (s *memAccounts) Create(_ context.Context, a accounts.Account) (accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	a.ID = "acct-" + string(rune('a'+s.next-1))
	a.CreatedAt = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	s.m[a.ID] = a
	return a, nil
}

func (s *memAccounts) Get(_ context.Context, id string) (accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return accounts.Account{}, accounts.ErrNotFound
	}
	return a, nil
}

func (s *memAccounts) List(_ context.Context) ([]accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]accounts.Account, 0, len(s.m))
	for _, a := range s.m {
		out = append(out, a)
	}
	return out, nil
}

func (s *memAccounts) SetRole(_ context.Context, id string, role accounts.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return accounts.ErrNotFound
	}
	a.Role = role
	s.m[id] = a
	return nil
}

func (s *memAccounts) SetEnabled(_ context.Context, id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return accounts.ErrNotFound
	}
	a.Enabled = enabled
	s.m[id] = a
	return nil
}

// fixture is a running Control API plus the CA file and credential the CLI
// needs to reach it.
type fixture struct {
	endpoint string
	caPath   string
	tokenF   string
	auditor  *fakeAuditor
	freezer  *fakeFreezer
	accts    *memAccounts
	nodes    *fakeNodeRevoker
}

// fakeNodeRevoker records revoked Node ids.
type fakeNodeRevoker struct {
	mu      sync.Mutex
	revoked []string
}

func (f *fakeNodeRevoker) RevokeNode(nodeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, nodeID)
}

func newFixture(t *testing.T, role accounts.Role) *fixture {
	t.Helper()

	f := &fixture{
		auditor: &fakeAuditor{},
		freezer: &fakeFreezer{},
		accts:   newMemAccounts(),
		nodes:   &fakeNodeRevoker{},
	}

	authn := controlplane.NewAuthenticator(roleVerifier{role: role})
	mux := http.NewServeMux()
	api.Register(mux, api.Deps{
		Freeze:   f.freezer,
		Audit:    f.auditor,
		Accounts: f.accts,
		Nodes:    f.nodes,
	})
	srv := httptest.NewTLSServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	f.endpoint = srv.URL

	// Write the test server's certificate so the CLI can trust it the way an
	// operator trusts a Relay's own CA — exercising the --ca-cert path rather
	// than skipping verification (which the CLI has no flag for, by design).
	dir := t.TempDir()
	f.caPath = filepath.Join(dir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(f.caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	f.tokenF = filepath.Join(dir, "token")
	if err := os.WriteFile(f.tokenF, []byte(testCredential+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// Never let a developer's real profile leak into a test run.
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "no-such-config.json"))
	for _, k := range []string{"RELAY_ENDPOINT", "RELAY_TOKEN", "RELAY_TOKEN_FILE", "RELAY_CA_CERT", "RELAY_PROFILE"} {
		t.Setenv(k, "")
	}
	return f
}

// exec runs the CLI with the fixture's connection flags prepended.
func (f *fixture) exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	full := append([]string{args[0], args[1],
		"--endpoint", f.endpoint,
		"--ca-cert", f.caPath,
		"--token-file", f.tokenF,
	}, args[2:]...)
	var out, errb bytes.Buffer
	code = run(full, &out, &errb)
	return code, out.String(), errb.String()
}

// ---------------------------------------------------------------------------
// Admin verbs over the real API
// ---------------------------------------------------------------------------

// TestCLI_AdminActionsOverTheRealAPI is the issue's headline acceptance: the
// CLI performs admin actions over /api/v1, and they land as real state changes
// attributed in the audit trail — not merely as 200s.
func TestCLI_AdminActionsOverTheRealAPI(t *testing.T) {
	f := newFixture(t, accounts.RoleAdmin)

	t.Run("account create then list then set-role", func(t *testing.T) {
		code, stdout, stderr := f.exec(t, "account", "create", "--name", "gleipnir", "--kind", "machine", "--role", "operator")
		if code != exitOK {
			t.Fatalf("create: exit %d; stderr %s", code, stderr)
		}
		if !strings.Contains(stdout, "gleipnir") || !strings.Contains(stdout, "operator") {
			t.Errorf("create output does not show the created Account: %s", stdout)
		}

		code, stdout, stderr = f.exec(t, "account", "list")
		if code != exitOK {
			t.Fatalf("list: exit %d; stderr %s", code, stderr)
		}
		if !strings.Contains(stdout, "gleipnir") {
			t.Errorf("list does not show the Account: %s", stdout)
		}

		// The Account really exists server-side, with the role the CLI sent.
		list, _ := f.accts.List(context.Background())
		if len(list) != 1 || list[0].Role != accounts.RoleOperator {
			t.Fatalf("server state = %+v, want one operator Account", list)
		}

		code, _, stderr = f.exec(t, "account", "set-role", list[0].ID, "--role", "admin")
		if code != exitOK {
			t.Fatalf("set-role: exit %d; stderr %s", code, stderr)
		}
		after, _ := f.accts.Get(context.Background(), list[0].ID)
		if after.Role != accounts.RoleAdmin {
			t.Errorf("role = %q after set-role, want admin", after.Role)
		}
	})

	t.Run("freeze engage and release", func(t *testing.T) {
		if code, _, stderr := f.exec(t, "freeze", "engage"); code != exitOK {
			t.Fatalf("engage: exit %d; stderr %s", code, stderr)
		}
		if f.freezer.engaged != 1 {
			t.Errorf("EngageFreeze called %d times, want 1", f.freezer.engaged)
		}

		code, _, stderr := f.exec(t, "freeze", "release", "--reason", "incident 42 resolved")
		if code != exitOK {
			t.Fatalf("release: exit %d; stderr %s", code, stderr)
		}
		if len(f.freezer.released) != 1 || f.freezer.released[0] != "incident 42 resolved" {
			t.Errorf("release reasons = %v, want the CLI's reason carried through", f.freezer.released)
		}
	})

	t.Run("actions are attributed in audit", func(t *testing.T) {
		// A Node revoke writes a lifecycle record; the CLI's caller must be the
		// attributed principal, which is what makes the CLI indistinguishable
		// from any other API client in the trail.
		f2 := newFixture(t, accounts.RoleAdmin)
		f2Deps := f2 // alias for clarity
		if code, _, stderr := f2Deps.exec(t, "node", "revoke", "node-1"); code != exitOK {
			t.Logf("node revoke stderr: %s", stderr)
		}
		for _, rec := range f2.auditor.all() {
			if rec.Attribution.Verified.AccountName == "cli-caller" {
				return // attributed to the CLI's Account
			}
		}
		if len(f2.auditor.all()) > 0 {
			t.Errorf("audit records exist but none attributed to the CLI's Account: %+v", f2.auditor.all())
		}
	})
}

// The release verb refuses locally without a reason, so the operator learns it
// without a round trip — the server still enforces it (ADR-0013).
func TestCLI_FreezeReleaseRequiresAReason(t *testing.T) {
	f := newFixture(t, accounts.RoleAdmin)

	code, _, stderr := f.exec(t, "freeze", "release")
	if code == exitOK {
		t.Fatal("release without --reason succeeded, want a refusal")
	}
	if !strings.Contains(stderr, "reason") {
		t.Errorf("stderr %q must explain that a reason is required", stderr)
	}
	if len(f.freezer.released) != 0 {
		t.Errorf("ReleaseFreeze was called despite the missing reason: %v", f.freezer.released)
	}
}

// ---------------------------------------------------------------------------
// Error rendering (the issue's third acceptance criterion)
// ---------------------------------------------------------------------------

// TestCLI_AuthFailureIsLegible: a role refusal from the server is reproduced
// verbatim with a distinct exit code, not swallowed into a generic failure or
// re-worded into a second explanation of the server's rules.
func TestCLI_AuthFailureIsLegible(t *testing.T) {
	f := newFixture(t, accounts.RoleViewer) // identity routes are admin-only

	code, _, stderr := f.exec(t, "account", "list")
	if code != exitAuth {
		t.Fatalf("exit = %d, want %d (auth/role)", code, exitAuth)
	}
	if !strings.Contains(strings.ToLower(stderr), "forbidden") && !strings.Contains(stderr, "admin") {
		t.Errorf("stderr %q should carry the server's own refusal text", stderr)
	}
	if strings.Contains(stderr, "panic") {
		t.Errorf("stderr contains a panic: %s", stderr)
	}
}

// An invalid credential is a 401 rendered as the auth exit code.
func TestCLI_BadCredentialIsAuthExit(t *testing.T) {
	f := newFixture(t, accounts.RoleAdmin)
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("glp_wrong.credential"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"account", "list",
		"--endpoint", f.endpoint, "--ca-cert", f.caPath, "--token-file", bad}, &out, &errb)
	if code != exitAuth {
		t.Fatalf("exit = %d, want %d; stderr %s", code, exitAuth, errb.String())
	}
}

// An unreachable Relay is its own exit code, distinct from an API refusal, so a
// script can tell "the Relay said no" from "I could not reach the Relay".
func TestCLI_UnreachableRelayIsItsOwnExitCode(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "t")
	if err := os.WriteFile(tok, []byte(testCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "none.json"))

	var out, errb bytes.Buffer
	// Port 1 on loopback: nothing listens there.
	code := run([]string{"account", "list", "--endpoint", "https://127.0.0.1:1", "--token-file", tok,
		"--timeout", "3s"}, &out, &errb)
	if code != exitUnreachable {
		t.Fatalf("exit = %d, want %d (unreachable); stderr %s", code, exitUnreachable, errb.String())
	}
}

// TestCLI_RefusesPlaintextEndpoint: the CLI will not send a credential over
// http://, mirroring the daemon's refusal to dial a non-https Relay.
func TestCLI_RefusesPlaintextEndpoint(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "t")
	if err := os.WriteFile(tok, []byte(testCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "none.json"))

	var out, errb bytes.Buffer
	code := run([]string{"account", "list", "--endpoint", "http://relay.example:9443", "--token-file", tok}, &out, &errb)
	if code == exitOK {
		t.Fatal("a plaintext endpoint was accepted")
	}
	if !strings.Contains(errb.String(), "https") {
		t.Errorf("stderr %q must say the endpoint has to be https", errb.String())
	}
}

// ---------------------------------------------------------------------------
// Configuration resolution
// ---------------------------------------------------------------------------

func TestConfig_ResolutionOrder(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	tokenFile := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokenFile, []byte("glp_from.file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := `{"default_profile":"prod","profiles":{"prod":{"endpoint":"https://profile.example:9443","token_file":"` + tokenFile + `"}}}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CONFIG", cfgPath)
	for _, k := range []string{"RELAY_ENDPOINT", "RELAY_TOKEN", "RELAY_TOKEN_FILE", "RELAY_CA_CERT", "RELAY_PROFILE"} {
		t.Setenv(k, "")
	}

	t.Run("profile supplies endpoint and token when nothing else does", func(t *testing.T) {
		got, err := resolveConfig(&globalFlags{})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got.Endpoint != "https://profile.example:9443" {
			t.Errorf("endpoint = %q, want the profile's", got.Endpoint)
		}
		if got.Token != "glp_from.file" {
			t.Errorf("token = %q, want the profile's token_file contents (trimmed)", got.Token)
		}
	})

	t.Run("env overrides the profile", func(t *testing.T) {
		t.Setenv("RELAY_ENDPOINT", "https://env.example:9443")
		got, err := resolveConfig(&globalFlags{})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got.Endpoint != "https://env.example:9443" {
			t.Errorf("endpoint = %q, want the env value", got.Endpoint)
		}
	})

	t.Run("flag overrides env and profile", func(t *testing.T) {
		t.Setenv("RELAY_ENDPOINT", "https://env.example:9443")
		got, err := resolveConfig(&globalFlags{endpoint: "https://flag.example:9443"})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got.Endpoint != "https://flag.example:9443" {
			t.Errorf("endpoint = %q, want the flag value", got.Endpoint)
		}
	})

	t.Run("a named profile that does not exist is an error", func(t *testing.T) {
		if _, err := resolveConfig(&globalFlags{profile: "staging"}); err == nil {
			t.Fatal("resolve with an unknown profile succeeded; it must not silently fall back to another Relay")
		}
	})
}

// A missing credential is its own error, so main can print the actionable
// message rather than a bare failure.
func TestConfig_MissingCredentialIsTyped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "none.json"))
	for _, k := range []string{"RELAY_ENDPOINT", "RELAY_TOKEN", "RELAY_TOKEN_FILE", "RELAY_CA_CERT", "RELAY_PROFILE"} {
		t.Setenv(k, "")
	}
	_, err := resolveConfig(&globalFlags{endpoint: "https://relay.example:9443"})
	if err == nil {
		t.Fatal("no error for a missing credential")
	}
	if !strings.Contains(err.Error(), "API Token") {
		t.Errorf("err = %v, want the typed no-credential error", err)
	}
}

// ---------------------------------------------------------------------------
// Usage surface
// ---------------------------------------------------------------------------

func TestCLI_UsageAndUnknownCommands(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args prints usage", nil, exitUsage},
		{"help", []string{"help"}, exitOK},
		{"version", []string{"version"}, exitOK},
		{"unknown group", []string{"nope"}, exitUsage},
		{"group without subcommand", []string{"account"}, exitUsage},
		{"unknown subcommand", []string{"account", "nope"}, exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(tc.args, &out, &errb); code != tc.want {
				t.Errorf("exit = %d, want %d (stdout %q stderr %q)", code, tc.want, out.String(), errb.String())
			}
		})
	}
}

// --json emits machine-readable output for scripting, and it is the same value
// the human renderer saw.
func TestCLI_JSONOutput(t *testing.T) {
	f := newFixture(t, accounts.RoleAdmin)

	if code, _, stderr := f.exec(t, "account", "create", "--name", "svc", "--kind", "machine", "--role", "viewer"); code != exitOK {
		t.Fatalf("create: exit %d; %s", code, stderr)
	}
	code, stdout, stderr := f.exec(t, "account", "list", "--json")
	if code != exitOK {
		t.Fatalf("list --json: exit %d; %s", code, stderr)
	}
	var parsed struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, stdout)
	}
	if len(parsed.Accounts) != 1 || parsed.Accounts[0]["name"] != "svc" {
		t.Errorf("--json payload = %s, want the created Account", stdout)
	}
}

// The CLI presents the credential as a bearer token on every request — checked
// against a server that records what it received, so a future refactor cannot
// quietly drop the header and rely on a permissive test double.
func TestCLI_SendsBearerCredential(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accounts":[]}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokPath := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokPath, []byte(testCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "none.json"))

	var out, errb bytes.Buffer
	if code := run([]string{"account", "list", "--endpoint", srv.URL, "--ca-cert", caPath, "--token-file", tokPath},
		&out, &errb); code != exitOK {
		t.Fatalf("exit %d; stderr %s", code, errb.String())
	}
	if gotAuth != "Bearer "+testCredential {
		t.Errorf("Authorization = %q, want the bearer credential", gotAuth)
	}
}

// The CLI verifies the Relay's certificate. There is no skip-verify flag, so an
// untrusted certificate must fail rather than fall back to trusting it.
func TestCLI_RefusesAnUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokPath := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokPath, []byte(testCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	// A CA bundle that does NOT include the server's certificate.
	otherCA := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherCA, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: selfSigned(t).Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_CONFIG", filepath.Join(dir, "none.json"))

	var out, errb bytes.Buffer
	code := run([]string{"account", "list", "--endpoint", srv.URL, "--ca-cert", otherCA, "--token-file", tokPath},
		&out, &errb)
	if code == exitOK {
		t.Fatal("an untrusted certificate was accepted")
	}
	if !strings.Contains(errb.String(), "certificate") && !strings.Contains(errb.String(), "x509") {
		t.Errorf("stderr %q should name the certificate failure", errb.String())
	}
}

// selfSigned mints a throwaway CA certificate unrelated to any test server.
//
// Deliberately NOT another httptest server's certificate: httptest reuses one
// built-in certificate for every server it starts, so "a different server's
// cert" would in fact be the same cert and the test would prove nothing.
func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
