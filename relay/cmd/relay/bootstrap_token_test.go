package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// runBootstrap runs the subcommand with stdout/stderr captured to temp files
// (the command writes to *os.File, matching the real os.Stdout/os.Stderr) and
// returns the exit code and both streams.
func runBootstrap(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}

	code = runBootstrapTokenCommand(args, outF, errF)
	outF.Close() //nolint:errcheck
	errF.Close() //nolint:errcheck

	o, _ := os.ReadFile(filepath.Join(dir, "stdout"))
	e, _ := os.ReadFile(filepath.Join(dir, "stderr"))
	return code, string(o), string(e)
}

// The whole point of the command: the credential it prints authenticates
// against the control plane, as the founding admin Account.
func TestBootstrapToken_MintsAWorkingFoundingAdminCredential(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "relay.db")

	code, stdout, stderr := runBootstrap(t, "-store-path", storePath)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %s", code, stderr)
	}

	credential := strings.TrimSpace(stdout)
	if !strings.HasPrefix(credential, accounts.TokenPrefix) {
		t.Fatalf("stdout %q is not a %q-prefixed credential", credential, accounts.TokenPrefix)
	}
	// Stdout carries the credential and NOTHING else, so it can be piped
	// straight into a secret store without parsing.
	if len(strings.Split(strings.TrimSpace(stdout), "\n")) != 1 {
		t.Errorf("stdout has more than one line; it must carry only the credential:\n%s", stdout)
	}
	// ...and no diagnostic ever repeats the secret.
	if strings.Contains(stderr, credential) {
		t.Errorf("stderr echoes the credential: %s", stderr)
	}

	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	authn := controlplane.NewAuthenticator(svc)

	var seen string
	h := authn.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := controlplane.PrincipalFromContext(r.Context())
		seen = p.Attribution()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the minted credential did not authenticate: status %d", rec.Code)
	}
	if seen != controlplane.FoundingAdmin().Attribution() {
		t.Errorf("authenticated as %q, want %q", seen, controlplane.FoundingAdmin().Attribution())
	}
}

// Running it twice mints a second, independent credential rather than
// replacing the first — so an operator who lost the plaintext can get a new
// one without silently invalidating a credential that may still be in use.
func TestBootstrapToken_IsRepeatableAndAdditive(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "relay.db")

	_, first, _ := runBootstrap(t, "-store-path", storePath)
	code, second, stderr := runBootstrap(t, "-store-path", storePath)
	if code != 0 {
		t.Fatalf("second run exit code = %d; stderr = %s", code, stderr)
	}
	if strings.TrimSpace(first) == strings.TrimSpace(second) {
		t.Fatal("the second run returned the same credential; each mint must be independent")
	}

	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	ctx := context.Background()
	admin, err := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	if err != nil {
		t.Fatalf("founding admin: %v", err)
	}
	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	list, err := svc.List(ctx, admin.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("token count = %d (err %v), want 2 live tokens", len(list), err)
	}
	for _, tok := range list {
		if tok.Revoked() {
			t.Error("a previous bootstrap token was revoked by the second run; revocation must be a deliberate act")
		}
	}

	// Both still authenticate: the first was not invalidated.
	for _, credential := range []string{strings.TrimSpace(first), strings.TrimSpace(second)} {
		if _, _, err := svc.Verify(ctx, credential); err != nil {
			t.Errorf("credential %q… stopped working: %v", credential[:len(accounts.TokenPrefix)+8], err)
		}
	}
}

// A disabled founding admin is a deliberate retirement of that identity's
// authority. Minting it a fresh credential would undo that decision at exactly
// the moment nobody is watching, so the command refuses instead — and says why.
func TestBootstrapToken_RefusesADisabledFoundingAdmin(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "relay.db")
	ctx := context.Background()

	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	admin, err := st.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := st.Accounts().SetEnabled(ctx, admin.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	st.Close() //nolint:errcheck

	code, stdout, stderr := runBootstrap(t, "-store-path", storePath)
	if code == 0 {
		t.Fatal("minting for a disabled founding admin succeeded")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout is non-empty on refusal: %q", stdout)
	}
	if !strings.Contains(stderr, "disabled") {
		t.Errorf("stderr does not explain the refusal: %s", stderr)
	}

	// It also did not re-enable the Account as a side effect.
	st2, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { st2.Close() }) //nolint:errcheck
	after, err := st2.Accounts().Get(ctx, admin.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Enabled {
		t.Error("the refused run re-enabled the founding admin")
	}
}

func TestBootstrapToken_TTLAndUsageErrors(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "relay.db")

	if code, _, _ := runBootstrap(t); code == 0 {
		t.Error("missing -store-path exited 0")
	}
	if code, _, _ := runBootstrap(t, "-store-path", storePath, "-ttl", "-1h"); code == 0 {
		t.Error("negative -ttl exited 0")
	}

	// The default is no expiry, stated explicitly in the diagnostics so an
	// operator cannot mint an immortal credential without being told.
	_, _, stderr := runBootstrap(t, "-store-path", storePath)
	if !strings.Contains(stderr, "does not expire") {
		t.Errorf("stderr does not state that the default token never expires: %s", stderr)
	}

	// An explicit TTL is honoured and reported.
	_, stdout, stderr := runBootstrap(t, "-store-path", storePath, "-ttl", "1h")
	if !strings.Contains(stderr, "expires at") {
		t.Errorf("stderr does not report the expiry: %s", stderr)
	}
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	ctx := context.Background()
	admin, _ := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	list, err := svc.List(ctx, admin.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var bounded int
	for _, tok := range list {
		if !tok.ExpiresAt.IsZero() {
			bounded++
			if d := time.Until(tok.ExpiresAt); d > time.Hour+time.Minute || d < 59*time.Minute {
				t.Errorf("expiry is %v away, want ~1h", d)
			}
		}
	}
	if bounded != 1 {
		t.Errorf("%d tokens carry an expiry, want exactly the -ttl one", bounded)
	}
	_ = stdout
}
