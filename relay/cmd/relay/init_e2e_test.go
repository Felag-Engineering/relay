//go:build integration

package main

// init_e2e_test.go proves RC-28 over the shippable binary: `relay init` run as the
// Relay's own uid, through the separate-uid harness, against the store a real Relay
// created at its first start. A credential init prints is proven by spending it on that
// Relay's Control API; the audit trail is read from a copy of the store taken after the
// Relay is stopped. Runs under make test-integration (RELAY_SHIPPABLE_BIN).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const initE2EPassword = "a long enough console passphrase"

// initRelay is one Relay layout `relay init` runs against.
type initRelay struct {
	layout    *relaytest.RelayLayout
	bin       string
	cfg       string
	storePath string
	caDir     string
	proc      *relaytest.RelayProcess
	base      string
	tls       *tls.Config
}

// newInitRelay writes a configuration with the control plane and Console on, and does
// not start the Relay.
func newInitRelay(t *testing.T) *initRelay {
	t.Helper()
	bin := os.Getenv("RELAY_SHIPPABLE_BIN")
	if bin == "" {
		relaytest.SkipMissingBin(t, "RELAY_SHIPPABLE_BIN not set; skipping the relay init e2e (run via make test-integration)")
	}
	layout := relaytest.NewRelayLayout(t, "test-integration")
	r := &initRelay{
		layout:    layout,
		bin:       layout.InstallBinary(t, bin),
		storePath: filepath.Join(layout.StateDir(), "relay.db"),
		caDir:     filepath.Join(layout.StateDir(), "ca"),
	}
	node, control := freeAddr(t), freeAddr(t)
	r.base = "https://" + control
	r.cfg = layout.WriteConfig(t, fmt.Sprintf(`[node_plane]
listen_address = %q

[control_plane]
enabled = true
listen_address = %q

[console]
enabled = true

[ca]
dir = %q

[store]
path = %q

[tls]
hostname = "localhost"
`, node, control, r.caDir, r.storePath))
	return r
}

// start runs the Relay until it is listening, which is when its CA and store exist.
func (r *initRelay) start(t *testing.T) {
	t.Helper()
	proc, err := r.layout.Start(t, r.bin, relaySubprocessEnv(), "--config", r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.proc = proc
	waitForRelayLog(t, proc, "relay listening")
	pem, err := os.ReadFile(r.layout.CopyOut(t, filepath.Join(r.caDir, "ca-cert.pem")))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the Relay's CA certificate did not parse")
	}
	r.tls = &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
}

// startAndStop runs the Relay once so its CA and store exist, then stops it.
func (r *initRelay) startAndStop(t *testing.T) {
	t.Helper()
	r.start(t)
	r.stop(t)
}

func (r *initRelay) stop(t *testing.T) {
	t.Helper()
	if r.proc == nil {
		return
	}
	if err := r.proc.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.proc.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the Relay did not exit")
	}
	r.proc = nil
}

// init runs `relay init --config <cfg> args...` as the Relay's uid.
func (r *initRelay) init(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return r.layout.Run(t, r.bin, relaySubprocessEnv(), stdin, append([]string{"init", "--config", r.cfg}, args...)...)
}

// firstAdmin runs `relay init --admin name` and returns the credential it printed.
func (r *initRelay) firstAdmin(t *testing.T, name string) string {
	t.Helper()
	out, errOut, code := r.init(t, initE2EPassword+"\n", "--admin", name)
	if code != 0 {
		t.Fatalf("relay init --admin %s: exit %d\nstderr: %s", name, code, errOut)
	}
	return oneCredential(t, out, errOut)
}

// oneCredential checks stdout is exactly one API Token line that stderr does not repeat.
func oneCredential(t *testing.T, stdout, stderr string) string {
	t.Helper()
	cred := strings.TrimSuffix(stdout, "\n")
	if cred == "" || strings.Contains(cred, "\n") || !strings.HasPrefix(cred, accounts.TokenPrefix) {
		t.Fatalf("stdout = %q, want exactly one API Token line", stdout)
	}
	if strings.Contains(stderr, cred) {
		t.Fatal("stderr repeats the credential")
	}
	if strings.Contains(stdout+stderr, initE2EPassword) {
		t.Fatal("the password was printed")
	}
	return cred
}

func (r *initRelay) client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: r.tls}}
}

// api calls the running Relay's Control API with cred and returns the status and body.
func (r *initRelay) api(t *testing.T, cred, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

type e2eAccount struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Role    string `json:"role"`
	Enabled bool   `json:"enabled"`
}

func (r *initRelay) accounts(t *testing.T, cred string) []e2eAccount {
	t.Helper()
	code, body := r.api(t, cred, http.MethodGet, "/api/v1/accounts", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/accounts = %d: %s", code, body)
	}
	var resp struct {
		Accounts []e2eAccount `json:"accounts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode accounts %s: %v", body, err)
	}
	return resp.Accounts
}

func (r *initRelay) createAccount(t *testing.T, cred, name, kind, role string) e2eAccount {
	t.Helper()
	code, body := r.api(t, cred, http.MethodPost, "/api/v1/accounts",
		map[string]string{"name": name, "kind": kind, "role": role})
	if code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, code, body)
	}
	var a e2eAccount
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return a
}

func (r *initRelay) tokenCount(t *testing.T, cred, accountID string) int {
	t.Helper()
	code, body := r.api(t, cred, http.MethodGet, "/api/v1/accounts/"+accountID+"/tokens", nil)
	if code != http.StatusOK {
		t.Fatalf("list tokens: %d %s", code, body)
	}
	var resp struct {
		Tokens []json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tokens %s: %v", body, err)
	}
	return len(resp.Tokens)
}

// signIn reports whether the Console accepts name and password.
func (r *initRelay) signIn(t *testing.T, name, password string) bool {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: r.tls},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	getResp, err := client.Get(r.base + console.LoginPath)
	if err != nil {
		t.Fatalf("GET login page: %v", err)
	}
	csrf := consoleHiddenField(t, readAll(t, getResp), "csrf_token")
	resp, err := client.PostForm(r.base+console.LoginPath,
		url.Values{"username": {name}, "password": {password}, "csrf_token": {csrf}})
	if err != nil {
		t.Fatalf("POST sign-in: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusSeeOther
}

// trail stops the Relay and returns the audit trail from a copy of its store.
func (r *initRelay) trail(t *testing.T) []audit.Record {
	t.Helper()
	r.stop(t)
	dir := t.TempDir()
	copyIn := func(src, name string) {
		b, err := os.ReadFile(r.layout.CopyOut(t, src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyIn(r.storePath, "relay.db")
	if r.layout.ExistsInState(t, r.storePath+"-wal") {
		copyIn(r.storePath+"-wal", "relay.db-wal")
	}
	st, err := store.Open(filepath.Join(dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	recs, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// RC-28: on a store with no human Account, init creates one human admin with the
// given name, sets its Console password and mints its first API Token once, the
// credential alone on stdout, every act audited and attributed to local-host.
func TestInit_CreatesNamedAdminAndMintsOnce(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	cred := r.firstAdmin(t, "alice")

	list := r.accounts(t, cred)
	if len(list) != 1 {
		t.Fatalf("accounts = %+v, want exactly the one admin init created: the Relay seeds none", list)
	}
	if a := list[0]; a.Name != "alice" || a.Kind != "human" || a.Role != "admin" || !a.Enabled {
		t.Fatalf("account = %+v, want alice, an enabled human admin", a)
	}
	if n := r.tokenCount(t, cred, list[0].ID); n != 1 {
		t.Errorf("alice holds %d API Tokens, want the 1 init minted", n)
	}
	if !r.signIn(t, "alice", initE2EPassword) {
		t.Error("the Console refused alice's password")
	}
	if r.signIn(t, "alice", initE2EPassword+"x") {
		t.Error("the Console accepted a wrong password, so the sign-in check above proves nothing")
	}

	var kinds []string
	for _, rec := range r.trail(t) {
		switch rec.Kind {
		case audit.KindAccountCreate, audit.KindPasswordSet, audit.KindAPITokenMint:
			kinds = append(kinds, rec.Kind)
			if rec.Principal != audit.PrincipalLocalHost {
				t.Errorf("%s attributed to %q, want %q", rec.Kind, rec.Principal, audit.PrincipalLocalHost)
			}
			if strings.Contains(rec.Reason, cred) || strings.Contains(rec.Reason, initE2EPassword) {
				t.Errorf("%s carries a secret", rec.Kind)
			}
		}
	}
	if strings.Join(kinds, ",") != "account_create,password_set,api_token_mint" {
		t.Errorf("credential records = %v, want account_create, password_set, api_token_mint", kinds)
	}
}

// RC-28: with any human Account present, init creates nothing and emits no secret,
// whatever name it is given.
func TestInit_RefusesWhenAHumanAccountExists(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	cred := r.firstAdmin(t, "alice")

	out, errOut, code := r.init(t, initE2EPassword+"\n", "--admin", "bob")
	if code != 0 || out != "" {
		t.Fatalf("init --admin bob on an initialised Relay: exit %d, stdout %q; want 0 and nothing", code, out)
	}
	if !strings.Contains(errOut, "alice") {
		t.Errorf("stderr = %q, want the state, naming alice", errOut)
	}
	for _, a := range r.accounts(t, cred) {
		if a.Name == "bob" {
			t.Fatal("bob was created")
		}
	}
}

// RC-28: a re-run reports state and emits nothing, and mints nothing.
func TestInit_RerunEmitsNothing(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	cred := r.firstAdmin(t, "alice")

	out, errOut, code := r.init(t, initE2EPassword+"\n", "--admin", "alice")
	if code != 0 || out != "" {
		t.Fatalf("re-run: exit %d, stdout %q; want 0 and nothing", code, out)
	}
	if !strings.Contains(errOut, "already") || !strings.Contains(errOut, "--recover") {
		t.Errorf("re-run stderr = %q, want the state and the recovery path", errOut)
	}
	list := r.accounts(t, cred)
	if len(list) != 1 || r.tokenCount(t, cred, list[0].ID) != 1 {
		t.Errorf("after a re-run: %d Accounts, want 1 holding 1 token", len(list))
	}
}

// RC-28: --recover names an enabled human admin and re-mints its API Token, audited
// and attributed to local-host; the new token works and the old one is untouched.
func TestInit_RecoverReMintsAndAudits(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	first := r.firstAdmin(t, "alice")

	out, errOut, code := r.init(t, "", "--recover", "alice")
	if code != 0 {
		t.Fatalf("init --recover alice: exit %d\nstderr: %s", code, errOut)
	}
	second := oneCredential(t, out, errOut)
	if second == first {
		t.Fatal("recovery printed the first credential again")
	}
	list := r.accounts(t, second)
	if len(list) != 1 || list[0].Name != "alice" {
		t.Fatalf("the recovered credential lists %+v, want alice", list)
	}
	if n := r.tokenCount(t, second, list[0].ID); n != 2 {
		t.Errorf("alice holds %d tokens, want 2: recovery adds one and revokes none", n)
	}
	tokenID := strings.SplitN(strings.TrimPrefix(second, accounts.TokenPrefix), ".", 2)[0]

	recs := r.trail(t)
	var mints []audit.Record
	for _, rec := range recs {
		if rec.Kind == audit.KindAPITokenMint {
			mints = append(mints, rec)
		}
	}
	if len(mints) != 2 {
		t.Fatalf("%d api_token_mint records, want 2 (first and recovered)", len(mints))
	}
	last := mints[1]
	if last.Principal != audit.PrincipalLocalHost || !strings.Contains(last.Reason, tokenID) || strings.Contains(last.Reason, second) {
		t.Errorf("recovery record = %q by %q, want the new token's id by %s and never its value", last.Reason, last.Principal, audit.PrincipalLocalHost)
	}
}

// RC-28: recovery refuses a disabled admin, a non-admin, a machine Account and an
// unknown name, and mints nothing for any of them.
func TestInit_RecoverRefusesDisabledOrNonAdmin(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	cred := r.firstAdmin(t, "alice")

	olga := r.createAccount(t, cred, "olga", "human", "operator")
	dora := r.createAccount(t, cred, "dora", "human", "admin")
	bot := r.createAccount(t, cred, "bot", "machine", "admin")
	if code, body := r.api(t, cred, http.MethodPost, "/api/v1/accounts/"+dora.ID+"/disable", nil); code != http.StatusOK {
		t.Fatalf("disable dora: %d %s", code, body)
	}

	for _, name := range []string{"dora", "olga", "bot", "nobody"} {
		out, errOut, code := r.init(t, "", "--recover", name)
		if code != 1 || out != "" {
			t.Errorf("init --recover %s: exit %d, stdout %q; want 1 and nothing\nstderr: %s", name, code, out, errOut)
		}
	}
	for _, a := range []e2eAccount{olga, dora, bot} {
		if n := r.tokenCount(t, cred, a.ID); n != 0 {
			t.Errorf("%s holds %d tokens after a refused recovery, want 0", a.Name, n)
		}
	}
}

// RC-28: no Account name is reserved. The name the Relay once seeded is an ordinary
// name on every creation path: init takes it, and so does the Control API.
func TestInit_NoReservedName(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	cred := r.firstAdmin(t, "founding-admin")
	r.createAccount(t, cred, "admin", "human", "viewer")
	r.createAccount(t, cred, "first-admin", "machine", "operator")
	if n := len(r.accounts(t, cred)); n != 3 {
		t.Errorf("%d Accounts, want 3", n)
	}
}

// RC-28 and RC-15: init loads relay.toml through the server's own start-time check,
// so as root it refuses before touching the store. The same command as the Relay's
// uid then succeeds, so the refusal was root and nothing else.
func TestInit_RefusesRoot(t *testing.T) {
	r := newInitRelay(t)
	r.startAndStop(t)

	out, errOut, code := r.layout.RunAsRoot(t, r.bin, relaySubprocessEnv(), initE2EPassword+"\n",
		"init", "--config", r.cfg, "--admin", "alice")
	if code == 0 || out != "" {
		t.Fatalf("init as root: exit %d, stdout %q; want a refusal and nothing", code, out)
	}
	if !strings.Contains(errOut, "root") {
		t.Errorf("stderr = %q, want the start-time check's root refusal", errOut)
	}

	r.firstAdmin(t, "alice")
}

// RC-28: init refuses when the store does not exist yet, saying to start the Relay
// first, and creates neither the CA nor the store.
func TestInit_RefusesAbsentStore(t *testing.T) {
	r := newInitRelay(t)

	out, errOut, code := r.init(t, initE2EPassword+"\n", "--admin", "alice")
	if code != 1 || out != "" {
		t.Fatalf("init before the Relay ever started: exit %d, stdout %q; want 1 and nothing", code, out)
	}
	if !strings.Contains(errOut, "Start the Relay first") {
		t.Errorf("stderr = %q, want it to say to start the Relay first", errOut)
	}
	for _, p := range []string{r.storePath, r.caDir} {
		if r.layout.ExistsInState(t, p) {
			t.Errorf("%s exists after a refused init; init creates neither the CA nor the store", p)
		}
	}

	// Positive control: once the Relay has started, the same command succeeds.
	r.startAndStop(t)
	r.firstAdmin(t, "alice")
}

// EN-39: without a terminal init mints no Enrollment Token and says how to mint
// later, over the shippable binary.
func TestInit_WithoutATerminalMintsNoEnrollmentToken(t *testing.T) {
	r := newInitRelay(t)
	r.start(t)
	out, errOut, code := r.init(t, initE2EPassword+"\n", "--admin", "alice")
	if code != 0 {
		t.Fatalf("relay init --admin alice: exit %d\nstderr: %s", code, errOut)
	}
	oneCredential(t, out, errOut)
	if !strings.Contains(errOut, "Add Nodes") {
		t.Errorf("stderr = %q, want how to mint later", errOut)
	}
	for _, rec := range r.trail(t) {
		if rec.Kind == audit.KindTokenMint {
			t.Errorf("a token_mint record exists: %+v", rec)
		}
	}
}
