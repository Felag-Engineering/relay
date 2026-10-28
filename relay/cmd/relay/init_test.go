package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// These are in-process tests of init's parts. The start-time check refuses every
// directory a test can make, so the whole command, over the shippable binary and a
// store the Relay created, is proven in init_e2e_test.go.

// initIO is a stdin holding input, and stdout and stderr files to read back.
type initIO struct {
	stdin, stdout, stderr *os.File
}

func newInitIO(t *testing.T, input string) initIO {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "stdin")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	open := func(p string, flag int) *os.File {
		f, err := os.OpenFile(p, flag, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	return initIO{
		stdin:  open(in, os.O_RDONLY),
		stdout: open(filepath.Join(dir, "stdout"), os.O_CREATE|os.O_RDWR),
		stderr: open(filepath.Join(dir, "stderr"), os.O_CREATE|os.O_RDWR),
	}
}

func (o initIO) read(t *testing.T) (stdout, stderr string) {
	t.Helper()
	b, err := os.ReadFile(o.stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.ReadFile(o.stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b), string(e)
}

func openInitStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

const initTestPassword = "correct horse battery staple"

func TestInitCommand_RefusesBadArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--admin", "alice", "--recover", "alice"},
		{"--admin", "alice", "extra"},
		{"--config", "", "--admin", "alice"},
		{"--password", "hunter2hunter2", "--admin", "alice"},
		{"--ttl", "-1h", "--admin", "alice"},
		{"--ttl", "soon", "--recover", "alice"},
	} {
		io := newInitIO(t, "")
		if code := runInitCommand(args, nil, io.stdin, io.stdout, io.stderr); code != 2 {
			t.Errorf("args %q: exit %d, want 2", args, code)
		}
		if out, _ := io.read(t); out != "" {
			t.Errorf("args %q: stdout = %q, want nothing", args, out)
		}
	}
}

// A configuration the start-time check cannot accept refuses before any store is
// touched: init has no path round the server's own check.
func TestInitCommand_GoesThroughTheServersConfigurationCheck(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "relay.toml")
	io := newInitIO(t, initTestPassword+"\n")
	if code := runInitCommand([]string{"--config", missing, "--admin", "alice"}, nil, io.stdin, io.stdout, io.stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	out, errOut := io.read(t)
	if out != "" || !strings.Contains(errOut, "does not exist") {
		t.Errorf("stdout %q, stderr %q: want nothing on stdout and the configuration refusal", out, errOut)
	}

	io = newInitIO(t, "")
	envErr := relayconfig.RefuseRetiredEnv([]string{"RELAY_STORE_PATH=/x"})
	if envErr == nil {
		t.Fatal("RELAY_STORE_PATH is not refused; this check proves nothing")
	}
	code := runInitCommand([]string{"--admin", "alice"}, envErr, io.stdin, io.stdout, io.stderr)
	if code != 1 {
		t.Errorf("a retired RELAY_* variable: exit %d, want 1", code)
	}
}

func TestInitFirstAdmin_CreatesOnceAndPrintsOnlyTheCredential(t *testing.T) {
	st := openInitStore(t)
	ctx := context.Background()
	io := newInitIO(t, initTestPassword+"\n")
	if code := initFirstAdmin(ctx, st, "alice", 0, io.stdin, io.stdout, io.stderr); code != 0 {
		_, e := io.read(t)
		t.Fatalf("exit %d: %s", code, e)
	}
	out, errOut := io.read(t)
	cred := strings.TrimSuffix(out, "\n")
	if strings.Contains(cred, "\n") || !strings.HasPrefix(cred, accounts.TokenPrefix) {
		t.Fatalf("stdout = %q, want the one credential", out)
	}
	if strings.Contains(errOut, cred) || strings.Contains(errOut, initTestPassword) {
		t.Error("stderr carries the credential or the password")
	}

	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	acct, _, err := svc.Verify(ctx, cred)
	if err != nil || acct.Name != "alice" || acct.Kind != accounts.KindHuman || acct.Role != accounts.RoleAdmin || !acct.Enabled {
		t.Fatalf("the credential verifies as %+v (err %v), want the enabled human admin alice", acct, err)
	}
	hash, err := st.Passwords().GetPassword(ctx, acct.ID)
	if err != nil {
		t.Fatalf("no password stored: %v", err)
	}
	if !hash.Hash.Verify(accounts.NewPassword(initTestPassword)) {
		t.Error("the stored password does not verify")
	}
	recs, err := st.Audit().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range recs {
		kinds = append(kinds, r.Kind)
		if r.Principal != audit.PrincipalLocalHost {
			t.Errorf("%s attributed to %q, want %q", r.Kind, r.Principal, audit.PrincipalLocalHost)
		}
		if strings.Contains(r.Reason, initTestPassword) || strings.Contains(r.Reason, cred) {
			t.Errorf("%s carries a secret: %q", r.Kind, r.Reason)
		}
	}
	if strings.Join(kinds, ",") != "account_create,password_set,api_token_mint" {
		t.Errorf("audit kinds = %v, want account_create, password_set, api_token_mint", kinds)
	}

	// A re-run, under any name, creates nothing and prints nothing.
	again := newInitIO(t, initTestPassword+"\n")
	if code := initFirstAdmin(ctx, st, "bob", 0, again.stdin, again.stdout, again.stderr); code != 0 {
		t.Fatalf("re-run exit %d, want 0", code)
	}
	out, errOut = again.read(t)
	if out != "" {
		t.Errorf("re-run stdout = %q, want nothing", out)
	}
	if !strings.Contains(errOut, "alice") || !strings.Contains(errOut, "--recover") {
		t.Errorf("re-run stderr = %q, want the state: alice, and how to recover", errOut)
	}
	if all, _ := st.Accounts().List(ctx); len(all) != 1 {
		t.Errorf("accounts after re-run = %+v, want only alice", all)
	}
}

func TestInitFirstAdmin_RefusesAShortPasswordAndCreatesNothing(t *testing.T) {
	st := openInitStore(t)
	io := newInitIO(t, "short\n")
	if code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if out, _ := io.read(t); out != "" {
		t.Errorf("stdout = %q, want nothing", out)
	}
	if all, _ := st.Accounts().List(context.Background()); len(all) != 0 {
		t.Errorf("accounts = %+v, want none", all)
	}
}

func TestInitFirstAdmin_RefusesAnEmptyStdinAndAnInvalidName(t *testing.T) {
	st := openInitStore(t)
	io := newInitIO(t, "")
	if code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr); code != 1 {
		t.Errorf("empty stdin: exit %d, want 1", code)
	}
	io = newInitIO(t, initTestPassword+"\n")
	if code := initFirstAdmin(context.Background(), st, "bad name", 0, io.stdin, io.stdout, io.stderr); code != 2 {
		t.Errorf("invalid name: exit %d, want 2", code)
	}
	if all, _ := st.Accounts().List(context.Background()); len(all) != 0 {
		t.Errorf("accounts = %+v, want none", all)
	}
}

func TestInitRecover_MintsForAnEnabledHumanAdminOnly(t *testing.T) {
	st := openInitStore(t)
	ctx := context.Background()
	mk := func(name string, kind accounts.Kind, role accounts.Role, enabled bool) {
		t.Helper()
		if _, err := st.Accounts().Create(ctx, accounts.Account{Name: name, Kind: kind, Role: role, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if !enabled {
			a, _ := st.Accounts().GetByName(ctx, name)
			if err := st.Accounts().SetEnabled(ctx, a.ID, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("alice", accounts.KindHuman, accounts.RoleAdmin, true)
	mk("dora", accounts.KindHuman, accounts.RoleAdmin, false)
	mk("olga", accounts.KindHuman, accounts.RoleOperator, true)
	mk("bot", accounts.KindMachine, accounts.RoleAdmin, true)

	for _, name := range []string{"dora", "olga", "bot", "nobody"} {
		io := newInitIO(t, "")
		if code := initRecover(ctx, st, name, 0, io.stdout, io.stderr); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if out, _ := io.read(t); out != "" {
			t.Errorf("%s: stdout = %q, want nothing", name, out)
		}
	}
	if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
		t.Errorf("%d audit records after refusals, want none", len(recs))
	}

	io := newInitIO(t, "")
	if code := initRecover(ctx, st, "alice", 0, io.stdout, io.stderr); code != 0 {
		_, e := io.read(t)
		t.Fatalf("alice: exit %d: %s", code, e)
	}
	out, _ := io.read(t)
	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	if acct, _, err := svc.Verify(ctx, strings.TrimSuffix(out, "\n")); err != nil || acct.Name != "alice" {
		t.Errorf("the recovered credential verifies as %+v (err %v), want alice", acct, err)
	}
	recs, _ := st.Audit().List(ctx)
	if len(recs) != 1 || recs[0].Kind != audit.KindAPITokenMint || recs[0].Principal != audit.PrincipalLocalHost {
		t.Errorf("audit trail = %+v, want one api_token_mint by %s", recs, audit.PrincipalLocalHost)
	}
}

// A credential that cannot be written is not reported as delivered: the command
// fails and names the token to revoke.
func TestEmitCredential_AFailedWriteFailsAndNamesTheToken(t *testing.T) {
	io := newInitIO(t, "")
	closed, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if code := emitCredential(closed, io.stderr, "glp_x.y", "tok-1"); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if _, errOut := io.read(t); !strings.Contains(errOut, "tok-1") || strings.Contains(errOut, "glp_x.y") {
		t.Errorf("stderr = %q, want the token id and never the credential", errOut)
	}
}

// --ttl sets the lifetime of the token either path mints; without it the token
// does not expire.
// Proves RC-28.
func TestInit_TTLAppliesToTheFirstAndTheRecoveredToken(t *testing.T) {
	st := openInitStore(t)
	ctx := context.Background()
	svc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	expiry := func(out string) time.Time {
		t.Helper()
		_, tok, err := svc.Verify(ctx, strings.TrimSuffix(out, "\n"))
		if err != nil {
			t.Fatalf("the credential does not verify: %v", err)
		}
		return tok.ExpiresAt
	}

	io := newInitIO(t, initTestPassword+"\n")
	before := time.Now()
	if code := initFirstAdmin(ctx, st, "alice", 24*time.Hour, io.stdin, io.stdout, io.stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out, _ := io.read(t)
	if exp := expiry(out); exp.Before(before.Add(24*time.Hour-time.Minute)) || exp.After(time.Now().Add(24*time.Hour+time.Minute)) {
		t.Errorf("first token expires at %v, want about 24h from now", exp)
	}

	io = newInitIO(t, "")
	if code := initRecover(ctx, st, "alice", 2*time.Hour, io.stdout, io.stderr); code != 0 {
		t.Fatalf("recover exit %d", code)
	}
	out, _ = io.read(t)
	if exp := expiry(out); exp.Before(time.Now().Add(2*time.Hour-time.Minute)) || exp.After(time.Now().Add(2*time.Hour+time.Minute)) {
		t.Errorf("recovered token expires at %v, want about 2h from now", exp)
	}

	io = newInitIO(t, "")
	if code := initRecover(ctx, st, "alice", 0, io.stdout, io.stderr); code != 0 {
		t.Fatalf("recover exit %d", code)
	}
	out, _ = io.read(t)
	if exp := expiry(out); !exp.IsZero() {
		t.Errorf("a token minted without --ttl expires at %v, want never", exp)
	}
}

// A name a machine Account already holds is refused before the password is
// asked for, on a store with no human Account.
func TestInitFirstAdmin_RefusesATakenNameBeforeThePrompt(t *testing.T) {
	st := openInitStore(t)
	ctx := context.Background()
	if _, err := st.Accounts().Create(ctx, accounts.Account{Name: "alice", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	io := newInitIO(t, "") // an empty stdin: reaching the prompt would fail differently
	if code := initFirstAdmin(ctx, st, "Alice", 0, io.stdin, io.stdout, io.stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	out, errOut := io.read(t)
	if out != "" || !strings.Contains(errOut, "already exists") || strings.Contains(errOut, "stdin") {
		t.Errorf("stdout %q, stderr %q: want the name refusal, before any password read", out, errOut)
	}
	if all, _ := st.Accounts().List(ctx); len(all) != 1 {
		t.Errorf("accounts = %+v, want only the machine Account", all)
	}
}

// With only disabled human Accounts, init names the way out rather than only the
// state.
func TestInitFirstAdmin_OnlyDisabledHumansNamesTheWayOut(t *testing.T) {
	st := openInitStore(t)
	ctx := context.Background()
	if _, err := st.Accounts().Create(ctx, accounts.Account{Name: "bot", Kind: accounts.KindMachine, Role: accounts.RoleAdmin, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	dora, err := st.Accounts().Create(ctx, accounts.Account{Name: "dora", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Accounts().SetEnabled(ctx, dora.ID, false); err != nil {
		t.Fatal(err)
	}
	io := newInitIO(t, initTestPassword+"\n")
	if code := initFirstAdmin(ctx, st, "alice", 0, io.stdin, io.stdout, io.stderr); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	out, errOut := io.read(t)
	if out != "" {
		t.Errorf("stdout = %q, want nothing", out)
	}
	for _, want := range []string{"No human admin is enabled", "machine Account", "/enable", "local root"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr does not say %q:\n%s", want, errOut)
		}
	}
}

func TestReadLine_RefusesAnOverlongLineRatherThanTruncatingIt(t *testing.T) {
	long := strings.Repeat("x", accounts.MaxPasswordBytes+50)
	got, err := readLine(strings.NewReader(long + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.NewPassword(got).Validate(); err == nil {
		t.Error("an over-long line became a valid password")
	}
	got, _ = readLine(strings.NewReader("pass word\r\nnext\n"))
	if got != "pass word" {
		t.Errorf("readLine = %q, want the first line without its ending", got)
	}
}
