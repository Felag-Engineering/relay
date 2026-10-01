package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// trailOf reopens the store at path and returns its whole audit trail.
func trailOf(t *testing.T, path string) []audit.Record {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	recs, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("List audit: %v", err)
	}
	return recs
}

// requireEmptyTrail fails if a refused command wrote an audit record.
func requireEmptyTrail(t *testing.T, path string) {
	t.Helper()
	if recs := trailOf(t, path); len(recs) != 0 {
		t.Errorf("a refused command wrote %d audit records: %+v", len(recs), recs)
	}
}

// collideAuditID makes every host lever's audit record collide with a record
// already on the trail, so the record cannot be written. It swaps a package
// var, so callers must not be parallel.
func collideAuditID(t *testing.T, path string) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	err = st.Audit().Append(context.Background(), audit.Record{
		ID: "collide", Timestamp: time.Now().UTC(), Kind: audit.KindPasswordSet, Principal: audit.PrincipalLocalHost,
	})
	st.Close() //nolint:errcheck
	if err != nil {
		t.Fatalf("seed colliding record: %v", err)
	}
	orig := hostAuditID
	hostAuditID = func() (string, error) { return "collide", nil }
	t.Cleanup(func() { hostAuditID = orig })
}

// requireHostLeverRecord checks rec is attributed to the local host, not an
// Account, and carries no trace of secret.
func requireHostLeverRecord(t *testing.T, rec audit.Record, kind string, secrets ...string) {
	t.Helper()
	if rec.Kind != kind {
		t.Errorf("Kind = %q, want %q", rec.Kind, kind)
	}
	if rec.Principal != audit.PrincipalLocalHost {
		t.Errorf("Principal = %q, want %q", rec.Principal, audit.PrincipalLocalHost)
	}
	if rec.Attribution.Verified.AccountID != "" {
		t.Errorf("Verified.AccountID = %q, want empty: a host lever is not an Account", rec.Attribution.Verified.AccountID)
	}
	fields := []string{
		rec.Principal, rec.Selector, rec.Reason, string(rec.Stdout), string(rec.Stderr),
		rec.Attribution.Verified.AccountName, rec.Attribution.Verified.Role, rec.Attribution.Verified.TokenID,
		rec.Attribution.Verified.Method, rec.Attribution.Verified.Source,
		rec.Attribution.Asserted.OnBehalfOf, rec.Attribution.Asserted.SessionRef,
		rec.Attribution.Asserted.ChangeRef, rec.Attribution.Asserted.Traceparent,
	}
	for _, v := range rec.Args {
		fields = append(fields, v)
	}
	for _, secret := range secrets {
		for _, f := range fields {
			if strings.Contains(f, secret) {
				t.Errorf("a record field carries a secret (%q in %q)", secret, f)
			}
		}
	}
}

// consolePasswordFixture opens a store with a seeded founding admin and
// returns its path.
func consolePasswordFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.Accounts().EnsureFoundingAdmin(context.Background()); err != nil {
		t.Fatalf("seed founding admin: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return path
}

// run invokes the subcommand with stdout and stderr captured to temp files,
// returning the exit code and both streams.
func runConsolePassword(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()

	mk := func(name, contents string) *os.File {
		f, err := os.CreateTemp(t.TempDir(), name)
		if err != nil {
			t.Fatalf("temp %s: %v", name, err)
		}
		if contents != "" {
			if _, err := f.WriteString(contents); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			if _, err := f.Seek(0, 0); err != nil {
				t.Fatalf("seek %s: %v", name, err)
			}
		}
		return f
	}
	in, out, errF := mk("stdin", stdin), mk("stdout", ""), mk("stderr", "")

	code := runConsolePasswordCommand(args, in, out, errF)

	read := func(f *os.File) string {
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatalf("seek: %v", err)
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(b)
	}
	return code, read(out), read(errF)
}

func TestConsolePassword_SetsAPasswordThatVerifies(t *testing.T) {
	path := consolePasswordFixture(t)

	code, stdout, stderr := runConsolePassword(t, "a strong console passphrase\n",
		"-store-path", path, "-account", accounts.FoundingAdminName)
	if code != 0 {
		t.Fatalf("exit %d; stderr = %s", code, stderr)
	}
	// Nothing on stdout: there is no credential to emit, and echoing the
	// password would put it in the terminal scrollback.
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if strings.Contains(stderr, "a strong console passphrase") {
		t.Error("the subcommand echoed the password to stderr")
	}

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	ctx := context.Background()
	admin, err := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	if err != nil {
		t.Fatalf("get founding admin: %v", err)
	}
	hash, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if !hash.Verify(accounts.NewPassword("a strong console passphrase")) {
		t.Error("the stored hash does not verify the password that was set")
	}
	// The trailing newline is stripped: a credential that silently includes
	// one is a credential nobody can reproduce.
	if hash.Verify(accounts.NewPassword("a strong console passphrase\n")) {
		t.Error("the stored password includes the trailing newline")
	}
}

func TestConsolePassword_ReadsAPasswordFile(t *testing.T) {
	path := consolePasswordFixture(t)
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("a strong console passphrase\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	code, _, stderr := runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-password-file", pwFile)
	if code != 0 {
		t.Fatalf("exit %d; stderr = %s", code, stderr)
	}
}

func TestConsolePassword_HasNoFlagThatTakesThePassword(t *testing.T) {
	path := consolePasswordFixture(t)

	// A password passed on a command line is a password in every process
	// listing and shell history. There must be no such flag — asserted by
	// running one and requiring a usage error rather than by reading the code.
	code, _, _ := runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-password", "hunter2hunter2")
	if code == 0 {
		t.Fatal("-password was accepted; a password on a command line is a password in every process listing")
	}
}

func TestConsolePassword_RefusesAShortPassword(t *testing.T) {
	path := consolePasswordFixture(t)

	code, _, stderr := runConsolePassword(t, "short\n",
		"-store-path", path, "-account", accounts.FoundingAdminName)
	if code == 0 {
		t.Fatal("a password below the minimum was accepted")
	}
	requireEmptyTrail(t, path)
	// Say WHY the floor is where it is: an operator who understands the reason
	// picks a good passphrase, one who thinks it is bureaucracy picks the
	// shortest thing that passes.
	if !strings.Contains(stderr, "no lockout") {
		t.Errorf("the refusal does not explain the floor: %s", stderr)
	}
}

func TestConsolePassword_RefusesAMachineAccount(t *testing.T) {
	path := consolePasswordFixture(t)

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.Accounts().Create(context.Background(), accounts.Account{
		Name: "gleipnir", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
	}); err != nil {
		t.Fatalf("create machine account: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The Console establishes a per-human identity. A Console password on a
	// machine Account is a credential that can never be used, and suggests the
	// Console is somewhere a bot belongs.
	code, _, stderr := runConsolePassword(t, "a strong console passphrase\n",
		"-store-path", path, "-account", "gleipnir")
	if code == 0 {
		t.Fatal("a machine Account was given a Console password")
	}
	if !strings.Contains(stderr, "humans only") {
		t.Errorf("stderr = %s", stderr)
	}
	requireEmptyTrail(t, path)
}

func TestConsolePassword_ClearRemovesTheCredential(t *testing.T) {
	path := consolePasswordFixture(t)

	if code, _, stderr := runConsolePassword(t, "a strong console passphrase\n",
		"-store-path", path, "-account", accounts.FoundingAdminName); code != 0 {
		t.Fatalf("set: exit %d; %s", code, stderr)
	}
	if code, _, stderr := runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-clear"); code != 0 {
		t.Fatalf("clear: exit %d; %s", code, stderr)
	}

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	ctx := context.Background()
	admin, err := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	if err != nil {
		t.Fatalf("get founding admin: %v", err)
	}
	if _, err := st.Passwords().GetPassword(ctx, admin.ID); err == nil {
		t.Error("the password survived -clear")
	}
	// Clearing a credential is not disabling the identity: the Account keeps
	// its role and its API Tokens.
	if !admin.Enabled || admin.Role != accounts.RoleAdmin {
		t.Errorf("-clear changed the Account itself: %+v", admin)
	}
}

func TestConsolePassword_RefusesAnUnknownAccount(t *testing.T) {
	path := consolePasswordFixture(t)
	code, _, _ := runConsolePassword(t, "a strong console passphrase\n",
		"-store-path", path, "-account", "no-such-person")
	if code == 0 {
		t.Fatal("a password was set for an Account that does not exist")
	}
	requireEmptyTrail(t, path)
}

func TestConsolePassword_RecordsThePasswordSetAttributedToLocalHost(t *testing.T) {
	path := consolePasswordFixture(t)
	const password = "a strong console passphrase"

	code, stdout, stderr := runConsolePassword(t, password+"\n",
		"-store-path", path, "-account", accounts.FoundingAdminName)
	if code != 0 {
		t.Fatalf("exit %d; stderr = %s", code, stderr)
	}

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	ctx := context.Background()
	admin, _ := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	hash, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}

	recs := trailOf(t, path)
	if len(recs) != 1 {
		t.Fatalf("trail has %d records, want exactly one password_set", len(recs))
	}
	requireHostLeverRecord(t, recs[0], audit.KindPasswordSet, password, hash.Encoded())
	if !strings.Contains(recs[0].Reason, admin.ID) {
		t.Errorf("Reason = %q, want it to name the Account %s", recs[0].Reason, admin.ID)
	}
	if strings.Contains(stdout+stderr, hash.Encoded()) {
		t.Error("the hash reached the command's output")
	}
}

func TestConsolePassword_ClearIsRecorded(t *testing.T) {
	path := consolePasswordFixture(t)

	if code, _, stderr := runConsolePassword(t, "a strong console passphrase\n",
		"-store-path", path, "-account", accounts.FoundingAdminName); code != 0 {
		t.Fatalf("set: exit %d; %s", code, stderr)
	}
	if code, _, stderr := runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-clear"); code != 0 {
		t.Fatalf("clear: exit %d; %s", code, stderr)
	}
	// A second clear finds nothing to remove; it is still recorded, and says so.
	if code, _, stderr := runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-clear"); code != 0 {
		t.Fatalf("second clear: exit %d; %s", code, stderr)
	}

	recs := trailOf(t, path)
	if len(recs) != 3 {
		t.Fatalf("trail has %d records, want password_set, password_clear, password_clear", len(recs))
	}
	requireHostLeverRecord(t, recs[1], audit.KindPasswordClear, "a strong console passphrase")
	requireHostLeverRecord(t, recs[2], audit.KindPasswordClear)
	if !strings.HasSuffix(recs[1].Reason, "removed=true") || !strings.HasSuffix(recs[2].Reason, "removed=false") {
		t.Errorf("Reasons = %q, %q, want removed=true then removed=false", recs[1].Reason, recs[2].Reason)
	}
}

func TestConsolePassword_AnUnrecordableChangeLeavesThePasswordUnchanged(t *testing.T) {
	path := consolePasswordFixture(t)
	if code, _, stderr := runConsolePassword(t, "passphrase number one\n",
		"-store-path", path, "-account", accounts.FoundingAdminName); code != 0 {
		t.Fatalf("set: exit %d; %s", code, stderr)
	}
	collideAuditID(t, path)

	code, _, stderr := runConsolePassword(t, "passphrase number two\n",
		"-store-path", path, "-account", accounts.FoundingAdminName)
	if code == 0 {
		t.Fatal("a password change whose record could not be written succeeded")
	}
	if !strings.Contains(stderr, "The password was not changed") {
		t.Errorf("stderr does not say the password was left alone: %s", stderr)
	}
	code, _, stderr = runConsolePassword(t, "",
		"-store-path", path, "-account", accounts.FoundingAdminName, "-clear")
	if code == 0 {
		t.Fatal("a clear whose record could not be written succeeded")
	}
	if !strings.Contains(stderr, "The password was not changed") {
		t.Errorf("stderr does not say the password was left alone: %s", stderr)
	}

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	ctx := context.Background()
	admin, _ := st.Accounts().GetByName(ctx, accounts.FoundingAdminName)
	hash, err := st.Passwords().GetPassword(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if !hash.Verify(accounts.NewPassword("passphrase number one")) || hash.Verify(accounts.NewPassword("passphrase number two")) {
		t.Error("the password changed although its record could not be written")
	}
}
