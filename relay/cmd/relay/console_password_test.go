package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

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
}
