package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// initMintTestAddress is the node-plane address the tests that need no running
// Relay give the mint.
const initMintTestAddress = "relay.example.com:7654"

// fakeInitMinter stands in for the capability mint. A nil result with a nil
// error would be a bug in the test, so the zero value fails the test if called
// without a purpose.
type fakeInitMinter struct {
	t     *testing.T
	err   error
	calls int
}

func (m *fakeInitMinter) MintEnrollmentTokenFromForm(context.Context, capability.Principal, capability.EnrollmentMintForm) (capability.MintedEnrollmentToken, error) {
	m.t.Helper()
	m.calls++
	if m.err == nil {
		m.t.Fatal("the form reached the mint, which this case says it must not")
	}
	return capability.MintedEnrollmentToken{}, m.err
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func tokenMintRecords(t *testing.T, st *store.Store) []audit.Record {
	t.Helper()
	recs, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindTokenMint {
			out = append(out, r)
		}
	}
	return out
}

// formOver returns an init form that answers from input over the real capability mint.
func formOver(t *testing.T, st *store.Store, io initIO, input string) *initMintForm {
	t.Helper()
	tokens, err := initEnrollmentTokens(st, mintTestFingerprintSource{}, initMintTestAddress, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return &initMintForm{tokens: formEnrollmentMint{tokens: tokens}, in: strings.NewReader(input), prompt: io.stderr, out: io.stdout}
}

func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

// Proves EN-39. Proves EN-46.
func TestInitMintForm_ThreeNodesJoinAndAFourthIsRefused(t *testing.T) {
	var cfg Config
	f := startRelay(t, WithConfig(func(c *Config) {
		c.EnrollIPBurst = 10
		cfg = *c
	}))
	ctx := context.Background()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	addr, err := advertisedNodePlaneAddress(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := initEnrollmentTokens(f.Deps.store, f.Deps.ca, addr, logger)
	if err != nil {
		t.Fatal(err)
	}

	io := newInitIO(t, initTestPassword+"\n")
	openForm := func() (*initMintForm, error) {
		return &initMintForm{tokens: formEnrollmentMint{tokens: tokens}, in: strings.NewReader("3\n\n"), prompt: io.stderr, out: io.stdout}, nil
	}
	if code := initFirstAdmin(ctx, f.Deps.store, "alice", 0, io.stdin, io.stdout, io.stderr, openForm); code != 0 {
		_, e := io.read(t)
		t.Fatalf("exit %d: %s", code, e)
	}
	out, errOut := io.read(t)

	outLines := lines(out)
	if len(outLines) != 2 {
		t.Fatalf("stdout = %q, want the API Token then the join string", out)
	}
	joinString := outLines[1]
	js, err := enroll.DecodeJoinString(joinString)
	if err != nil {
		t.Fatalf("the second stdout line is not a join string: %v", err)
	}
	if fp := f.Deps.ca.Fingerprint(); fmt.Sprintf("%x", js.CAFingerprint()) != fp {
		t.Errorf("join string fingerprint = %x, want the running Relay's CA %s", js.CAFingerprint(), fp)
	}
	serverMinted, err := f.Deps.minter.Mint(ctx, nil, time.Hour, enroll.UseLimit{MaxUses: 1}, testHumanMinter)
	if err != nil {
		t.Fatal(err)
	}
	serverJS, err := enroll.DecodeJoinString(serverMinted.JoinString())
	if err != nil {
		t.Fatal(err)
	}
	if js.RelayAddress() != serverJS.RelayAddress() {
		t.Errorf("join string address = %q, the server's mint puts %q", js.RelayAddress(), serverJS.RelayAddress())
	}

	var sawCommand bool
	for _, l := range lines(errOut) {
		if l == "    sudo relay-daemon join" {
			sawCommand = true
		}
	}
	if !sawCommand {
		t.Errorf("stderr has no line that is exactly the join command: %s", errOut)
	}
	for _, l := range append(outLines, lines(errOut)...) {
		if strings.Contains(l, "relay-daemon") && strings.Contains(l, joinString) {
			t.Errorf("a line holds the command and the join string: %q", l)
		}
	}

	alice, err := f.Deps.store.Accounts().GetByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	mints := tokenMintRecords(t, f.Deps.store)
	if len(mints) != 1 {
		t.Fatalf("token_mint records = %d, want one", len(mints))
	}
	tokenID := strings.TrimPrefix(mints[0].Reason, "token_id=")
	stored, err := f.Deps.store.Tokens().ByID(ctx, tokenID)
	if err != nil {
		t.Fatalf("ByID(%s): %v", tokenID, err)
	}
	if stored.MaxUses != 3 || !stored.CreatedByHuman || stored.CreatedByAccountID != alice.ID {
		t.Errorf("stored token = %+v, want 3 uses, human, by alice", stored)
	}
	if d := time.Until(stored.ExpiresAt) - 2*time.Hour; d > time.Minute || d < -time.Minute {
		t.Errorf("ExpiresAt is %v off two hours from now", d)
	}

	enrollConn := dialTLS(t, f.Bufconn, &tls.Config{RootCAs: relaytest.CertPool(t, f.Deps.ca.Bundle())})
	for i := range 4 {
		csrPEM, _ := relaytest.NewCSR(t, "ignored-cn")
		_, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
			EnrollmentToken: js.EnrollmentToken(), Csr: csrPEM,
			Facts: &relayv1.Facts{Hostname: fmt.Sprintf("host-init-%d", i), Os: "linux"},
		})
		if i < 3 && err != nil {
			t.Fatalf("Enroll %d with the join string: %v", i, err)
		}
		if i == 3 && err == nil {
			t.Fatal("a fourth Node enrolled on a token for three")
		}
	}
	if got := len(f.Deps.registry.List()); got != 3 {
		t.Errorf("registry holds %d Nodes, want 3", got)
	}

	// The one record is the capability layer's own, written by the same floor the
	// Console's form uses (EN-36).
	recs := tokenMintRecords(t, f.Deps.store)
	if len(recs) != 1 || recs[0].Attribution.Verified.AccountID != alice.ID {
		t.Fatalf("token_mint records = %+v, want one by alice", recs)
	}

	all, err := f.Deps.store.Audit().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{joinString, js.EnrollmentToken()}
	for i, r := range all {
		b, _ := json.Marshal(r)
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("audit record %d carries the join string or token", i)
			}
		}
	}
	files := map[string][]byte{"log": logs.Bytes(), "stderr": []byte(errOut)}
	mainDB, err := os.ReadFile(cfg.StorePath)
	if err != nil {
		t.Fatalf("read the store file: %v", err)
	}
	files[cfg.StorePath] = mainDB
	if b, err := os.ReadFile(cfg.StorePath + "-wal"); err == nil {
		files[cfg.StorePath+"-wal"] = b
	}
	for name, b := range files {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds the join string or token", name)
			}
		}
	}
}

// Proves EN-46: a count outside 1 to 256, or not a number, mints nothing, names
// the limit, and init still emits the founding API Token.
func TestInitMintForm_ACountOutside1To256OrNotANumberMintsNothing(t *testing.T) {
	for name, input := range map[string]string{
		"257, 0 and a word": "257\n0\nthree\n",
		"end of input":      "",
	} {
		t.Run(name, func(t *testing.T) {
			st := openInitStore(t)
			io := newInitIO(t, initTestPassword+"\n")
			minter := &fakeInitMinter{t: t, err: errors.New("unreachable")}
			form := &initMintForm{tokens: minter, in: strings.NewReader(input), prompt: io.stderr, out: io.stdout}
			code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr, func() (*initMintForm, error) { return form, nil })
			if code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			out, errOut := io.read(t)
			if len(lines(out)) != 1 {
				t.Errorf("stdout = %q, want the API Token alone", out)
			}
			if name != "end of input" && (!strings.Contains(errOut, "at most 256 Nodes") || !strings.Contains(errOut, "no unlimited token")) {
				t.Errorf("stderr does not name the limit: %s", errOut)
			}
			if !strings.Contains(errOut, initMintLater) {
				t.Errorf("stderr does not say how to mint later: %s", errOut)
			}
			if minter.calls != 0 || len(tokenMintRecords(t, st)) != 0 {
				t.Errorf("minted %d times, %d records; want none", minter.calls, len(tokenMintRecords(t, st)))
			}
		})
	}

	t.Run("a refused count re-asks and a valid one mints", func(t *testing.T) {
		st := openInitStore(t)
		io := newInitIO(t, "")
		form := formOver(t, st, io, "257\n2\n\n")
		minted, ok := form.ask(context.Background(), capability.Principal{AccountID: "a-1", Account: "alice", Role: "admin", Kind: "human"})
		if !ok || minted.MaxUses() != 2 || len(tokenMintRecords(t, st)) != 1 {
			t.Fatalf("minted = %v ok = %v, records = %d; want one token for 2 Nodes", minted, ok, len(tokenMintRecords(t, st)))
		}
	})

	// The capability layer holds the bound itself: past the form's own pre-check,
	// 257 is refused and nothing is minted (EN-31, EN-36).
	t.Run("the capability layer refuses 257 on its own", func(t *testing.T) {
		st := openInitStore(t)
		tokens, err := initEnrollmentTokens(st, mintTestFingerprintSource{}, initMintTestAddress, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		admin := capability.Principal{AccountID: "a-1", Account: "alice", Role: "admin", Kind: "human"}
		_, err = tokens.MintEnrollmentTokenFromForm(context.Background(), admin, capability.EnrollmentMintForm{Nodes: 257, TTL: time.Hour})
		if !errors.Is(err, capability.ErrEnrollmentFormNodes) {
			t.Fatalf("err = %v, want ErrEnrollmentFormNodes", err)
		}
		if n := len(tokenMintRecords(t, st)); n != 0 {
			t.Errorf("%d token_mint records after a refused mint", n)
		}
	})
}

// Proves EN-46: the expiry defaults to two hours and may be changed.
func TestInitMintForm_TheExpiryDefaultsToTwoHoursAndMayBeChanged(t *testing.T) {
	admin := capability.Principal{AccountID: "a-1", Account: "alice", Role: "admin", Kind: "human"}
	for name, c := range map[string]struct {
		input string
		want  time.Duration
	}{
		"empty":                 {"1\n\n", 2 * time.Hour},
		"8h":                    {"1\n8h\n", 8 * time.Hour},
		"too long then 8h":      {"1\n9000h\n8h\n", 8 * time.Hour},
		"not a duration, 30m":   {"1\nsoon\n30m\n", 30 * time.Minute},
		"last line, no newline": {"1\n45m", 45 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			st := openInitStore(t)
			io := newInitIO(t, "")
			form := formOver(t, st, io, c.input)
			minted, ok := form.ask(context.Background(), admin)
			if !ok {
				_, e := io.read(t)
				t.Fatalf("ask did not mint: %s", e)
			}
			if d := time.Until(minted.ExpiresAt()) - c.want; d > time.Minute || d < -time.Minute {
				t.Errorf("expires %v off %v", d, c.want)
			}
			if n := len(tokenMintRecords(t, st)); n != 1 {
				t.Errorf("token_mint records = %d, want 1", n)
			}
			out, prompted := io.read(t)
			if out != "" {
				t.Errorf("the form wrote %q to stdout", out)
			}
			if !strings.Contains(prompted, "(default 2h): ") {
				t.Errorf("the prompt does not say (default 2h): %q", prompted)
			}
		})
	}
}

// Proves EN-39: without a terminal, init mints nothing and says how to mint later.
func TestInitFirstAdmin_WithoutATerminalMintsNothing(t *testing.T) {
	st := openInitStore(t)
	io := newInitIO(t, initTestPassword+"\n")
	if code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr, nil); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out, errOut := io.read(t)
	if len(lines(out)) != 1 {
		t.Errorf("stdout = %q, want the API Token alone", out)
	}
	if !strings.Contains(errOut, initNoTerminalNoMint) || !strings.Contains(errOut, "Add Nodes") || !strings.Contains(errOut, "/api/v1/enrollment-tokens") {
		t.Errorf("stderr does not say how to mint later: %s", errOut)
	}
	if n := len(tokenMintRecords(t, st)); n != 0 {
		t.Errorf("token_mint records = %d, want 0", n)
	}
}

// Proves EN-39: a mint that fails leaves the admin and its API Token, shows no
// join string and says how to mint later.
func TestInitMintForm_AFailedMintSaysHowToMintLater(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want []string
	}{
		"not recorded": {fmt.Errorf("mint: %w", capability.ErrEnrollmentMintNotRecorded), []string{"withdrawn"}},
		"may be live": {&capability.EnrollmentTokenLiveError{TokenID: "tok-1", RecordErr: errors.New("r"), WithdrawErr: errors.New("w")},
			[]string{"tok-1", "DELETE /api/v1/enrollment-tokens/tok-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			st := openInitStore(t)
			io := newInitIO(t, initTestPassword+"\n")
			form := &initMintForm{tokens: &fakeInitMinter{t: t, err: c.err}, in: strings.NewReader("2\n\n"), prompt: io.stderr, out: io.stdout}
			code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr, func() (*initMintForm, error) { return form, nil })
			if code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			out, errOut := io.read(t)
			if len(lines(out)) != 1 || strings.Contains(out, enroll.JoinStringPrefix) {
				t.Errorf("stdout = %q, want the API Token alone", out)
			}
			for _, w := range c.want {
				if !strings.Contains(errOut, w) {
					t.Errorf("stderr lacks %q: %s", w, errOut)
				}
			}
			if !strings.Contains(errOut, initMintLater) {
				t.Errorf("stderr lacks the mint-later line: %s", errOut)
			}
		})
	}
}

// Proves EN-39. Mirrors TestEmitCredential_AFailedWriteFailsAndNamesTheToken.
func TestInitMintForm_RevealWriteFailureNamesTheTokenToRevoke(t *testing.T) {
	var prompt bytes.Buffer
	form := &initMintForm{prompt: &prompt, out: failingWriter{}}
	m := capability.NewMintedEnrollmentToken("tok-9", "secret", enroll.JoinStringPrefix+"abc", nil, time.Now().Add(time.Hour), 2, false)
	if code := form.reveal(m, "alice:admin"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	got := prompt.String()
	if !strings.Contains(got, "tok-9") || !strings.Contains(got, "DELETE /api/v1/enrollment-tokens/tok-9") {
		t.Errorf("stderr does not name the token to revoke: %s", got)
	}
	if strings.Contains(got, enroll.JoinStringPrefix) || strings.Contains(got, "secret") {
		t.Errorf("stderr carries the join string: %s", got)
	}
}

// Proves EN-39: a form that cannot be built refuses before anything is created.
func TestInitFirstAdmin_AFormThatCannotBeBuiltCreatesNothing(t *testing.T) {
	st := openInitStore(t)
	io := newInitIO(t, initTestPassword+"\n")
	code := initFirstAdmin(context.Background(), st, "alice", 0, io.stdin, io.stdout, io.stderr, func() (*initMintForm, error) {
		return nil, errors.New("the Relay's CA does not exist yet")
	})
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	out, errOut := io.read(t)
	if out != "" || !strings.Contains(errOut, "Nothing was created.") {
		t.Errorf("stdout %q, stderr %q", out, errOut)
	}
	if all, _ := st.Accounts().List(context.Background()); len(all) != 0 {
		t.Errorf("accounts = %+v, want none", all)
	}
}
