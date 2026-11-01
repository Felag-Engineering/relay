package main

// init_mint.go is relay init's mint form (EN-46) and its reveal (EN-39). init
// mints only in the run that created the founding admin, before that admin's
// credential is emitted (ADR-0030). It mints through the capability layer's
// mint-form entry, so the Console and init share one floor, one cap and one
// record (invariant 10, EN-36).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const (
	// initFormAttempts is the answers allowed per question before the form gives up.
	initFormAttempts = 3
	// initFormInputLimit is the total bytes the form reads.
	initFormInputLimit = 4096

	initMintLater        = "Nothing was minted. Mint the first join string on the Console's Add Nodes form, or with POST /api/v1/enrollment-tokens."
	initNoTerminalNoMint = "No Enrollment Token was minted: relay init mints the first join string only when stdin and stdout are a terminal. Mint one on the Console's Add Nodes form, or with POST /api/v1/enrollment-tokens."
)

// initInteractive reports whether init may show a join string: stdin and
// stdout are both terminals. The join string is shown to a person and never
// captured: with stdout piped (relay init --admin alice into vault kv put, as
// docs/operations/control-plane-credential.md documents) it would land in the
// capture, so init does not mint. The shipped Relay is Linux-only; the
// non-Linux isTerminal is a development-build convenience.
func initInteractive(stdin, stdout *os.File) bool {
	return isTerminal(stdin) && isTerminal(stdout)
}

// initFormMinter is the mint-form entry of the capability mint, and only it.
type initFormMinter interface {
	MintEnrollmentTokenFromForm(ctx context.Context, p capability.Principal, f capability.EnrollmentMintForm) (capability.MintedEnrollmentToken, error)
}

// initMintForm asks for a count and an expiry and mints the first Enrollment
// Token. in is the terminal, read with echo on because neither answer is a
// secret; prompt is stderr and out is stdout.
type initMintForm struct {
	tokens initFormMinter
	in     io.Reader
	prompt io.Writer
	out    io.Writer
}

// initEnrollmentTokens builds the Enrollment Token mint over the store the
// Relay shares with init: the same RoleGate floor, the same trail and the same
// newEnrollmentMint the server uses. init holds no enroll.Minter.
func initEnrollmentTokens(st *store.Store, fingerprints enroll.FingerprintSource, advertisedAddress string, logger *slog.Logger) (*capability.EnrollmentTokens, error) {
	rec := capability.NewRecorder(auditsink.New(st.Audit(), auditsink.WithLogger(logger)), nil, logger)
	control := capability.NewControl(rec, authz.NewRoleGate(), st.Freeze())
	tokens, _, err := newEnrollmentMint(control, enroll.NewService(st.Tokens()), fingerprints, advertisedAddress)
	return tokens, err
}

// newInitMintForm builds the form over the Relay's existing CA. It creates no
// CA: init acts on what the Relay made at its first start (RC-28).
func newInitMintForm(st *store.Store, cfg Config, stdin, stdout, stderr *os.File) (*initMintForm, error) {
	relayCA, err := ca.OpenExisting(cfg.CADir)
	if errors.Is(err, ca.ErrAbsent) {
		return nil, fmt.Errorf("the Relay's CA in %s does not exist yet. Start the Relay first: it creates its CA and store at its first start", cfg.CADir)
	}
	if err != nil {
		return nil, fmt.Errorf("open the Relay's CA: %w", err)
	}
	addr, err := advertisedNodePlaneAddress(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := initEnrollmentTokens(st, relayCA, addr, slog.Default())
	if err != nil {
		return nil, err
	}
	return &initMintForm{tokens: formEnrollmentMint{tokens: tokens}, in: stdin, prompt: stderr, out: stdout}, nil
}

// foundingAdminPrincipal is the founding admin as the capability layer sees it.
// AuthMethod, Source and TokenID stay empty: this mint arrived through no
// network or token boundary.
func foundingAdminPrincipal(a accounts.Account) capability.Principal {
	return capability.Principal{AccountID: a.ID, Account: a.Name, Role: string(a.Role), Kind: string(a.Kind)}
}

// ask puts the two questions and mints. It writes every question and refusal
// to f.prompt and nothing to f.out. It never guesses a count.
func (f *initMintForm) ask(ctx context.Context, p capability.Principal) (capability.MintedEnrollmentToken, bool) {
	// One buffered reader for the whole form, so no answer is lost to a second buffer.
	r := bufio.NewReader(io.LimitReader(f.in, initFormInputLimit))
	line := func() (string, bool) {
		s, err := r.ReadString('\n')
		if err != nil && s == "" {
			return "", false
		}
		return strings.TrimSpace(s), true
	}

	fmt.Fprintln(f.prompt, "Now the first Enrollment Token, for the Nodes that join first.")
	fmt.Fprintf(f.prompt, "If you abandon this prompt, the admin already exists: relay init --recover %s mints its API Token again.\n", p.Account)

	nodes, ok := f.askNodes(line)
	if !ok {
		return capability.MintedEnrollmentToken{}, false
	}
	for range initFormAttempts {
		fmt.Fprintf(f.prompt, "It expires after (default %dh): ", int(capability.DefaultEnrollmentTokenTTL/time.Hour))
		answer, ok := line()
		if !ok {
			fmt.Fprintln(f.prompt)
			return capability.MintedEnrollmentToken{}, false
		}
		ttl := capability.DefaultEnrollmentTokenTTL
		if answer != "" {
			d, err := time.ParseDuration(answer)
			if err != nil {
				fmt.Fprintln(f.prompt, "relay init: give the expiry as a duration such as 30m, 2h or 24h.")
				continue
			}
			ttl = d
		}
		minted, err := f.tokens.MintEnrollmentTokenFromForm(ctx, p, capability.EnrollmentMintForm{Nodes: nodes, TTL: ttl})
		if errors.Is(err, capability.ErrEnrollmentTTL) {
			fmt.Fprintf(f.prompt, "relay init: an Enrollment Token's expiry is positive and at most one year (%dh).\n", int(capability.MaxEnrollmentTokenTTL/time.Hour))
			continue
		}
		if err != nil {
			f.explainMintFailure(err)
			return capability.MintedEnrollmentToken{}, false
		}
		return minted, true
	}
	return capability.MintedEnrollmentToken{}, false
}

// askNodes asks how many Nodes the token is for. The capability layer decides
// the bound; the form only pre-checks it to re-ask (invariant 10).
func (f *initMintForm) askNodes(line func() (string, bool)) (int, bool) {
	for range initFormAttempts {
		fmt.Fprintf(f.prompt, "How many Nodes is it for? (1 to %d): ", capability.MaxEnrollmentFormNodes)
		answer, ok := line()
		if !ok {
			fmt.Fprintln(f.prompt)
			return 0, false
		}
		n, err := strconv.Atoi(answer)
		if err != nil {
			fmt.Fprintf(f.prompt, "relay init: say how many Nodes, as a whole number from 1 to %d.\n", capability.MaxEnrollmentFormNodes)
			continue
		}
		if capability.CheckEnrollmentFormNodes(n) == nil {
			return n, true
		}
		if n > capability.MaxEnrollmentFormNodes {
			fmt.Fprintf(f.prompt, "relay init: a token from this form is for at most %d Nodes, and there is no unlimited token.\n", capability.MaxEnrollmentFormNodes)
		} else {
			fmt.Fprintln(f.prompt, "relay init: a token is for at least 1 Node.")
		}
	}
	return 0, false
}

// explainMintFailure says why the mint failed. The capability errors are
// constant text and never carry the join string.
func (f *initMintForm) explainMintFailure(err error) {
	var live *capability.EnrollmentTokenLiveError
	switch {
	case errors.As(err, &live):
		fmt.Fprintf(f.prompt, "relay init: the mint could not be recorded and token %s could not be withdrawn, so it may admit Nodes until it expires: revoke it (DELETE /api/v1/enrollment-tokens/%s). No join string is shown.\n", live.TokenID, live.TokenID)
	case errors.Is(err, capability.ErrEnrollmentMintNotRecorded):
		fmt.Fprintln(f.prompt, "relay init: the mint could not be recorded, so its token was withdrawn and admits no Node.")
	default:
		fmt.Fprintf(f.prompt, "relay init: mint the first Enrollment Token: %v\n", err)
	}
}

// reveal shows the command and, apart from it, the join string. The one
// Fprintln to f.out is the only place the string leaves the process. It
// returns the exit code.
func (f *initMintForm) reveal(m capability.MintedEnrollmentToken, by string) int {
	fmt.Fprintf(f.prompt, "Minted Enrollment Token %s for %d Nodes, expiring %s.\n", m.ID(), m.MaxUses(), m.ExpiresAt().UTC().Format(time.RFC3339))
	fmt.Fprintf(f.prompt, "Recorded on the audit trail as %s, attributed to %s.\n", audit.KindTokenMint, by)
	fmt.Fprintln(f.prompt, "On each Node, run:")
	fmt.Fprintln(f.prompt)
	fmt.Fprintln(f.prompt, "    sudo relay-daemon join")
	fmt.Fprintln(f.prompt)
	fmt.Fprintln(f.prompt, "and paste the join string below at its prompt. It is shown once and nothing shows it again: a lost one means minting another token. Move it only over SSH or your vault, never chat, email or a ticket.")
	if _, err := fmt.Fprintln(f.out, m.JoinString()); err != nil {
		fmt.Fprintf(f.prompt, "relay init: writing the join string to stdout failed: %v\n", err)
		fmt.Fprintf(f.prompt, "Token %s was minted and recorded but not delivered: revoke it (DELETE /api/v1/enrollment-tokens/%s), and mint another on the Console's Add Nodes form.\n", m.ID(), m.ID())
		return 1
	}
	return 0
}
