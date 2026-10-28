package console

// temporarypassword.go is the Console's fifth write seam: the temporary
// password a human Account is issued at its creation (accounts_write.go) or by
// re-issue while its human has never set their own (ADR-0045 decisions 1 and
// 4). Only the Console is handed it; the Control API and MCP are not
// (decision 11).
//
// # The one view a temporary password may occupy
//
// temporaryPasswordView.Password is a plain string, because Reveal has already
// run by the time it lands there. Like mintedView it is a reveal-once response:
// 200, Cache-Control no-store, never a redirect, so the value cannot enter a
// URL, a Location header or a history entry. It carries its own LogValue.
//
// # What this file decides: nothing
//
// The admin and human-only floors, the "has never set their own" rule and every
// audit row are the capability layer's (invariant 10).

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// TemporaryPasswordIssuer is the write seam this file holds. Every method
// mirrors capability.TemporaryPasswords' signature exactly, so
// *capability.TemporaryPasswords satisfies it with no adapter.
type TemporaryPasswordIssuer interface {
	CreateHumanAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, accounts.TemporaryPassword, error)
	IssueTemporaryPassword(ctx context.Context, p capability.Principal, accountID string) (accounts.TemporaryPassword, error)
	PasswordStatus(ctx context.Context, p capability.Principal, accountID string) (accounts.PasswordStatus, error)
}

// issueTemporaryPasswordPattern is the re-issue route, named like the other
// write patterns.
const issueTemporaryPasswordPattern = "POST /console/accounts/{account_id}/temporary-password"

func issueTemporaryPasswordAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/temporary-password"
}

// temporaryPasswordView is the reveal-once response. Password is the plaintext.
type temporaryPasswordView struct {
	Heading     string
	AccountName string
	Password    string // revealed once (accounts.Password.Reveal)
	ExpiresAt   time.Time
	Back        backLink
}

// LogValue implements slog.LogValuer, omitting Password entirely.
func (v temporaryPasswordView) LogValue() slog.Value {
	return slog.GroupValue(slog.String("account_name", v.AccountName))
}

// ExpiresIn is the lifetime drawn as data, e.g. "72 hours". A temporary
// password is revealed the moment it is issued, so the constant is the time left.
func (v temporaryPasswordView) ExpiresIn() string {
	return fmt.Sprintf("%d hours", int(accounts.TemporaryPasswordLifetime/time.Hour))
}

var temporaryPasswordTmpl = newScreen("temporary-password", `
<section class="panel minted">
  <h3>{{.Heading}}{{with .AccountName}} &mdash; <span class="ident">{{.}}</span>{{end}}</h3>
  <p><code>{{.Password}}</code></p>
  <p class="note">Shown once.</p>
  <p class="note"><time datetime="{{.ExpiresAt.UTC.Format "2006-01-02T15:04:05Z07:00"}}" title="{{stamp .ExpiresAt}}">expires in {{.ExpiresIn}}</time></p>
  <p><a href="{{.Back.Href}}">{{.Back.Label}}</a></p>
</section>
`)

// renderTemporaryPassword writes the reveal of tp. no-store is set before any
// write. The Reveal below is this file's only one, and the only place in the
// package a temporary password is unwrapped (TestTemporaryPassword_RevealIsCalledExactlyOnce).
func renderTemporaryPassword(w http.ResponseWriter, pg Page, heading, accountName string, tp accounts.TemporaryPassword) {
	w.Header().Set("Cache-Control", "no-store")
	renderScreen(w, pg, temporaryPasswordTmpl, temporaryPasswordView{
		Heading:     heading,
		AccountName: accountName,
		Password:    tp.Password.Reveal(),
		ExpiresAt:   tp.ExpiresAt,
		Back:        accountBack(accountName, false),
	})
}

// createHuman creates a human Account with its generated temporary password
// (ADR-0045 decision 1) and reveals it once, as the mint does: 200, no-store, no
// redirect. With no TemporaryPasswords wired the create is refused as
// unavailable, never made without a password the person could use to sign in.
func createHuman(d Deps, w http.ResponseWriter, r *http.Request, pg Page, caller capability.Principal, form accountCreateForm, a accounts.Account) {
	w.Header().Set("Cache-Control", "no-store")
	if d.TemporaryPasswords == nil {
		unavailable(w, "Account administration")
		return
	}
	created, tp, err := d.TemporaryPasswords.CreateHumanAccount(r.Context(), caller, a)
	if err != nil {
		writeFailedWith(w, pg, err, createAccountPattern, a.Name, "Nothing was created.", "Account", createRefusal(form))
		return
	}
	renderTemporaryPassword(w, pg, "Account created", created.Name, tp)
}

// handleIssueTemporaryPassword implements
// POST /console/accounts/{account_id}/temporary-password.
//
// ALWAYS step-up, windowed like every granting Account act: issuing brings a
// credential into existence. Like the mint it does not post-redirect-get.
func handleIssueTemporaryPassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}
		if d.TemporaryPasswords == nil {
			unavailable(w, "Account administration")
			return
		}

		if !requireStepUp(d, w, r, &pg, accountsStepUp("Nothing was issued.")) {
			return
		}

		tp, err := d.TemporaryPasswords.IssueTemporaryPassword(r.Context(), caller, id)
		if err != nil {
			writeFailed(w, pg, err, issueTemporaryPasswordPattern, id, "Nothing was issued.", "Account")
			return
		}

		// The Account's NAME, for the heading and the back link, comes from a
		// read, never from the request. Best-effort: a failed read costs the
		// link to the Account page, never the reveal.
		name := ""
		if target, readErr := d.Accounts.Account(r.Context(), caller, id); readErr == nil {
			name = target.Name
		}
		renderTemporaryPassword(w, pg, "Temporary password issued", name, tp)
	}
}
