// Package main: console_e2e_helpers_test.go holds the browser-lane helpers
// for composition-root tests that sign in to the Console: a cookie-jar client,
// a real sign-in, and an Account carrying both an API token and a Console
// password.
package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
)

// consoleClient builds a browser-shaped http.Client for f: TLS trusting the
// fixture's CA (f.ClientFor builds an equivalent transport for the bearer
// lane; this is the browser lane's counterpart), a cookie jar so the session
// cookie set by sign-in persists across requests the way a real browser's
// would, and CheckRedirect disabled so a redirect is ASSERTED rather than
// silently followed by the client.
//
// Named fallback, not needed today: if Go's cookiejar ever declines to store
// a __Host- cookie for an IP-literal host, the fix is to carry cookies by
// hand — as console's own loginFixture.do does in-package — rather than to
// weaken any cookie attribute to make the jar accept it.
func consoleClient(t *testing.T, f *relayFixture) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Transport:     &http.Transport{TLSClientConfig: f.TLSConfig()},
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// readAll reads and closes resp.Body, failing the test on either error.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(b)
}

// consoleHiddenField scrapes the value of the named hidden form field from a
// rendered page. The pattern is built per name, which keeps the call site
// readable as consoleHiddenField(t, body, "csrf_token").
func consoleHiddenField(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no hidden field %q found in the rendered page:\n%s", name, body)
	}
	return m[1]
}

// mintConsoleHumanAccount creates a human Account carrying BOTH an API token
// (so a test can read back through the Control API exactly as the
// requester's own channel does) and a Console password (so it can sign in
// through the browser lane) — the two credentials one Account legitimately
// holds on two different surfaces.
//
// store.Passwords().SetPassword takes an accounts.PasswordHash, never a
// plaintext, so accounts.HashPassword runs first.
//
// role is explicit rather than hardcoded to admin, so a test can sign in at
// the role it is about.
func mintConsoleHumanAccount(t *testing.T, f *relayFixture, name, password string, role accounts.Role) (accountID, token string) {
	t.Helper()
	ctx := context.Background()
	acct, err := f.Deps.store.Accounts().Create(ctx, accounts.Account{
		Name: name, Kind: accounts.KindHuman, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	svc := accounts.NewTokenService(f.Deps.store.APITokens(), f.Deps.store.Accounts(), nil)
	_, plaintext, err := svc.Mint(ctx, acct.ID, name+"-token", 0)
	if err != nil {
		t.Fatalf("mint token for %s: %v", name, err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword(password))
	if err != nil {
		t.Fatalf("hash password for %s: %v", name, err)
	}
	if err := f.Deps.store.Passwords().SetPassword(ctx, acct.ID, hash); err != nil {
		t.Fatalf("set password for %s: %v", name, err)
	}
	return acct.ID, plaintext.Reveal()
}

// consoleSignIn drives the real sign-in form over client (which must carry a
// cookie jar — see consoleClient) and fails the test unless it redirects: a
// genuine browser session established through the production handler, never
// a hand-built cookie.
func consoleSignIn(t *testing.T, client *http.Client, f *relayFixture, username, password string) {
	t.Helper()
	getResp, err := client.Get(f.ControlBase + console.LoginPath)
	if err != nil {
		t.Fatalf("GET login page: %v", err)
	}
	token := consoleHiddenField(t, readAll(t, getResp), "csrf_token")

	form := url.Values{"username": {username}, "password": {password}, "csrf_token": {token}}
	postResp, err := client.PostForm(f.ControlBase+console.LoginPath, form)
	if err != nil {
		t.Fatalf("POST sign-in: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want 303 (redirect after sign-in)", postResp.StatusCode)
	}
}
