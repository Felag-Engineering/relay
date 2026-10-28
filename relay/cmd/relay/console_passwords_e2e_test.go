package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// console_passwords_e2e_test.go drives ADR-0045 through the real composition
// root: an admin creates a human Account (a temporary password, revealed once),
// re-issues one, the human signs in with it into a restricted session, is forced
// to change it, a second session is evicted, and the human later changes their
// own password. Nothing is faked on the path.

// exchange is one request/response seen on the wire by the recording transport:
// the headers rendered whole (Set-Cookie and Location included) and the body.
type exchange struct {
	label string
	text  string
}

// recordingTransport records every exchange of the client it wraps, then
// hands the response on with its body intact.
type recordingTransport struct {
	inner http.RoundTripper
	log   *[]exchange
}

func (r recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	var headers strings.Builder
	for name, values := range resp.Header {
		for _, v := range values {
			fmt.Fprintf(&headers, "%s: %s\n", name, v)
		}
	}
	*r.log = append(*r.log, exchange{
		label: fmt.Sprintf("%s %s -> %d", req.Method, req.URL.Path, resp.StatusCode),
		text:  headers.String() + "\n" + string(body),
	})
	return resp, nil
}

// recordedClient is consoleClient, with its traffic recorded into log.
func recordedClient(t *testing.T, f *relayFixture, log *[]exchange) *http.Client {
	t.Helper()
	c := consoleClient(t, f)
	c.Transport = recordingTransport{inner: c.Transport, log: log}
	return c
}

type pwBrowser struct {
	t      *testing.T
	f      *relayFixture
	client *http.Client
}

func (b pwBrowser) get(path string) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.client.Get(b.f.ControlBase + path)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	return resp, readAll(b.t, resp)
}

// csrf reads a CSRF token for the browser's CURRENT session off path.
func (b pwBrowser) csrf(path string) string {
	b.t.Helper()
	resp, body := b.get(path)
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("GET %s = %d, want 200 to read a CSRF token", path, resp.StatusCode)
	}
	return consoleHiddenField(b.t, body, "csrf_token")
}

func (b pwBrowser) post(path, csrfPath string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	form.Set("csrf_token", b.csrf(csrfPath))
	resp, err := b.client.PostForm(b.f.ControlBase+path, form)
	if err != nil {
		b.t.Fatalf("POST %s: %v", path, err)
	}
	return resp, readAll(b.t, resp)
}

var revealedPasswordPattern = regexp.MustCompile(`<code>([^<]+)</code>`)

func scrapeReveal(t *testing.T, body string) string {
	t.Helper()
	m := revealedPasswordPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the response carries no revealed password:\n%s", body)
	}
	return m[1]
}

// signInStatus drives the real sign-in form and returns the POST's status.
func signInStatus(t *testing.T, f *relayFixture, client *http.Client, username, password string) int {
	t.Helper()
	getResp, err := client.Get(f.ControlBase + "/console/login")
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	token := consoleHiddenField(t, readAll(t, getResp), "csrf_token")
	resp, err := client.PostForm(f.ControlBase+"/console/login", url.Values{"username": {username}, "password": {password}, "csrf_token": {token}})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// passwordFlow is the whole ADR-0045 story. It returns the secrets it used and
// the exchanges it saw, for the assertions on top.
type passwordFlow struct {
	f            *relayFixture
	adminID      string
	humanID      string
	traffic      []exchange
	createReveal exchange // the create response, which carries temp1
	issueReveal  exchange // the re-issue response, which carries temp2
	plaintexts   []string
	hashes       []string
}

const (
	flowAdminPassword = "the admin's console password"
	flowOwn1          = "the humans first own password"
	flowOwn2          = "the humans second own password"
	flowWrong         = "a wrong current password, typed"
)

func (p *passwordFlow) captureHash(t *testing.T, accountID string) {
	t.Helper()
	stored, err := p.f.Deps.store.Passwords().GetPassword(context.Background(), accountID)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	p.hashes = append(p.hashes, stored.Hash.Encoded())
}

func runPasswordFlow(t *testing.T, f *relayFixture) *passwordFlow {
	t.Helper()
	p := &passwordFlow{f: f, plaintexts: []string{flowAdminPassword, flowOwn1, flowOwn2, flowWrong}}
	var err error
	p.adminID, _ = mintConsoleHumanAccount(t, f, "ada", flowAdminPassword, accounts.RoleAdmin)
	p.captureHash(t, p.adminID)

	admin := pwBrowser{t, f, recordedClient(t, f, &p.traffic)}
	consoleSignIn(t, admin.client, f, "ada", flowAdminPassword)

	// 1. Create a human Account: 200, no-store, the temporary password once.
	resp, body := admin.post("/console/new-account/create", "/console/new-account",
		url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {flowAdminPassword}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Location") != "" {
		t.Fatalf("create = %d Cache-Control %q Location %q; body %s", resp.StatusCode, resp.Header.Get("Cache-Control"), resp.Header.Get("Location"), body)
	}
	temp1 := scrapeReveal(t, body)
	p.createReveal = p.traffic[len(p.traffic)-1]
	human, err := f.Deps.store.Accounts().GetByName(context.Background(), "newbie")
	if err != nil {
		t.Fatalf("the created Account: %v", err)
	}
	p.humanID = human.ID
	p.plaintexts = append(p.plaintexts, temp1)
	p.captureHash(t, p.humanID)

	// 2. Re-issue (a step-up inside the window needs no password, but the
	// session rotated at the create, so a fresh token is read first).
	resp, body = admin.post("/console/accounts/"+p.humanID+"/temporary-password", "/console/accounts/newbie",
		url.Values{"password": {flowAdminPassword}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Location") != "" {
		t.Fatalf("re-issue = %d Cache-Control %q Location %q; body %s", resp.StatusCode, resp.Header.Get("Cache-Control"), resp.Header.Get("Location"), body)
	}
	temp2 := scrapeReveal(t, body)
	p.issueReveal = p.traffic[len(p.traffic)-1]
	p.plaintexts = append(p.plaintexts, temp2)
	p.captureHash(t, p.humanID)
	if temp1 == temp2 {
		t.Fatal("a re-issue returned the same temporary password")
	}

	// The replaced temporary password no longer signs in.
	other := recordedClient(t, f, &p.traffic)
	if code := signInStatus(t, f, other, "newbie", temp1); code != http.StatusUnauthorized {
		t.Fatalf("sign-in with the replaced temporary password = %d, want 401", code)
	}
	time.Sleep(1100 * time.Millisecond) // past the throttle's first delay

	// 3. The human signs in twice (two sessions) with the live temporary password.
	first := pwBrowser{t, f, recordedClient(t, f, &p.traffic)}
	consoleSignIn(t, first.client, f, "newbie", temp2)
	second := pwBrowser{t, f, recordedClient(t, f, &p.traffic)}
	consoleSignIn(t, second.client, f, "newbie", temp2)

	// Restricted: every other page redirects to the form, which draws no nav.
	resp, _ = first.get("/console/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console/account" {
		t.Fatalf("GET /console/ in a restricted session = %d Location %q, want 303 /console/account", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = first.get("/console/accounts")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/console/account?next=") {
		t.Fatalf("GET /console/accounts in a restricted session = %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = first.get("/console/account")
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `class="navitem`) {
		t.Fatalf("the restricted form = %d, nav drawn = %v", resp.StatusCode, strings.Contains(body, `class="navitem`))
	}

	// 4. A wrong current password is refused (a strike), then the forced change.
	resp, body = first.post("/console/account/password", "/console/account",
		url.Values{"current_password": {flowWrong}, "new_password": {flowOwn1}, "confirm_password": {flowOwn1}})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "That password did not match") {
		t.Fatalf("a wrong current password = %d; body %s", resp.StatusCode, body)
	}
	time.Sleep(1100 * time.Millisecond)
	resp, body = first.post("/console/account/password", "/console/account",
		url.Values{"current_password": {temp2}, "new_password": {flowOwn1}, "confirm_password": {flowOwn1}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console/" {
		t.Fatalf("the forced change = %d Location %q; body %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	p.captureHash(t, p.humanID)

	// The other session is evicted; this one is ordinary now.
	if resp, _ := second.get("/console/"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/console/login") {
		t.Fatalf("the other session after the change = %d Location %q, want to be sent to sign in", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := first.get("/console/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/ after the change = %d, want 200", resp.StatusCode)
	}

	// The redeemed temporary password is refused at sign-in.
	if code := signInStatus(t, f, recordedClient(t, f, &p.traffic), "newbie", temp2); code != http.StatusUnauthorized {
		t.Fatalf("sign-in with the redeemed temporary password = %d, want 401", code)
	}
	time.Sleep(1100 * time.Millisecond)

	// 5. A self-service change: a third session exists and is ended.
	third := pwBrowser{t, f, recordedClient(t, f, &p.traffic)}
	consoleSignIn(t, third.client, f, "newbie", flowOwn1)
	resp, body = first.post("/console/account/password", "/console/account",
		url.Values{"current_password": {flowOwn1}, "new_password": {flowOwn2}, "confirm_password": {flowOwn2}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console/account?done=password" {
		t.Fatalf("the self-service change = %d Location %q; body %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	p.captureHash(t, p.humanID)
	if resp, _ := third.get("/console/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the third session after the change = %d, want it ended", resp.StatusCode)
	}

	// Access lists the acts, to the admin.
	_, access := admin.get("/console/access")
	for _, want := range []string{"issued a temporary password", "set their own password, redeeming a temporary one", "changed their own password"} {
		if !strings.Contains(access, want) {
			t.Errorf("Access does not say %q", want)
		}
	}
	return p
}

func TestConsolePasswords_TemporaryPasswordForcedChangeAndSelfServiceChange(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	p := runPasswordFlow(t, f)

	recs, err := f.Deps.store.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string][]audit.Record{}
	for _, r := range recs {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}

	issues := byKind[audit.KindPasswordTemporarySet]
	if len(issues) != 2 {
		t.Fatalf("%d password_temporary_set records, want 2 (the create and the re-issue)", len(issues))
	}
	for _, r := range issues {
		if v := r.Attribution.Verified; v.AccountID != p.adminID || v.AccountName != "ada" || v.Source == "" {
			t.Errorf("password_temporary_set verified lane = %+v, want the admin and a source address", v)
		}
		if !strings.HasPrefix(r.Reason, "account_id="+p.humanID) {
			t.Errorf("password_temporary_set Reason = %q, want it to open with the subject", r.Reason)
		}
	}
	if n := len(byKind[audit.KindAccountCreate]); n != 1 {
		t.Errorf("%d account_create records, want newbie's alone (the admin was seeded through the store)", n)
	}

	changes := byKind[audit.KindPasswordChange]
	if len(changes) != 2 {
		t.Fatalf("%d password_change records, want 2", len(changes))
	}
	if want := "account_id=" + p.humanID + " forced=true other_sessions_ended=1"; changes[0].Reason != want {
		t.Errorf("first password_change Reason = %q, want %q", changes[0].Reason, want)
	}
	if want := "account_id=" + p.humanID + " forced=false other_sessions_ended=1"; changes[1].Reason != want {
		t.Errorf("second password_change Reason = %q, want %q", changes[1].Reason, want)
	}
	for _, r := range changes {
		if v := r.Attribution.Verified; v.AccountID != p.humanID || v.Source == "" {
			t.Errorf("password_change verified lane = %+v, want the human and a source address", v)
		}
	}

	// The proof of each current password is a recorded step-up; the wrong one
	// is a step_up_failed, never an account row.
	if n := len(byKind[audit.KindStepUpFailed]); n != 1 {
		t.Errorf("%d step_up_failed records, want 1 (the wrong current password)", n)
	}
	if n := len(byKind[audit.KindStepUp]); n < 3 {
		t.Errorf("%d step_up records, want at least 3 (the admin's two and the human's two proofs)", n)
	}
}

// TestConsolePasswords_NoResponseLogOrAuditRowCarriesAPasswordOrHash is the
// issue's pin: across the whole flow, no password appears in any log line,
// audit row, header or body except the temporary password in exactly its own
// reveal response, and no stored hash appears anywhere at all.
func TestConsolePasswords_NoResponseLogOrAuditRowCarriesAPasswordOrHash(t *testing.T) {
	// The composition root's logger is built from slog.Default() when the
	// server is assembled (main.go), so installing the buffer BEFORE startRelay
	// is what captures the logger the production code actually uses. The
	// assertion below that the buffer saw the Console start proves it did.
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	p := runPasswordFlow(t, f)

	if !strings.Contains(logBuf.String(), "admin console enabled") {
		t.Fatal("the log buffer did not capture the composition root's logger; the log assertions below would prove nothing")
	}

	recs, err := f.Deps.store.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	haystacks := map[string]string{"log": logBuf.String()}
	for i, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		haystacks[fmt.Sprintf("audit record %d (%s) json", i, r.Kind)] = string(b)
		haystacks[fmt.Sprintf("audit record %d (%s) %%+v", i, r.Kind)] = fmt.Sprintf("%+v", r)
	}
	for i, x := range p.traffic {
		// A temporary password may appear in its own reveal response, and
		// nowhere else.
		haystacks[fmt.Sprintf("exchange %d (%s)", i, x.label)] = x.text
	}

	hashes := append([]string{"$argon2id$"}, p.hashes...)
	for name, h := range haystacks {
		for _, hash := range hashes {
			if strings.Contains(h, hash) {
				t.Errorf("%s carries a password hash", name)
			}
		}
		for _, secret := range p.plaintexts {
			if !strings.Contains(h, secret) {
				continue
			}
			if isOwnReveal(name, secret, p) {
				continue
			}
			t.Errorf("%s carries the password %q", name, secret)
		}
	}

	// The reveals really did carry them: the carve-out is exactly two.
	revealed := 0
	for _, x := range []exchange{p.createReveal, p.issueReveal} {
		for _, secret := range p.plaintexts {
			if strings.Contains(x.text, secret) && secret != flowAdminPassword {
				revealed++
			}
		}
	}
	if revealed != 2 {
		t.Errorf("the create and re-issue responses carry %d temporary passwords, want exactly 2", revealed)
	}
}

// isOwnReveal reports whether haystack name is the one response that is
// allowed to carry secret: the create response for the first temporary
// password and the re-issue response for the second.
func isOwnReveal(name, secret string, p *passwordFlow) bool {
	for _, own := range []exchange{p.createReveal, p.issueReveal} {
		if !strings.Contains(name, own.label) || !strings.HasPrefix(name, "exchange ") {
			continue
		}
		if !strings.Contains(own.text, secret) {
			continue
		}
		// One reveal carries exactly one temporary password.
		return strings.Count(own.text, secret) == 1
	}
	return false
}

func TestControlAPI_CreatesAHumanAccountWithoutATemporaryPassword(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	resp := controlAPIRequest(t, f.Client(), http.MethodPost, f.ControlBase+"/api/v1/accounts", "",
		map[string]string{"name": "api-human", "kind": "human", "role": "viewer"})
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID == "" {
		t.Fatalf("decode %s: %v", body, err)
	}
	if strings.Contains(strings.ToLower(body), "password") {
		t.Errorf("the Control API response mentions a password: %s", body)
	}

	ctx := context.Background()
	status, err := f.Deps.store.PasswordStatuses().Status(ctx, created.ID)
	if err != nil || status.Own || !status.TemporaryUntil.IsZero() {
		t.Errorf("Status = %+v, %v; want not Own and no temporary password", status, err)
	}
	if _, err := f.Deps.store.Passwords().GetPassword(ctx, created.ID); !errors.Is(err, accounts.ErrNoPassword) {
		t.Errorf("GetPassword = %v, want ErrNoPassword", err)
	}
	recs, err := f.Deps.store.Audit().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Kind == audit.KindPasswordTemporarySet || r.Kind == audit.KindPasswordChange {
			t.Errorf("the Control API write recorded %s", r.Kind)
		}
	}
}
