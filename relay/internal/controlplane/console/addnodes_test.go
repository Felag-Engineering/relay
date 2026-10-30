package console

// addnodes_test.go covers Add Nodes, the Console's Enrollment Token mint form:
// the admin-only mount, the per-act password, the form's two narrowings, the
// reveal and the absence of any way to render it again.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const fakeJoinString = "glp_join_FAKEJOINSTRINGXYZ"

type enrollmentMintCall struct {
	Principal capability.Principal
	Form      capability.EnrollmentMintForm
}

// fakeEnrollmentTokens is the mint seam: it records each call and returns a
// token carrying fakeJoinString, or err. The recorder is guarded because
// sweepFixture shares one instance across parallel sweeps.
type fakeEnrollmentTokens struct {
	mu    sync.Mutex
	recd  []enrollmentMintCall
	err   error
	order *[]string
}

func (f *fakeEnrollmentTokens) MintEnrollmentTokenFromForm(_ context.Context, p capability.Principal, m capability.EnrollmentMintForm) (capability.MintedEnrollmentToken, error) {
	f.mu.Lock()
	f.recd = append(f.recd, enrollmentMintCall{Principal: p, Form: m})
	if f.order != nil {
		*f.order = append(*f.order, "MintEnrollmentTokenFromForm")
	}
	f.mu.Unlock()
	if f.err != nil {
		return capability.MintedEnrollmentToken{}, f.err
	}
	return capability.NewMintedEnrollmentToken("tok-fake-1", "fake-credential", fakeJoinString, m.InitialTags, testNow.Add(m.TTL), m.Nodes, false), nil
}

func (f *fakeEnrollmentTokens) calls() []enrollmentMintCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]enrollmentMintCall(nil), f.recd...)
}

// addNodesFix is a writeFix whose Deps carry a recording fakeEnrollmentTokens.
func addNodesFix(t *testing.T, tokens *fakeEnrollmentTokens) *writeFix {
	t.Helper()
	return newWriteFix(t, func(d *Deps) { d.EnrollmentTokens = tokens })
}

func mintForm(extra url.Values) url.Values {
	form := url.Values{"nodes": {"3"}, "ttl": {defaultEnrollmentTTL}, "password": {consolePassword}}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

// Proves EN-36.
func TestAddNodes_ALowerRoleFindsTheMintAbsent(t *testing.T) {
	tokens := &fakeEnrollmentTokens{}
	d := sweepFixture()
	d.EnrollmentTokens = tokens

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		h := newTestHandler(d, role)
		miss := get(t, h, "/console/no-such-route")
		got := get(t, h, addNodesPath)
		if got.Code != http.StatusNotFound || got.Body.String() != miss.Body.String() {
			t.Errorf("role %s: GET %s = %d, want the byte-identical 404 of an unmounted path", role, addNodesPath, got.Code)
		}
		if strings.Contains(get(t, h, "/console/").Body.String(), ">Add Nodes<") {
			t.Errorf("role %s: the nav offers Add Nodes", role)
		}

		unchecked := newTestHandlerSkippingCSRF(d, role)
		missPost := postSkippingCSRF(t, unchecked, "/console/no-such-route")
		gotPost := postSkippingCSRF(t, unchecked, mintEnrollmentTokenAction)
		if gotPost.Code != http.StatusNotFound || gotPost.Body.String() != missPost.Body.String() {
			t.Errorf("role %s: POST %s = %d, want the byte-identical 404 of an unmounted path", role, mintEnrollmentTokenAction, gotPost.Code)
		}
	}
	if n := len(tokens.calls()); n != 0 {
		t.Errorf("a lower role reached the mint %d times", n)
	}

	nav := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	add, acct := strings.Index(nav, ">Add Nodes<"), strings.Index(nav, ">Accounts<")
	if add < 0 || acct < 0 || add > acct {
		t.Errorf("an admin's nav should draw Add Nodes before Accounts (add=%d, accounts=%d)", add, acct)
	}
}

// Proves EN-36.
func TestAddNodes_ACapabilityRefusalIsRenderedAndRevealsNothing(t *testing.T) {
	tokens := &fakeEnrollmentTokens{err: errors.Join(
		fmt.Errorf("%w: minting an Enrollment Token needs admin", authz.ErrUnauthorized),
		errors.New("record failed"))}
	x := addNodesFix(t, tokens)

	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(body, "Nothing was minted.") {
		t.Errorf("the refusal does not say nothing was minted: %s", contentOf(body))
	}
	for _, leaked := range []string{fakeJoinString, "record failed"} {
		if strings.Contains(body, leaked) {
			t.Errorf("the refusal page shows %q", leaked)
		}
	}
}

// Proves EN-36.
func TestAddNodes_EveryMintCostsAPassword(t *testing.T) {
	t.Run("a wrong password", func(t *testing.T) {
		tokens := &fakeEnrollmentTokens{}
		x := addNodesFix(t, tokens)
		x.auth.stepUpErr = consoleauth.ErrBadCredentials
		rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
		if rec.Code != http.StatusUnauthorized || len(tokens.calls()) != 0 {
			t.Errorf("status = %d, calls = %d, want 401 and no mint", rec.Code, len(tokens.calls()))
		}
	})
	t.Run("no password even inside a fresh window", func(t *testing.T) {
		tokens := &fakeEnrollmentTokens{}
		x := addNodesFix(t, tokens)
		x.auth.fresh = true
		rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"password": {""}}))
		if rec.Code != http.StatusUnauthorized || len(tokens.calls()) != 0 {
			t.Errorf("status = %d, calls = %d, want 401 and no mint", rec.Code, len(tokens.calls()))
		}
		if x.auth.requireCalls != 0 {
			t.Errorf("the step-up window was consulted %d times; a mint never reads it", x.auth.requireCalls)
		}
	})
	t.Run("a throttled attempt", func(t *testing.T) {
		tokens := &fakeEnrollmentTokens{}
		x := addNodesFix(t, tokens)
		x.auth.stepUpErr = &consoleauth.ThrottledError{RetryAfter: 42 * time.Second}
		rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "42" || len(tokens.calls()) != 0 {
			t.Errorf("status = %d, Retry-After = %q, calls = %d", rec.Code, rec.Header().Get("Retry-After"), len(tokens.calls()))
		}
	})
	t.Run("a correct password comes first", func(t *testing.T) {
		tokens := &fakeEnrollmentTokens{}
		x := addNodesFix(t, tokens)
		var order []string
		x.auth.order, tokens.order = &order, &order
		rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if len(order) != 2 || order[0] != "StepUp" || order[1] != "MintEnrollmentTokenFromForm" {
			t.Errorf("call order = %v, want StepUp then MintEnrollmentTokenFromForm", order)
		}
	})
}

// Proves EN-36.
func TestAddNodes_TheFormAsksHowManyNodesAndOffersNoUnlimitedOption(t *testing.T) {
	tokens := &fakeEnrollmentTokens{}
	x := addNodesFix(t, tokens)

	form := x.get(t, addNodesPath).Body.String()
	if !strings.Contains(form, `name="nodes" type="number" min="1" max="256" step="1" required`) {
		t.Errorf("the form's nodes input is not a required number of at least 1: %s", contentOf(form))
	}
	if strings.Contains(strings.ToLower(form), "unlimited") {
		t.Error("the form mentions unlimited use")
	}

	rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"nodes": {"7"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("nodes=7: status = %d", rec.Code)
	}
	if c := tokens.calls(); len(c) != 1 || c[0].Form.Nodes != 7 {
		t.Fatalf("calls = %+v, want one with Nodes 7", c)
	}

	for _, bad := range []string{"", "0", "-1", "abc", "unlimited", "1.5"} {
		before := len(tokens.calls())
		rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"nodes": {bad}}))
		body := rec.Body.String()
		if rec.Code != http.StatusBadRequest || len(tokens.calls()) != before {
			t.Errorf("nodes=%q: status = %d, new calls = %d, want 400 and none", bad, rec.Code, len(tokens.calls())-before)
		}
		if bad != "" && !strings.Contains(body, `value="`+bad+`"`) {
			t.Errorf("nodes=%q was not echoed", bad)
		}
		if strings.Contains(body, consolePassword) {
			t.Errorf("nodes=%q: the password was echoed", bad)
		}
	}
}

// Proves EN-46.
func TestAddNodes_ACountAbove256IsRefusedNamingTheLimitAndMintsNothing(t *testing.T) {
	tokens := &fakeEnrollmentTokens{}
	x := addNodesFix(t, tokens)

	rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"nodes": {"257"}}))
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "256") || !strings.Contains(body, "Nothing was minted.") {
		t.Fatalf("nodes=257: status = %d, body %s", rec.Code, contentOf(body))
	}
	if strings.Contains(body, fakeJoinString) || len(tokens.calls()) != 0 {
		t.Errorf("nodes=257 revealed a join string or reached the mint (%d calls)", len(tokens.calls()))
	}

	rec = x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"nodes": {"256"}}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), fakeJoinString) {
		t.Fatalf("nodes=256: status = %d, want 200 with the reveal", rec.Code)
	}
	if c := tokens.calls(); len(c) != 1 || c[0].Form.Nodes != 256 {
		t.Errorf("calls = %+v, want one with Nodes 256", c)
	}
}

// Proves EN-46.
func TestAddNodes_ACapabilityFormRefusalNamesTheLimit(t *testing.T) {
	x := addNodesFix(t, &fakeEnrollmentTokens{err: capability.ErrEnrollmentFormNodes})
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "256") {
		t.Errorf("status = %d, body %s", rec.Code, contentOf(body))
	}
	if strings.Contains(body, fakeJoinString) {
		t.Error("a refused mint shows the join string")
	}
}

// Proves EN-36.
func TestAddNodes_TheExpiryDefaultsToTwoHoursAndMayBeChanged(t *testing.T) {
	tokens := &fakeEnrollmentTokens{}
	x := addNodesFix(t, tokens)

	form := x.get(t, addNodesPath).Body.String()
	if got := strings.Count(form, " selected"); got != 1 || !strings.Contains(form, `<option value="2h" selected>`) {
		t.Errorf("the form should preselect exactly the 2 hour option: %s", contentOf(form))
	}
	if ttl, ok := enrollmentTTLFor(defaultEnrollmentTTL); !ok || ttl != capability.DefaultEnrollmentTokenTTL {
		t.Errorf("the default choice resolves to %v, want the capability layer's %v", ttl, capability.DefaultEnrollmentTokenTTL)
	}

	for value, want := range map[string]time.Duration{"2h": 2 * time.Hour, "8h": 8 * time.Hour} {
		if rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"ttl": {value}})); rec.Code != http.StatusOK {
			t.Fatalf("ttl=%s: status = %d", value, rec.Code)
		}
		c := tokens.calls()
		if got := c[len(c)-1].Form.TTL; got != want {
			t.Errorf("ttl=%s reached the seam as %v, want %v", value, got, want)
		}
	}

	before := len(tokens.calls())
	for _, bad := range []string{"", "2h30m", "8760h", "forever"} {
		form := mintForm(url.Values{"ttl": {bad}})
		if bad == "" {
			form.Del("ttl")
		}
		if rec := x.post(t, mintEnrollmentTokenAction, form); rec.Code != http.StatusBadRequest {
			t.Errorf("ttl=%q: status = %d, want 400", bad, rec.Code)
		}
	}
	if len(tokens.calls()) != before {
		t.Error("an unrecognised expiry reached the seam")
	}
}

// Proves EN-36, EN-40.
func TestAddNodes_InitialTagsArePassedAsWrittenAndARefusedOneIsNamed(t *testing.T) {
	tokens := &fakeEnrollmentTokens{}
	x := addNodesFix(t, tokens)

	x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"initial_tags": {"tag:env=prod\r\ntag:team=web"}}))
	x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"initial_tags": {""}}))
	x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"initial_tags": {"tag:env=pro d"}}))
	x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"initial_tags": {" tag:env=prod \r\n\r\n   \r\ntag:team=web\r\n"}}))
	c := tokens.calls()
	if len(c) != 4 {
		t.Fatalf("calls = %d, want 4", len(c))
	}
	if got := strings.Join(c[3].Form.InitialTags, "|"); got != " tag:env=prod |tag:team=web" {
		t.Fatalf("padded/blank lines: tags = %q, want the padded entry unchanged, blanks dropped, no CR", c[3].Form.InitialTags)
	}
	c = c[:3]
	if len(c) != 3 || strings.Join(c[0].Form.InitialTags, "|") != "tag:env=prod|tag:team=web" || c[1].Form.InitialTags != nil ||
		strings.Join(c[2].Form.InitialTags, "|") != "tag:env=pro d" {
		t.Fatalf("calls = %+v, want the two tags as written, nil, then the entry with its inner space whole", c)
	}

	tokens.err = fmt.Errorf("%w: %w", capability.ErrEnrollmentInitialTags,
		&registry.InitialTagError{Entry: "relay:x=y", Err: registry.ErrInitialTagRelayLabel})
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(url.Values{"nodes": {"4"}, "initial_tags": {"relay:x=y"}}))
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	for _, want := range []string{"The initial tag relay:x=y was refused", "relay: labels are written only by the Relay", `value="4"`, ">relay:x=y</textarea>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal is missing %q", want)
		}
	}
	for _, leaked := range []string{consolePassword, fakeJoinString} {
		if strings.Contains(body, leaked) {
			t.Errorf("the refusal shows %q", leaked)
		}
	}
}

// Proves EN-36.
func TestAddNodes_TheRevealShowsTheCommandAndTheJoinStringApartOnce(t *testing.T) {
	x := addNodesFix(t, &fakeEnrollmentTokens{})
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	body := rec.Body.String()

	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("status = %d, Location = %q, want a 200 with no redirect", rec.Code, rec.Header().Get("Location"))
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(body, "<code>sudo relay-daemon join</code>") {
		t.Errorf("the command is not alone in a code element: %s", contentOf(body))
	}
	if n := strings.Count(body, fakeJoinString); n != 1 {
		t.Errorf("the join string appears %d times, want exactly 1", n)
	}
	if !strings.Contains(body, "<code>"+fakeJoinString+"</code>") {
		t.Error("the join string is not alone in its own code element")
	}
	idx := strings.Index(body, fakeJoinString)
	for _, attr := range []string{`value="`, `href="`, `data-`} {
		if strings.HasSuffix(body[:idx], attr) {
			t.Errorf("the join string sits in an attribute (%s)", attr)
		}
	}
	for _, banned := range []string{"install", "agent"} {
		if strings.Contains(strings.ToLower(contentOf(body)), banned) {
			t.Errorf("the reveal says %q", banned)
		}
	}
	assertCSPClean(t, "add nodes reveal", body)
}

// Proves EN-36.
func TestAddNodes_TheRevealCannotBeRenderedAgain(t *testing.T) {
	x := addNodesFix(t, &fakeEnrollmentTokens{})
	if rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil)); rec.Code != http.StatusOK {
		t.Fatalf("mint status = %d", rec.Code)
	}

	form := x.get(t, addNodesPath)
	if strings.Contains(form.Body.String(), fakeJoinString) {
		t.Error("the form page carries the join string after a mint")
	}
	lower := strings.ToLower(form.Body.String())
	for _, control := range []string{"show again", "re-render", "render again"} {
		if strings.Contains(lower, control) {
			t.Errorf("the form page offers %q", control)
		}
	}

	var methods []string
	for _, r := range Routes(sweepFixture()) {
		if strings.HasPrefix(r.Path, addNodesPath) {
			methods = append(methods, r.Method+" "+r.Path)
		}
	}
	if strings.Join(methods, ",") != "GET /console/add-nodes,POST /console/add-nodes/tokens" {
		t.Errorf("routes under %s = %v, want the form and the POST only", addNodesPath, methods)
	}

	twin := x.get(t, mintEnrollmentTokenAction)
	if twin.Code == http.StatusOK || strings.Contains(twin.Body.String(), fakeJoinString) {
		t.Errorf("GET %s = %d; the POST path must not render anything", mintEnrollmentTokenAction, twin.Code)
	}
}

func TestAddNodes_TheMintedViewRedactsTheJoinStringInLogs(t *testing.T) {
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("minted", "view", mintedEnrollmentView{TokenID: "tok-1", JoinString: fakeJoinString})
	if strings.Contains(buf.String(), fakeJoinString) {
		t.Errorf("the log line carries the join string: %s", buf.String())
	}
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil || !strings.Contains(buf.String(), "tok-1") {
		t.Errorf("the log line does not carry the token ID: %s", buf.String())
	}

	var logs bytes.Buffer
	tokens := &fakeEnrollmentTokens{err: errors.New("store exploded")}
	x := newWriteFix(t, func(d *Deps) {
		d.EnrollmentTokens = tokens
		d.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	})
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "could not confirm this mint") {
		t.Errorf("status = %d, body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if strings.Contains(logs.String(), fakeJoinString) || !strings.Contains(logs.String(), "store exploded") {
		t.Errorf("the failure log line is wrong: %s", logs.String())
	}
}

func TestAddNodes_UnwiredSeamAnswersUnavailable(t *testing.T) {
	for name, mutate := range map[string]func(*Deps){
		"no mint seam": func(d *Deps) { d.EnrollmentTokens = nil },
		"no auth":      func(d *Deps) { d.Auth = nil },
	} {
		d := sweepFixture()
		d.EnrollmentTokens = &fakeEnrollmentTokens{}
		mutate(&d)
		h := newTestHandlerSkippingCSRF(d, accounts.RoleAdmin)
		if rec := get(t, h, addNodesPath); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "not wired") {
			t.Errorf("%s: GET = %d, want the unavailable answer", name, rec.Code)
		}
		if rec := postSkippingCSRF(t, h, mintEnrollmentTokenAction); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: POST = %d, want the unavailable answer", name, rec.Code)
		}
	}
}

func TestAddNodes_AnUnrecordedUnwithdrawnMintNamesTheLiveToken(t *testing.T) {
	live := &capability.EnrollmentTokenLiveError{TokenID: "tok-live", RecordErr: errors.New("disk full"), WithdrawErr: errors.New("store down")}
	x := addNodesFix(t, &fakeEnrollmentTokens{err: live})
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, "tok-live") || !strings.Contains(body, "may still be live") || !strings.Contains(body, "Control API") {
		t.Errorf("status = %d, body %s", rec.Code, contentOf(body))
	}
	if strings.Contains(body, "token withdrawn") || strings.Contains(body, fakeJoinString) {
		t.Errorf("the live-token page claims a withdrawal or shows the join string: %s", contentOf(body))
	}
}

// Proves EN-4.
func TestAddNodes_AnUnrecordedMintSaysItWasDiscarded(t *testing.T) {
	tokens := &fakeEnrollmentTokens{err: fmt.Errorf("%w: disk full", capability.ErrEnrollmentMintNotRecorded)}
	x := addNodesFix(t, tokens)
	rec := x.post(t, mintEnrollmentTokenAction, mintForm(nil))
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(body, "Its join string was discarded") {
		t.Errorf("status = %d, body %s", rec.Code, contentOf(body))
	}
	if strings.Contains(body, fakeJoinString) {
		t.Error("an unrecorded mint shows the join string")
	}
}
