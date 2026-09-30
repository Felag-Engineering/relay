package console

// access_test.go is spec 20's acceptance criteria: the Access screen answers
// "who got in, and who changed who can get in?" admin-only, in the Console
// only (D17 ruling 4).
//
// The store-backed fixtures here mirror read_audit_test.go's realLaneDeps and
// reads_test.go's TestReads_EnumerationHeadlineAndPrincipalTableAreOneSnapshot:
// a fakeQueries answers instantly and cannot prove what the REAL writers
// (auditsink.Sink.RecordLogin, RecordAccountAdmin) actually put on the trail,
// which is exactly the #463/#517/#520 failure mode — a fixture built by hand
// passing a mapping bug the real seam would not.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// accessFixtureSource is the peer address every seeded sign-in and step-up
// record carries, so the Source assertion has one fixed value to look for.
const accessFixtureSource = "10.0.0.9"

// accessFixtureSubject is the Account every seeded account/api-token record
// names as ITS SUBJECT (the record's Reason), never the acting admin.
const accessFixtureSubject = "acct-x"

// accessDeps is renderableDeps with a query lane the test controls.
func accessDeps(q *fakeQueries) Deps {
	d := renderableDeps()
	d.Queries = q
	return d
}

// accessStoreDeps is a Console wired to a REAL *capability.Service over a
// REAL *auditsink.Sink and *auditquery.Queries, built exactly like
// TestReads_EnumerationHeadlineAndPrincipalTableAreOneSnapshot (reads_test.go)
// — the fixture that reproduces the read lane's own ordering rather than
// answering instantly. Returns the sink and store a test seeds through, and
// the acting admin Principal every seeded account/api-token record is
// attributed to.
func accessStoreDeps(t *testing.T) (Deps, *auditsink.Sink, *store.Store, capability.Principal) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sink := auditsink.New(st.Audit(), auditsink.WithClock(func() time.Time { return testNow }))
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	svc := capability.New(registry.NewInMemory(),
		capability.WithAuditSink(sink),
		capability.WithQueries(q, q),
	)

	actor := capability.Principal{
		AccountID: testAccountID(accounts.RoleAdmin),
		Account:   testAccountName(accounts.RoleAdmin),
		Role:      string(accounts.RoleAdmin),
		Kind:      string(accounts.KindHuman),
	}

	d := renderableDeps()
	d.Queries = svc
	d.Now = func() time.Time { return testNow }
	return d, sink, st, actor
}

// seedAccessTrail writes the 13 Access records plus the two Enrollment Token
// records Activity keeps, through the REAL writers: sink.RecordLogin for the
// seven login/step-up kinds, shaped exactly as consoleauth/service.go emits
// them, sink.RecordAccountAdmin for the six account/api-token kinds
// (attributed to actor, naming accessFixtureSubject), and st.Audit().Append
// directly for the two Enrollment Token kinds neither writer produces.
func seedAccessTrail(t *testing.T, sink *auditsink.Sink, st *store.Store, actor capability.Principal) {
	t.Helper()
	ctx := context.Background()

	logins := []consoleauth.LoginEvent{
		// --- sign-in (4) -----------------------------------------------------
		{
			Kind: audit.KindLoginSucceeded, Account: actor.Account, AccountID: actor.AccountID, Role: actor.Role,
			SubmittedName: actor.Account, Method: consoleauth.MethodPassword, Source: accessFixtureSource,
		},
		{
			Kind: audit.KindLoginFailed, SubmittedName: "nobody", Method: consoleauth.MethodPassword,
			Source: accessFixtureSource, Reason: "invalid credentials",
		},
		{
			Kind: audit.KindLoginThrottled, SubmittedName: actor.Account, Method: consoleauth.MethodPassword,
			Source: accessFixtureSource,
			Reason: "refused before any credential was checked; next attempt accepted in 5s",
		},
		{
			Kind: audit.KindLogout, Account: actor.Account, AccountID: actor.AccountID, Role: actor.Role,
			Method: consoleauth.MethodPassword, Source: accessFixtureSource,
		},
		// --- step-up (3) -------------------------------------------------------
		{
			Kind: audit.KindStepUp, Account: actor.Account, AccountID: actor.AccountID, Role: actor.Role,
			Method: consoleauth.MethodPassword, Source: accessFixtureSource, Reason: "step-up re-authentication",
		},
		{
			Kind: audit.KindStepUpFailed, SubmittedName: actor.Account, Method: consoleauth.MethodPassword,
			Source: accessFixtureSource, Reason: "step-up re-authentication refused",
		},
		{
			Kind: audit.KindStepUpThrottled, SubmittedName: actor.Account, Method: consoleauth.MethodPassword,
			Source: accessFixtureSource,
			Reason: "step-up re-authentication refused before any credential was checked; " +
				"next attempt accepted in 5s",
		},
	}
	for _, e := range logins {
		if err := sink.RecordLogin(ctx, e); err != nil {
			t.Fatalf("RecordLogin(%s): %v", e.Kind, err)
		}
	}

	admins := []capability.AccountAdminEvent{
		{Kind: capability.AccountAdminCreate, AccountID: accessFixtureSubject, AccountName: accessFixtureSubject,
			Role: string(accounts.RoleOperator), AccountKind: string(accounts.KindHuman)},
		{Kind: capability.AccountAdminRole, AccountID: accessFixtureSubject, Role: string(accounts.RoleOperator)},
		{Kind: capability.AccountAdminEnable, AccountID: accessFixtureSubject},
		{Kind: capability.AccountAdminDisable, AccountID: accessFixtureSubject},
		{Kind: capability.AccountAdminTokenMint, AccountID: accessFixtureSubject, TokenID: "tok-1"},
		{Kind: capability.AccountAdminTokenRevoke, TokenID: "tok-1"},
	}
	for _, e := range admins {
		if err := sink.RecordAccountAdmin(ctx, actor, e); err != nil {
			t.Fatalf("RecordAccountAdmin(%v): %v", e.Kind, err)
		}
	}

	for _, kind := range []string{audit.KindTokenMint, audit.KindTokenRevoke} {
		if err := st.Audit().Append(ctx, audit.Record{
			ID: "fixture-" + kind, Timestamp: testNow, Kind: kind,
			Principal: actor.Account + ":" + actor.Role,
			Attribution: audit.Attribution{
				Verified: audit.Verified{AccountID: actor.AccountID, AccountName: actor.Account, Role: actor.Role},
			},
		}); err != nil {
			t.Fatalf("Append(%s): %v", kind, err)
		}
	}
}

// accessArticles splits body into its <article class="ev" ...>...</article>
// blocks.
func accessArticles(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, `<article class="ev"`)
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, "</article>")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j+len("</article>")])
		rest = rest[j+len("</article>"):]
	}
}

func accessArticlesOfKind(body string, kind accessKind) []string {
	var out []string
	for _, a := range accessArticles(body) {
		if strings.Contains(a, `data-kind="`+string(kind)+`"`) {
			out = append(out, a)
		}
	}
	return out
}

func accessArticleContaining(t *testing.T, body, needle string) string {
	t.Helper()
	for _, a := range accessArticles(body) {
		if strings.Contains(a, needle) {
			return a
		}
	}
	t.Fatalf("no article contains %q:\n%s", needle, body)
	return ""
}

// accessCountingAccounts is a minimal AccountReader that records every call it
// receives, answering an Account named differently from anything a seeded
// record's Reason carries.
//
// A local type rather than fakes_test.go's shared fakeAccounts: this file's
// job is to prove access.go calls the registry ZERO times, and a call
// counter added to a fixture type used across the package is the wrong place
// to answer that question.
type accessCountingAccounts struct {
	calls int
}

const countingAccountName = "a-name-no-seeded-record-carries"

func (c *accessCountingAccounts) Accounts(context.Context, capability.Principal) ([]accounts.Account, error) {
	c.calls++
	return []accounts.Account{{ID: accessFixtureSubject, Name: countingAccountName, Kind: accounts.KindHuman,
		Role: accounts.RoleOperator, Enabled: true}}, nil
}

func (c *accessCountingAccounts) Account(_ context.Context, _ capability.Principal, id string) (accounts.Account, error) {
	c.calls++
	if id == accessFixtureSubject {
		return accounts.Account{ID: accessFixtureSubject, Name: countingAccountName}, nil
	}
	return accounts.Account{}, accounts.ErrNotFound
}

func (c *accessCountingAccounts) APITokens(context.Context, capability.Principal, string) ([]accounts.APIToken, error) {
	c.calls++
	return nil, nil
}

// accessSource reads access.go's own source, so a test can grep it for a
// banned identifier the same way TestAccounts_NoConsoleFileNamesSecretHash
// reads accounts.go.
func accessSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(".", "access.go"))
	if err != nil {
		t.Fatalf("read access.go: %v", err)
	}
	return string(src)
}

// TestAccess_AnAdminAnswersWhoSignedInFailedAndChangedAnAccount is spec 20's
// first acceptance line.
func TestAccess_AnAdminAnswersWhoSignedInFailedAndChangedAnAccount(t *testing.T) {
	d, sink, st, actor := accessStoreDeps(t)
	seedAccessTrail(t, sink, st, actor)

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access").Body.String()
	content := contentOf(body)

	if n := strings.Count(content, `<article class="ev"`); n != 13 {
		t.Fatalf("the page rendered %d articles, want exactly 13 — the 13 Access records, none of "+
			"the 2 Enrollment Token records seeded alongside them:\n%s", n, content)
	}
	for _, kind := range accessKindOrder {
		if len(accessArticlesOfKind(content, kind)) == 0 {
			t.Errorf("family %q rendered no row", kind)
		}
	}
	for _, evkind := range []string{audit.KindTokenMint, audit.KindTokenRevoke} {
		if strings.Contains(content, `<span class="evkind">`+evkind+`<`) {
			t.Errorf("an Enrollment Token record (%q) rendered on Access — its home is Activity", evkind)
		}
	}

	if !strings.Contains(content, "from <code>"+accessFixtureSource+"</code>") {
		t.Error("no row carries the sign-in Source")
	}
	for _, kind := range []accessKind{accessStepUp, accessAccount, accessAPIToken} {
		for _, a := range accessArticlesOfKind(content, kind) {
			if strings.Contains(a, "from <code>") {
				t.Errorf("a %s article carries a Source, which spec 20 reserves for sign-in rows:\n%s", kind, a)
			}
		}
	}

	for _, a := range accessArticlesOfKind(content, accessAccount) {
		if !strings.Contains(a, `data-trust="verified"`) {
			t.Errorf("an account row does not carry a verified Actor chip:\n%s", a)
		}
	}
	for _, a := range accessArticlesOfKind(content, accessAPIToken) {
		if !strings.Contains(a, `data-trust="verified"`) {
			t.Errorf("an api-token row does not carry a verified Actor chip:\n%s", a)
		}
	}

	failed := accessArticleContaining(t, content, "failed a Console sign-in")
	if strings.Contains(failed, `data-trust="verified"`) {
		t.Error("a login_failed row carries a verified chip — a failed attempt names no Account")
	}
	if !strings.Contains(failed, "no Account named") {
		t.Errorf("a login_failed row does not say \"no Account named\":\n%s", failed)
	}

	// The window and the explicit range both reach the lane.
	windowQ := &fakeQueries{}
	get(t, newTestHandler(accessDeps(windowQ), accounts.RoleAdmin), "/console/access?window=24h")
	if len(windowQ.auditFilters) != 1 {
		t.Fatalf("?window=24h made %d audit queries, want 1", len(windowQ.auditFilters))
	}
	if want := testNow.Add(-24 * time.Hour); !windowQ.auditFilters[0].Since.Equal(want) {
		t.Errorf("?window=24h resolved Since=%v, want %v", windowQ.auditFilters[0].Since, want)
	}

	since, until := "2026-08-20T00:00:00Z", "2026-08-26T00:00:00Z"
	rangeQ := &fakeQueries{}
	get(t, newTestHandler(accessDeps(rangeQ), accounts.RoleAdmin), "/console/access?since="+since+"&until="+until)
	wantSince, _ := time.Parse(time.RFC3339, since)
	wantUntil, _ := time.Parse(time.RFC3339, until)
	if len(rangeQ.auditFilters) != 1 {
		t.Fatalf("the explicit range made %d audit queries, want 1", len(rangeQ.auditFilters))
	}
	if !rangeQ.auditFilters[0].Since.Equal(wantSince) || !rangeQ.auditFilters[0].Until.Equal(wantUntil) {
		t.Errorf("the explicit range did not reach the lane: %+v", rangeQ.auditFilters[0])
	}
}

// TestAccess_EachFamilyChipNarrowsAtTheSeam pins the seam-level narrowing
// every accessKindOrder chip must do, and the unknown-kind refusal for a
// kind this screen does not carry (nonesuch) and for Activity's own (token).
func TestAccess_EachFamilyChipNarrowsAtTheSeam(t *testing.T) {
	sample := map[accessKind]capability.AuditRow{
		accessSignIn: {Kind: audit.KindLoginSucceeded, Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-x", AccountName: "acct-x"}},
		accessStepUp: {Kind: audit.KindStepUp, Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-x", AccountName: "acct-x"}},
		accessAccount: {Kind: audit.KindAccountCreate, Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-x", AccountName: "acct-x"}},
		accessAPIToken: {Kind: audit.KindAPITokenMint, Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-x", AccountName: "acct-x"}},
	}
	var rows []capability.AuditRow
	for _, row := range sample {
		rows = append(rows, row)
	}

	for _, family := range accessKindOrder {
		t.Run(string(family), func(t *testing.T) {
			q := &fakeQueries{rows: rows}
			body := get(t, newTestHandler(accessDeps(q), accounts.RoleAdmin), "/console/access?kind="+string(family)).Body.String()

			if len(q.auditFilters) != 1 {
				t.Fatalf("?kind=%s made %d audit queries, want 1", family, len(q.auditFilters))
			}
			want := accessKindsByFamily[family]
			if !reflect.DeepEqual(q.auditFilters[0].Kinds, want) {
				t.Errorf("?kind=%s sent Kinds=%v, want exactly %v", family, q.auditFilters[0].Kinds, want)
			}

			content := contentOf(body)
			for other := range sample {
				want := other == family
				got := strings.Contains(content, `data-kind="`+string(other)+`"`)
				if got != want {
					t.Errorf("?kind=%s rendered family %q = %v, want %v", family, other, got, want)
				}
			}
		})
	}

	for _, bad := range []string{"nonesuch", "token"} {
		q := &fakeQueries{rows: rows}
		body := get(t, newTestHandler(accessDeps(q), accounts.RoleAdmin), "/console/access?kind="+bad).Body.String()
		if len(q.auditFilters) != 0 {
			t.Errorf("?kind=%s made %d audit queries, want 0", bad, len(q.auditFilters))
		}
		if !strings.Contains(body, "There is no row kind called") {
			t.Errorf("?kind=%s does not say the kind was not recognised", bad)
		}
	}
}

// TestAccess_ASubjectIsShownAsItsRecordNamesIt is spec 20's second
// acceptance line: the subject is the record's Reason, verbatim, never a
// registry lookup.
func TestAccess_ASubjectIsShownAsItsRecordNamesIt(t *testing.T) {
	d, sink, _, actor := accessStoreDeps(t)
	ctx := context.Background()
	if err := sink.RecordAccountAdmin(ctx, actor, capability.AccountAdminEvent{
		Kind: capability.AccountAdminRole, AccountID: accessFixtureSubject, Role: string(accounts.RoleOperator),
	}); err != nil {
		t.Fatalf("RecordAccountAdmin: %v", err)
	}

	fa := &accessCountingAccounts{}
	d.Accounts = fa

	const wantReason = "account_id=" + accessFixtureSubject + " role=operator"
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access?kind=account").Body.String()
	if !strings.Contains(contentOf(body), wantReason) {
		t.Errorf("the account_role row does not render the record's Reason verbatim (%q):\n%s",
			wantReason, contentOf(body))
	}
	if strings.Contains(body, countingAccountName) {
		t.Error("the page contains the registry's current name for the subject — the subject must " +
			"come from the record alone")
	}
	if fa.calls != 0 {
		t.Errorf("access.go called the Account registry %d times — it must never resolve a subject "+
			"through it", fa.calls)
	}

	src := accessSource(t)
	for _, banned := range []string{"d.Accounts", "Accounts("} {
		if strings.Contains(src, banned) {
			t.Errorf("access.go contains %q — this screen must never read the Account registry", banned)
		}
	}
}

// TestAccess_ANonAdminGets404AndNoNavEntry pins D17 ruling 4 by name, the way
// TestAccounts_AViewerFindsTheScreenAbsentNotForbidden pins the Accounts
// screen's own mount gate.
func TestAccess_ANonAdminGets404AndNoNavEntry(t *testing.T) {
	d, _, _, _ := accessStoreDeps(t)

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		h := newTestHandler(d, role)
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			got := request(t, h, method, "/console/access")
			unmounted := request(t, h, method, "/console/no-such-route")
			if got.Code != http.StatusNotFound {
				t.Fatalf("%s /console/access as %s = %d, want 404", method, role, got.Code)
			}
			if got.Body.String() != unmounted.Body.String() {
				t.Errorf("%s /console/access as %s renders a different body from a path that was "+
					"never mounted — the difference is the oracle", method, role)
			}
			if strings.Contains(got.Body.String(), `href="/console/access"`) {
				t.Errorf("%s /console/access as %s's refusal links to itself", method, role)
			}
		}
		if nav := navOf(get(t, h, "/console/").Body.String()); strings.Contains(nav, `href="/console/access"`) {
			t.Errorf("a %s's nav links to /console/access", role)
		}
	}

	admin := newTestHandler(d, accounts.RoleAdmin)
	if got := get(t, admin, "/console/access").Code; got != http.StatusOK {
		t.Fatalf("GET /console/access as an admin = %d, want 200", got)
	}
	if nav := navOf(get(t, admin, "/console/").Body.String()); !strings.Contains(nav, ">Access<") {
		t.Error("an admin's nav does not draw Access")
	}
}

// assertedChipText masks the caller-supplied text an asserted trust chip
// carries, so two renders that legitimately differ only in what was typed
// (or when) can be compared byte-for-byte.
var assertedChipText = regexp.MustCompile(
	`(data-trust="asserted" title="The caller claimed this\. Nothing checked it\.">)[^<]*(<)`)

func maskAssertedChip(s string) string { return assertedChipText.ReplaceAllString(s, "${1}MASKED${2}") }

// accessEnumerationBannedWords is the vocabulary a failed sign-in or step-up
// must never use — the enumeration oracle spec 20 and consoleauth.LoginEvent
// both forbid.
var accessEnumerationBannedWords = []string{"unknown", "no such", "does not exist", "wrong password", "not found"}

// TestAccess_AFailedSignInCarriesNoWhichHalfIndication is spec 20's fourth
// acceptance line, driven through a REAL consoleauth.Service so the
// enumeration oracle is tested against what the service ACTUALLY emits
// (consoleauth.LoginEvent's own doc), not a fixture shaped by hand.
func TestAccess_AFailedSignInCarriesNoWhichHalfIndication(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	mike, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword("correct horse battery staple"))
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, mike.ID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}

	sink := auditsink.New(st.Audit(), auditsink.WithClock(func() time.Time { return testNow }))
	sessions := consoleauth.NewStore()
	// A testClock drives the THROTTLE'S clock, not the sink's: each failed
	// attempt below imposes a progressive per-name delay
	// (DefaultAccountBaseDelay), and the next attempt against the same name
	// — including the eventual correct password — must advance past it or
	// it is refused as throttled rather than compared.
	clk := &testClock{t: testNow}
	svc := consoleauth.NewService(st.Accounts(), st.Passwords(), sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now)), sink)

	if _, _, err := svc.Login(ctx, consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword("wrong password"), Source: accessFixtureSource,
	}); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("Login(mike, wrong password) = %v, want ErrBadCredentials", err)
	}
	clk.advance(consoleauth.DefaultAccountMaxDelay)
	if _, _, err := svc.Login(ctx, consoleauth.Attempt{
		Name: "nobody", Password: accounts.NewPassword("anything"), Source: accessFixtureSource,
	}); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("Login(nobody, anything) = %v, want ErrBadCredentials", err)
	}
	clk.advance(consoleauth.DefaultAccountMaxDelay)

	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	svcCap := capability.New(registry.NewInMemory(), capability.WithAuditSink(sink), capability.WithQueries(q, q))
	d := renderableDeps()
	d.Queries = svcCap
	d.Now = func() time.Time { return testNow }

	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access?kind=sign-in").Body.String())
	var fails []string
	for _, a := range accessArticlesOfKind(body, accessSignIn) {
		if strings.Contains(a, "failed a Console sign-in") {
			fails = append(fails, a)
		}
	}
	if len(fails) != 2 {
		t.Fatalf("got %d login_failed articles, want 2:\n%s", len(fails), body)
	}
	a1, a2 := maskAssertedChip(fails[0]), maskAssertedChip(fails[1])
	if a1 != a2 {
		t.Errorf("the two failed sign-ins are not byte-identical once the submitted name is "+
			"masked:\n%s\n---\n%s", a1, a2)
	}
	for _, article := range fails {
		lower := strings.ToLower(article)
		for _, word := range accessEnumerationBannedWords {
			if strings.Contains(lower, word) {
				t.Errorf("a failed sign-in contains the banned word %q:\n%s", word, article)
			}
		}
	}

	// Step-up half: byte-identity is not possible there, because
	// step_up_failed always carries SubmittedName = sess.Account
	// (consoleauth/service.go), so there is no "unknown Account" counterpart
	// to compare against. Drive a real step-up failure instead and check
	// what the article contains.
	id, _, err := svc.Login(ctx, consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword("correct horse battery staple"), Source: accessFixtureSource,
	})
	if err != nil {
		t.Fatalf("Login(mike, correct password): %v", err)
	}
	if err := svc.StepUp(ctx, id, accounts.NewPassword("wrong password"), accessFixtureSource); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp(wrong password) = %v, want ErrBadCredentials", err)
	}

	stepUpBody := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access?kind=step-up").Body.String())
	failedStepUp := accessArticleContaining(t, stepUpBody, "failed a step-up re-authentication")
	if !strings.Contains(failedStepUp, `<span class="evkind">`+audit.KindStepUpFailed+`<`) {
		t.Errorf("the step-up failure article does not carry its evkind:\n%s", failedStepUp)
	}
	if !strings.Contains(failedStepUp, `data-trust="asserted" title="The caller claimed this. Nothing checked it.">mike<`) {
		t.Errorf("the step-up failure article does not carry the asserted chip for the session's "+
			"Account:\n%s", failedStepUp)
	}
	if !strings.Contains(failedStepUp, `data-attempt="failed"`) {
		t.Errorf("the step-up failure article is not marked data-attempt=\"failed\":\n%s", failedStepUp)
	}
	if strings.Contains(failedStepUp, "from <code>") {
		t.Error("the step-up failure article carries a Source, which spec 20 reserves for sign-in rows")
	}
	lower := strings.ToLower(failedStepUp)
	for _, word := range accessEnumerationBannedWords {
		if strings.Contains(lower, word) {
			t.Errorf("the step-up failure article contains the banned word %q:\n%s", word, failedStepUp)
		}
	}
}

// TestAccess_AThrottledAttemptIsDrawnAsThrottledNotFailed is spec 20's
// fifth acceptance line.
func TestAccess_AThrottledAttemptIsDrawnAsThrottledNotFailed(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindLoginThrottled, Timestamp: testNow},
		{Kind: audit.KindStepUpThrottled, Timestamp: testNow},
	}

	body := contentOf(get(t, newTestHandler(accessDeps(&fakeQueries{rows: rows}), accounts.RoleAdmin), "/console/access").Body.String())
	if n := strings.Count(body, `data-attempt="throttled"`); n != 2 {
		t.Errorf("got %d throttled rows, want 2:\n%s", n, body)
	}
	if strings.Contains(body, `data-attempt="failed"`) {
		t.Error("a throttled attempt rendered data-attempt=\"failed\"")
	}

	q := &fakeQueries{rows: rows}
	failuresBody := contentOf(get(t, newTestHandler(accessDeps(q), accounts.RoleAdmin), "/console/access?failures=1").Body.String())
	if len(q.auditFilters) != 1 || !reflect.DeepEqual(q.auditFilters[0].Kinds, accessFailureKinds) {
		t.Errorf("?failures=1 sent Kinds=%v, want exactly %v", q.auditFilters[0].Kinds, accessFailureKinds)
	}
	if strings.Contains(failuresBody, `data-attempt="throttled"`) {
		t.Error("?failures=1 rendered a throttled row")
	}

	noneQ := &fakeQueries{}
	none := get(t, newTestHandler(accessDeps(noneQ), accounts.RoleAdmin), "/console/access?kind=account&failures=1").Body.String()
	if len(noneQ.auditFilters) != 1 || !reflect.DeepEqual(noneQ.auditFilters[0].Kinds, []string{noSuchAuditKind}) {
		t.Errorf("?kind=account&failures=1 sent Kinds=%v, want the no-such-kind sentinel",
			noneQ.auditFilters[0].Kinds)
	}
	if !strings.Contains(none, "Nothing matches.") {
		t.Error("?kind=account&failures=1 does not say nothing matches")
	}
}

// TestAccess_VocabularyIsExactlySpec20s hand-pins the 13 kinds by family,
// spec 20's Row kinds table: 4 sign-in, 3 step-up, 4 account, 2 api-token.
func TestAccess_VocabularyIsExactlySpec20s(t *testing.T) {
	want := map[accessKind][]string{
		accessSignIn:   {audit.KindLoginSucceeded, audit.KindLoginFailed, audit.KindLoginThrottled, audit.KindLogout},
		accessStepUp:   {audit.KindStepUp, audit.KindStepUpFailed, audit.KindStepUpThrottled},
		accessAccount:  {audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountEnable, audit.KindAccountDisable},
		accessAPIToken: {audit.KindAPITokenMint, audit.KindAPITokenRevoke},
	}
	for family, kinds := range want {
		got := accessKindsByFamily[family]
		if len(got) != len(kinds) {
			t.Errorf("family %q has %d kinds (%v), want exactly %d (%v)", family, len(got), got, len(kinds), kinds)
			continue
		}
		for _, k := range kinds {
			if !containsString(got, k) {
				t.Errorf("family %q does not contain %q", family, k)
			}
		}
	}

	if len(accessAllKinds) != 13 {
		t.Errorf("accessAllKinds has %d kinds, want exactly 13", len(accessAllKinds))
	}
	if containsString(accessAllKinds, audit.KindTokenMint) || containsString(accessAllKinds, audit.KindTokenRevoke) {
		t.Error("accessAllKinds contains an Enrollment Token kind — those stay on Activity")
	}
}

// TestAccess_EveryAuthFailureKindIsAnAccessKind is a test-only tripwire: a
// new auth failure kind added to internal/audit without a matching
// accessKindOf case would otherwise fall silently to Activity's `other`
// family. Production code does not couple to audit.AuthFailureKinds —
// failures-only still uses accessFailureKinds — this guards the vocabulary
// only.
func TestAccess_EveryAuthFailureKindIsAnAccessKind(t *testing.T) {
	for _, k := range audit.AuthFailureKinds() {
		if _, ok := accessKindOf(k); !ok {
			t.Errorf("audit.AuthFailureKinds() contains %q, which accessKindOf does not classify", k)
		}
	}
}

// TestAccess_ARowHasNoFieldASecretCouldOccupy follows
// TestAccounts_ATokenRowHasNoFieldASecretCouldOccupy's shape.
func TestAccess_ARowHasNoFieldASecretCouldOccupy(t *testing.T) {
	typ := reflect.TypeOf(accessRow{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		for _, word := range []string{"Password", "Hash", "Secret", "Plaintext", "Value"} {
			if strings.Contains(f.Name, word) {
				t.Errorf("accessRow.%s names %q — this screen must never hold a credential's material",
					f.Name, word)
			}
		}
	}
}

// TestAccess_NoRoleComparisonLivesInThisScreen follows
// TestAccounts_NoRoleComparisonLivesInThisScreen's shape: the route's
// MinRole (console.go) and the capability layer's AuthorizeControl are the
// only two places a role is compared for this screen, and neither is here.
func TestAccess_NoRoleComparisonLivesInThisScreen(t *testing.T) {
	src := accessSource(t)
	for _, banned := range []string{
		".AtLeast(", "ReachableBy(", "== accounts.Role", "!= accounts.Role",
		"RoleGate", "requiredRole", "caller.Role",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("access.go contains %q — this screen must interpret no role. The route's "+
				"MinRole subtracts reach at mount time and the capability layer authorizes; a "+
				"comparison here would be a third, unreviewed answer (invariant 10).", banned)
		}
	}
}

// TestAccess_APageViewRecordsExactlyOneReadRecord proves the ADR-0025 half:
// one query_audit record per view, attributed to the signed-in admin.
func TestAccess_APageViewRecordsExactlyOneReadRecord(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/access = %d, want 200", rec.Code)
	}

	var queryAudits []audit.Record
	for _, r := range trail.ofKind(audit.KindRead) {
		if r.OperationName == "query_audit" {
			queryAudits = append(queryAudits, r)
		}
	}
	if len(queryAudits) != 1 {
		t.Fatalf("GET /console/access wrote %d query_audit records, want exactly 1", len(queryAudits))
	}
	if got := queryAudits[0].Attribution.Verified.AccountID; got != testAccountID(accounts.RoleAdmin) {
		t.Errorf("the read record's verified AccountID = %q, want %q", got, testAccountID(accounts.RoleAdmin))
	}
}

// --- Moved from activity_test.go (#785) -------------------------------------

// TestAccess_AStepUpIsNotASignIn is #477's Console-rendering seam, run
// through the REAL auditsink.Sink rather than a fixture built by hand: that
// is what actually turns a consoleauth.LoginEvent into the audit.Record this
// package reads, and auditsink.RecordLogin has had no test of its own before
// this one (the #463/#517/#520 lesson — a fixture built by hand can pass a
// mapping bug the real seam would not).
func TestAccess_AStepUpIsNotASignIn(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sink := auditsink.New(st.Audit())
	ctx := context.Background()

	if err := sink.RecordLogin(ctx, consoleauth.LoginEvent{
		Kind: audit.KindLoginSucceeded, Account: "mike", AccountID: "acct-1", Role: "admin",
	}); err != nil {
		t.Fatalf("RecordLogin (sign-in): %v", err)
	}
	if err := sink.RecordLogin(ctx, consoleauth.LoginEvent{
		Kind: audit.KindStepUp, Account: "mike", AccountID: "acct-1", Role: "admin",
		Reason: "step-up re-authentication",
	}); err != nil {
		t.Fatalf("RecordLogin (step-up): %v", err)
	}

	records, err := st.Audit().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("recorded %d rows, want 2", len(records))
	}

	var signIn, stepUp trailFacts
	for _, rec := range records {
		switch rec.Kind {
		case audit.KindLoginSucceeded:
			signIn = factsOfRecord(rec)
		case audit.KindStepUp:
			stepUp = factsOfRecord(rec)
		default:
			t.Fatalf("unexpected recorded kind %q", rec.Kind)
		}
	}

	if got, _ := accessKindOf(audit.KindStepUp); got != accessStepUp {
		t.Errorf("accessKindOf(KindStepUp) = %q, want accessStepUp", got)
	}

	signInSentence, stepUpSentence := accessSummary(signIn), accessSummary(stepUp)
	if stepUpSentence == signInSentence {
		t.Errorf("a step-up and a sign-in render the same sentence: %q", stepUpSentence)
	}
	// Hyphenated, so the raw kind string "step_up" falling through
	// accessSummary's default arm cannot satisfy this.
	if !strings.Contains(stepUpSentence, "step-up") {
		t.Errorf("accessSummary(step-up) = %q, does not read as a step-up", stepUpSentence)
	}
	if stepUpSentence == audit.KindStepUp {
		t.Errorf("accessSummary(step-up) rendered the raw kind string %q", stepUpSentence)
	}
}

// TestAccess_StepUpFailureKindsRenderDistinctly covers #477's amendment:
// three step-up kinds, not one, each classified and each carrying its own
// sentence. Omitting an accessSummary case is #562's exact failure mode — the
// row still lands in accessStepUp via accessKindOf's classification, and
// nothing else fails — which is why each case is checked against BOTH its
// sign-in counterpart and its step-up siblings, not just asserted non-empty.
func TestAccess_StepUpFailureKindsRenderDistinctly(t *testing.T) {
	cases := []struct {
		kind       string
		signInTwin string
	}{
		{audit.KindStepUp, audit.KindLoginSucceeded},
		{audit.KindStepUpFailed, audit.KindLoginFailed},
		{audit.KindStepUpThrottled, audit.KindLoginThrottled},
	}
	seen := map[string]string{} // sentence -> kind that produced it
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if got, _ := accessKindOf(tc.kind); got != accessStepUp {
				t.Errorf("accessKindOf(%q) = %q, want accessStepUp", tc.kind, got)
			}
			got := accessSummary(trailFacts{Kind: tc.kind})
			if got == tc.kind {
				t.Fatalf("accessSummary(%q) rendered the raw kind string — no case for it in the switch", tc.kind)
			}
			if !strings.Contains(got, "step-up") {
				t.Errorf("accessSummary(%q) = %q, does not read as a step-up", tc.kind, got)
			}
			if twin := accessSummary(trailFacts{Kind: tc.signInTwin}); got == twin {
				t.Errorf("accessSummary(%q) == accessSummary(%q) == %q; the step-up door must read "+
					"distinctly from the sign-in door", tc.kind, tc.signInTwin, got)
			}
			if by, dup := seen[got]; dup {
				t.Errorf("accessSummary(%q) = %q, duplicates accessSummary(%q)", tc.kind, got, by)
			}
			seen[got] = tc.kind
		})
	}
}
