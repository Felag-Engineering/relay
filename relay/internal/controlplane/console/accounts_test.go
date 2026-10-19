package console

// accounts_test.go is the Accounts screen's read half (#654, spec 15).
//
// Three of its acceptance criteria are already swept by guards this package
// keeps — the mount gate (TestConsole_ARouteAboveTheSessionRoleIsAbsent), the
// read-audit classification (read_audit_test.go) and the day-one criterion's
// named skip (dayone_test.go). Those sweeps activate the moment the fixture is
// wired, and what is here is the rest: the properties no sweep can express,
// and a NAMED pin for each acceptance line so a failure says which criterion
// broke rather than which sweep noticed.
//
// The "?account=" cases matter more than they look. walkableScreens emits BARE
// paths only, so the token panel, the unknown-Account note and the failed
// token read are reached by NO structural guard in this package — not the
// inline-script sweep, not the CSRF sweep, not the day-one sweep. Every
// assertion about them has to be written here explicitly.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

const accountsPath = "/console/accounts"

// accountsFixture is sweepFixture narrowed to what this file drives: the rich
// Account set, with the agent-call row that gives the machine Account a last
// call.
func accountsFixture() Deps { return sweepFixture() }

// rowFor returns the <tr>…</tr> containing name, so an assertion about ONE
// Account's row cannot accidentally be satisfied by another Account's.
func rowFor(t *testing.T, body, name string) string {
	t.Helper()
	i := strings.Index(body, ">"+name+"<")
	if i < 0 {
		t.Fatalf("no cell renders the Account %q:\n%s", name, contentOf(body))
	}
	start := strings.LastIndex(body[:i], "<tr")
	end := strings.Index(body[i:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("the cell for %q is not inside a table row", name)
	}
	return body[start : i+end]
}

// tbodyRows counts the rows in the FIRST <tbody> of body — the Account table.
func tbodyRows(t *testing.T, body string) int {
	t.Helper()
	i := strings.Index(body, "<tbody>")
	j := strings.Index(body, "</tbody>")
	if i < 0 || j < 0 {
		t.Fatalf("no <tbody> in the rendered page:\n%s", contentOf(body))
	}
	return strings.Count(body[i:j], "<tr")
}

// ---------------------------------------------------------------------------
// "The route is absent below admin — 404 byte-identical, on GET and OPTIONS."
// ---------------------------------------------------------------------------

// TestAccounts_AViewerFindsTheScreenAbsentNotForbidden is the owner decision
// of 2026-09-19 ("a viewer can see the fleet etc but not administrative
// settings such as accounts"), pinned by name.
//
// 404 and not 403, because a 403 is itself the disclosure: it confirms the
// screen exists to exactly the role that must not learn that (ADR-0026
// decision 5). The sweep in console_test.go asserts this generically for every
// constrained route; this pins it for THIS route, so the acceptance line has a
// test that names it.
func TestAccounts_AViewerFindsTheScreenAbsentNotForbidden(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleViewer)

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		got := request(t, h, method, accountsPath)
		unmounted := request(t, h, method, "/console/no-such-route")

		if got.Code != http.StatusNotFound {
			t.Fatalf("%s %s as a viewer = %d, want 404", method, accountsPath, got.Code)
		}
		if got.Body.String() != unmounted.Body.String() {
			t.Errorf("%s %s renders a different body from a path that was never mounted — "+
				"the difference is the oracle", method, accountsPath)
		}
		body := got.Body.String()
		if strings.Contains(body, "Accounts") {
			t.Errorf("%s %s names Accounts in the refusal — the screen must be ABSENT for a viewer, "+
				"including in the navigation", method, accountsPath)
		}
		if strings.Contains(strings.ToLower(body), "forbidden") {
			t.Errorf("%s %s reads as forbidden rather than absent", method, accountsPath)
		}
	}

	// And an admin reaches it, so the assertion above is about the ROLE and
	// not about a route nobody mounted.
	if got := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Code; got != http.StatusOK {
		t.Fatalf("GET %s as an admin = %d, want 200", accountsPath, got)
	}
}

// ---------------------------------------------------------------------------
// "This package interprets no role; the refusal rendered is the capability
// layer's."
// ---------------------------------------------------------------------------

// TestAccounts_ACapabilityRefusalIsRenderedNotReinterpreted drives an ADMIN —
// a role the mount gate admits — into a seam that refuses. What must come back
// is the capability layer's own sentence, not a second opinion composed here.
func TestAccounts_ACapabilityRefusalIsRenderedNotReinterpreted(t *testing.T) {
	d := accountsFixture()
	d.Accounts = &fakeAccounts{err: authz.ErrUnauthorized}

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a refused Account read = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), authz.ErrUnauthorized.Error()) {
		t.Errorf("the refusal does not carry the capability layer's own text (%q):\n%s",
			authz.ErrUnauthorized.Error(), contentOf(rec.Body.String()))
	}
}

// TestAccounts_ARefusedTokenReadIsAlsoTheLayersRefusal: the same rule on the
// second read. A screen that rendered the Account table and silently dropped a
// REFUSED token panel would be interpreting the refusal.
func TestAccounts_ARefusedTokenReadIsAlsoTheLayersRefusal(t *testing.T) {
	d := accountsFixture()
	f := sweepAccounts()
	f.tokensErr = authz.ErrUnauthorized
	d.Accounts = f

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath+"?account=gleipnir-prod")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a refused API-Token read = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), authz.ErrUnauthorized.Error()) {
		t.Error("the refused token read does not carry the capability layer's own text")
	}
}

// TestAccounts_NoRoleComparisonLivesInThisScreen is invariant 10 as a source
// fact rather than a rendered one: accounts.go must not decide anything about
// role. The route's MinRole (console.go) and the capability layer's
// AuthorizeControl are the only two places a role is compared for this screen,
// and neither is here.
func TestAccounts_NoRoleComparisonLivesInThisScreen(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "accounts.go"))
	if err != nil {
		t.Fatalf("read accounts.go: %v", err)
	}
	// The COMPARISON shapes, not every mention of a role: this file
	// legitimately renders a role name in a table cell and names the three
	// roles in the "what a role means" block. What it must never do is decide
	// anything from one.
	// "caller.Role" is the load-bearing entry, and it is a ban on READING the
	// caller's role at all rather than on any particular comparison shape.
	// The operator-shaped entries below do not catch a switch on the role, nor
	// a comparison against a string literal (`string(caller.Role) != "admin"`)
	// — both compile, and both are the third, unreviewed answer. This file
	// never legitimately reads caller.Role: it passes `caller` whole to the
	// capability layer, which is the whole point.
	for _, banned := range []string{
		".AtLeast(", "ReachableBy(", "== accounts.Role", "!= accounts.Role",
		"RoleGate", "requiredRole", "caller.Role",
	} {
		if strings.Contains(string(src), banned) {
			t.Errorf("accounts.go contains %q — this screen must interpret no role. The route's "+
				"MinRole subtracts reach at mount time and the capability layer authorizes; a "+
				"comparison here would be a third, unreviewed answer (invariant 10).", banned)
		}
	}
}

// ---------------------------------------------------------------------------
// "A machine Account with no call in the read page says so in words."
// ---------------------------------------------------------------------------

func TestAccounts_AMachineAccountWithNoCallSaysSoInWords(t *testing.T) {
	d := accountsFixture()
	d.Accounts = &fakeAccounts{accounts: []accounts.Account{{
		ID: "acct-quiet", Name: "quiet-ci", Kind: accounts.KindMachine,
		Role: accounts.RoleOperator, Enabled: true, LastSeenAt: testNow.Add(-time.Hour),
	}}}
	// No agent-call rows at all, so this Account cannot be in the page.
	d.Queries = &fakeQueries{}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath).Body.String()
	row := rowFor(t, body, "quiet-ci")

	want := "no tool call in the last 200 recorded calls"
	if !strings.Contains(row, want) {
		t.Errorf("a machine Account with no call in the page does not say so. Row:\n%s", row)
	}
	// Never blank and never a zero: both read as facts the screen cannot back.
	if strings.Contains(row, "0001-01-01") {
		t.Error("the row rendered a zero time rather than saying what it does not know")
	}
	if strings.Contains(row, ">0<") {
		t.Error("the row rendered a zero rather than words")
	}
}

func TestAccounts_AMachineAccountsLastCallLinksToActivityScopedToItsID(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String()
	row := rowFor(t, body, "gleipnir-prod")

	if !strings.Contains(row, `href="/console/activity?account=`+sweepMachineAccountID+`"`) {
		t.Errorf("the last tool call does not link to Activity scoped to this Account's ID (spec 15 Rows). Row:\n%s", row)
	}
	if strings.Contains(row, "/console/activity?account=gleipnir-prod") {
		t.Errorf("the last tool call link names the Account, not its ID (D18). Row:\n%s", row)
	}
	if strings.Contains(row, "no tool call") {
		t.Error("an Account WITH a call on the page rendered the honest-absence copy instead")
	}
}

// TestAccounts_AnAccountNameIsURLEncodedInEveryLink is the #467 regression, on
// this screen's two links. An Account name or id is a string this package
// does not constrain, and "bob&co" concatenated into a query yields a link to
// a different Account entirely.
func TestAccounts_AnAccountNameIsURLEncodedInEveryLink(t *testing.T) {
	d := accountsFixture()
	d.Accounts = &fakeAccounts{accounts: []accounts.Account{{
		ID: "acct&co", Name: "bob&co", Kind: accounts.KindMachine,
		Role: accounts.RoleOperator, Enabled: true,
	}}}
	// With a call on the page, so the Activity link is actually rendered
	// — the encoding of a link that never draws proves nothing.
	d.Queries = &fakeQueries{rows: []capability.AuditRow{{
		Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow.Add(-time.Minute),
		Verified: capability.VerifiedIdentity{AccountID: "acct&co", AccountName: "bob&co"},
	}}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath).Body.String()
	for _, want := range []string{
		"/console/accounts?account=bob%26co",
		"/console/activity?account=acct%26co",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("a name containing & is not URL-encoded in %q — the link reaches the wrong "+
				"Account (#467):\n%s", want, contentOf(body))
		}
	}
}

// TestAccounts_AHumanAccountHasNoLastToolCallCell: spec 15 scopes the column
// to machine Accounts. A human's empty cell is CORRECT, and rendering the
// honest-absence sentence there would state something about a kind of Account
// that does not make tool calls.
func TestAccounts_AHumanAccountHasNoLastToolCallCell(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String()
	row := rowFor(t, body, "mike")

	if strings.Contains(row, "no tool call") {
		t.Errorf("a human Account renders the machine-only absence copy. Row:\n%s", row)
	}
	if strings.Contains(row, "/console/activity?account=") {
		t.Errorf("a human Account renders a last-tool-call link. Row:\n%s", row)
	}
}

// ---------------------------------------------------------------------------
// "The read is classified, and records exactly one query_audit per page view."
// ---------------------------------------------------------------------------

// TestAccounts_APageViewRecordsExactlyOneReadRecord drives the real lane over
// the real sink, twice: the bare path and a selected Account.
//
// The second run is the load-bearing one. The Account and API-Token reads
// record NOTHING on success (capability/accountadmin.go), so selecting an
// Account must not change the count — if it ever did, something in this
// package started auditing on its own, which invariant 10 and
// read_audit_test.go both forbid.
func TestAccounts_APageViewRecordsExactlyOneReadRecord(t *testing.T) {
	for _, path := range []string{
		accountsPath,
		accountsPath + "?account=" + testAdminName,
	} {
		trail := &recordingTrail{}
		rec := get(t, newTestHandler(realLaneDeps(trail), accounts.RoleAdmin), path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}

		reads := trail.ofKind(audit.KindRead)
		if len(reads) != 1 {
			var names []string
			for _, r := range reads {
				names = append(names, r.OperationName)
			}
			t.Fatalf("GET %s wrote %d read records (%v), want exactly 1", path, len(reads), names)
		}
		if reads[0].OperationName != "query_audit" {
			t.Errorf("GET %s recorded %q, want %q", path, reads[0].OperationName, "query_audit")
		}
	}
}

// ---------------------------------------------------------------------------
// "No SecretHash, no token value, no Relay configuration."
// ---------------------------------------------------------------------------

// TestAccounts_ATokenRowHasNoFieldASecretCouldOccupy is the structural half:
// the view type carries no field a secret could be put in, so "no token value
// renders" does not depend on the template remembering.
func TestAccounts_ATokenRowHasNoFieldASecretCouldOccupy(t *testing.T) {
	typ := reflect.TypeOf(tokenRow{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("tokenRow.%s is a []byte — the only []byte on an API Token is its SecretHash, "+
				"and no screen type may have somewhere to put one", f.Name)
		}
		for _, word := range []string{"Secret", "Hash", "Plaintext"} {
			if strings.Contains(f.Name, word) {
				t.Errorf("tokenRow.%s names %q — a token's secret exists once, at mint, and never "+
					"reaches a rendered page", f.Name, word)
			}
		}
	}
}

// TestAccounts_NoSecretHashReachesTheRenderedPage is the rendered half, driven
// at the path that actually renders tokens. The fixture token carries a real
// SecretHash: a leak test against a fixture with nothing to leak proves
// nothing.
func TestAccounts_NoSecretHashReachesTheRenderedPage(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin),
		accountsPath+"?account=gleipnir-prod").Body.String()

	// The panel must have rendered, or the assertion below is vacuous.
	if !strings.Contains(body, "tok-live") {
		t.Fatalf("the token panel did not render, so the leak assertion proves nothing:\n%s", contentOf(body))
	}
	if strings.Contains(body, sweepTokenSecretHash) {
		t.Error("a token's SecretHash reached the rendered page")
	}
}

// TestAccounts_NoConsoleFileNamesSecretHash is the source-level half, and it
// was written to survive #655. It did: that issue legitimately names
// accounts.Plaintext — accounts_write.go mints, once, and reveals once — and
// names SecretHash nowhere. The Plaintext side of that prediction has its own
// guard now (TestAccountsWrite_NoConsoleFileNamesPlaintextOutsideTheMint),
// which bans the type everywhere BUT that one file; this one still bans
// SecretHash everywhere without exception.
//
// An AST walk rather than a substring scan, in no_dispatch_test.go's shape,
// because the property is about CODE. Parsed without comments, so a doc
// comment that names the field in order to say it is absent — accounts.go's
// own tokenRow comment does exactly that — is not itself the violation.
func TestAccounts_NoConsoleFileNamesSecretHash(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if v.Name == "SecretHash" {
					t.Errorf("%s names SecretHash. The Console renders tokens by id and name; the "+
						"hash of a credential has no rendering, so naming the field is the first "+
						"half of giving it one.", name)
				}
			case *ast.BasicLit:
				// A template is a string literal, so an identifier walk
				// alone would miss "{{.SecretHash}}" entirely — the one
				// place this could actually reach a rendered page.
				if strings.Contains(v.Value, "SecretHash") {
					t.Errorf("%s has a string literal naming SecretHash (%.60s…) — a template that "+
						"names the field renders it", name, v.Value)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("the guard inspected zero files — it is not running")
	}
}

// TestAccounts_AboutNamesThePolicyCeiling: spec 15 asks for the sentence that
// the ceiling is always the fleet's own Policy. Since #849 the screen draws no
// per-role lines — what each role may do is ADR-0010's and GLOSSARY.md's — so
// the ceiling is what remains. It must not become a permission matrix, and it
// must not become Relay configuration (invariant 11, foundations rule 7).
func TestAccounts_AboutNamesThePolicyCeiling(t *testing.T) {
	body := contentOf(get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String())

	// Compared against the const rather than a copy of the prose, so the
	// sentence and this assertion cannot drift. Unescaped first: html/template
	// turns the apostrophe in "Node's" into &#39;, which is correct output and
	// would make a raw comparison fail for the wrong reason.
	if !strings.Contains(html.UnescapeString(body), policyCeilingNote) {
		t.Errorf("the screen does not state that a Node's own Policy is the ceiling:\n%s", body)
	}
	// Not configuration, and not a fleet inventory: this screen is about
	// identity, and a Node id, Selector or Operation name here would be the
	// start of a settings page.
	for _, banned := range []string{"node-web-1", "blast", "selector", "console_execution"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Errorf("the Accounts screen renders %q — it must carry no Relay configuration and no "+
				"fleet detail (spec 15 'Must not appear', invariant 11)", banned)
		}
	}
}

// ---------------------------------------------------------------------------
// Day one — the shape dayone_test.go's named skip hands over.
// ---------------------------------------------------------------------------

// TestAccounts_DayOneShowsTheFoundingAdmin is what makes the day-one exemption
// honest. The criterion dayone_test.go sweeps is about measuring a fleet that
// does not exist yet; an Account table is not a fleet, and on a fresh Relay it
// has exactly one true row — the admin `relay init` created, without whom
// nobody could have signed in to see it.
//
// The <thead> is EXPECTED here, not tolerated: one real row under column
// headings is the honest first-boot shape, and it is the shape a real operator
// sees the first time they open this screen.
func TestAccounts_DayOneShowsTheFoundingAdmin(t *testing.T) {
	rec := get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), accountsPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s on a fresh Relay = %d, want 200", accountsPath, rec.Code)
	}
	body := contentOf(rec.Body.String())

	if !strings.Contains(body, "<thead>") {
		t.Error("the Account table renders without column headings — the founding admin's row is a " +
			"real row and belongs under them")
	}
	if got := tbodyRows(t, body); got != 1 {
		t.Fatalf("a fresh Relay renders %d Account rows, want exactly 1 (the founding admin)", got)
	}

	row := rowFor(t, body, testAdminName)
	for _, want := range []string{
		string(accounts.KindHuman),
		string(accounts.RoleAdmin),
		// In WORDS: a bare boolean in a state column is unreadable at the
		// moment somebody is reading this screen in a hurry.
		"enabled",
		// stamp's zero rendering. Nobody has signed in yet, and the row must
		// say that rather than printing the zero time. Matched as ">—</td>"
		// because each cell now opens with a data-label attribute.
		">—</td>",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("the founding admin's row does not render %q. Row:\n%s", want, row)
		}
	}
	if strings.Contains(row, "0001-01-01") {
		t.Error("the founding admin's never-authenticated row rendered a zero time")
	}
	// Human, so the machine-only column is empty for it.
	if strings.Contains(row, "no tool call") || strings.Contains(row, "/console/activity?account=") {
		t.Error("the founding admin is human and must have no last-tool-call cell")
	}
}

// ---------------------------------------------------------------------------
// "?account=" — swept by NO structural guard, so every case is written here.
// ---------------------------------------------------------------------------

// TestAccounts_TheTokenPanelRendersOnlyForTheSelectedAccount, with every
// column spec 15 asks for.
func TestAccounts_TheTokenPanelRendersOnlyForTheSelectedAccount(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)

	bare := get(t, h, accountsPath).Body.String()
	if strings.Contains(bare, "tok-live") {
		t.Error("the bare Accounts path rendered a token panel — tokens are per selected Account")
	}
	if strings.Contains(bare, "Role and state") || strings.Contains(bare, "API Tokens &mdash;") {
		t.Error("the bare Accounts path rendered a selected Account's panel")
	}

	selected := get(t, h, accountsPath+"?account=gleipnir-prod").Body.String()
	for _, want := range []string{
		"tok-live",             // id
		"ci-deploy",            // name
		"2026-08-15 12:00:00Z", // created
		"2026-08-25 11:58:30Z", // last used
		"does not expire",      // expiry, in words for a token with none
		"revoked",              // the revoked token's state
		"2026-08-26 12:00:00Z", // the revoked token's expiry
	} {
		if !strings.Contains(selected, want) {
			t.Errorf("the token panel does not render %q:\n%s", want, contentOf(selected))
		}
	}
	panel, list := strings.Index(selected, "API Tokens &mdash;"), strings.Index(selected, `<table class="rows cards">`)
	if panel < 0 || list < 0 || panel > list {
		t.Errorf("the token panel (at %d) does not come before the Account list (at %d)", panel, list)
	}
}

// TestAccounts_ASelectedAccountsPageCarriesNoInlineScript is the sweep that
// does not exist: walkableScreens emits bare paths, so the inline-script and
// banned-attribute guards never see this body.
func TestAccounts_ASelectedAccountsPageCarriesNoInlineScript(t *testing.T) {
	path := accountsPath + "?account=gleipnir-prod"
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), path).Body.String()

	assertCSPClean(t, path, body)
}

// TestAccounts_AnUnknownSelectionSaysSoRatherThanRenderingABlankPanel. A blank
// panel reads as "this Account has no tokens", which is a claim about an
// Account that does not exist.
func TestAccounts_AnUnknownSelectionSaysSoRatherThanRenderingABlankPanel(t *testing.T) {
	rec := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath+"?account=nobody")
	if rec.Code != http.StatusOK {
		t.Fatalf("an unknown ?account= = %d, want 200 — the list is still readable", rec.Code)
	}
	body := contentOf(rec.Body.String())

	if !strings.Contains(body, "No Account on this Relay is named") {
		t.Errorf("an unknown ?account= does not say so:\n%s", body)
	}
	if !strings.Contains(body, "gleipnir-prod") {
		t.Error("an unknown ?account= dropped the Account table — the list is a separate read and is fine")
	}
	if strings.Contains(body, "has no API Tokens") {
		t.Error("an unknown ?account= rendered the empty-token-panel copy, which claims the Account exists")
	}
}

// TestAccounts_AFailedTokenReadDegradesOnePanel. A store that failed is not an
// unauditable read: the Account table beside it IS readable, and refusing the
// whole page would hide what this operator can still see. The unauditable case
// is the opposite and is covered by
// TestConsole_AnUnauditableReadRefusesTheScreen.
func TestAccounts_AFailedTokenReadDegradesOnePanel(t *testing.T) {
	d := accountsFixture()
	f := sweepAccounts()
	f.tokensErr = errQueryFailed
	d.Accounts = f

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath+"?account=gleipnir-prod")
	if rec.Code != http.StatusOK {
		t.Fatalf("a failed token read = %d, want 200 with one degraded panel", rec.Code)
	}
	body := contentOf(rec.Body.String())

	if !strings.Contains(body, "could not be read") {
		t.Errorf("the token panel does not say it could not be read:\n%s", body)
	}
	if !strings.Contains(body, "mike") {
		t.Error("a failed token read took the Account table down with it")
	}
	if !strings.Contains(body, "the Account list below is unaffected") {
		t.Errorf("the degraded panel does not say the list below is unaffected:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// The rest of the screen's honest-refusal and vocabulary properties.
// ---------------------------------------------------------------------------

// TestAccounts_AnUnwiredSeamRefusesRatherThanClaimingThereAreNoAccounts. Both
// shapes of "not wired" — a nil seam and an AccountAdmin built without
// its stores — must say so. "You have no Accounts" is a claim about who
// can reach this Relay, and it is the worst one to make by accident.
func TestAccounts_AnUnwiredSeamRefusesRatherThanClaimingThereAreNoAccounts(t *testing.T) {
	cases := map[string]AccountReader{
		"nil seam":              nil,
		"account admin unwired": &fakeAccounts{err: capability.ErrAccountsUnavailable},
	}
	for name, seam := range cases {
		t.Run(name, func(t *testing.T) {
			d := accountsFixture()
			d.Accounts = seam

			rec := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("an unwired Account seam = %d, want 500", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "was not wired into this Relay") {
				t.Errorf("the refusal does not distinguish a wiring problem from an empty Account "+
					"registry:\n%s", rec.Body.String())
			}
		})
	}
}

// TestAccounts_ADisabledAccountSaysDisabledInWords. The durable off-switch is
// the field an operator scans this table for during an incident, and "false"
// is not a word anybody reads at a glance.
func TestAccounts_ADisabledAccountSaysDisabledInWords(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String()

	if row := rowFor(t, body, "retired-ci"); !strings.Contains(row, "disabled") {
		t.Errorf("a disabled Account does not say so in words. Row:\n%s", row)
	}
	if row := rowFor(t, body, "mike"); !strings.Contains(row, "enabled") {
		t.Errorf("an enabled Account does not say so in words. Row:\n%s", row)
	}
	for _, banned := range []string{">true</td>", ">false</td>"} {
		if strings.Contains(body, banned) {
			t.Errorf("the table rendered %q — a bare boolean is not a state an operator can read", banned)
		}
	}
}

// TestAccounts_LastAuthenticationAndLastToolCallAreDifferentColumns.
// Account.LastSeenAt is last AUTHENTICATION; spec 15 asks for both, separately,
// and conflating them would make an idle-but-authenticating machine Account
// look busy.
func TestAccounts_LastAuthenticationAndLastToolCallAreDifferentColumns(t *testing.T) {
	body := contentOf(get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String())

	for _, want := range []string{"Last authentication", "Last tool call"} {
		if !strings.Contains(body, want) {
			t.Errorf("the table has no %q column", want)
		}
	}
	// mike authenticated two hours ago and is human, so his row carries a
	// last-authentication stamp and no tool-call cell at all.
	if row := rowFor(t, body, "mike"); !strings.Contains(row, "2026-08-25 10:00:00Z") {
		t.Errorf("a human Account's last authentication is not rendered. Row:\n%s", row)
	}
}

// TestAccounts_TheLastCallFilterNamesEveryAgentCallKind pins agentCallKinds as
// DERIVED from audit.Kinds() through isAgentCallKind, never hand-listed — the
// same shape buildKindsByFamily (activity.go) uses. A hand-list can go stale
// the moment a new Kind is classified by isAgentCallKind and nobody remembers
// to add it to a second list.
func TestAccounts_TheLastCallFilterNamesEveryAgentCallKind(t *testing.T) {
	var want []string
	for _, k := range audit.Kinds() {
		if isAgentCallKind(k) {
			want = append(want, k)
		}
	}
	// Comparing against the SAME derivation the test names would make this
	// test satisfiable by nil == nil, which is exactly the fail-open finding
	// buildAgentCallKinds' own panic guards against. Pin non-emptiness here
	// too, so a mutation that makes isAgentCallKind fall through for
	// everything cannot pass by having both sides agree on empty.
	if len(agentCallKinds) == 0 {
		t.Fatal("agentCallKinds is empty — an empty Kinds filter matches EVERY " +
			"row (capability.AuditFilter's zero-value semantics), which would put " +
			"login, token, Account and Freeze records on the AI-agent call surface")
	}
	if !reflect.DeepEqual(agentCallKinds, want) {
		t.Fatalf("agentCallKinds = %v, want the kinds isAgentCallKind admits, %v", agentCallKinds, want)
	}
	for _, k := range agentCallKinds {
		switch k {
		case audit.KindApprovalExpired:
			t.Error("agentCallKinds includes approval_expired — an expiry is the clock, not a caller")
		case audit.KindLoginSucceeded, audit.KindLoginFailed, audit.KindFreezeEngage:
			t.Errorf("agentCallKinds includes %s — a control-plane event is not an AI-agent call", k)
		}
	}
}

// TestAccounts_TheLastCallReadAsksForAgentCallKindsOnly proves the Kinds
// filter reaches the lane: the Accounts handler's one QueryAudit carries
// agentCallKinds. Without it, a login is on the last-call surface.
func TestAccounts_TheLastCallReadAsksForAgentCallKindsOnly(t *testing.T) {
	q := &fakeQueries{}
	d := accountsFixture()
	d.Queries = q

	get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath)

	if q.auditCalls != 1 {
		t.Fatalf("QueryAudit was called %d times, want exactly 1", q.auditCalls)
	}
	if !reflect.DeepEqual(q.auditFilters[0].Kinds, agentCallKinds) {
		t.Errorf("QueryAudit filter Kinds = %v, want %v", q.auditFilters[0].Kinds, agentCallKinds)
	}
}

// TestAccounts_AControlPlaneEventIsNotAToolCall: a verified login for the
// machine Account is on the trail but is not a tool call, so the last-call
// cell must keep saying there is none.
func TestAccounts_AControlPlaneEventIsNotAToolCall(t *testing.T) {
	d := accountsFixture()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{{
		Kind:      audit.KindLoginSucceeded,
		Timestamp: testNow.Add(-time.Minute),
		Verified: capability.VerifiedIdentity{
			AccountID:   sweepMachineAccountID,
			AccountName: "gleipnir-prod",
			Role:        string(accounts.RoleOperator),
		},
	}}}

	row := rowFor(t, get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath).Body.String(), "gleipnir-prod")

	if !strings.Contains(row, "no tool call in the last") {
		t.Errorf("a login rendered as the Account's last tool call. Row:\n%s", row)
	}
	if strings.Contains(row, "/console/activity?account=") {
		t.Errorf("the last-call cell links to Activity although the Account made no tool call. Row:\n%s", row)
	}
}
