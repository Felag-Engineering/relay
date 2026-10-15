package console

// identity_filters_test.go covers #835's Access and Activity halves: the
// verified actor chip links by Account ID, the asserted chip shows only when it
// adds something, and the Actor/Principal box takes the Account's ID alone.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

func TestAccess_VerifiedActorIsALinkedNameChipByAccountID(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{{
		Kind: audit.KindLoginSucceeded, Timestamp: testNow,
		Verified: capability.VerifiedIdentity{AccountID: "acct-1", AccountName: "admin"},
	}}}
	content := contentOf(get(t, newTestHandler(accessDeps(q), accounts.RoleAdmin), "/console/access?kind=sign-in").Body.String())

	a := accessArticleContaining(t, content, "signed in to the Console")
	const link = `<a class="chiplink" href="/console/access?account=acct-1&amp;kind=sign-in">`
	i := strings.Index(a, link)
	if i < 0 {
		t.Fatalf("the verified chip is not linked by Account ID, keeping the filters:\n%s", a)
	}
	end := strings.Index(a[i:], "</a>")
	if chip := a[i : i+end]; !strings.Contains(chip, `data-trust="verified"`) || !strings.Contains(chip, ">admin<") {
		t.Errorf("the link does not wrap the verified name chip:\n%s", chip)
	}
	if strings.Contains(a, "account=admin") {
		t.Error("the link names the Account by name; links use verified IDs (D18)")
	}
}

func TestAccess_AssertedChipOnlyWhenItDiffersOrTheAttemptFailed(t *testing.T) {
	verified := capability.VerifiedIdentity{AccountID: "acct-1", AccountName: "admin"}
	nameless := capability.VerifiedIdentity{AccountID: "acct-1"}
	tests := []struct {
		name string
		row  capability.AuditRow
		want bool
	}{
		{"succeeded, same name", capability.AuditRow{Kind: audit.KindLoginSucceeded, Verified: verified,
			Asserted: capability.Assertions{OnBehalfOf: "admin"}}, false},
		{"succeeded, differs in case", capability.AuditRow{Kind: audit.KindLoginSucceeded, Verified: verified,
			Asserted: capability.Assertions{OnBehalfOf: "Admin"}}, true},
		{"succeeded, another name", capability.AuditRow{Kind: audit.KindLoginSucceeded, Verified: verified,
			Asserted: capability.Assertions{OnBehalfOf: "bob"}}, true},
		{"step-up failed", capability.AuditRow{Kind: audit.KindStepUpFailed, Verified: verified,
			Asserted: capability.Assertions{OnBehalfOf: "admin"}}, true},
		{"login failed, real name", capability.AuditRow{Kind: audit.KindLoginFailed,
			Asserted: capability.Assertions{OnBehalfOf: "mike"}}, true},
		{"login throttled, real name", capability.AuditRow{Kind: audit.KindLoginThrottled,
			Asserted: capability.Assertions{OnBehalfOf: "mike"}}, true},
		{"verified ID with no name", capability.AuditRow{Kind: audit.KindLoginSucceeded, Verified: nameless,
			Asserted: capability.Assertions{OnBehalfOf: "x"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.row.Timestamp = testNow
			q := &fakeQueries{rows: []capability.AuditRow{tc.row}}
			content := contentOf(get(t, newTestHandler(accessDeps(q), accounts.RoleAdmin), "/console/access").Body.String())
			if got := strings.Contains(content, `data-trust="asserted"`); got != tc.want {
				t.Errorf("asserted chip drawn = %v, want %v:\n%s", got, tc.want, content)
			}
		})
	}
}

// The Actor and Principal boxes take an Account ID and nothing else. Resolving
// a name would be an Account-registry read no audit record covers (#659), so no
// request to either screen reads the registry, ?actor= is not a parameter, and
// whatever ?account= carries narrows as the literal value.
func TestAccessAndActivity_FiltersTakeTheLiteralIDAndNeverReadTheAccountRegistry(t *testing.T) {
	for _, tc := range []struct {
		path string
		deps func(*fakeQueries) Deps
	}{
		{"/console/access", accessDeps},
		{"/console/activity", activityDeps},
	} {
		for _, query := range []string{
			"", "?account=" + countingAccountName, "?account=nobody&kind=read", "?actor=" + countingAccountName,
		} {
			reg := &accessCountingAccounts{}
			d := tc.deps(&fakeQueries{})
			d.Accounts = reg
			rec := get(t, newTestHandler(d, accounts.RoleAdmin), tc.path+query)
			if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
				t.Fatalf("%s%s: status %d, Location %q, want 200 in place", tc.path, query, rec.Code, rec.Header().Get("Location"))
			}
			if reg.calls != 0 {
				t.Errorf("%s%s consulted the Account registry %d times, want 0", tc.path, query, reg.calls)
			}
		}

		q := &fakeQueries{}
		d := tc.deps(q)
		d.Accounts = &accessCountingAccounts{}
		get(t, newTestHandler(d, accounts.RoleAdmin), tc.path+"?account="+countingAccountName)
		if len(q.auditFilters) == 0 {
			t.Fatalf("%s: the trail lane did not run", tc.path)
		}
		for _, f := range q.auditFilters {
			if f.AccountID != countingAccountName {
				t.Errorf("%s: audit filter %+v, want AccountID %q literally", tc.path, f, countingAccountName)
			}
		}
	}
}

// The Actor and Principal boxes submit ?account=, the verified ID's own
// parameter.
func TestAccessAndActivity_FilterBoxesSubmitAccount(t *testing.T) {
	for _, tc := range []struct {
		path string
		deps func(*fakeQueries) Deps
	}{
		{"/console/access", accessDeps},
		{"/console/activity", activityDeps},
	} {
		body := get(t, newTestHandler(tc.deps(&fakeQueries{}), accounts.RoleAdmin), tc.path+"?account=acct-1").Body.String()
		if !strings.Contains(body, `id="account" name="account" value="acct-1" placeholder="e.g. acct-…"`) {
			t.Errorf("%s: the box does not submit account with an ID hint", tc.path)
		}
		if strings.Contains(body, `name="actor"`) {
			t.Errorf("%s: a box still submits actor", tc.path)
		}
	}
}
