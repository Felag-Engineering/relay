package console

// refresh_test.go proves 00-foundations.md's "Refreshing a screen" and how
// specs 01, 03 and 04 apply it: Refresh is a plain link that reloads the
// screen with its query preserved, and the Console never reloads a screen on
// a timer.

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// pinnedCSP is the content security policy as it stood before the Refresh
// control existed; the control must not need it to change.
const pinnedCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

func refreshScreens() (Deps, []string) {
	return consoleCallsDeps(), []string{"/console/activity"}
}

func TestRefresh_ActivityOffersAPlainRefresh(t *testing.T) {
	d, paths := refreshScreens()
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, p := range paths {
		if !strings.Contains(contentOf(get(t, h, p).Body.String()), `<a class="refreshbtn" href="`+p+`">Refresh</a>`) {
			t.Errorf("%s has no plain Refresh control", p)
		}
	}
}

// TestRefresh_NoScreenReloadsItselfOnATimer: no rendered screen carries a
// meta refresh, and the refresh parameter that used to turn one on is gone.
func TestRefresh_NoScreenReloadsItselfOnATimer(t *testing.T) {
	d := withExecution(sweepFixture(), true)
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, path := range walkableScreens(routesFor(d, accounts.RoleAdmin), fixtureIDs) {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		body := strings.ToLower(get(t, h, path+sep+"refresh=30").Body.String())
		if strings.Contains(body, `http-equiv="refresh"`) {
			t.Errorf("%s reloads itself on a timer", path)
		}
		if strings.Contains(body, "refresh=") {
			t.Errorf("%s carries a refresh parameter on a link", path)
		}
	}
}

// TestRefresh_ControlsPreserveTheQuery: Refresh reloads exactly this view.
func TestRefresh_ControlsPreserveTheQuery(t *testing.T) {
	d, _ := refreshScreens()
	h := newTestHandler(d, accounts.RoleAdmin)

	activity := contentOf(get(t, h, "/console/activity?kind=approval&window=24h&ac=0").Body.String())
	if !strings.Contains(activity, `<a class="refreshbtn" href="/console/activity?ac=0&amp;kind=approval&amp;window=24h">Refresh</a>`) {
		t.Errorf("Activity's Refresh does not keep its filters and page position:\n%s", activity)
	}

	// Fleet spells the grouping out, so a default that shifts between loads
	// cannot change the view, and never echoes a parameter it does not know.
	fh := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	for _, tc := range []struct{ path, href string }{
		{"/console/?filter=node:role=web&group=env&pin=node-web-1", "/console/?filter=node%3Arole%3Dweb&amp;group=env&amp;pin=node-web-1"},
		{"/console/?group=-", "/console/?group=-"},
		{"/console/?filter=tag:x&group=env", "/console/?filter=tag%3Ax&amp;group=env"},
		{"/console/?filter=node:role=nonesuch&group=-", "/console/?filter=node%3Arole%3Dnonesuch&amp;group=-"},
		{"/console/?nonesuch=1&group=env", "/console/?group=env"},
	} {
		got := contentOf(get(t, fh, tc.path).Body.String())
		if !strings.Contains(got, `<a class="refreshbtn" href="`+tc.href+`">Refresh</a>`) {
			t.Errorf("Fleet's Refresh at %s is not %s:\n%s", tc.path, tc.href, got)
		}
		if strings.Contains(got, "nonesuch=1") {
			t.Errorf("Fleet's Refresh at %s echoes a parameter the screen does not understand", tc.path)
		}
	}

	access := contentOf(get(t, h, "/console/access?kind=sign-in&failures=1&window=24h").Body.String())
	if !strings.Contains(access, `<a class="refreshbtn" href="/console/access?failures=1&amp;kind=sign-in&amp;window=24h">Refresh</a>`) {
		t.Errorf("Access' Refresh does not keep its filters:\n%s", access)
	}
}

// TestRefresh_ActivityReloadControlKeepsTheFilter: Activity's control reloads
// the current filter at its newest page, and says what it counts in plain
// lower-case words.
func TestRefresh_ActivityReloadControlKeepsTheFilter(t *testing.T) {
	d := activityDeps(&fakeQueries{})
	d.Events = newFakeEvents()
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?kind=dispatch&op=service.restart&jc=c9").Body.String()

	if !strings.Contains(body, `<a class="newq" href="/console/activity?kind=dispatch&amp;op=service.restart" aria-live="polite">Reload to see new events`) {
		t.Errorf("the reload control does not keep the filter, or keeps the page position:\n%s", body)
	}
	if strings.Contains(body, "JOB EVENTS") {
		t.Error("the counter's caveat still shouts")
	}
}

// TestRefresh_NoScriptNoStyleCSPUnchanged: the controls add no inline script
// or style, and the policy every page carries is the one it was before.
func TestRefresh_NoScriptNoStyleCSPUnchanged(t *testing.T) {
	d, paths := refreshScreens()
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)
	fh := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	for _, p := range append(paths, "/console/activity", "/console/") {
		handler := h
		if p == "/console/" {
			handler = fh
		}
		rec := get(t, handler, p)
		if got := rec.Header().Get("Content-Security-Policy"); got != pinnedCSP {
			t.Errorf("%s: CSP = %q, want the unchanged policy", p, got)
		}
		assertCSPClean(t, p, rec.Body.String())
	}
}

// TestRefresh_EachScreenSaysBesideRefreshWhetherAReloadIsAudited: one visible
// sentence beside the control, true to what each screen's reads actually
// record (00-foundations.md, "Refreshing a screen").
func TestRefresh_EachScreenSaysBesideRefreshWhetherAReloadIsAudited(t *testing.T) {
	d, _ := refreshScreens()
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)
	fh := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	for path, note := range map[string]string{
		"/console/":         "Every Refresh is an audited read.",
		"/console/activity": "Every Refresh is an audited read made from this Console.",
		"/console/access":   "Every Refresh is an audited read.",
	} {
		handler := h
		if path == "/console/" {
			handler = fh
		}
		body := get(t, handler, path).Body.String()
		mustBeSituational(t, body, note)
		content := contentOf(body)
		at := strings.Index(content, `<p class="refreshlimit">`+note)
		btn := strings.Index(content, "refreshbtn")
		if at < 0 || btn < 0 || at < btn || at-btn > 300 {
			t.Errorf("%s: the sentence is not a refreshlimit beside the Refresh control", path)
		}
	}
}

// TestRefresh_ActivityReloadIsAnAuditedRead backs Activity's sentence beside
// Refresh with the reads the screen actually makes.
func TestRefresh_ActivityReloadIsAnAuditedRead(t *testing.T) {
	q := &fakeQueries{}
	get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity")
	if q.auditCalls+q.jobCalls == 0 {
		t.Error("an Activity reload made no read through the audited lane")
	}
}
