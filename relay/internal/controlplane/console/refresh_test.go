package console

// refresh_test.go proves 00-foundations.md's "Refreshing a screen" and how
// specs 03, 04 and 14 apply it: Refresh keeps the query; auto-refresh is off
// by default, takes only an interval chosen in code, needs no script, and is
// never rendered on a page holding a form an operator types into or showing a
// Cancel control.

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

const metaRefresh = `<meta http-equiv="refresh"`

// pinnedCSP is the content security policy as it stood before the refresh
// controls existed. Auto-refresh must not need it to change.
const pinnedCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

var metaContent = regexp.MustCompile(`<meta http-equiv="refresh" content="([^"]*)">`)

func TestParseRefresh_OnlyTheFixedIntervals(t *testing.T) {
	for _, s := range []string{"15", "30", "60"} {
		if secs, invalid := parseRefresh(url.Values{refreshParam: {s}}); invalid || secs == 0 {
			t.Errorf("refresh=%s: got (%d, %v), want an accepted interval", s, secs, invalid)
		}
	}
	for _, s := range []string{"1", "0", "-30", "5", "3600", "30s", " 30", "030", "30.0", "1e2"} {
		if secs, invalid := parseRefresh(url.Values{refreshParam: {s}}); !invalid || secs != 0 {
			t.Errorf("refresh=%q: got (%d, %v), want refused", s, secs, invalid)
		}
	}
	if secs, invalid := parseRefresh(url.Values{}); secs != 0 || invalid {
		t.Error("an absent parameter is not plain off")
	}
}

func refreshScreens() (Deps, []string) {
	d := consoleCallsDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{pendingApprovalRequest("ap-1")}}
	return d, []string{"/console/agents", "/console/approvals"}
}

func TestRefresh_AutoRefreshIsOffByDefault(t *testing.T) {
	d, paths := refreshScreens()
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, p := range paths {
		body := get(t, h, p).Body.String()
		if strings.Contains(body, metaRefresh) {
			t.Errorf("%s reloads itself by default", p)
		}
		if !strings.Contains(contentOf(body), `<a class="refreshbtn" href="`+p+`">Refresh</a>`) {
			t.Errorf("%s has no plain Refresh control", p)
		}
	}
}

func TestRefresh_AutoRefreshRendersOnlyAnAllowedInterval(t *testing.T) {
	d, paths := refreshScreens()
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, p := range paths {
		for _, s := range refreshIntervals {
			want := strconv.Itoa(s)
			body := get(t, h, p+"?refresh="+want).Body.String()
			m := metaContent.FindAllStringSubmatch(body, -1)
			if len(m) != 1 || m[0][1] != want {
				t.Errorf("%s?refresh=%s rendered %v, want one refresh of %s seconds", p, want, m, want)
			}
		}
		for _, bad := range []string{"1", "5", "3600", "30;url=https://example.com", "abc"} {
			body := get(t, h, p+"?refresh="+url.QueryEscape(bad)).Body.String()
			if strings.Contains(body, metaRefresh) {
				t.Errorf("%s?refresh=%q reloads itself", p, bad)
			}
			if !strings.Contains(body, "Auto-refresh can reload every 15, 30 or 60 seconds, and nothing else, so it is off.") {
				t.Errorf("%s?refresh=%q does not say auto-refresh is off", p, bad)
			}
			if strings.Contains(body, "example.com") {
				t.Errorf("%s?refresh=%q echoed the refused value into the page", p, bad)
			}
		}
	}
}

// TestRefresh_ControlsPreserveTheQuery: Refresh reloads exactly this view,
// and every link the screen draws keeps the auto-refresh choice.
func TestRefresh_ControlsPreserveTheQuery(t *testing.T) {
	d, _ := refreshScreens()
	h := newTestHandler(d, accounts.RoleAdmin)

	agents := contentOf(get(t, h, "/console/agents?account=gleipnir-prod&console=show&refresh=60").Body.String())
	for _, want := range []string{
		`<a class="refreshbtn" href="/console/agents?account=gleipnir-prod&amp;console=show&amp;refresh=60">Refresh</a>`,
		`href="/console/agents?account=gleipnir-prod&amp;console=show">off</a>`,
		`href="/console/agents?account=gleipnir-prod&amp;console=show&amp;refresh=15">15 s</a>`,
		`href="/console/agents?console=show&amp;refresh=60">Show every Account</a>`,
		`href="/console/agents?account=gleipnir-prod&amp;refresh=60">Leave them out</a>`,
	} {
		if !strings.Contains(agents, want) {
			t.Errorf("Agents does not carry the query on %s", want)
		}
	}

	queue := contentOf(get(t, h, "/console/approvals?risk=mutate&scope=all&refresh=30").Body.String())
	if !strings.Contains(queue, `<a class="refreshbtn" href="/console/approvals?refresh=30&amp;risk=mutate&amp;scope=all">Refresh</a>`) {
		t.Errorf("the queue's Refresh does not keep its filters:\n%s", queue)
	}
	i := strings.Index(queue, `<div class="kindbar">`)
	if i < 0 {
		t.Fatal("the queue renders no filter bar")
	}
	bar := queue[i : i+strings.Index(queue[i:], "</div>")]
	links := regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(bar, -1)
	if len(links) == 0 {
		t.Fatal("the filter bar carries no links")
	}
	for _, l := range links {
		if !strings.Contains(l[1], "refresh=30") {
			t.Errorf("the filter link %q turns auto-refresh off", l[1])
		}
	}
	for _, l := range regexp.MustCompile(`href="(/console/approvals[^"]*)">(Show everything|Clear the filters)`).FindAllStringSubmatch(queue, -1) {
		if !strings.Contains(l[1], "refresh=30") {
			t.Errorf("%q turns auto-refresh off", l[0])
		}
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
	if strings.Contains(body, metaRefresh) {
		t.Error("Activity reloads itself; its filter bar is a form")
	}
}

// TestRefresh_NoAutoRefreshOnAPageWithAForm is the structural half: every
// screen this Console serves, asked for auto-refresh, either renders no
// <meta> refresh or holds no control an operator types into and no Cancel.
func TestRefresh_NoAutoRefreshOnAPageWithAForm(t *testing.T) {
	d := withExecution(sweepFixture(), true)
	h := newTestHandler(d, accounts.RoleAdmin)
	typed := regexp.MustCompile(`<textarea|<select|<input(?:\s[^>]*)?>`)
	hidden := regexp.MustCompile(`<input[^>]*type="hidden"[^>]*>`)
	for _, path := range walkableScreens(routesFor(d, accounts.RoleAdmin), fixtureIDs) {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		rec := get(t, h, path+sep+"refresh=30")
		if rec.Code != http.StatusOK {
			continue
		}
		content := contentOf(rec.Body.String())
		if !strings.Contains(content, metaRefresh) {
			continue
		}
		for _, m := range typed.FindAllString(content, -1) {
			if !hidden.MatchString(m) {
				t.Errorf("%s reloads itself and holds %q, a control an operator types into", path, m)
			}
		}
		if strings.Contains(content, `class="jobcancel"`) {
			t.Errorf("%s reloads itself while showing Cancel", path)
		}
	}
	for _, path := range []string{"/console/approvals/ap-1", "/console/accounts", "/console/activity"} {
		if strings.Contains(get(t, h, path+"?refresh=30").Body.String(), metaRefresh) {
			t.Errorf("%s reloads itself", path)
		}
	}
}

// TestRefresh_TheApprovalQueueHoldsNoFormInAnyState is what makes offering
// auto-refresh there safe (spec 14, "Refreshing").
func TestRefresh_TheApprovalQueueHoldsNoFormInAnyState(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	states := map[string]*fakeApprovals{
		"empty":     {},
		"populated": {pending: []approval.Request{pendingApprovalRequest("ap-1")}},
		"grant":     {pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}},
	}
	for name, fa := range states {
		d := renderableDeps()
		d.Approvals = fa
		for _, q := range []string{"", "?scope=all", "?risk=read", "?refresh=30"} {
			content := contentOf(get(t, newTestHandler(d, accounts.RoleViewer), "/console/approvals"+q).Body.String())
			for _, tag := range []string{"<form", "<input", "<textarea", "<select", "<button"} {
				if strings.Contains(content, tag) {
					t.Errorf("%s%s: the queue renders %s", name, q, tag)
				}
			}
			if q == "?refresh=30" && !strings.Contains(content, `<meta http-equiv="refresh" content="30">`) {
				t.Errorf("%s: the queue does not auto-refresh when asked", name)
			}
		}
	}
}

// TestRefresh_AgentsPausesWhileItShowsCancel: a reload must not move a Cancel
// button under the operator's pointer.
func TestRefresh_AgentsPausesWhileItShowsCancel(t *testing.T) {
	q := &fakeQueries{
		rows: []capability.AuditRow{dispatchRow("job-1", "node-a")},
		jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}},
	}
	d := cancelDeps(q, &fakeCanceller{})
	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?refresh=30").Body.String())

	if !strings.Contains(body, `class="jobcancel"`) {
		t.Fatal("fixture renders no Cancel control; the test proves nothing")
	}
	if strings.Contains(body, metaRefresh) {
		t.Error("Agents reloads itself while showing Cancel")
	}
	if !strings.Contains(body, "Auto-refresh is paused while this page shows a Cancel") {
		t.Error("the pause is not stated")
	}
	if !strings.Contains(body, `class="refreshbtn"`) {
		t.Error("the manual Refresh is gone")
	}
}

// TestRefresh_NoScriptNoStyleCSPUnchanged: the controls add no inline script
// or style, and the policy every page carries is the one it was before.
func TestRefresh_NoScriptNoStyleCSPUnchanged(t *testing.T) {
	d, paths := refreshScreens()
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, p := range append(paths, "/console/activity") {
		for _, q := range []string{"", "?refresh=30", "?refresh=bogus"} {
			rec := get(t, h, p+q)
			if got := rec.Header().Get("Content-Security-Policy"); got != pinnedCSP {
				t.Errorf("%s%s: CSP = %q, want the unchanged policy", p, q, got)
			}
			assertCSPClean(t, p+q, rec.Body.String())
		}
	}
}

// TestRefresh_TheDisclosureSaysWhetherAReloadIsAudited: one sentence, in the
// About disclosure, true to what each screen's reads actually record.
func TestRefresh_TheDisclosureSaysWhetherAReloadIsAudited(t *testing.T) {
	d, _ := refreshScreens()
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)
	for path, note := range map[string]string{
		"/console/agents":    "<b>Every reload is an audited read</b>",
		"/console/activity":  "<b>Every reload is an audited read</b>",
		"/console/approvals": "<b>Reloading this queue is not recorded on the audit trail</b>",
	} {
		inside, outside := splitAbout(t, get(t, h, path).Body.String())
		mustBeStanding(t, inside, outside, note)
	}
}

// TestRefresh_AgentsReloadIsAnAuditedReadAndTheQueueIsNot backs the two
// sentences above with the reads each screen actually makes.
func TestRefresh_AgentsReloadIsAnAuditedReadAndTheQueueIsNot(t *testing.T) {
	d, _ := refreshScreens()
	q := d.Queries.(*fakeQueries)
	h := newTestHandler(d, accounts.RoleAdmin)

	get(t, h, "/console/agents?refresh=30")
	if q.auditCalls == 0 {
		t.Error("an Agents reload made no read through the audited lane")
	}
	before := q.auditCalls + q.jobCalls
	get(t, h, "/console/approvals?refresh=30")
	if after := q.auditCalls + q.jobCalls; after != before {
		t.Errorf("the queue made %d read-lane reads; its disclosure says a reload records none", after-before)
	}
}
