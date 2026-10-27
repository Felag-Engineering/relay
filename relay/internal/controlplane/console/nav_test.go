package console

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func currentLabels(sections []NavSection) []string {
	var got []string
	for _, s := range sections {
		for _, it := range s.Items {
			if it.Current {
				got = append(got, it.Label)
			}
		}
	}
	return got
}

func TestNav_ChildScreenMarksItsParentCurrent(t *testing.T) {
	d := renderableDeps()
	cases := map[string]string{
		"/console/":                                          "Fleet",
		"/console/nodes":                                     "Fleet",
		"/console/nodes/node-web-1":                          "Fleet",
		"/console/compare":                                   "Fleet",
		"/console/activity":                                  "Activity",
		"/console/jobs/job-1":                                "Activity",
		"/console/jobs/job-1/cancel":                         "Activity",
		"/console/accounts":                                  "Accounts",
		"/console/new-account":                               "Accounts",
		"/console/new-account/create":                        "Accounts",
		"/console/accounts/gleipnir-prod":                    "Accounts",
		"/console/accounts/acct-mike/disable":                "Accounts",
		"/console/accounts/acct-mike/lower":                  "Accounts",
		"/console/accounts/acct-mike/tokens/tok-live/revoke": "Accounts",
		"/console/api-tokens/tok-live/revoke":                "Accounts",
		"/console/access":                                    "Access",
		"/console/tags/confirm":                              "Fleet",
		"/console/tags":                                      "Fleet",
		"/console/policy-aliases":                            "Fleet",
		"/console/nodes/node-web-1/tags":                     "Fleet",

		// Nothing current: the empty path (the 404 shell), unknown paths, a
		// near-miss of a root, and a Link, which is exact and never a prefix.
		"":                      "",
		"/console/nonesuch":     "",
		"/console/accountsx":    "",
		"/console/new-accountx": "",
		"/console/compare-x":    "",
		"/console/jobsx/1":      "",
		"/console/tagsx":        "",
		"/console/run":          "",
		"/console/run/x":        "",
	}
	for path, want := range cases {
		got := currentLabels(Nav(d, accounts.RoleAdmin, path))
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%q: current = %v, want none", path, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: current = %v, want exactly [%s]", path, got, want)
		}
	}
}

// Under roots are what keep exactly one item current; two destinations that
// claim overlapping paths would mark two.
func TestNav_UnderRootsDoNotOverlap(t *testing.T) {
	type claim struct{ label, path string }
	var claims []claim
	for _, r := range Routes(renderableDeps()) {
		if r.Nav.Label == "" {
			continue
		}
		claims = append(claims, claim{r.Nav.Label, r.Link()})
		for _, root := range r.Nav.Under {
			claims = append(claims, claim{r.Nav.Label, root})
		}
	}
	for i, a := range claims {
		for j, b := range claims {
			if i == j || a.label == b.label {
				continue
			}
			if a.path == b.path || strings.HasPrefix(b.path, a.path+"/") {
				t.Errorf("%s claims %q, which overlaps %s's %q", a.label, a.path, b.label, b.path)
			}
		}
	}
}

var currentNavItem = regexp.MustCompile(`<a class="navitem on" href="[^"]*" aria-current="page">([^<]*)</a>`)

func TestNav_EveryMountedScreenMarksExactlyOneItemCurrent(t *testing.T) {
	wantCurrent := map[string]string{
		"/console/{$}":                                            "Fleet",
		"/console/nodes/{node_id}":                                "Fleet",
		"/console/compare":                                        "Fleet",
		"/console/activity":                                       "Activity",
		"/console/jobs/{job_id}":                                  "Activity",
		"/console/accounts":                                       "Accounts",
		"/console/accounts/{account_name}":                        "Accounts",
		"/console/new-account":                                    "Accounts",
		"/console/accounts/{account_id}/disable":                  "Accounts",
		"/console/accounts/{account_id}/lower":                    "Accounts",
		"/console/accounts/{account_id}/tokens/{token_id}/revoke": "Accounts",
		"/console/access":                                         "Access",
		"/console/tags/confirm":                                   "Fleet",
	}
	d := sweepFixture()
	walked := map[string]bool{}
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		for _, r := range routesFor(d, role) {
			paths := walkableScreens([]Route{r}, fixtureIDs)
			if len(paths) == 0 {
				continue
			}
			want, ok := wantCurrent[r.Path]
			if !ok {
				t.Errorf("%s renders the shell but has no expected current nav item; add it to wantCurrent", r.Path)
				continue
			}
			rec := get(t, h, paths[0])
			if rec.Code != 200 {
				continue
			}
			walked[r.Path] = true
			nav := navOf(rec.Body.String())
			if n := strings.Count(nav, `aria-current="page"`); n != 1 {
				t.Errorf("%s as %s: %d aria-current items, want 1", paths[0], role, n)
			}
			if n := strings.Count(nav, `navitem on"`); n != 1 {
				t.Errorf("%s as %s: %d navitem on items, want 1", paths[0], role, n)
			}
			m := currentNavItem.FindStringSubmatch(nav)
			if m == nil || m[1] != want {
				t.Errorf("%s as %s: current = %v, want %s", paths[0], role, m, want)
			}
		}
	}
	if len(walked) == 0 {
		t.Fatal("no screen was walked")
	}
	for p := range wantCurrent {
		if !walked[p] {
			t.Errorf("%s was never rendered at 200 by any role", p)
		}
	}
}
