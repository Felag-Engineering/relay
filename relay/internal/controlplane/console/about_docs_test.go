package console

// about_docs_test.go proves the "About this screen" docs pointer is one
// choice made in one place (aboutDocsShipped), whichever of its three modes is
// shipped, and that the substance #849 cut from the screens still lives in
// the documents 00-foundations.md now lets a deletion rely on.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// repoPath resolves a repository-relative path from this package's directory.
func repoPath(rel string) string {
	return filepath.Join("..", "..", "..", "..", filepath.FromSlash(rel))
}

func TestAboutDocs_EveryModeNamesARealDocumentOrNothing(t *testing.T) {
	if len(aboutDocScreens) == 0 {
		t.Fatal("aboutDocScreens is empty, so nothing below is tested")
	}
	for _, mode := range []aboutDocsMode{aboutDocsNone, aboutDocsDesign, aboutDocsOperator} {
		for screen := range aboutDocScreens {
			doc := aboutDocFor(mode, screen)
			switch {
			case mode == aboutDocsNone && doc != "":
				t.Errorf("mode none names %q for %s", doc, screen)
			case mode == aboutDocsDesign && doc == "":
				t.Errorf("mode design names nothing for %s", screen)
			}
			if doc == "" {
				continue
			}
			if _, err := os.Stat(repoPath(doc)); err != nil {
				t.Errorf("%s's About would name %s, which does not exist: %v", screen, doc, err)
			}
		}
	}
	if got := aboutDocFor(aboutDocsDesign, "no-such-screen"); got != "" {
		t.Errorf("an unknown screen names %q, want nothing", got)
	}
}

var aboutDocsCall = regexp.MustCompile(`\{\{template "about-docs" "([a-z]+)"\}\}`)

// TestAboutDocs_EveryAboutEndsInThePartial: every About disclosure in a
// template carries exactly one call to the partial, keyed to a known screen,
// so the owner's choice reaches every About and no About hard-codes one.
func TestAboutDocs_EveryAboutEndsInThePartial(t *testing.T) {
	regions := 0
	keys := map[string]bool{}
	for _, src := range consoleTemplateSources(t) {
		text := src.text
		for {
			i := strings.Index(text, `<details class="about">`)
			if i < 0 {
				break
			}
			j := strings.Index(text[i:], "</details>")
			if j < 0 {
				t.Fatalf("%s:%d: an About disclosure is never closed", src.file, src.line)
			}
			region := text[i : i+j]
			text = text[i+j:]
			regions++
			calls := aboutDocsCall.FindAllStringSubmatch(region, -1)
			if len(calls) != 1 {
				t.Errorf("%s:%d: an About disclosure calls about-docs %d times, want exactly once", src.file, src.line, len(calls))
				continue
			}
			key := calls[0][1]
			if _, ok := aboutDocScreens[key]; !ok {
				t.Errorf("%s:%d: about-docs is called with %q, which aboutDocScreens does not know", src.file, src.line, key)
			}
			if keys[key] {
				t.Errorf("%s:%d: two About disclosures share the key %q", src.file, src.line, key)
			}
			keys[key] = true
		}
	}
	if regions == 0 {
		t.Fatal("found no About disclosure in any template, so nothing was checked")
	}
	for key := range aboutDocScreens {
		if !keys[key] {
			t.Errorf("aboutDocScreens has %q, which no About disclosure uses", key)
		}
	}
}

// TestAboutDocs_RenderedPointerFollowsTheShippedChoice compares each rendered
// About with aboutDocFor(aboutDocsShipped, …) — never with a hard-coded
// answer, so changing the shipped mode is a one-line change.
func TestAboutDocs_RenderedPointerFollowsTheShippedChoice(t *testing.T) {
	d := copyBudgetFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	screens := map[string]struct {
		path string
		deps Deps
	}{
		"fleet":     {"/console/", d},
		"activity":  {"/console/activity", d},
		"dayone":    {"/console/", dayOneDeps()},
		"approvals": {"/console/approvals", d},
		"accounts":  {"/console/accounts", d},
		"access":    {"/console/access", d},
	}
	if len(screens) != len(aboutDocScreens) {
		t.Fatalf("this test renders %d screens, aboutDocScreens has %d — add the new one here", len(screens), len(aboutDocScreens))
	}
	for key, s := range screens {
		hh := h
		if key == "dayone" {
			hh = newTestHandler(s.deps, accounts.RoleAdmin)
		}
		inside, _ := splitAbout(t, get(t, hh, s.path).Body.String())
		want := aboutDocFor(aboutDocsShipped, key)
		got := strings.Contains(inside, "<code>docs/")
		switch {
		case want == "" && got:
			t.Errorf("%s's About names a document, but the shipped choice names none:\n%s", key, inside)
		case want != "" && !strings.Contains(inside, "More in <code>"+want+"</code>."):
			t.Errorf("%s's About does not name %s, the shipped choice:\n%s", key, want, inside)
		}
	}
}

// TestAbout_DeletedStandingNotesLiveInTheDocs: 00-foundations.md lets a
// standing note be deleted only when its substance is already in the docs.
// Where #849 deleted one and wrote its substance into a design document,
// that sentence must stay there — a deletion whose substance lives nowhere is
// the defect this guards.
func TestAbout_DeletedStandingNotesLiveInTheDocs(t *testing.T) {
	for _, c := range []struct{ doc, cut, substance string }{
		{"docs/design/console/04-activity.md", "Activity: paging",
			"the two lanes page separately, so a page does not end at a single moment, and Older continues each"},
		{"docs/design/console/04-activity.md", "Activity: single-lane boundary",
			"a filter that reads only one lane does end at a single moment"},
		{"docs/design/console/04-activity.md", "Activity: no Selector or Node filter",
			"filter box offers no Selector and no Node field yet"},
		{"docs/design/console/04-activity.md", "Activity: export contents",
			"The export is the fetched rows, not the"},
		{"docs/design/console/04-activity.md", "Activity: chips carry no counts",
			"chips carry no counts"},
		{"docs/design/console/04-activity.md", "Activity: request, not reasoning",
			"What it can honestly show is the request, not the reasoning."},
		{"docs/design/console/04-activity.md", "Activity: no sessions",
			"## There are no sessions"},
		{"docs/design/console/02-node-detail.md", "Node: not-reported reasoning",
			"an answer remembered from before a restart could be out of date"},
		{"docs/design/console/02-node-detail.md", "Node: renewal note",
			"renewal is cert-authenticated and preserves `node_id`"},
		{"docs/design/console/02-node-detail.md", "Node: Facts",
			"No Fact is in a facet, filterable or targetable"},
		{"docs/design/console/02-node-detail.md", "Node: Facts, in full on this page only",
			"**In full on this page only.**"},
		{"docs/design/console/02-node-detail.md", "Node: fingerprints",
			"string equality, not trust"},
		{"docs/design/console/01-fleet-view.md", "Fleet: no host metrics",
			"Scope is the four questions in `00-foundations.md`. No collected metrics."},
		{"docs/design/console/04-activity.md", "Activity: prompt-injection reasoning",
			"which an agent under prompt injection would happily fabricate"},
		{"docs/design/console/04-activity.md", "Activity: why read records are left out",
			"would otherwise bury the calls that change something"},
		{"docs/design/console/04-activity.md", "Activity: Cancel in Running now",
			"viewers see the section but are never offered Cancel"},
		{"docs/design/console/20-access.md", "Access: host-lever rows",
			"the screen draws them as the Relay host rather than as a verified or asserted chip"},
		{"docs/design/console/20-access.md", "Access: a failed sign-in records the name typed only for a real Account",
			"the row says \"a name that is not an Account\""},
		{"docs/design/console/20-access.md", "Access: a throttled attempt",
			"A throttled attempt is not a failed one."},
		{"docs/design/console/10-day-one.md", "Day one: why a daemon trusts this Relay",
			"a daemon trusts this Relay because it was installed with the CA bundle"},
		{"docs/design/console/14-approval-queue.md", "Approvals: no Approve on a row",
			"A one-click Approve control on a row"},
		{"docs/design/console/14-approval-queue.md", "Approvals: lapsed requests sort last",
			"A **lapsed** request sorts **last**"},
		{"docs/design/console/14-approval-queue.md", "Approvals: the audience reasoning",
			"a Request with no audience is shown rather than hidden"},
		{"docs/design/console/15-accounts-and-tokens.md", "Accounts: one password covers granting acts until the window lapses",
			"one password covers granting acts until the window lapses"},
		{"docs/design/console/15-accounts-and-tokens.md", "Accounts: the token value is shown once",
			"The plaintext is shown once at mint and never again"},
		{"docs/specs/accounts-and-access.md", "Accounts: the Relay holds only a hash of a token",
			"Relay stores a hash of the secret component and never the plaintext"},
		{"docs/design/console/13-job-detail.md", "Job: the Nodes were fixed at dispatch",
			"Everything the block renders is fixed at dispatch"},
		{"docs/design/console/02-node-detail.md", "Compare: nothing self-reported is compared",
			"nothing self-reported is compared"},
	} {
		raw, err := os.ReadFile(repoPath(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.doc, err)
		}
		if !strings.Contains(strings.Join(strings.Fields(string(raw)), " "), c.substance) {
			t.Errorf("%s (cut from the screen by #849) relies on %s holding %q, and it no longer does",
				c.cut, c.doc, c.substance)
		}
	}
}
