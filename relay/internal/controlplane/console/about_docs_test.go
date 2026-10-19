package console

// about_docs_test.go proves that every standing note deleted from a screen
// still has its substance in the docs. 00-foundations.md (D31) removed the
// "About this screen" disclosure and the docs pointer it carried; a note is
// now one visible sentence or deleted, and a deletion may rely only on a
// document that holds what it said.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoPath resolves a repository-relative path from this package's directory.
func repoPath(rel string) string {
	return filepath.Join("..", "..", "..", "..", filepath.FromSlash(rel))
}

// TestAbout_DeletedStandingNotesLiveInTheDocs: 00-foundations.md lets a
// standing note be deleted only when its substance is already in the docs.
// Where #849 or D31 deleted one and wrote its substance into a design document,
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
		{"docs/design/console/04-activity.md", "Activity: fleet events are on the audit trail, not here",
			"they remain on the audit trail"},
		{"docs/design/console/10-day-one.md", "Day one: check the CA fingerprint before installing",
			"Until then the quickstart carries the check"},
		{"docs/design/console/14-approval-queue.md", "Approvals: the unaudited queue reload, restated in the About",
			"Reloading the queue is not an audited read"},
	} {
		raw, err := os.ReadFile(repoPath(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.doc, err)
		}
		if !strings.Contains(strings.Join(strings.Fields(string(raw)), " "), c.substance) {
			t.Errorf("%s (cut from the screen by #849 or D31) relies on %s holding %q, and it no longer does",
				c.cut, c.doc, c.substance)
		}
	}
}
