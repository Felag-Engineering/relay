package console

// visible_qualifiers_test.go proves the note that stays VISIBLE after the
// standing notes were folded (00-foundations.md, "Standing notes and
// situational messages"): Activity's read-records sentence is one quiet
// sentence drawn with the control it qualifies, never a dashed gap box, and
// never inside the About disclosure.

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

const readsLeftOut = "are left out of this feed"

// TestActivity_DefaultFeedSaysReadRecordsAreLeftOut: with no kind filter the
// feed does not ask for `read` records, so a responder filtering to one
// Account would see none of its enumeration. The screen says so beside the
// kind chips, and the link keeps the Account filter.
func TestActivity_DefaultFeedSaysReadRecordsAreLeftOut(t *testing.T) {
	h := newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin)
	body := get(t, h, "/console/activity?account=acct-9").Body.String()

	mustBeSituational(t, body, readsLeftOut)
	note := section(t, contentOf(body), `<p class="kindnote">`, `</p>`)
	if !strings.Contains(note, "kind=read") || !strings.Contains(note, "account=acct-9") {
		t.Errorf("the read link does not keep the Account filter:\n%s", note)
	}
	if strings.Contains(note, "/console/reads") {
		t.Error("the read-records sentence still links to the retired Read egress screen")
	}
	// Directly under the chips it qualifies, not somewhere down the page.
	content := contentOf(body)
	if strings.Index(content, `<p class="kindnote">`)-strings.Index(content, `<div class="kindbar">`) > 2000 {
		t.Error("the read-records sentence is not drawn with the kind chips")
	}
}

func TestActivity_ReadRecordsSentenceIsAbsentUnderAKindFilter(t *testing.T) {
	h := newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin)
	for _, kind := range []string{"dispatch", "read", "approval"} {
		if body := get(t, h, "/console/activity?kind="+kind).Body.String(); strings.Contains(body, readsLeftOut) {
			t.Errorf("kind=%s: the feed says read records are left out, but a kind filter leaves nothing out", kind)
		}
	}
}

// TestVisibleQualifiers_AreNotDashedBoxes: the owner's intent is that nothing
// reads as unfinished, so the visible sentence never uses the gap box.
func TestVisibleQualifiers_AreNotDashedBoxes(t *testing.T) {
	activity := contentOf(get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String())
	for _, c := range []struct{ page, sentence string }{
		{activity, readsLeftOut},
	} {
		i := strings.Index(c.page, c.sentence)
		if i < 0 {
			t.Fatalf("%q is not rendered", c.sentence)
		}
		open := strings.LastIndex(c.page[:i], "<p")
		if strings.HasPrefix(c.page[open:], `<p class="gap"`) {
			t.Errorf("%q is drawn as a dashed gap box", c.sentence)
		}
	}
}
