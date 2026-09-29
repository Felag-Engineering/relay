package console

// visible_qualifiers_test.go proves the three notes that stay VISIBLE after
// the standing notes were folded (00-foundations.md, "Standing notes and
// situational messages"): each is one quiet sentence drawn with the control or
// figure it qualifies, never a dashed gap box, and never inside the About
// disclosure.

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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
	if !strings.Contains(note, `href="/console/reads"`) {
		t.Error("the sentence does not link to Read egress")
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

// TestReads_ExactClaimCarriesItsClockCaveat: the visible "exact over the
// window" claim is never stronger than the truth — the same sentence says what
// the figures cannot count.
func TestReads_ExactClaimCarriesItsClockCaveat(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		reachStub: func(f capability.AuditFilter) capability.Reach {
			if f.Outcome != nil || containsString(f.Kinds, audit.KindRead) {
				return capability.Reach{}
			}
			return capability.Reach{Calls: 3, DistinctTargets: 1, DistinctNodes: 3}
		},
	}
	body := readsBody(t, q, "")
	const claim = "Every figure shown above is exact over the audit records timestamped in the"
	const caveat = "except that the read and refusal figures miss a read-class Job created just before it whose records\nland inside it.</b>"
	mustBeSituational(t, body, claim)
	i := strings.Index(body, claim)
	if j := strings.Index(body[i:], caveat); j < 0 || j > 200 {
		t.Error("the exact claim is not qualified in the same sentence by what it cannot count")
	}
	if !strings.Contains(body, "The three figures are exact over the\n  window, except that they miss a read-class Job") {
		t.Error("the refusal panel's exact claim carries no clock caveat")
	}
}

// TestReads_RetainedOutputStatementStaysVisible: the ADR-0025 statement is a
// property the Console is visibly bound by (00-foundations.md names it), so
// its one-sentence form is outside the disclosure, as a quiet note.
func TestReads_RetainedOutputStatementStaysVisible(t *testing.T) {
	body := readsBody(t, &fakeQueries{}, "")
	const sentence = "The trail never keeps read output (ADR-0025); what a daemon sent stays on"
	mustBeSituational(t, body, sentence)
	if !strings.Contains(body, `<p class="note">`+sentence) {
		t.Error("the retained-output statement is not drawn as a quiet note")
	}
	if !strings.Contains(body, "this page will never show it.") {
		t.Error("the visible statement does not say this page will never show read output")
	}
}

// TestVisibleQualifiers_AreNotDashedBoxes: the owner's intent is that nothing
// reads as unfinished, so the three visible sentences never use the gap box.
func TestVisibleQualifiers_AreNotDashedBoxes(t *testing.T) {
	activity := contentOf(get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String())
	reads := contentOf(readsBody(t, &fakeQueries{}, ""))
	for _, c := range []struct{ page, sentence string }{
		{activity, readsLeftOut},
		{reads, "The trail never keeps read output"},
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
