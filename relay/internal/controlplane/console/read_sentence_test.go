package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
)

// TestReadSentence_SingleNodeReadIsNotAnEnumeration: the listing verb belongs
// to listings. A read of one named Node says "read"; the verb is chosen by tool
// name, so a NodeID on a listing (list_operations for a Node) does not change it.
func TestReadSentence_SingleNodeReadIsNotAnEnumeration(t *testing.T) {
	for _, c := range []struct {
		facts trailFacts
		want  string
	}{
		{trailFacts{Kind: audit.KindRead, OperationName: "list_nodes"}, "enumerated list_nodes"},
		{trailFacts{Kind: audit.KindRead, OperationName: "list_operations", NodeID: "node-1"}, "enumerated list_operations"},
		{trailFacts{Kind: audit.KindRead, OperationName: "describe_node", NodeID: "node-1"}, "read describe_node"},
		{trailFacts{Kind: audit.KindRead, ActionKind: "describe_node"}, "read describe_node"},
	} {
		if got := summarize(c.facts); got != c.want {
			t.Errorf("summarize(%+v) = %q, want %q", c.facts, got, c.want)
		}
	}
}

// TestActivity_SinkWrittenDescribeNodeReadSaysRead renders the record the real
// sink writes for a describe_node read, so the verb is proven against the
// product's own record shape (issue 1114).
func TestActivity_SinkWrittenDescribeNodeReadSaysRead(t *testing.T) {
	// No Job: a read of one Node is not part of one, and a row with a Job
	// renders its tool as a link rather than as this sentence.
	repo := &captureRepo{}
	sink := auditsink.New(repo, auditsink.WithClock(func() time.Time { return testNow }))
	if err := sink.RecordRead(context.Background(), agentFixturePrincipal(), "describe_node", "", "node-1", ""); err != nil {
		t.Fatal(err)
	}
	recs := repo.recs
	body := activityOutcomeChips(t, "/console/activity?kind=read&console=show", recs)

	if !strings.Contains(body, "read describe_node") {
		t.Error("a describe_node read is not drawn as a read of one Node")
	}
	if strings.Contains(body, "enumerated describe_node") {
		t.Error("a read of one named Node is drawn with the listing verb")
	}
}

// TestCompare_LastRowHeaderDrawsNoBottomEdge: the row header is a th, which the
// global last-row td rule does not reach, so it alone drew a bottom edge under
// the last row and the 3px accent looked cut short. The rule is matched as a
// parsed rule, not a substring, so a changed selector or value fails it.
func TestCompare_LastRowHeaderDrawsNoBottomEdge(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin), "/console/assets/console.css").Body.String()
	for _, m := range cssRulePattern.FindAllStringSubmatch(cssCommentPattern.ReplaceAllString(css, ""), -1) {
		if strings.TrimSpace(m[1]) == ".cmp tbody tr:last-child th" &&
			strings.Contains(m[2], "border-bottom: 0") {
			return
		}
	}
	t.Error("console.css has no `.cmp tbody tr:last-child th` rule that sets border-bottom: 0")
}
