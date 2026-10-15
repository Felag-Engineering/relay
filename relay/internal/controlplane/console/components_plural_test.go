package console

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestPlan_MatchedCountAgreesWithItsNoun: the shared Plan block (Job detail,
// the composer, the approval object) said "1 Nodes matched". The count comes
// from the caller and the noun from plural, the package's one template
// plural, so each count appears exactly once and agrees with its word.
func TestPlan_MatchedCountAgreesWithItsNoun(t *testing.T) {
	for matched, want := range map[int]string{
		0:   "0 Nodes matched",
		1:   "1 Node matched",
		2:   "2 Nodes matched",
		412: "412 Nodes matched",
	} {
		out := render(t, "plan", Plan{Selector: "node:env=prod", Matched: matched, RiskClass: jobs.RiskClassRead})
		if !strings.Contains(out, want) {
			t.Errorf("Matched=%d: want %q in %s", matched, want, out)
		}
		if matched == 1 && strings.Contains(out, "1 Nodes") {
			t.Errorf("Matched=1 still renders %q", "1 Nodes")
		}
	}
}
