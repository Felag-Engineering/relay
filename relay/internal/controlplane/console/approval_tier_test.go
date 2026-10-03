package console

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// D18 point 5 on the approval queue and object: the tier chip is drawn from
// the request's ActionKind, so a parked Raw Exec carries it and a parked
// run_operation does not, whatever its Summary says.
func TestApprovals_TheRawExecTierIsDrawnFromActionKind(t *testing.T) {
	for _, c := range []struct {
		name string
		kind jobs.ActionKind
		chip bool
	}{
		{name: "Raw Exec", kind: jobs.ActionRawExec, chip: true},
		{name: "run_operation", kind: jobs.ActionOperation},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := pendingApprovalRequest("ap-1")
			req.ActionKind = c.kind
			req.Summary = "raw_exec Raw Exec on 3 Nodes"
			d := renderableDeps()
			d.Approvals = &fakeApprovals{pending: []approval.Request{req}}
			h := newTestHandler(d, accounts.RoleAdmin)
			for _, path := range []string{"/console/approvals", "/console/approvals/ap-1"} {
				content := contentOf(get(t, h, path).Body.String())
				if !strings.Contains(content, "ap-1") {
					t.Fatalf("%s does not render the request:\n%s", path, content)
				}
				if got := strings.Contains(content, rawExecChip); got != c.chip {
					t.Errorf("%s: Raw Exec chip drawn = %v, want %v:\n%s", path, got, c.chip, content)
				}
			}
		})
	}
}
