package console

// kind_lane_test.go: the kind label qualifies the VERIFIED lane only
// (00-foundations.md, "Kind label"), the on-screen keys say what machine means
// on a decision, and the new markup is accessible.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

const (
	dashedChip   = `data-trust="asserted" title="The caller claimed this. Nothing checked it.">`
	verifiedChip = `data-trust="verified" title="The Relay authenticated this identity.">`
)

// unattributedDecider has no Account ID: its chip is dashed, and it must carry
// no kind label although its record says not-human.
func unattributedDecider() approval.Decision {
	return approval.Decision{Account: "ghost", Approve: true, Channel: approval.ChannelOutOfBand, DeciderHuman: false, At: testNow}
}

func TestJob_DeciderWithNoAccountIDGetsNoKind(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{
		jobs:  []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)},
		tasks: tasks,
		rows:  []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, ApprovalID: "ap-1"}},
	}
	d := jobDeps(q)
	d.Approvals = &fakeApprovals{pending: []approval.Request{{
		ID: "ap-1", State: approval.StateApproved,
		Decisions: []approval.Decision{
			unattributedDecider(),
			{Account: "mike", AccountID: "acct-2", Approve: true, Channel: approval.ChannelOutOfBand, DeciderHuman: true, At: testNow},
		},
	}}}
	approvalSection := section(t, jobBody(t, d, jobPath("")), `<section class="jobapproval"`, `</section>`)

	if !strings.Contains(approvalSection, dashedChip+"ghost</span>") {
		t.Fatalf("the unattributed decider is not a dashed chip:\n%s", approvalSection)
	}
	if strings.Contains(approvalSection, dashedChip+`ghost</span> <span class="kind"`) {
		t.Error("a kind label was drawn beside a dashed chip")
	}
	if !strings.Contains(approvalSection, verifiedChip+`mike</span> `+kindLabel("human")) {
		t.Error("the verified decider lost its kind label")
	}
}

func TestActivity_UnverifiedRequesterGetsNoKind(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate,
		Requester: "legacy", RequesterKind: "machine", Total: 1, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
	}}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()
	if !strings.Contains(body, dashedChip+"legacy</span>") {
		t.Fatal("the fixture's requester is not dashed")
	}
	if n := drawnKinds(body); n != 0 {
		t.Errorf("an unverified requester drew %d kind labels", n)
	}
}

func TestJob_UnverifiedRequesterGetsNoKind(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate)
	sum.RequesterAccountID, sum.RequesterKind = "", "human"
	body := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks}), jobPath(""))
	if n := drawnKinds(body); n != 0 {
		t.Errorf("an unverified requester drew %d kind labels", n)
	}
}

// TestKindKeys_SayWhatMachineMeansOnADecision: a Decision made before the
// Relay recorded its decider's kind reads not-human, so the key on both
// screens says machine means "not recorded as human".
func TestKindKeys_SayWhatMachineMeansOnADecision(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	job := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}), jobPath(""))
	if key := section(t, job, `<p class="lanekey"><span class="kind">`, `</p>`); !strings.Contains(key, "machine means &ldquo;not recorded as human&rdquo;") {
		t.Errorf("Job detail's key does not say what machine means on a decision:\n%s", key)
	}
}

// TestA11y_KindLabelIsPlainText: the kind label is plain text a screen reader
// reads (not hidden, not an image, no empty element).
func TestA11y_KindLabelIsPlainText(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate)
	sum.RequesterKind = "machine"
	job := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks}), jobPath(""))

	tags := regexp.MustCompile(`<span class="kind"[^>]*>([^<]*)</span>`).FindAllStringSubmatch(job, -1)
	if len(tags) == 0 {
		t.Fatal("no kind label rendered")
	}
	for _, m := range tags {
		if strings.Contains(m[0], "aria-hidden") || strings.Contains(m[0], `role="img"`) {
			t.Errorf("a kind label is hidden from assistive technology: %s", m[0])
		}
		if w := strings.TrimSpace(m[1]); w != "human" && w != "machine" {
			t.Errorf("a kind label's text is %q, want the word itself", w)
		}
	}

}
