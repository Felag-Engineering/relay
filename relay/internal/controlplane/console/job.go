package console

// job.go is the record of one dispatch (spec 13).
//
// # The whole design problem
//
// It must be legible at 3 Nodes and at 10,000. Those are not the same screen
// rendered at two sizes — at 3 Nodes an operator wants every row, and at 10,000
// a list of rows is an insult. Two things resolve it:
//
//   - the SEGMENTED OUTCOME BAR, which carries a floor width for minority
//     segments, because 14 denies out of 10,000 is 0.14% of the bar and is the
//     entire reason anyone opened the page;
//   - ORDERING BY INTEREST rather than alphabetically: denied first, then the
//     failures, then the three different kinds of never-ran, then success LAST.
//     Success is the mode, and the mode is the least informative thing here.
//
// # The denied group is the showpiece
//
// It renders the Policy rule that fired, verbatim, in mono, with a link to that
// Node's effective Policy. Slate, never red. A deny is the product working
// correctly, and if it ever renders as a failure the product is arguing against
// itself.
//
// # Read-class Jobs carry no output, at any age
//
// ADR-0025: reading is exfiltration, and read output is not retained. This page
// shows a read Job's outcomes and timings and says the output was never kept —
// it does not promise a detail view that will show it later, because there will
// not be one.

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// outcomeInterest orders the result groups. Lower sorts first.
//
// This is the spec's ordering made executable, and it is worth stating why each
// position is where it is: a deny means Policy made a decision and someone
// should read it; a failure means something ran and broke; the three never-rans
// are diagnostics about the fleet rather than about the command; a cancel is a
// human's own act; success is what was supposed to happen.
var outcomeInterest = map[jobs.Outcome]int{
	jobs.OutcomeDeniedByPolicy: 0,
	jobs.OutcomeFailure:        1,
	jobs.OutcomeTimeout:        2,
	jobs.OutcomeUnreachable:    3,
	jobs.OutcomeVersionRefused: 4,
	jobs.OutcomeUnsupported:    5,
	jobs.OutcomeCancelled:      6,
	jobs.OutcomeSuccess:        7,
}

// taskRow is one Node's result within a group.
type taskRow struct {
	NodeID   string
	NodeHref string

	// ExitCode is rendered only when ShowExit. The daemon uses -1 EXCLUSIVELY as
	// its "no exit status" sentinel — denied before spawn, spawn failure,
	// signal kill, timeout kill — and Relay-synthesized outcomes (unreachable,
	// version_refused) carry a zero that means nothing at all.
	//
	// The Control API omits the field for the same reason (execution.go makes
	// it a pointer). Rendering "exit -1" beside a deny invites an operator to
	// read "did not run" as a real process result, and "exit 0" beside
	// `unreachable` is worse: it says the thing succeeded.
	ExitCode int32

	// ShowExit is true only when the code says something the outcome does not
	// already imply. `success` implies zero, so "exit 0" beside a success chip
	// is noise — and worse than noise here, because .exit is painted in the
	// failure colour, and the budget reserves muted red for failure and timeout
	// and nothing else, ever. A green row with a red "exit 0" on it spends the
	// one alarming colour in the product on the least alarming event in it.
	ShowExit bool
	Output   string
	// Truncated is the daemon-side size cap, reported as the daemon reported
	// it: one flag over the whole result, not per-stream.
	Truncated bool
	Deny      *Deny
}

// outcomeGroup is one collapsible block: every Node that reported one outcome.
type outcomeGroup struct {
	Outcome jobs.Outcome
	Label   string
	Count   int

	// Clusters group identical output within the group. "9,797 identical (view
	// one) · 3 differ" is the pre-aggregation stand-in for the v0.9.0 histogram
	// primitive, laid out so that primitive slots into the same component — the
	// SHAPE of the answer does not change, only how it is computed.
	Clusters []outputCluster

	// SharedRule is set when every deny in the group fired the same rule. Then
	// the rule is shown once and the page says so, instead of printing one
	// identical block per Node.
	SharedRule string

	// Open is whether the group renders expanded. Anything interesting is open;
	// success is not, because success is the mode.
	Open bool
}

// outputCluster is a set of Nodes that reported byte-identical output.
type outputCluster struct {
	Output    string
	Count     int
	Rows      []taskRow
	Truncated bool
	// Representative is true for a cluster rendered as "N identical, here is
	// one". A cluster of one is not a cluster and renders as itself.
	Representative bool
}

type jobView struct {
	ID        string
	Created   string
	Operation string
	Args      string
	Risk      string
	RiskClass jobs.RiskClass
	ReadClass bool

	Principal  string
	Verified   bool
	OnBehalfOf string
	Selector   string

	ApprovalID   string
	ApprovalHref string
	GrantID      string

	FanOut   int
	InFlight int
	Bar      OutcomeBar
	Groups   []outcomeGroup

	// TasksWired is false when the composition root gave the Console no Job
	// reader. The page then renders what the audit trail knows, which is the
	// outcomes but not the captured output.
	TasksWired bool
	Found      bool
}

const clusterFloor = 3

func handleJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobID := r.PathValue("job_id")
		p, ok := page(d, w, r, "Job "+shortHash(jobID))
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Audit == nil {
			unavailable(w, "the audit trail")
			return
		}
		recs, err := d.Audit.ByJob(r.Context(), jobID)
		if err != nil {
			unavailable(w, "the audit trail (it returned an error)")
			return
		}

		v := buildJobView(d, r, jobID, recs)
		if !v.Found {
			w.WriteHeader(http.StatusNotFound)
		}
		renderScreen(w, p, jobTmpl, v)
	}
}

func buildJobView(d Deps, r *http.Request, jobID string, recs []audit.Record) jobView {
	v := jobView{ID: jobID, TasksWired: d.Jobs != nil}

	// Identity comes from the FIRST record, which is the oldest: the dispatch
	// that created the Job. Later records describe results, and reading the
	// Operation off one of those would silently follow a re-drive.
	for _, rec := range recs {
		if rec.Kind == audit.KindApprovalRequested || rec.Kind == audit.KindApprovalDecided {
			if v.ApprovalID == "" {
				v.ApprovalID = rec.ApprovalID
			}
			continue
		}
		if v.Operation == "" {
			v.Found = true
			v.Created = rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z")
			v.Operation = operationText(rec)
			v.Args = argsText(rec)
			v.RiskClass = riskOf(rec)
			// ReadClass gates whether captured output renders. It follows the
			// risk class, not the record kind: `file.read` is a KindDispatch
			// and is still a read, and its bytes must not appear here.
			v.ReadClass = v.RiskClass == jobs.RiskClassRead
			v.Principal = principalText(rec)
			v.Verified = rec.Attribution.Verified.AccountID != ""
			v.OnBehalfOf = rec.Attribution.Asserted.OnBehalfOf
			v.Selector = rec.Selector
			if rec.ApprovalID != "" {
				v.ApprovalID = rec.ApprovalID
			}
			v.GrantID = rec.GrantID
		}
	}
	if v.ApprovalID != "" {
		v.ApprovalHref = "/console/approvals/" + v.ApprovalID
	}
	v.Risk = RiskLabel(v.RiskClass)

	// Results. Prefer the Task store — it carries exit codes and captured
	// output — and fall back to the audit trail, which carries the outcome for
	// every Node either way.
	var tasks []jobs.Task
	if d.Jobs != nil {
		if ts, err := d.Jobs.Tasks(r.Context(), jobID); err == nil {
			tasks = ts
		}
	}
	if len(tasks) > 0 {
		v.Found = true
		v.Groups, v.Bar, v.FanOut, v.InFlight = groupTasks(tasks, v.ReadClass)
	} else {
		v.Groups, v.Bar, v.FanOut = groupAuditResults(recs, v.ReadClass)
	}
	return v
}

// groupTasks builds the result groups from the Task store.
func groupTasks(tasks []jobs.Task, readClass bool) ([]outcomeGroup, OutcomeBar, int, int) {
	byOutcome := map[jobs.Outcome][]taskRow{}
	counts := map[jobs.Outcome]int{}
	inFlight := 0

	for _, t := range tasks {
		if t.State != jobs.DispatchStateResolved {
			inFlight++
			continue
		}
		row := taskRow{
			NodeID:   t.NodeID,
			NodeHref: "/console/nodes/" + t.NodeID,
			ExitCode: t.ExitCode,
			ShowExit: hasRealExitStatus(t.Outcome, t.ExitCode) && t.ExitCode != 0,
		}
		// A read-class Task's captured output is NOT rendered here at any age.
		// The Task row may still hold it while the Job lives, and this page
		// deliberately does not become the durable place it is read from.
		if !readClass {
			row.Output = combinedOutput(t.Stdout, t.Stderr)
		}
		if t.Outcome == jobs.OutcomeDeniedByPolicy {
			row.Deny = &Deny{
				NodeID:        t.NodeID,
				OperationName: t.Action.OperationName,
				Rule:          firstNonEmpty(strings.TrimSpace(string(t.Stderr)), "the daemon refused this Operation and did not report the deciding rule"),
				PolicyHref:    "/console/nodes/" + t.NodeID,
			}
		}
		byOutcome[t.Outcome] = append(byOutcome[t.Outcome], row)
		counts[t.Outcome]++
	}
	return assembleGroups(byOutcome, counts, readClass), barFrom(counts), len(tasks), inFlight
}

// groupAuditResults builds the same groups from the trail, for a Job whose
// Tasks the Console cannot read.
func groupAuditResults(recs []audit.Record, readClass bool) ([]outcomeGroup, OutcomeBar, int) {
	byOutcome := map[jobs.Outcome][]taskRow{}
	counts := map[jobs.Outcome]int{}
	total := 0
	for _, rec := range recs {
		if rec.Kind != audit.KindDispatch && rec.Kind != audit.KindRead {
			continue
		}
		total++
		row := taskRow{NodeID: rec.NodeID, NodeHref: "/console/nodes/" + rec.NodeID, Truncated: rec.Truncated}
		if !readClass {
			row.Output = combinedOutput(rec.Stdout, rec.Stderr)
		}
		if rec.Outcome == jobs.OutcomeDeniedByPolicy {
			row.Deny = &Deny{
				NodeID:        rec.NodeID,
				OperationName: operationText(rec),
				Rule:          denyExplanation(rec),
				PolicyHref:    "/console/nodes/" + rec.NodeID,
			}
		}
		byOutcome[rec.Outcome] = append(byOutcome[rec.Outcome], row)
		counts[rec.Outcome]++
	}
	return assembleGroups(byOutcome, counts, readClass), barFrom(counts), total
}

func barFrom(counts map[jobs.Outcome]int) OutcomeBar {
	oc := make([]OutcomeCount, 0, len(counts))
	for o, n := range counts {
		oc = append(oc, OutcomeCount{Outcome: o, Count: n})
	}
	return NewOutcomeBar(oc)
}

// assembleGroups orders the groups by interest and clusters identical output.
func assembleGroups(byOutcome map[jobs.Outcome][]taskRow, counts map[jobs.Outcome]int, readClass bool) []outcomeGroup {
	var out []outcomeGroup
	for outcome, rows := range byOutcome {
		g := outcomeGroup{
			Outcome:  outcome,
			Label:    OutcomeLabel(outcome),
			Count:    counts[outcome],
			Clusters: clusterOutput(rows, readClass),
			// Everything interesting opens. Success does not: it is the mode,
			// and a page that opens the mode by default has buried the three
			// denies under nine thousand successes.
			Open: outcome != jobs.OutcomeSuccess,
		}
		if outcome == jobs.OutcomeDeniedByPolicy {
			g.SharedRule = sharedRule(rows)
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return outcomeInterest[out[i].Outcome] < outcomeInterest[out[j].Outcome]
	})
	return out
}

// clusterOutput groups rows by byte-identical output, largest cluster first.
//
// readClass suppresses the "N reported identical output" label: on a read Job
// there IS no retained output, every row's is the empty string, and saying they
// all reported the same thing describes the Relay's retention policy as if it
// were a fact about the fleet.
func clusterOutput(rows []taskRow, readClass bool) []outputCluster {
	byOutput := map[string][]taskRow{}
	var order []string
	for _, r := range rows {
		if _, seen := byOutput[r.Output]; !seen {
			order = append(order, r.Output)
		}
		byOutput[r.Output] = append(byOutput[r.Output], r)
	}
	var out []outputCluster
	for _, key := range order {
		rs := byOutput[key]
		c := outputCluster{Output: key, Count: len(rs)}
		if len(rs) >= clusterFloor && !readClass {
			// "N identical — here is one." The full list stays one click away
			// and is never the default: showing 9,797 identical rows is the
			// behaviour the clustering exists to prevent.
			c.Representative = true
			c.Rows = rs[:1]
		} else {
			c.Rows = rs
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// sharedRule returns the deciding rule when every deny in the group fired the
// same one, and "" when they differ.
//
// When they are the same, the page shows the rule ONCE and says so. Printing an
// identical deny block ten thousand times does not convey ten thousand facts;
// it conveys one, badly.
func sharedRule(rows []taskRow) string {
	rule := ""
	for _, r := range rows {
		if r.Deny == nil {
			return ""
		}
		if rule == "" {
			rule = r.Deny.Rule
			continue
		}
		if r.Deny.Rule != rule {
			return ""
		}
	}
	return rule
}

// hasRealExitStatus reports whether a Task's exit code came from a process that
// actually ran. Whether it is worth SCREEN is a separate question — see
// taskRow.ShowExit.
//
// Only success and failure can carry one. A deny never spawned; a timeout or
// cancel was killed; unreachable and version_refused never left the Relay; and
// unsupported means Policy was never even asked.
func hasRealExitStatus(outcome jobs.Outcome, code int32) bool {
	switch outcome {
	case jobs.OutcomeSuccess, jobs.OutcomeFailure:
		return code >= 0
	default:
		return false
	}
}

func combinedOutput(stdout, stderr []byte) string {
	var b strings.Builder
	b.Write(stdout)
	if len(stderr) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.Write(stderr)
	}
	return strings.TrimRight(b.String(), "\n")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

var jobTmpl = newScreen("job", `
{{if not .Found}}
<div class="placeholder"><p>No Job with the id <code>{{.ID}}</code> appears in this Relay's audit
trail.</p><p><a href="/console/activity?kind=dispatch">Back to dispatches</a>.</p></div>
{{else}}

<section class="jobhead">
  <div class="jhrow">
    <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
    <code class="jobop">{{.Operation}}</code>
    {{with .Args}}<span class="mono dim">{{.}}</span>{{end}}
  </div>
  <div class="jhrow">
    {{template "trust-chip" (trust .Principal .Verified)}}
    {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}<span class="dim">on behalf of — caller-claimed, nothing checked it</span>{{end}}
    {{with .ApprovalHref}}<a href="{{.}}">released by an approval</a>{{end}}
    {{with .GrantID}}<span class="grant" title="A human approved a window this plan fell inside, not this plan.">grant {{short .}}</span>{{end}}
  </div>
  <div class="jhrow">
    {{with .Selector}}<code class="selector">{{.}}</code>{{end}}
    <span class="fanmath">{{.FanOut}} {{plural .FanOut "Node" "Nodes"}}</span>
    {{if .InFlight}}<span class="overcap">{{.InFlight}} still in flight</span>{{end}}
    <span class="dim">{{.Created}}</span>
    <code class="planhash">{{short .ID}}</code>
  </div>
</section>

{{if .Bar.Total}}{{template "outcome-bar" .Bar}}{{end}}

{{if .ReadClass}}
<p class="gap"><b>This was a read.</b> Its outcomes and timings are recorded; its output was never
retained and nothing on this page will show it later. Reading is exfiltration, so what left the
Node is audited and what it said is not kept.</p>
{{end}}

{{range .Groups}}
<details class="ogroup"{{if .Open}} open{{end}}>
  <summary>
    <span class="chip outcome" data-outcome="{{.Label}}">{{.Label}}</span>
    <b>{{.Count}}</b> {{plural .Count "Node" "Nodes"}}
    {{if eq .Label "success"}}<span class="dim">the mode — collapsed, because it is the least informative thing here</span>{{end}}
  </summary>

  {{if .SharedRule}}
  <p class="note">Every one of these {{.Count}} denials fired the same rule. It is shown once.</p>
  <pre class="denyrule">{{.SharedRule}}</pre>
  {{end}}

  {{range .Clusters}}
    <div class="cluster">
      {{if .Representative}}
        <div class="clabel"><b>{{.Count}}</b> Nodes reported identical output — one shown.
          <span class="dim">Listing all of them is one more click away and never the default.</span></div>
      {{end}}
      {{range .Rows}}
        <div class="trow">
          <a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>
          {{if .ShowExit}}<span class="exit">exit {{.ExitCode}}</span>{{end}}
          {{if .Truncated}}<span class="dim">output truncated by the daemon's size cap</span>{{end}}
        </div>
        {{with .Output}}<pre class="taskout">{{.}}</pre>{{end}}
      {{end}}
    </div>
  {{end}}

  {{if eq .Label "denied_by_policy"}}
    {{if not .SharedRule}}
      {{range .Clusters}}{{range .Rows}}{{with .Deny}}{{template "deny-block" .}}{{end}}{{end}}{{end}}
    {{end}}
  {{end}}
</details>
{{end}}

{{if not .TasksWired}}
<p class="gap">Per-Node exit codes and captured output are read from the audit trail on this page.
The Job store was not wired into this Console, so a Task still in flight does not appear here at
all — only what has already been recorded.</p>
{{end}}
{{end}}
`)
