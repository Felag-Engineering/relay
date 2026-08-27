package console

// approvals.go is the queue (spec 14) and the single approval object (spec 08),
// both READ-ONLY in v0.6.0.
//
// # Why there is no Approve button here, and will not be one on a row
//
// Deciding happens on the approval OBJECT, never in the list. A row-level
// Approve control would let someone approve without seeing what they approved,
// which is the entire failure the approval mechanism exists to prevent — a
// human who clicks through a queue is a rubber stamp with an audit trail, and an
// audit trail of rubber stamps is worse than no gate at all, because it looks
// like oversight.
//
// The asymmetry is deliberate and worth stating: a BULK DENY is safe in a way
// bulk approve is not, because refusing without reading fails closed. That
// arrives in v0.7.0 with step-up and a reason.
//
// # Order by urgency, never by arrival
//
// An approval that lapses because it sat below the fold is a failure of this
// screen. Nearest expiry first, then largest fan-out.
//
// # v0.6.0 is read-only, structurally
//
// The Console's approval seam (seams.go) has PendingApprovals and Approval on
// it and no decision method at all. The acceptance criterion "zero mutating
// routes in the Console" is therefore a fact about the interface rather than a
// property of these handlers, and #435 adds deciding through the capability
// layer's decision method — the same one the Control API calls, so quorum,
// audience, requester exclusion and channel strength stay one implementation.

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// expiryPressure is the window inside which a pending approval renders as
// urgent. This is the one place in the Console where a countdown earns its keep.
const expiryPressure = 15 * time.Minute

type approvalRow struct {
	ID   string
	Href string

	Summary   string
	Operation string
	Risk      string

	Requester string
	Verified  bool

	Signed   int
	Required int

	TTL    string
	Urgent bool
	Lapsed bool

	MatchedRules []string
	PlanHash     string

	// ShapeKey groups pending approvals that are the same shape. Approving
	// three identical requests one at a time without noticing they are
	// identical is precisely the fatigue failure the grouping exists to catch.
	ShapeKey  string
	SameShape int
}

type approvalsView struct {
	Rows  []approvalRow
	Count int
	Wired bool
}

type decisionRow struct {
	Account string
	Approve bool
	Reason  string
	Channel string
	Human   bool
	At      string
}

type approvalView struct {
	Found bool
	ID    string

	Summary   string
	Operation string
	Risk      string
	PlanHash  string

	Requester string
	Verified  bool

	State            string
	Pending          bool
	Signed           int
	Required         int
	Audience         []string
	RequesterAllowed bool

	Created string
	Expires string
	TTL     string
	Urgent  bool

	MatchedRules []string
	Decisions    []decisionRow

	JobID   string
	JobHref string
}

func handleApprovals(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := page(d, w, r, "Approvals")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		v := approvalsView{Wired: d.Approvals != nil}
		if d.Approvals == nil {
			renderScreen(w, p, approvalsTmpl, v)
			return
		}
		reqs, err := d.Approvals.PendingApprovals(r.Context())
		if err != nil {
			unavailable(w, "the approval queue (it returned an error)")
			return
		}
		v.Rows = buildApprovalRows(reqs, d.now())
		v.Count = len(v.Rows)
		renderScreen(w, p, approvalsTmpl, v)
	}
}

func buildApprovalRows(reqs []approval.Request, now time.Time) []approvalRow {
	shapes := map[string]int{}
	for _, req := range reqs {
		shapes[shapeKey(req)]++
	}

	rows := make([]approvalRow, 0, len(reqs))
	for _, req := range reqs {
		key := shapeKey(req)
		ttl := req.ExpiresAt.Sub(now)
		row := approvalRow{
			ID:           req.ID,
			Href:         "/console/approvals/" + req.ID,
			Summary:      req.Summary,
			Operation:    approvalOperation(req),
			Risk:         RiskLabel(req.RiskClass),
			Requester:    req.RequestedBy,
			Verified:     req.RequestedByID != "",
			Signed:       countApprovals(req),
			Required:     req.Require.Count,
			TTL:          renderTTL(ttl),
			Urgent:       ttl > 0 && ttl <= expiryPressure,
			Lapsed:       ttl <= 0,
			MatchedRules: req.MatchedRules,
			PlanHash:     req.PlanHash,
			ShapeKey:     key,
			SameShape:    shapes[key],
		}
		rows = append(rows, row)
	}

	// Nearest expiry first, then largest fan-out. Never arrival order: the
	// oldest request is not the most urgent one, and sorting by arrival is how
	// a request lapses unreviewed at the bottom of a list.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Lapsed != rows[j].Lapsed {
			return rows[i].Lapsed
		}
		return rows[i].TTL < rows[j].TTL
	})
	return rows
}

func handleApproval(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("approval_id")
		p, ok := page(d, w, r, "Approval "+shortHash(id))
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Approvals == nil {
			unavailable(w, "the approval queue")
			return
		}
		req, err := d.Approvals.Approval(r.Context(), id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			renderScreen(w, p, approvalTmpl, approvalView{ID: id})
			return
		}
		renderScreen(w, p, approvalTmpl, buildApprovalView(req, d.now()))
	}
}

func buildApprovalView(req approval.Request, now time.Time) approvalView {
	ttl := req.ExpiresAt.Sub(now)
	v := approvalView{
		Found:            true,
		ID:               req.ID,
		Summary:          req.Summary,
		Operation:        approvalOperation(req),
		Risk:             RiskLabel(req.RiskClass),
		PlanHash:         req.PlanHash,
		Requester:        req.RequestedBy,
		Verified:         req.RequestedByID != "",
		State:            req.State.String(),
		Pending:          req.State == approval.StatePending,
		Signed:           countApprovals(req),
		Required:         req.Require.Count,
		Audience:         req.Require.Audience,
		RequesterAllowed: req.Require.RequesterAllowed,
		Created:          req.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
		Expires:          req.ExpiresAt.UTC().Format("2006-01-02 15:04:05Z"),
		TTL:              renderTTL(ttl),
		Urgent:           ttl > 0 && ttl <= expiryPressure,
		MatchedRules:     req.MatchedRules,
		JobID:            req.JobID,
	}
	if req.JobID != "" {
		v.JobHref = "/console/jobs/" + req.JobID
	}
	for _, dec := range req.Decisions {
		v.Decisions = append(v.Decisions, decisionRow{
			Account: dec.Account,
			Approve: dec.Approve,
			Reason:  dec.Reason,
			Channel: dec.Channel.String(),
			Human:   dec.DeciderHuman,
		})
	}
	return v
}

// approvalOperation names what was parked, from the STRUCTURED fields.
//
// Never parsed out of Summary. The summary is Relay-authored prose a human
// reads; the ActionKind is what the role floor for deciding is computed from,
// and deriving one from the other would make the authorization ladder depend on
// string formatting.
func approvalOperation(req approval.Request) string {
	switch req.ActionKind {
	case jobs.ActionRawExec:
		return "raw_exec"
	case jobs.ActionOperation:
		return "run_operation"
	default:
		return "dispatch"
	}
}

// shapeKey groups pending requests that are the same shape.
//
// Approximated from the structured fields the Request already carries, because
// the stored shape key is its own issue (#415). Approximating it here is honest
// as a GROUPING hint and would be wrong as anything an approval committed to —
// which is why the plan hash, not this, is what a decision is recorded against.
func shapeKey(req approval.Request) string {
	return strings.Join([]string{
		approvalOperation(req),
		RiskLabel(req.RiskClass),
		strings.Join(req.MatchedRules, "+"),
	}, "|")
}

func countApprovals(req approval.Request) int {
	n := 0
	for _, d := range req.Decisions {
		if d.Approve {
			n++
		}
	}
	return n
}

func renderTTL(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return itoa(int(d.Seconds())) + "s left"
	}
	if d < time.Hour {
		return itoa(int(d.Minutes())) + "m left"
	}
	return itoa(int(d.Hours())) + "h left"
}

var approvalsTmpl = newScreen("approvals", `
{{if not .Wired}}
<p class="dim">The approval queue is not wired into this Console.</p>
{{else if not .Rows}}
<div class="empty">
  <h2>Nothing is waiting.</h2>
  <p>An empty approval queue is good news. When a gate rule parks a dispatch, it appears here with
  the Plan it is asking you to authorise.</p>
</div>
{{else}}
<p class="lede"><b>{{.Count}}</b> {{plural .Count "dispatch is" "dispatches are"}} waiting for a
human. Ordered by <b>nearest expiry</b>, never by arrival — a request that lapses because it sat
below the fold is a failure of this screen.</p>

<div class="queue">
{{range .Rows}}
  <a class="qrow{{if .Urgent}} urgent{{end}}{{if .Lapsed}} lapsed{{end}}" href="{{.Href}}">
    <div class="qmain">
      <div class="qhead">
        <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
        <code>{{.Operation}}</code>
        {{template "trust-chip" (trust .Requester .Verified)}}
      </div>
      <div class="qsummary">{{.Summary}}</div>
      {{with .MatchedRules}}<div class="qrules">parked by <code>{{join ", " .}}</code></div>{{end}}
    </div>
    <div class="qside">
      <div class="quorum"><b>{{.Signed}}</b> of {{.Required}} signed</div>
      <div class="qttl">{{.TTL}}</div>
      {{if gt .SameShape 1}}<div class="qshape">{{.SameShape}} pending with the same shape</div>{{end}}
    </div>
  </a>
{{end}}
</div>

<p class="note">There is no Approve control on a row, and there will not be one. A decision is made
on the approval itself, with its Plan in front of you — approving from a list is approving without
seeing what you approved. Deciding arrives with step-up in the administration milestone.</p>
{{end}}
`)

var approvalTmpl = newScreen("approval", `
{{if not .Found}}
<div class="placeholder"><p>No approval request with the id <code>{{.ID}}</code> exists on this
Relay.</p><p><a href="/console/approvals">Back to the queue</a>.</p></div>
{{else}}

<section class="panel">
  <div class="jhrow">
    <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
    <code class="jobop">{{.Operation}}</code>
    <span class="chip outcome" data-outcome="{{if .Pending}}unsupported{{else}}success{{end}}">{{.State}}</span>
    {{if .Urgent}}<span class="overcap">{{.TTL}}</span>{{else}}<span class="dim">{{.TTL}}</span>{{end}}
  </div>

  <p class="summary">{{.Summary}}</p>
  <p class="note">That sentence is written by the Relay, not by the caller. An agent chose the
  Operation; it did not choose one word a human reads about it.</p>

  <dl class="kv">
    <dt>requested by</dt><dd>{{template "trust-chip" (trust .Requester .Verified)}}</dd>
    <dt>plan hash</dt><dd><code class="planhash" title="This is what a decision commits to — not the prose above it.">{{.PlanHash}}</code></dd>
    <dt>quorum</dt><dd><b>{{.Signed}}</b> of {{.Required}} signed{{if not .RequesterAllowed}} · the requester may not sign their own{{end}}</dd>
    {{with .Audience}}<dt>audience</dt><dd>{{join ", " .}}</dd>{{end}}
    {{with .MatchedRules}}<dt>parked by</dt><dd><code>{{join ", " .}}</code></dd>{{end}}
    <dt>created</dt><dd>{{.Created}}</dd>
    <dt>expires</dt><dd>{{.Expires}}</dd>
    {{with .JobHref}}<dt>job</dt><dd><a href="{{.}}">{{short $.JobID}}</a></dd>{{end}}
  </dl>
</section>

{{if .Decisions}}
<section class="panel">
  <h3>Decisions</h3>
  <table class="rows">
    <thead><tr><th>Account</th><th>Answer</th><th>Channel</th><th>Note</th></tr></thead>
    <tbody>
    {{range .Decisions}}
      <tr>
        <td>{{template "trust-chip" (trust .Account true)}}{{if not .Human}}<span class="dim">machine</span>{{end}}</td>
        <td><span class="chip outcome" data-outcome="{{if .Approve}}success{{else}}denied_by_policy{{end}}">{{if .Approve}}approved{{else}}denied{{end}}</span></td>
        <td><code>{{.Channel}}</code></td>
        <td>{{.Reason}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  <p class="note">The channel is recorded rather than assumed. A decision that arrived over a
  credential the requesting session does not hold is evidence; one that arrived in-band is a
  delivery convenience, and the difference is the whole security property.</p>
</section>
{{end}}

{{if .Pending}}
<p class="gap"><b>Deciding is not available in this Console yet.</b> Approve and deny arrive with
step-up re-authentication, because a session proves a human authorised the session and step-up
proves a human intended this act. Until then, answer through the Control API's decision endpoint —
which is the same code path, and will stay the one that decides.</p>
{{end}}
{{end}}
`)
