package console

// activity.go is the live stream and the audit trail, deliberately ONE surface
// (spec 04).
//
// # Why one screen and not two
//
// "What is happening" and "what happened" are the same events read at different
// distances. Building them as two screens means two renderers of one event type,
// and two renderers of one event type drift: the live view gains a chip the
// history view lacks, the history view gains a filter the live view cannot
// express, and eventually an operator watching the stream and an auditor reading
// the trail disagree about what the fleet did. Same rows, same chips, one
// renderer — live tail on is "now", filtered is history.
//
// # Job-grained, not Task-grained
//
// One mutate across 2,214 Nodes emits 2,214 Task records. A tail that renders
// them individually becomes unreadable at exactly the moment something important
// is happening, which is the opposite of what a stream is for. So dispatch
// records collapse to one row per Job, carrying live outcome counts, and expand
// to Tasks on the Job's own page.
//
// Non-dispatch events are first-class rows, not a footnote: approvals, token
// mints, enrollments, Freeze transitions and sign-ins are things that happened
// to the fleet, and an operator who has to look in a second place for "who
// minted that token" has a trail with a hole in it.
//
// # There is no Jobs destination
//
// This screen filtered to dispatch IS the Jobs list (open decision D6). The
// filter is a linkable URL state rather than a widget an operator has to
// reconstruct, which is what makes "the Jobs list" a thing you can send someone.

import (
	"net/http"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// rowKind is the family a row belongs to, which is what the filter chips select
// and what decides a row's shape. It is coarser than audit.Kind on purpose: an
// operator filters for "approvals", not for the four distinct approval record
// kinds the trail distinguishes.
type rowKind string

const (
	rowDispatch rowKind = "dispatch"
	rowApproval rowKind = "approval"
	rowToken    rowKind = "token"
	rowNode     rowKind = "node"
	rowFreeze   rowKind = "freeze"
	rowAuth     rowKind = "auth"
	rowAccount  rowKind = "account"
	rowRead     rowKind = "read"
	rowRefusal  rowKind = "refusal"
	rowOther    rowKind = "other"
)

// kindOf maps a trail record onto a row family.
func kindOf(k string) rowKind {
	switch k {
	case audit.KindDispatch:
		return rowDispatch
	case audit.KindRead:
		return rowRead
	case audit.KindRefusal:
		return rowRefusal
	case audit.KindApprovalRequested, audit.KindApprovalDecided,
		audit.KindApprovalExpired, audit.KindApprovalPendingObserved:
		return rowApproval
	case audit.KindTokenMint, audit.KindTokenRevoke, audit.KindAPITokenMint, audit.KindAPITokenRevoke:
		return rowToken
	case audit.KindNodeRevoke:
		return rowNode
	case audit.KindFreezeEngage, audit.KindFreezeRelease:
		return rowFreeze
	case audit.KindLoginSucceeded, audit.KindLoginFailed, audit.KindLoginThrottled, audit.KindLogout:
		return rowAuth
	case audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountEnable, audit.KindAccountDisable:
		return rowAccount
	default:
		return rowOther
	}
}

// activityRow is one rendered event.
type activityRow struct {
	Kind rowKind
	// EventKind is the exact audit kind, shown in mono. The coarse family
	// decides the shape; the exact kind is what an auditor quotes.
	EventKind string

	When    string
	Rel     string
	Summary string

	// Principal and Verified are the trust chip. OnBehalfOf is the asserted
	// lane and is rendered as a SEPARATE, dashed chip — never merged into the
	// verified one. A jailbroken agent can assert anything it likes; the whole
	// point of the two-chip grammar is that it cannot make its claim look like
	// something the Relay checked.
	Principal  string
	Verified   bool
	OnBehalfOf string

	Selector string
	NodeID   string
	NodeHref string

	Operation string
	Args      string
	Risk      string

	JobID   string
	JobHref string

	// Outcomes are the per-Job rollup: the segmented bar and its key.
	Outcomes OutcomeBar
	FanOut   int

	ApprovalID   string
	ApprovalHref string

	// GrantID is set only when a batch/window Grant released this dispatch.
	// Rendered separately from ApprovalID because the distinction — "a human
	// approved THIS plan" versus "a human approved a window this plan fell
	// inside" — is one an auditor needs and cannot recover from the approval
	// id alone.
	GrantID string

	Reason string

	// ReadClass marks a row whose output was never retained.
	ReadClass bool
}

type activityView struct {
	Rows       []activityRow
	Filter     string
	KindFilter string
	Kinds      []kindCount
	Truncated  bool
	Window     int
	Wired      bool
}

type kindCount struct {
	Kind    rowKind
	Count   int
	Current bool
	Href    string
}

func handleActivity(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := page(d, w, r, "Activity")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		v := activityView{
			Filter:     r.URL.Query().Get("q"),
			KindFilter: r.URL.Query().Get("kind"),
			Window:     auditWindow,
			Wired:      d.Audit != nil,
		}
		if d.Audit == nil {
			renderScreen(w, p, activityTmpl, v)
			return
		}

		recs, err := d.Audit.List(r.Context())
		if err != nil {
			unavailable(w, "the audit trail (it returned an error)")
			return
		}

		rows, counts, truncated := buildActivity(recs, v.Filter, v.KindFilter)
		v.Rows, v.Kinds, v.Truncated = rows, counts, truncated
		renderScreen(w, p, activityTmpl, v)
	}
}

// buildActivity collapses dispatch records into Job rows, renders everything
// else as its own row, and applies the filter.
//
// The collapse is the reason this is a function and not a loop in the handler:
// it is the screen's one real algorithm, and it has to hold at 10,000 Tasks.
func buildActivity(recs []audit.Record, q, kindFilter string) ([]activityRow, []kindCount, bool) {
	window, truncated := windowed(recs, auditWindow)

	// Job rollup. Dispatch records for one Job become one row carrying the
	// outcome distribution; the FIRST record seen (newest, since the window is
	// reversed) supplies the row's identity, and every record contributes a
	// count.
	byJob := map[string]*activityRow{}
	counts := map[string]map[jobs.Outcome]int{}
	var rows []activityRow

	for _, rec := range window {
		kind := kindOf(rec.Kind)
		if (kind == rowDispatch || kind == rowRead) && rec.JobID != "" {
			if row, seen := byJob[rec.JobID]; seen {
				counts[rec.JobID][rec.Outcome]++
				row.FanOut++
				continue
			}
			row := dispatchRow(rec)
			byJob[rec.JobID] = &row
			counts[rec.JobID] = map[jobs.Outcome]int{rec.Outcome: 1}
			row.FanOut = 1
			rows = append(rows, activityRow{}) // placeholder, filled below
			rows[len(rows)-1] = row
			continue
		}
		rows = append(rows, eventRow(rec))
	}

	// Fill the rollups back in. Done after the walk rather than during it
	// because a Job's row is created on its first (newest) record and its
	// counts keep arriving as the walk continues into older ones.
	for i := range rows {
		if rows[i].JobID == "" {
			continue
		}
		c, ok := counts[rows[i].JobID]
		if !ok {
			continue
		}
		oc := make([]OutcomeCount, 0, len(c))
		for outcome, n := range c {
			oc = append(oc, OutcomeCount{Outcome: outcome, Count: n})
		}
		rows[i].Outcomes = NewOutcomeBar(oc)
		rows[i].FanOut = byJob[rows[i].JobID].FanOut
	}

	// Kind counts are computed over the UNFILTERED window, so the chips show
	// what is there rather than what survived the current filter — a filter
	// whose own facets change as you use it cannot be used to explore.
	kc := map[rowKind]int{}
	for _, row := range rows {
		kc[row.Kind]++
	}

	var out []activityRow
	for _, row := range rows {
		if kindFilter != "" && string(row.Kind) != kindFilter {
			continue
		}
		if !matchesQuery(row, q) {
			continue
		}
		out = append(out, row)
	}

	order := []rowKind{rowDispatch, rowRead, rowRefusal, rowApproval, rowFreeze, rowNode, rowToken, rowAccount, rowAuth, rowOther}
	var chips []kindCount
	for _, k := range order {
		if kc[k] == 0 {
			continue
		}
		href := "/console/activity?kind=" + string(k)
		if q != "" {
			href += "&q=" + q
		}
		if string(k) == kindFilter {
			href = "/console/activity"
			if q != "" {
				href += "?q=" + q
			}
		}
		chips = append(chips, kindCount{Kind: k, Count: kc[k], Current: string(k) == kindFilter, Href: href})
	}
	return out, chips, truncated
}

// matchesQuery is a substring match over the fields an operator would type.
//
// Deliberately not a query language. The real filter — principal, Operation,
// Selector, outcome, Node, time range, with cursor pagination — is the capability
// layer's read lane (#441), and inventing a second grammar here would guarantee
// the two disagree about what `outcome:denied` means.
func matchesQuery(row activityRow, q string) bool {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{
		row.EventKind, row.Summary, row.Principal, row.OnBehalfOf, row.Selector,
		row.NodeID, row.Operation, row.Args, row.JobID, row.Reason, row.ApprovalID, row.GrantID,
	}, " "))
	for _, term := range strings.Fields(q) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

func dispatchRow(rec audit.Record) activityRow {
	row := baseRow(rec)
	// A Job row spans every matched Node, so it carries no single Node. The
	// record it was built from happens to describe one Task, and rendering that
	// Task's Node here would say the Job targeted one machine when it targeted
	// the Selector's whole fan-out. Per-Node results are on the Job's own page.
	row.NodeID, row.NodeHref = "", ""
	row.Operation = operationText(rec)
	row.Args = argsText(rec)
	row.JobID = rec.JobID
	row.JobHref = "/console/jobs/" + rec.JobID
	row.ReadClass = rec.Kind == audit.KindRead
	row.Summary = row.Operation
	return row
}

func eventRow(rec audit.Record) activityRow {
	row := baseRow(rec)
	row.Operation = operationText(rec)
	row.Args = argsText(rec)
	row.Reason = rec.Reason
	row.Summary = summarize(rec)
	if rec.JobID != "" {
		row.JobID = rec.JobID
		row.JobHref = "/console/jobs/" + rec.JobID
	}
	return row
}

func baseRow(rec audit.Record) activityRow {
	row := activityRow{
		Kind:       kindOf(rec.Kind),
		EventKind:  rec.Kind,
		When:       rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Principal:  principalText(rec),
		Verified:   rec.Attribution.Verified.AccountID != "",
		OnBehalfOf: rec.Attribution.Asserted.OnBehalfOf,
		Selector:   rec.Selector,
		NodeID:     rec.NodeID,
		ApprovalID: rec.ApprovalID,
		GrantID:    rec.GrantID,
	}
	if rec.NodeID != "" {
		row.NodeHref = "/console/nodes/" + rec.NodeID
	}
	if rec.ApprovalID != "" {
		row.ApprovalHref = "/console/approvals/" + rec.ApprovalID
	}
	return row
}

// summarize renders the one-line description of a non-dispatch event.
//
// It is a switch and not a format string on the record because these events are
// not variations of one thing: a Freeze release and a sign-in have nothing in
// common except that they happened, and prose that pretends otherwise reads as
// machine output rather than as a trail.
func summarize(rec audit.Record) string {
	switch rec.Kind {
	case audit.KindFreezeEngage:
		return "engaged the Relay-wide Freeze — no new Tasks dispatch"
	case audit.KindFreezeRelease:
		return "released the Freeze"
	case audit.KindJobCancel:
		return "cancelled Job " + shortHash(rec.JobID)
	case audit.KindTokenMint:
		return "minted an Enrollment Token"
	case audit.KindTokenRevoke:
		return "revoked an Enrollment Token — every Node it enrolled is revoked with it"
	case audit.KindNodeRevoke:
		return "revoked Node " + rec.NodeID
	case audit.KindAPITokenMint:
		return "minted an API Token"
	case audit.KindAPITokenRevoke:
		return "revoked an API Token"
	case audit.KindAccountCreate:
		return "created an Account"
	case audit.KindAccountRole:
		return "changed an Account's role"
	case audit.KindAccountEnable:
		return "enabled an Account"
	case audit.KindAccountDisable:
		return "disabled an Account"
	case audit.KindLoginSucceeded:
		return "signed in to the Console"
	case audit.KindLoginFailed:
		return "failed a Console sign-in"
	case audit.KindLoginThrottled:
		return "was throttled signing in"
	case audit.KindLogout:
		return "signed out"
	case audit.KindApprovalRequested:
		return "parked a dispatch for approval"
	case audit.KindApprovalPendingObserved:
		return "re-drove a dispatch that is already parked"
	case audit.KindApprovalDecided:
		return "answered an approval request"
	case audit.KindApprovalExpired:
		return "an approval request expired unanswered"
	case audit.KindRefusal:
		return "was refused"
	case audit.KindPlan:
		return "resolved a Plan — nothing executed"
	default:
		return rec.Kind
	}
}

var activityTmpl = newScreen("activity", `
<form class="viewbar" method="get" action="/console/activity">
  <label class="vlabel" for="q">Filter</label>
  <input id="q" name="q" value="{{.Filter}}" placeholder="account, Operation, Node, Job, Selector" spellcheck="false" autocomplete="off">
  {{with .KindFilter}}<input type="hidden" name="kind" value="{{.}}">{{end}}
  <button type="submit">Apply</button>
  <span class="vcount">{{len .Rows}} {{plural (len .Rows) "event" "events"}}</span>
</form>

{{if .Kinds}}
<div class="kindbar">
  {{range .Kinds}}<a class="kchip{{if .Current}} on{{end}}" href="{{.Href}}">{{.Kind}} <b>{{.Count}}</b></a>{{end}}
</div>
{{end}}

{{if not .Wired}}
<p class="dim">The audit trail is not wired into this Console.</p>
{{else if .Truncated}}
<p class="gap"><b>Showing the most recent {{.Window}} records.</b> The trail holds more. This is a
window, not a page — filtered, paginated history over principal, Operation, outcome and time
range is the capability layer's read lane, and it is not built yet. Do not read the absence of an
event here as the event not having happened.</p>
{{end}}

<div class="feed">
{{range .Rows}}
  <article class="ev" data-kind="{{.Kind}}">
    <div class="evwhen"><time>{{.When}}</time><span class="evkind">{{.EventKind}}</span></div>
    <div class="evbody">
      <div class="evhead">
        {{template "trust-chip" (trust .Principal .Verified)}}
        {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}{{end}}
        {{if .JobHref}}<a class="evop" href="{{.JobHref}}"><code>{{.Operation}}</code></a>
        {{else}}<span class="evsum">{{.Summary}}</span>{{end}}
        {{if .ReadClass}}<span class="chip risk" data-risk="read">read</span>{{end}}
      </div>
      {{with .Args}}<div class="evargs mono">{{.}}</div>{{end}}
      <div class="evmeta">
        {{with .Selector}}<code class="selector">{{.}}</code>{{end}}
        {{if .FanOut}}<span class="fanmath">{{.FanOut}} {{plural .FanOut "Node" "Nodes"}}</span>{{end}}
        {{if .NodeHref}}<a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>{{end}}
        {{with .ApprovalHref}}<a href="{{.}}">approval</a>{{end}}
        {{with .GrantID}}<span class="grant" title="A batch/window Grant released this — a human approved a window this plan fell inside, not this plan.">grant {{short .}}</span>{{end}}
      </div>
      {{if .Outcomes.Total}}{{template "outcome-bar" .Outcomes}}{{end}}
      {{with .Reason}}<div class="evreason">{{.}}</div>{{end}}
      {{if .ReadClass}}<div class="evnote">Output was not retained. Nothing here will show it later.</div>{{end}}
    </div>
  </article>
{{else}}
  {{if .Wired}}<p class="dim">Nothing matches.</p>{{end}}
{{end}}
</div>
`)
