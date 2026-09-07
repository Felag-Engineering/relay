package console

// agents.go is the trust surface (spec 03): every call an AI-agent makes.
//
// # There are no sessions
//
// The MCP transport is stateless (ADR-0028): no `Mcp-Session-Id`, no connection
// to show as connected, no connect time, no idle state, and nothing to
// disconnect. Every tool call is an independent, authenticated request. So the
// unit here is the ACCOUNT, and "active" means it has made a call inside the
// activity window.
//
// The file keeps its spec's `03-agent-sessions.md` name so existing links hold,
// and the screen deliberately does not.
//
// # What this screen can honestly show
//
// The REQUEST, never the reasoning. The Relay sees tool calls; it does not see
// the model's intent and must never pretend to. That is a feature rather than a
// limitation: a verified record of what was asked beats a narrated account of
// why, which an agent under prompt injection would fabricate happily and
// convincingly.
//
// # Why this is not the Activity screen
//
// Different grain, different scope, different retention. Activity is Job-grained
// and durable; this is call-grained and holds payloads only while they are in
// flight. Keeping them apart is what lets each be honest about retention —
// a `list_nodes` call belongs here and never on Activity, and read OUTPUT
// belongs on neither, at any age (ADR-0025).

import (
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// activeWindow is how recently an Account must have acted to count as active.
// Fifteen minutes, per spec 03 — long enough that an agent thinking between
// calls does not blink out, short enough that "active" means something.
const activeWindow = 15 * time.Minute

type agentAccount struct {
	Name     string
	Verified bool
	Calls    int
	Mutates  int
	Denied   int
	LastSeen string
	Active   bool
	Current  bool
	Href     string
}

type agentCall struct {
	When       string
	Tool       string
	Principal  string
	Verified   bool
	OnBehalfOf string

	Risk     string
	Selector string
	Args     string
	NodeID   string
	NodeHref string

	Outcome string
	JobID   string
	JobHref string

	Deny *Deny

	// RepeatDeny marks a deny whose Operation and rule were already explained
	// higher up the stream. The row keeps its outcome chip and its Node; only
	// the duplicated prose is dropped.
	//
	// One fleet-wide dispatch produces one deny per Node, all with the same
	// explanation. Repeating the full block per Node made a three-Node refusal
	// three screens tall and would make a thousand-Node one unreadable — the
	// stream then hides the NEXT call rather than showing this one. Node detail
	// already collapses these the same way.
	RepeatDeny bool

	ReadClass bool
}

type agentsView struct {
	Accounts  []agentAccount
	Calls     []agentCall
	Account   string
	Wired     bool
	Truncated bool
	Window    int
}

func handleAgents(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := page(d, w, r, "Agents")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		v := agentsView{
			Account: r.URL.Query().Get("account"),
			Wired:   d.Audit != nil,
			Window:  auditWindow,
		}
		if d.Audit == nil {
			renderScreen(w, p, agentsTmpl, v)
			return
		}
		recs, err := d.Audit.List(r.Context())
		if err != nil {
			unavailable(w, "the audit trail (it returned an error)")
			return
		}
		v.Accounts, v.Calls, v.Truncated = buildAgents(recs, v.Account, d.now())
		renderScreen(w, p, agentsTmpl, v)
	}
}

// buildAgents rolls the trail up per Account and renders the call stream.
func buildAgents(recs []audit.Record, account string, now time.Time) ([]agentAccount, []agentCall, bool) {
	window, truncated := windowed(recs, auditWindow)

	type acc struct {
		agentAccount
		last time.Time
	}
	byAccount := map[string]*acc{}
	var calls []agentCall

	for _, rec := range window {
		if !isAgentCall(rec) {
			continue
		}
		f := factsOfRecord(rec)
		name := principalText(f)
		a, seen := byAccount[name]
		if !seen {
			a = &acc{agentAccount: agentAccount{
				Name:     name,
				Verified: rec.Attribution.Verified.AccountID != "",
				// url.Values, not concatenation: an Account name is a principal
				// string this package does not constrain, and html/template's URL
				// normaliser leaves & # = alone. "bob&co:operator" concatenated
				// yields ?account=bob plus a stray parameter, so the rail links
				// to the wrong Account (#467). Same idiom as compare.go.
				Href: "/console/agents?" + url.Values{"account": {name}}.Encode(),
			}}
			byAccount[name] = a
		}
		a.Calls++
		// Unconditional, where this used to be the second arm of a switch whose
		// first arm counted read-class records into a Reads field. Nothing
		// writes a KindRead record with an Outcome (auditsink.RecordRead sets
		// none), so no record changes lane; the switch was hiding a denied read
		// from the Denied count for no reason a reader could see.
		if rec.Outcome == jobs.OutcomeDeniedByPolicy {
			a.Denied++
		}
		// The mutate count is mutate-class CALLS, counted through the same one
		// inference as the per-row chip (riskOf, vocab.go) — so the rail's "3
		// mutate" is by construction the number of rows below it chipped
		// mutate, and an operator can verify the rail by scrolling.
		//
		// # What the number claims, and why it counts asks rather than runs
		//
		// Every mutate-class call this Account made: including a raw_exec the
		// role gate REFUSED, a dispatch still PARKED for approval, and one
		// Policy DENIED. None of those changed a Node, and the count still
		// includes them, because this screen is the request and never the
		// result ("as the Relay received it", above) and the rail's other
		// counters already read that way — Denied is a subset of Calls, not a
		// column beside it. On a trust surface an attempted mutate is the
		// signal: a compromised agent probing a fleet and being refused every
		// time must not read quieter than an honest one. What actually RAN is
		// Activity's question, at Job grain, where an outcome means something.
		//
		// The outcome chip on each row is what separates asked from ran, and it
		// is on the same screen — which is the other half of why the count is
		// derived this way rather than filtered down to executed dispatches:
		// two numbers on one screen disagreeing about one record is the drift
		// riskOf exists to prevent (#463).
		//
		// The predicate this replaces was `Kind == KindDispatch && ActionKind
		// != "" && OperationName == ""` — raw_exec only. A mutating
		// run_operation carries an OperationName, so fifty service.restart
		// dispatches counted zero.
		//
		// There is deliberately no read counter beside it. Spec 03 does not ask
		// the rail for one, riskOf answers read or mutate and nothing else — so
		// reads are Calls minus Mutates — and a third number an operator has to
		// reconcile with the other two buys nothing. The Reads field that used
		// to be computed here was never rendered and disagreed with the chip
		// anyway (it tested Kind == KindRead, so a read-class DISPATCH like
		// file.read chipped read and counted as neither).
		if riskOf(f) == jobs.RiskClassMutate {
			a.Mutates++
		}
		if rec.Timestamp.After(a.last) {
			a.last = rec.Timestamp
		}

		if account == "" || account == name {
			calls = append(calls, agentCallFrom(rec))
		}
	}

	// Collapse repeated deny prose, newest kept. Keyed on Operation AND rule,
	// not the rule alone as Node detail can afford to: this stream spans Nodes
	// and Operations, and read-class denies share one generic explanation, so
	// keying on the text alone would silently collapse refusals of DIFFERENT
	// Operations into one.
	seenDeny := map[string]bool{}
	for i := range calls {
		d := calls[i].Deny
		if d == nil {
			continue
		}
		key := d.OperationName + "\x00" + d.Rule
		if seenDeny[key] {
			calls[i].Deny = nil
			calls[i].RepeatDeny = true
			continue
		}
		seenDeny[key] = true
	}

	out := make([]agentAccount, 0, len(byAccount))
	for _, a := range byAccount {
		a.LastSeen = timeSince(a.last, now)
		a.Active = now.Sub(a.last) <= activeWindow
		a.Current = a.Name == account
		out = append(out, a.agentAccount)
	}
	// Active first, then busiest. An operator opens this screen because
	// something is happening now.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Name < out[j].Name
	})
	return out, calls, truncated
}

// isAgentCall reports whether a record describes a call somebody made THROUGH a
// control surface, as opposed to something the Relay did.
//
// Sign-ins, Freeze transitions and Account changes are control-plane events and
// belong on Activity. An approval expiring is the clock, not a caller.
func isAgentCall(rec audit.Record) bool {
	switch kindOf(rec.Kind) {
	case rowDispatch, rowRead, rowRefusal, rowApproval:
		return rec.Kind != audit.KindApprovalExpired
	default:
		return false
	}
}

func agentCallFrom(rec audit.Record) agentCall {
	f := factsOfRecord(rec)
	c := agentCall{
		When:       rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Tool:       toolName(f),
		Principal:  principalText(f),
		Verified:   rec.Attribution.Verified.AccountID != "",
		OnBehalfOf: rec.Attribution.Asserted.OnBehalfOf,
		Selector:   rec.Selector,
		Args:       argsText(f),
		NodeID:     rec.NodeID,
		Outcome:    OutcomeLabel(rec.Outcome),
		JobID:      rec.JobID,
		ReadClass:  rec.Kind == audit.KindRead,
	}
	// The risk class comes from ONE inference (vocab.go), not from the record
	// kind. Deriving it here from `Kind == KindDispatch` labelled file.read as a
	// mutate and a parked raw_exec as a read — the second of which is the most
	// misleading thing this Console could say, since Raw Exec always takes the
	// mutate cap without exception.
	c.Risk = RiskLabel(riskOf(f))
	if rec.NodeID != "" {
		c.NodeHref = "/console/nodes/" + rec.NodeID
	}
	if rec.JobID != "" {
		c.JobHref = "/console/jobs/" + rec.JobID
	}
	if rec.Outcome == jobs.OutcomeDeniedByPolicy {
		c.Deny = &Deny{
			NodeID:        rec.NodeID,
			OperationName: operationText(f),
			Rule:          denyExplanation(rec),
			PolicyHref:    "/console/nodes/" + rec.NodeID,
		}
	}
	// A record that never reached a Node has no per-Node outcome, and the zero
	// value renders as "unspecified" — which reads as "we don't know" for an
	// event whose outcome is perfectly well known. Name what actually happened.
	switch rec.Kind {
	case audit.KindRefusal:
		c.Outcome = "refused"
	case audit.KindApprovalRequested:
		c.Outcome = "parked"
	case audit.KindApprovalPendingObserved:
		c.Outcome = "already parked"
	case audit.KindApprovalDecided:
		c.Outcome = "decided"
	case audit.KindPlan:
		c.Outcome = "planned"
	}
	return c
}

// toolName renders what was called, in the vocabulary an operator sees on the
// MCP surface rather than in audit's internal kinds.
//
// # The read case is first, and the order is the whole function
//
// A read record carries its tool name in OperationName — the SAME field a
// dispatch carries its Operation in (auditsink.RecordRead) — so testing
// OperationName before the Kind rendered every non-dispatching read as
// `run_operation · get_job`. That is a read relabelled as a dispatch on the
// one screen billed as what the AI-agent actually asked for, and it left the
// KindRead arm this replaces unreachable for every record the sink writes
// (#463).
//
// # What a read renders as is not this screen's invention
//
// readTargetOf is the shared naming core Activity ("enumerated list_nodes")
// and Read egress both already go through (vocab.go). A third spelling here
// would recreate precisely the drift
// TestActivity_ControlPlaneReadsSayWhatWasRead was written to end — two
// screens naming one audit record two ways, each looking right in isolation.
// It also keeps the tool NAME, which the bare word "read" it replaces threw
// away: on a trust surface, WHICH read happened is the useful half.
//
// It takes trailFacts rather than an audit.Record because every field it reads
// is on the shared projection, and its caller has already built one — a second
// projection per row is a second place the two could disagree.
func toolName(f trailFacts) string {
	if f.Kind == audit.KindRead {
		return readTargetOf(f)
	}
	if f.OperationName != "" {
		return "run_operation · " + f.OperationName
	}
	if len(f.RawExecArgv) > 0 {
		return "raw_exec"
	}
	switch f.Kind {
	case audit.KindApprovalRequested, audit.KindApprovalPendingObserved:
		return "parked for approval"
	case audit.KindApprovalDecided:
		return "approval decision"
	case audit.KindRefusal:
		return "refused"
	}
	if f.ActionKind != "" {
		return f.ActionKind
	}
	return f.Kind
}

func timeSince(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	default:
		return itoa(int(d.Hours()/24)) + "d ago"
	}
}

var agentsTmpl = newScreen("agents", `
<p class="lede">Every call an AI-agent makes, as the Relay received it. This screen shows the
<b>request</b> and never the reasoning — the Relay sees tool calls, not intent, and a narrated
account of <em>why</em> is exactly what an agent under prompt injection would fabricate.</p>

{{if not .Wired}}
<p class="dim">The audit trail is not wired into this Console.</p>
{{else}}

<div class="agentcols">
  <aside class="agentrail">
    <div class="ftitle">Accounts <span class="phint">active = a call in the last 15 minutes · mutate counts what was asked, refused and parked included</span></div>
    {{range .Accounts}}
    <a class="arow{{if .Current}} on{{end}}" href="{{if .Current}}/console/agents{{else}}{{.Href}}{{end}}">
      <span class="dot" data-live="{{if .Active}}on{{else}}off{{end}}"></span>
      <span class="aname">{{template "trust-chip" (trust .Name .Verified)}}</span>
      <span class="astats"><b>{{.Calls}}</b> {{plural .Calls "call" "calls"}}{{if .Mutates}} · {{.Mutates}} mutate{{end}}{{if .Denied}} · {{.Denied}} denied{{end}}</span>
      <span class="asub">{{.LastSeen}}</span>
    </a>
    {{else}}
    <p class="dim">No Account has called a control surface yet.</p>
    {{end}}
    <p class="note">There are no sessions. The MCP transport is stateless, so every call is an
    independent authenticated request — there is no connection to show and nothing to disconnect.
    Stopping one actor is revoking its API Tokens, or the Freeze.</p>
  </aside>

  <div class="agentfeed">
    {{if .Account}}<p class="scoped">Showing <b>{{.Account}}</b> only. <a href="/console/agents">Show every Account</a>.</p>{{end}}
    {{range .Calls}}
    <article class="ev" data-kind="call">
      <div class="evwhen"><time>{{.When}}</time></div>
      <div class="evbody">
        <div class="evhead">
          {{template "trust-chip" (trust .Principal .Verified)}}
          {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}{{end}}
          <span class="evop"><code>{{.Tool}}</code></span>
          <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
          <span class="chip outcome" data-outcome="{{.Outcome}}">{{.Outcome}}</span>
        </div>
        {{with .Args}}<div class="evargs mono">{{.}}</div>{{end}}
        <div class="evmeta">
          {{with .Selector}}<code class="selector">{{.}}</code>{{end}}
          {{if .NodeHref}}<a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>{{end}}
          {{if .JobHref}}<a href="{{.JobHref}}">job {{short .JobID}}</a>{{end}}
        </div>
        {{with .Deny}}{{template "deny-block" .}}{{end}}
        {{if .RepeatDeny}}<div class="repeatdeny">Same Operation and rule as above.</div>{{end}}
        {{if .ReadClass}}<div class="evnote">The call is audited; the result is not retained.</div>{{end}}
      </div>
    </article>
    {{else}}
    <p class="dim">No calls in the window.</p>
    {{end}}
    {{if .Truncated}}<p class="gap">Showing the most recent {{.Window}} records of the trail.
    Older calls are not rendered.</p>{{end}}
  </div>
</div>
{{end}}
`)
