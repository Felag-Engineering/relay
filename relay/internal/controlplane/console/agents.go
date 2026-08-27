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
	Reads    int
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
		name := principalText(rec)
		a, seen := byAccount[name]
		if !seen {
			a = &acc{agentAccount: agentAccount{
				Name:     name,
				Verified: rec.Attribution.Verified.AccountID != "",
				Href:     "/console/agents?account=" + name,
			}}
			byAccount[name] = a
		}
		a.Calls++
		switch {
		case rec.Kind == audit.KindRead:
			a.Reads++
		case rec.Outcome == jobs.OutcomeDeniedByPolicy:
			a.Denied++
		}
		if rec.Kind == audit.KindDispatch && rec.ActionKind != "" && rec.OperationName == "" {
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
	c := agentCall{
		When:       rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Tool:       toolName(rec),
		Principal:  principalText(rec),
		Verified:   rec.Attribution.Verified.AccountID != "",
		OnBehalfOf: rec.Attribution.Asserted.OnBehalfOf,
		Selector:   rec.Selector,
		Args:       argsText(rec),
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
	c.Risk = RiskLabel(riskOf(rec))
	if rec.NodeID != "" {
		c.NodeHref = "/console/nodes/" + rec.NodeID
	}
	if rec.JobID != "" {
		c.JobHref = "/console/jobs/" + rec.JobID
	}
	if rec.Outcome == jobs.OutcomeDeniedByPolicy {
		c.Deny = &Deny{
			NodeID:        rec.NodeID,
			OperationName: operationText(rec),
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
func toolName(rec audit.Record) string {
	if rec.OperationName != "" {
		return "run_operation · " + rec.OperationName
	}
	if len(rec.RawExecArgv) > 0 {
		return "raw_exec"
	}
	switch rec.Kind {
	case audit.KindRead:
		return "read"
	case audit.KindApprovalRequested, audit.KindApprovalPendingObserved:
		return "parked for approval"
	case audit.KindApprovalDecided:
		return "approval decision"
	case audit.KindRefusal:
		return "refused"
	}
	if rec.ActionKind != "" {
		return rec.ActionKind
	}
	return rec.Kind
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
    <div class="ftitle">Accounts <span class="phint">active = a call in the last 15 minutes</span></div>
    {{range .Accounts}}
    <a class="arow{{if .Current}} on{{end}}" href="{{if .Current}}/console/agents{{else}}{{.Href}}{{end}}">
      <span class="dot" data-live="{{if .Active}}on{{else}}off{{end}}"></span>
      <span class="aname">{{template "trust-chip" (trust .Name .Verified)}}</span>
      <span class="astats"><b>{{.Calls}}</b> {{plural .Calls "call" "calls"}}{{if .Denied}} · {{.Denied}} denied{{end}}</span>
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
