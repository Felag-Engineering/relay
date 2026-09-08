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
//
// # This screen now reads the audited lane (#542)
//
// It used to read the whole trail through AuditReader.List, capped at a
// 200-record WINDOW (auditWindow) and filtered in Go by isAgentCall. Both are
// gone: the lane's Kinds filter (agentCallKinds) does the filtering in SQL, so
// what comes back is exactly this screen's rows rather than a window spent
// partly on login/token/freeze records this screen was going to discard
// anyway, and a 200-row PAGE with an Older link replaces a 200-record window
// with none. See handleAgents and buildAgents below.

import (
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// activeWindow is how recently an Account must have acted to count as active.
// Fifteen minutes, per spec 03 — long enough that an agent thinking between
// calls does not blink out, short enough that "active" means something.
const activeWindow = 15 * time.Minute

// agentsPageSize is this screen's page size, replacing auditWindow at the
// same number (200) deliberately: the only change an operator sees is that
// the note becomes true and an Older link exists where the trail has more.
// A 200-row PAGE is strictly more content than the old 200-record window —
// the kind filter now runs in SQL, so no row is spent on a login, a token
// mint or a Freeze transition only to be discarded by isAgentCallKind.
const agentsPageSize = 200

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

	// Reason is the Relay-AUTHORED sentence an approval-family record
	// carries. It is set for the approval family and for nothing else —
	// see agentCallFrom.
	Reason string

	ReadClass bool
}

type agentsView struct {
	Accounts []agentAccount
	Calls    []agentCall
	Account  string

	// PageSize is agentsPageSize, rendered in the position-aware note below.
	PageSize int

	// Older says there is a further, older page beyond this one (pg.Next !=
	// ""). OlderHref is drawn only when this is true (1h) — an unconditional
	// link would loop forever the moment a page ran out, the bug lanePos was
	// introduced for on Activity.
	Older     bool
	OlderHref string

	// Scrolled says THIS page was reached by following Older — i.e. the
	// request carried a cursor. It is a different question from Older above
	// (whether there is somewhere further to go) and drives the sentence that
	// makes the note honest under paging: a scrolled page must never claim to
	// hold the most recent calls, and its rail counts only the Accounts on
	// it, not the fleet's.
	Scrolled   bool
	NewestHref string
}

func handleAgents(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The read lane takes a capability.Principal, exactly as Activity and
		// node detail do. Both are context reads; page() resolves the same
		// principal itself for the shell.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Agents")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audit and Job query lane")
			return
		}
		// Every read this page makes goes through the latch: the "a page
		// whose read cannot be audited is not served" rule is one call rather
		// than a branch per read (screen.go).
		d, lane := latched(d)

		account := r.URL.Query().Get("account")
		// An unparseable cursor is NOT reset to page one — that would be a
		// silent "start over" for a caller who asked to go further, which is
		// the same class of lie a truncated trail would tell. It is instead
		// capability.ErrInvalidCursor from the lane, which readFailed below
		// renders as a legible refusal.
		cursor := r.URL.Query().Get("cursor")

		// ONE call. The rail below and the stream both derive from this SAME
		// page — see buildAgents' doc comment for why that is a stated
		// property of the screen and not an implementation convenience.
		pg, err := d.Queries.QueryAudit(r.Context(), caller,
			capability.AuditFilter{Kinds: agentCallKinds},
			capability.PageRequest{Limit: agentsPageSize, Cursor: cursor})
		if err != nil {
			readFailed(w, err, "the agent call trail")
			return
		}
		if refusedUnaudited(w, lane, "the agent call trail") {
			return
		}

		v := agentsView{
			Account:  account,
			PageSize: agentsPageSize,
			Scrolled: cursor != "",
		}
		v.Accounts, v.Calls = buildAgents(pg.Rows, account, d.now())
		if pg.Next != "" {
			v.Older = true
			v.OlderHref = agentsHref(account, pg.Next)
		}
		if v.Scrolled {
			v.NewestHref = agentsHref(account, "")
		}
		renderScreen(w, p, agentsTmpl, v)
	}
}

// agentsHref builds a /console/agents link preserving ?account=, the same
// url.Values idiom the rail's own Href uses (#467): html/template's URL
// normaliser leaves & # = alone, so concatenating an Account name with
// reserved characters into a query string silently links to the wrong
// Account or drops the cursor.
func agentsHref(account, cursor string) string {
	v := url.Values{}
	if account != "" {
		v.Set("account", account)
	}
	if cursor != "" {
		v.Set("cursor", cursor)
	}
	if len(v) == 0 {
		return "/console/agents"
	}
	return "/console/agents?" + v.Encode()
}

// buildAgents rolls one fetched page up per Account and renders the call
// stream.
//
// rows arrive NEWEST FIRST and PRE-FILTERED by the lane's Kinds filter
// (agentCallKinds, handleAgents) — there is deliberately no per-row
// isAgentCallKind test and no re-filter by kind here. A defensive re-filter
// would silently mask a mutation that dropped the Kinds filter from the
// query: the filtering is the lane's job now, done once in SQL, and this
// function trusts what it was handed rather than checking it twice.
//
// ONE QueryAudit call feeds both what this function returns: the rail's
// counts are computed over exactly the rows the stream below renders, so the
// rail's "3 mutate" is by construction the number of rows below it chipped
// mutate, and an operator can verify the rail by scrolling THIS page. A
// design that sourced the rail from a separate aggregate and the stream from
// a page would make that sentence false the first time the two queries ran
// at different moments.
func buildAgents(rows []capability.AuditRow, account string, now time.Time) ([]agentAccount, []agentCall) {
	type acc struct {
		agentAccount
		last time.Time
	}
	byAccount := map[string]*acc{}
	var calls []agentCall

	for _, row := range rows {
		f := factsOfRow(row)
		name := principalText(f)
		a, seen := byAccount[name]
		if !seen {
			a = &acc{agentAccount: agentAccount{
				Name:     name,
				Verified: row.Verified.AccountID != "",
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
		if row.Outcome == jobs.OutcomeDeniedByPolicy {
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
		// role gate REFUSED, a dispatch still PARKED for approval, one Policy
		// DENIED, and a mutate-shaped call PLANNED and never run. None of those
		// changed a Node, and the count still includes them, because this
		// screen is the request and never the result ("as the Relay received
		// it", above) and the rail's other counters already read that way —
		// Denied is a subset of Calls, not a column beside it. On a trust
		// surface an attempted mutate is the signal: a compromised agent
		// probing a fleet and being refused every time must not read quieter
		// than an honest one. What actually RAN is Activity's question, at Job
		// grain, where an outcome means something.
		//
		// The outcome chip on each row is what separates asked from ran, and it
		// is on the same screen — which is the other half of why the count is
		// derived this way rather than filtered down to executed dispatches:
		// two numbers on one screen disagreeing about one record is the drift
		// riskOf exists to prevent (#463).
		//
		// There is deliberately no read counter beside it. Spec 03 does not ask
		// the rail for one, riskOf answers read or mutate and nothing else — so
		// reads are Calls minus Mutates — and a third number an operator has to
		// reconcile with the other two buys nothing.
		//
		// A cancel counts here too, through the same one inference: riskOf
		// finds no argv, no read tool and no read Operation on the record and
		// answers mutate. That is the right answer for the right reason — a
		// cancel kills a process group on a Node (ADR-0013) and is nobody's
		// idea of a read — rather than the safe-direction default falling the
		// convenient way, which is worth saying out loud because the two are
		// indistinguishable in the code.
		if riskOf(f) == jobs.RiskClassMutate {
			a.Mutates++
		}
		if f.Timestamp.After(a.last) {
			a.last = f.Timestamp
		}

		if account == "" || account == name {
			calls = append(calls, agentCallFrom(f))
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
	return out, calls
}

// isAgentCallKind reports whether an audit Kind describes a call somebody
// made THROUGH a control surface, as opposed to something the Relay did.
//
// It is the SOURCE of this screen's lane filter (agentCallKinds below), not a
// per-row test any more: #542 moved this screen onto the read lane, whose
// Kinds filter does the selecting in SQL, so isAgentCallKind now runs once
// per audit Kind at var-init instead of once per row at render time. A kind
// added to internal/audit is classified by this predicate exactly as before;
// what changed is WHEN it runs, not what it decides.
//
// Sign-ins, Freeze transitions and Account changes are control-plane events
// and belong on Activity. An approval expiring is the clock, not a caller.
//
// # Why two of the eight tools are admitted by KIND rather than by family
//
// `cancel_job` and plan mode matched neither arm and so rendered NOWHERE,
// against spec 03's first acceptance criterion — every one of the eight tools
// renders with a request line and a result line (#537). Both are calls in
// exactly the sense this function means: an Account asked a control surface for
// something and the Relay recorded the ask. A cancel is the one act spec 03
// puts a CONTROL for on this very screen, so its record belonging here is not a
// stretch; and plan mode is the trust-critical case spec 03 asks to be badged —
// an agent saying what it would run is the request an operator most wants read.
//
// They are named as KINDS because kindOf (activity.go) maps both to rowOther,
// and rowOther is not theirs to take: it is Activity's catch-all, the family
// every audit kind nobody has classified yet falls into, so admitting it
// wholesale would put a kind added to internal/audit next month on the trust
// surface with nobody having decided it belonged. Promoting the two to
// families of their own is the other way to spell this, and it reaches past
// this screen — the row kind drives Activity's filter chips and decides which
// rows Activity draws a risk chip on. Narrower change, same result here.
func isAgentCallKind(kind string) bool {
	switch kind {
	case audit.KindJobCancel, audit.KindPlan:
		return true
	}
	switch kindOf(kind) {
	case rowDispatch, rowRead, rowRefusal, rowApproval:
		return kind != audit.KindApprovalExpired
	default:
		return false
	}
}

// agentCallKinds is this screen's lane filter, DERIVED from audit.Kinds()
// through isAgentCallKind rather than hand-listed — the same derived-not-
// enumerated shape buildKindsByFamily (activity.go) uses. Deriving it means
// the filter and the predicate cannot drift, and a kind added to
// internal/audit is classified by isAgentCallKind rather than by a second
// hand-kept list nobody remembers to update.
//
// Eight kinds today, against AuditFilter.validate's cap of 32.
// approval_expired stays excluded exactly as isAgentCallKind decides.
var agentCallKinds = buildAgentCallKinds()

func buildAgentCallKinds() []string {
	var out []string
	for _, k := range audit.Kinds() {
		if isAgentCallKind(k) {
			out = append(out, k)
		}
	}
	return out
}

func agentCallFrom(f trailFacts) agentCall {
	c := agentCall{
		When:       f.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Tool:       toolName(f),
		Principal:  principalText(f),
		Verified:   f.VerifiedAccountID != "",
		OnBehalfOf: f.OnBehalfOf,
		Selector:   f.Selector,
		Args:       argsText(f),
		NodeID:     f.NodeID,
		Outcome:    OutcomeLabel(f.Outcome),
		JobID:      f.JobID,
		ReadClass:  f.Kind == audit.KindRead,
	}
	// The risk class comes from ONE inference (vocab.go), not from the record
	// kind. Deriving it here from `Kind == KindDispatch` labelled file.read as a
	// mutate and a parked raw_exec as a read — the second of which is the most
	// misleading thing this Console could say, since Raw Exec always takes the
	// mutate cap without exception.
	c.Risk = RiskLabel(riskOf(f))
	if f.NodeID != "" {
		c.NodeHref = "/console/nodes/" + f.NodeID
	}
	if f.JobID != "" {
		c.JobHref = "/console/jobs/" + f.JobID
	}
	if f.Outcome == jobs.OutcomeDeniedByPolicy {
		c.Deny = &Deny{
			NodeID:        f.NodeID,
			OperationName: operationText(f),
			// denyRuleOffLane, not denyExplanation: this screen's rows are
			// capability.AuditRow, which carries no Stderr (vocab.go) — see
			// its doc comment for why that is deliberate and permanent.
			Rule:       denyRuleOffLane(f),
			PolicyHref: "/console/nodes/" + f.NodeID,
		}
	}
	// Reason is rendered ONLY for the approval family: every other kind's
	// Args/Selector/NodeID/JobID already carries its content, and
	// denyRuleOffLane (vocab.go) already falls back to f.Reason when the
	// daemon's verdict is not on this lane — an unconditional render here
	// would print the same sentence twice on a denied_by_policy row. The
	// approval family is exactly the set of rows that render nothing else at
	// all.
	if kindOf(f.Kind) == rowApproval {
		c.Reason = f.Reason
	}
	// A record with no per-Node outcome renders the zero value as
	// "unspecified" — which reads as "we don't know" for an event whose
	// disposition is perfectly well known. Name what actually happened.
	//
	// Two families arrive here, not one. Most never reached a Node at all (a
	// park, a refusal, a metadata-only read). A cancel is the other: it does
	// reach Nodes, but it is not a per-NODE act — it targets a Job by ID, so
	// there is no verdict to render however far it travelled.
	switch f.Kind {
	case audit.KindRead:
		// A metadata-only read is the case this switch was written for and did
		// not cover: no Node was asked anything, so the chip rendered
		// "unspecified" over a record whose whole content is known (#517). The
		// word is chosen and justified at readOutcomeAudited (vocab.go).
		c.Outcome = readOutcomeAudited
	case audit.KindRefusal:
		c.Outcome = "refused"
	case audit.KindApprovalRequested:
		c.Outcome = "parked"
	case audit.KindApprovalPendingObserved:
		c.Outcome = "already parked"
	case audit.KindApprovalDecided:
		// Only RevokeGrant writes a decided record carrying a GrantID
		// (capability/approval_grant.go). DecideApproval never sets one, so
		// this is a STRUCTURAL discriminator, not a guess. A revocation is
		// not a Decision at all in the glossary's sense — nobody answered a
		// parked Job — so "decided" over it is a category error the record
		// itself disproves.
		c.Outcome = "decided"
		if f.GrantID != "" {
			c.Outcome = "revoked"
		}
	case audit.KindJobCancel:
		// A cancel has no per-Node verdict either: RecordCancel records who
		// asked and which Job, and the per-Task truth is on the Job's own
		// Tasks (OutcomeCancelled, ADR-0013) — which this row already links
		// to, so the chip does not have to carry it.
		//
		// The word is "requested", and the obvious alternative is the trap.
		// "cancelled" is a TASK outcome word (OutcomeLabel) and, on a row that
		// names a Job, it claims that Job's fate. Cancellation is best-effort
		// and honest: a Task that already finished reports its real outcome
		// and is never retroactively cancelled (ADR-0013, CONTEXT.md), so a
		// mostly-finished Job would render as cancelled on the one screen
		// billed as what the agent actually asked for. "stopped", "aborted"
		// and "killed" are CONTEXT.md's rejected synonyms for Cancellation and
		// are not available at any price.
		//
		// "requested" says the one thing the record does carry, and carries
		// honestly: the stop was asked for. It is not a hedge — CancelJob
		// writes this row only AFTER the cancel itself succeeded, and records
		// nothing at all when it fails (capability/service.go) — so an ask
		// that reached the trail is an ask that landed. What each Task then
		// did is one click away.
		c.Outcome = "requested"
	case audit.KindPlan:
		// Live since #537. Plan records were filtered out of this screen by
		// isAgentCall, which left this arm unreachable from buildAgents: the
		// corrective switch named the case and nothing could enter it.
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
// # A cancel names its tool; a Plan names the tool it planned
//
// RecordCancel writes no Action at all — no Operation, no argv, not even an
// ActionKind (auditsink.go) — so a cancel reaches the Kind switch at the
// bottom, where it used to fall past every arm and render as the bare audit
// kind `job_cancel`. That is audit's internal spelling of the record, not
// something an operator can find on the tool surface, and it is the reason
// this screen was billed as showing eight tools while showing seven. It
// renders as `cancel_job`: the tool that was called, in the same vocabulary
// the read rows get from readTargetOf (`get_job`, `list_nodes`) and the
// dispatch rows get from `run_operation`. Activity calls the same record
// "cancelled Job 9d41" in prose and carries no Operation for it, so this is
// that sentence's tool-cell spelling rather than a second name for one record.
//
// A Plan needs NO arm here, and that is a decision rather than an omission.
// Plan mode is `plan: true` on run_operation / raw_exec and not a ninth tool
// (spec 03), and its record carries the same Action fields a dispatch does
// (auditsink's baseRecord), so it falls through the two branches above and
// renders `run_operation · service.restart` or `raw_exec` — which is what was
// called. That it never ran is the OUTCOME chip's job ("planned",
// agentCallFrom), which is exactly how Activity keeps the same two facts
// apart: `operationText` names the Operation and the summary says nothing
// executed.
//
// It takes trailFacts rather than an audit.Record because every field it reads
// is on the shared projection, and its caller has already built one — a second
// projection per row is a second place the two could disagree.
//
// # A decision row cannot be named "approve_request", and this is not an oversight
//
// audit.KindApprovalDecided covers THREE acts, not one: the MCP tool
// `approve_request` (mcp/tools_approval.go, ChannelInBand), the Control API's
// `POST /api/v1/approvals/{id}/decision` (api/approvals.go, ChannelOutOfBand),
// and `POST /api/v1/approval-grants/{id}/revoke` (capability/approval_grant.go).
// ADR-0027's whole point is that the Control API decision is the primary,
// stronger channel and the MCP tool is ADR-0029's weaker in-band shim — yet
// the first two write the IDENTICAL AuditKindApprovalDecided entry through the
// same capability.Service.DecideApproval, with no structured field
// distinguishing them. The Channel that tells them apart lives only inside the
// prose Reason ("… over out-of-band …"); it is on neither capability.AuditEntry
// nor audit.Record nor the audit table. Attribution.Verified.Method is the
// credential type and .Source is a peer address — neither names the surface.
//
// So returning "approve_request" here — for either DecideApproval channel —
// would label a Control API decision as an MCP tool that was never called,
// the same class of error #463/#517 already fixed elsewhere on this screen,
// committed fresh in this one. GrantID IS a reliable, structural discriminator
// (only RevokeGrant sets it), which is why that arm below returns a different
// string and this one does not. A decision row therefore names the ACT —
// "approval decision", CONTEXT.md's Decision — and never the MCP tool name.
// Do not "fix" this to `approve_request`.
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
		// GrantID is set ONLY by RevokeGrant (capability/approval_grant.go) —
		// a structural discriminator, not a guess. See the doc comment above
		// for why the other branch stays "approval decision" and must never
		// become "approve_request".
		if f.GrantID != "" {
			return "revoke approval grant"
		}
		return "approval decision"
	case audit.KindJobCancel:
		return "cancel_job"
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

<div class="agentcols">
  <aside class="agentrail">
    <div class="ftitle">{{if .Scrolled}}Accounts on this page{{else}}Accounts{{end}} <span class="phint">active = a call in the last 15 minutes · mutate counts what was asked, refused, parked and planned included · counted over the calls on this page</span></div>
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
        {{with .Reason}}<div class="evreason">{{.}}</div>{{end}}
        {{if .ReadClass}}<div class="evnote">The call is audited; the result is not retained.</div>{{end}}
      </div>
    </article>
    {{else}}
    <p class="dim">No calls on this page.</p>
    {{end}}
    {{if .Scrolled}}
    <p class="gap">These are NOT the most recent calls — this page was reached by following
    Older. <a href="{{.NewestHref}}">Newest</a>{{if .Older}} · <a href="{{.OlderHref}}">Older</a>{{end}}.</p>
    {{else if .Older}}
    <p class="gap">Showing the most recent {{.PageSize}} calls. There are older calls.
    <a href="{{.OlderHref}}">Older</a>.</p>
    {{end}}
  </div>
</div>
`)
