package console

// components.go holds the Console's shared components (#419): the pieces that
// appear on three or more screens each, built once, specified in
// docs/design/console/00-foundations.md.
//
// Each one exists because getting it wrong on one screen and right on another
// is worse than either. The chip grammars in particular sit within 200px of
// each other on the approval card, and if they read as the same kind of thing
// there, an operator will read a caller's CLAIM as something the Relay
// verified.
//
// Everything here renders through html/template. Nothing assembles a string:
// these components interpolate Node names, label values, Policy rule text and
// daemon output, all of which are ultimately attacker-influencable — a
// compromised Node can put anything it likes in a `node:` label.

import (
	"errors"
	"fmt"
	"html/template"
	"sort"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// --- Label chips ------------------------------------------------------------

// Namespace is one of the four label namespaces (invariant 7, ADR-0020,
// ADR-0034). The namespace decides who may write a label and whether it is a
// valid security-lane target, so it is the most load-bearing thing about a
// chip.
type Namespace string

const (
	// NamespaceNode is node-rooted, set out-of-band via config management and
	// immutable to the Relay. A compromised Node can forge its own.
	NamespaceNode Namespace = "node"

	// NamespaceTag is operator-set through the control plane and immutable to
	// the Node. Ad-hoc grouping; never a valid security-lane target.
	NamespaceTag Namespace = "tag"

	// NamespaceRelay is Relay-set (enrollment-stamped, or admin + step-up) and
	// immutable to the Node. THE security lane — quarantine, remediation and
	// secret-distribution targeting must use this and only this.
	NamespaceRelay Namespace = "relay"

	// NamespaceState is derived by the Relay from the registry and set by
	// nobody at all, evaluated at Selector-resolution time from a closed
	// vocabulary. Routine targeting only.
	NamespaceState Namespace = "state"
)

// Label is one rendered label chip.
type Label struct {
	Namespace Namespace
	Key       string
	Value     string

	// Attention marks a `state:` label that is a reason an operator cannot act
	// on this Node right now — offline, outdated, certificate expiring.
	//
	// Foundations says "`state:` carries the tint of its severity behind its
	// mono prefix", and the severity is the whole informational content of the
	// chip: "this Node refuses every Task it is sent" and "this Node's template
	// set failed to load" are different problems with different urgencies, and
	// rendering them in one grey says they are the same problem.
	//
	// It is presentation and nothing takes a decision from it. The derivation
	// lives in nodestate, which is the one place `state:` is computed.
	Attention bool
}

// String renders the label in Selector syntax — `node:env=prod`, or
// `state:offline` for a bare marker.
//
// This is the same text an operator types into the fleet view's filter box,
// which is the point: browsing trains targeting, so a chip must read as
// something you could paste into a Selector.
func (l Label) String() string {
	term := string(l.Namespace) + ":" + l.Key
	if l.Value != "" {
		term += "=" + l.Value
	}
	return term
}

// SecurityLane reports whether this namespace may be targeted by the
// security lane (quarantine, remediation, secret distribution).
//
// Rendered as the chip's lock glyph, so the one namespace that can fence a
// Node looks different from the three that cannot. `state:` is excluded even
// though the Relay derives it, because it is computed partly from what the
// Node itself reports in Hello.
func (l Label) SecurityLane() bool { return l.Namespace == NamespaceRelay }

// --- Trust chips ------------------------------------------------------------

// Trust is a rendered identity chip: who the Relay says acted.
//
// The trust lane owns FILL VERSUS OUTLINE and nothing else, because the
// namespace lane already owns hue, glyph and the mono prefix, and the two
// appear within 200px of each other. A solid chip is an identity the Relay
// authenticated; a dashed one is caller-asserted and nothing checked it.
//
// A jailbroken AI-agent can assert anything it likes. It cannot forge the
// filled one, and the two must never read as equally authoritative.
type Trust struct {
	Text string

	// Verified is true when the Relay established this identity itself.
	Verified bool
}

// --- Segmented outcome bar --------------------------------------------------

// minSegmentPercent is the floor width of any non-zero outcome segment.
//
// This is the entire reason the component exists. At 10,000 Nodes, 14 denies
// are 0.14% of the bar — a sub-pixel sliver at any realistic width — and they
// are the ENTIRE REASON anyone is looking at the bar. A proportional bar is
// correct and useless; this one is deliberately non-proportional in the small,
// and the deviation table beside it carries the exact counts.
const minSegmentPercent = 2.5

// OutcomeCount is one outcome and how many Nodes reported it.
type OutcomeCount struct {
	Outcome jobs.Outcome
	Count   int
}

// Segment is one rendered piece of the bar.
type Segment struct {
	Outcome jobs.Outcome
	Count   int

	// Label is the outcome's wire name, e.g. "denied_by_policy".
	Label string

	// Percent is the TRUE share, for the tooltip and for screen readers.
	Percent float64

	// Width is the rendered share after the floor is applied. It is not the
	// truth and must never be presented as it — Percent is.
	Width float64

	// Grow is Width quantised to an integer flex weight, which is what the
	// template actually renders.
	//
	// It exists because of the content security policy. `style-src 'self'`
	// blocks INLINE STYLES, so the obvious `style="width:42.15%"` is not
	// merely non-conforming — the browser discards it and every segment paints
	// at zero. That is exactly what happened, and no Go test caught it: the
	// segment was in the HTML, and the assertion was that the segment was in
	// the HTML. It took a real browser enforcing the real policy to show that
	// the bar had never once been visible.
	//
	// So the width crosses into CSS as a data attribute matched by a
	// pre-generated rule (see .oseg[data-grow] in console.css). Quantising
	// costs nothing real: this bar is already deliberately non-proportional
	// because of the minority floor, and the exact counts live in the key
	// beneath it, which is the truth. Using flex-grow rather than a width also
	// makes the row fill exactly, so rounding cannot leave a gap.
	Grow int
}

// growSteps is the flex-weight resolution: 40 steps over the bar, so one step
// is 2.5% — exactly minSegmentPercent. The floor the bar guarantees is
// therefore one step, the smallest weight growWeight returns, so a floored
// segment is always drawn at least one step wide; it also means Grow alone
// cannot distinguish a floored segment from a clamped one — the floor is a
// property of Width. The stylesheet carries 40 rules, one per step
// (.oseg[data-grow] in console.css); keep the two in step. Coarser is fine:
// the bar is deliberately non-proportional and the exact counts live in the
// key.
const growSteps = 40

// OutcomeBar is a rendered segmented bar.
type OutcomeBar struct {
	Total    int
	Segments []Segment
}

// NewOutcomeBar builds a bar from raw counts, applying the minority floor.
//
// Every non-zero outcome gets at least minSegmentPercent of the width, and the
// remainder is shared proportionally. Zero-count outcomes are dropped entirely
// rather than rendered empty: an outcome nobody reported is not a fact about
// this Job, and a bar full of hairlines teaches an operator to ignore
// hairlines.
func NewOutcomeBar(counts []OutcomeCount) OutcomeBar {
	total := 0
	nonZero := 0
	for _, c := range counts {
		if c.Count > 0 {
			total += c.Count
			nonZero++
		}
	}
	if total == 0 {
		return OutcomeBar{}
	}

	// With enough distinct outcomes the floor cannot be honoured at its
	// nominal size; shrink it rather than overflowing the bar. Eight outcomes
	// at 2.5% is 20%, so this only binds in pathological cases, but a
	// component that can render a 105%-wide bar is a component that will.
	floor := minSegmentPercent
	if f := 100.0 / float64(nonZero); floor > f {
		floor = f
	}
	remaining := 100.0 - floor*float64(nonZero)

	bar := OutcomeBar{Total: total}
	for _, c := range counts {
		if c.Count == 0 {
			continue
		}
		share := float64(c.Count) / float64(total)
		width := floor + remaining*share
		bar.Segments = append(bar.Segments, Segment{
			Outcome: c.Outcome,
			Count:   c.Count,
			Label:   jobs.OutcomeName(c.Outcome),
			Percent: share * 100,
			Width:   width,
			// Round up, never down, and never to zero: a segment that exists
			// must be visible. Rounding a single deny out of ten thousand down
			// to nothing would undo the floor the whole component is built
			// around.
			Grow: growWeight(width),
		})
	}
	// Sorted by the outcome enum, not by size: the order must be stable across
	// refreshes, or a live bar reshuffles under someone reading it (foundations
	// rule 6, live but stable).
	sort.SliceStable(bar.Segments, func(i, j int) bool {
		return bar.Segments[i].Outcome < bar.Segments[j].Outcome
	})
	return bar
}

// growWeight quantises a rendered width percentage to a flex weight in
// [1, growSteps]. It never returns zero for a segment that exists.
func growWeight(widthPercent float64) int {
	w := int(widthPercent*float64(growSteps)/100 + 0.5)
	if w < 1 {
		return 1
	}
	if w > growSteps {
		return growSteps
	}
	return w
}

// --- The deny block ---------------------------------------------------------

// DenyBoundary says which of the capability layer's two refusal framings this
// deny renders: the apply path (a Task was dispatched and the Node refused it)
// or a Policy preflight (the Node reports it WOULD refuse; nothing was
// dispatched). It exists so the Console SELECTS a framing and never AUTHORS
// one — the sentence is the capability layer's, one spelling for every adapter
// (invariant 10; refusal.go's rule 2).
//
// The zero value is deliberately not a path: BoundaryExplanation fails on it
// rather than returning "", so a block with no boundary text cannot render.
//
// What that does NOT buy, stated because the name suggests more than it does:
// it catches an UNSET boundary only. A Deny given the WRONG one — apply's
// past-tense "nothing executed" on a preflight verdict — renders silently and
// correctly-looking. Nothing here can catch that, and no test in this package
// does.
type DenyBoundary int

const (
	DenyBoundaryUnset DenyBoundary = iota
	DenyBoundaryApply
	DenyBoundaryPreflight
)

// Deny is the product's pitch rendered: one refusal, with the rule that made
// it, verbatim.
//
// A deny is NOT AN ERROR. It is the product working correctly, and it renders
// calm and informative — slate, never red. If a deny ever renders as a
// failure, the product is arguing against itself.
//
// An operator must get from "denied" to "I know exactly which file to change"
// without leaving the Console, and the Console must be visibly unable to make
// that change for them: the Relay has no code path that writes Policy to a
// Node (ADR-0002, invariant 2), so the second link drafts a rule to copy,
// never a button that applies one.
type Deny struct {
	NodeID string

	// What was asked for.
	OperationName string

	// Rule is the deciding rule, VERBATIM, as the daemon reported it. Rendered
	// in mono and never summarised — a paraphrased rule is a rule an operator
	// has to go and check.
	Rule string

	// RuleClipped says Rule was cut to a length bound before it got here, so
	// the block can say how much of it is shown.
	//
	// A rule is the daemon's stderr and a Node writes its own stderr, so a
	// screen that renders one per Node — Job detail lists up to 100 — renders
	// a Node-controlled string as many times. Verbatim is a promise about
	// FIDELITY, not about length: the bytes shown are exactly the bytes
	// reported, and the block says when there were more.
	RuleClipped bool

	// File and Line locate the rule in the Node's own Policy.
	File string
	Line int

	// PolicyHref links to this Node's effective Policy, read live from the
	// daemon's engine (never re-evaluated on the Relay, invariant 12).
	PolicyHref string

	// DraftRuleHref links to the Policy-fix screen (spec 07) pre-loaded with
	// this deny — one deny in, one minimal rule out.
	DraftRuleHref string

	// Boundary selects the capability layer's framing for this deny. It has no
	// usable zero value — see DenyBoundary. Note that it is a KEYED-literal
	// field like every other: omitting it compiles, and fails at render.
	Boundary DenyBoundary
}

// Location renders "file:line", or just the file when no line is known.
func (d Deny) Location() string {
	if d.File == "" {
		return ""
	}
	if d.Line <= 0 {
		return d.File
	}
	return fmt.Sprintf("%s:%d", d.File, d.Line)
}

// BoundaryExplanation is the Relay's framing of the boundary that refused this
// — the SAME BYTES the MCP and Control API adapters emit in
// refusal_explanation (capability/refusal.go). The Console renders it verbatim
// and adds nothing: a Console-specific sentence would be the third spelling
// the shared mapping exists to prevent, and the Console's real advantage over
// an MCP caller is expressed as affordances — PolicyHref, and DraftRuleHref
// once spec 07 is built — not as prose.
//
// It returns an error rather than "" so an unset Boundary aborts the render:
// renderScreen buffers and returns a 500 without a body byte, and logs the
// error (screen.go). The message is deliberately value-free — it reaches a log
// line, so anything interpolated here is logged.
func (d Deny) BoundaryExplanation() (string, error) {
	var text string
	switch d.Boundary {
	case DenyBoundaryApply:
		text = capability.RefusalExplanation(jobs.OutcomeDeniedByPolicy)
	case DenyBoundaryPreflight:
		text = capability.VerdictExplanation(capability.VerdictDeny)
	default:
		return "", errors.New("deny block built with no DenyBoundary")
	}
	// Unreachable today — both mappings return non-empty compile-time constants.
	// It catches a future refusal.go edit that empties either one, which would
	// otherwise reopen this issue silently.
	if text == "" {
		return "", errors.New("the capability layer returned no boundary explanation")
	}
	return text, nil
}

// --- The Plan renderer ------------------------------------------------------

// PlanVerdict is one Node's answer in a Plan.
type PlanVerdict struct {
	NodeID  string
	Allowed bool

	// Deny is set when Allowed is false and the daemon's engine explained
	// itself. Rendered as the deny block above.
	Deny *Deny
}

// Plan is a rendered Plan: what a dispatch WOULD do, before it does it.
//
// Plan-before-apply is foundations rule 4 and the mutating path is
// deliberately slower than the reading path. Once rendered, a Plan is PINNED
// and never reflows (rule 6): a human is reading it in order to decide, and a
// list that moves under them is a decision made about something else.
type Plan struct {
	// Selector as written, in the same syntax the fleet-view filter speaks.
	Selector string

	// SelectorNote fills the Selector's own SLOT — the same element, holding
	// prose instead of a Selector — when Selector is empty.
	//
	// It exists for one state: a Plan rendered for a Job that has ALREADY
	// been dispatched. A Job carries no Selector of its own — it lives in the
	// dispatch audit record, which the Job engine writes only after the
	// dispatch returns — so a running Job's Selector is not readable yet and
	// arrives at completion. Filling the slot rather than omitting it is what
	// keeps foundations rule 6 (a rendered Plan never reflows) true of the
	// BLOCK: one slot resolves, and nothing moves.
	SelectorNote string

	// Matched is how many Nodes the Selector resolved to; Cap is the
	// blast-radius cap for this risk class.
	//
	// Both are shown so the ARITHMETIC is visible. A cap that silently trims a
	// fan-out is a surprise at the worst possible moment; a cap you can see
	// coming is a control.
	Matched int
	Cap     int

	// RiskClass is `read` or `mutate`. Raw Exec always takes the mutate cap
	// (ADR-0012).
	RiskClass jobs.RiskClass

	// Hash is the plan hash, in mono. THIS is what an approval commits to —
	// not the prose above it — so it is rendered as the identity of the plan
	// rather than as a technical detail.
	//
	// EMPTY OMITS THE SLOT ENTIRELY. Only an approval retains a plan hash, so
	// a dispatch that was never gated has none, and rendering an empty hash —
	// or worse, some other identifier in its place — presents a thing an
	// operator is trained to compare.
	Hash string

	// Verdicts are the per-Node predictions. EMPTY OMITS THE "N would run · N
	// would be denied" LINE, because a Plan with no verdicts is a Plan that
	// predicted nothing: Job detail renders one for a dispatch that has
	// already happened, where "0 would run" would be a prediction nobody made.
	//
	// The consequence, stated because it is easy to trip over: a COMPOSED plan
	// whose Selector matched zero Nodes also renders no verdict line. If that
	// screen needs to say "0 would run" out loud, this type grows an explicit
	// Dispatched flag rather than the renderer guessing from the length of a
	// slice.
	Verdicts []PlanVerdict
}

// OverCap reports whether the Selector resolved to more Nodes than the cap
// allows.
func (p Plan) OverCap() bool { return p.Cap > 0 && p.Matched > p.Cap }

// AllowedCount and DeniedCount summarise the verdicts.
func (p Plan) AllowedCount() int { return p.countVerdicts(true) }
func (p Plan) DeniedCount() int  { return p.countVerdicts(false) }

func (p Plan) countVerdicts(allowed bool) int {
	n := 0
	for _, v := range p.Verdicts {
		if v.Allowed == allowed {
			n++
		}
	}
	return n
}

// --- The step-up modal ------------------------------------------------------

// StepUp is a re-authentication prompt.
//
// A session proves a human authorised the SESSION; step-up proves a human
// intended THIS ACTION. It is the reason ADR-0026 could give a browser an
// execution surface at all.
//
// Action is required and is the whole point: "confirm it is you" with no
// object is how people are trained to type their password into anything. The
// prompt must name what it is authorising, so a forged one has to lie about
// something the operator can check.
type StepUp struct {
	// Action is what is being authorised, in the operator's terms —
	// "Restart nginx on 412 Nodes", "Revoke node-7f2a".
	Action string

	// Detail is the consequence in one line, e.g. the plan hash, or the rung
	// on the incident ladder.
	Detail string

	// FormAction is where the confirmation posts. A step-up is a mutating
	// request like any other and carries the CSRF token.
	FormAction string
	CSRFToken  string

	// WindowText says how long the confirmation lasts, so an operator is not
	// surprised by being asked again. The window itself is file-only Relay
	// configuration that no Account can extend.
	WindowText string
}

// --- The Cancel control ------------------------------------------------------

// JobCancel is the Cancel control's rendered data (#595): a form that posts
// to one Job's cancel route, plus the CSRF token every Console POST needs.
// Its type lives in cancel.go, beside cancelJobAction, which is the only
// builder of Action; this doc lives here beside step-up because the two
// controls are compared on purpose below.
//
// Unlike [StepUp], Cancel carries no re-authentication: step-up exists for a
// mutate APPLY (ADR-0026), and Cancel is never that — it only asks something
// already running to stop, which is cheap to engage by design, the same
// asymmetry ADR-0013 gives the Freeze (engage cheap, release deliberate).
// There is nothing here to be careful granting, because Cancel can never
// make the fleet do more than it was already doing.
//
// A third paragraph, beside the two above, so the package does not quietly
// acquire two step-up idioms: the approval decision form (#453, decide.go
// and approvals.go's approvalDecideControl) deliberately does NOT use
// [StepUp], even though deciding an approval is exactly the kind of mutate
// release step-up exists for. StepUp models a STANDALONE confirmation — its
// own FormAction, one "Authorise" button, and a WindowText that assumes the
// recent-auth WINDOW model (spec 11), where a stale stamp triggers a
// separate prompt. The approval decision rejects that model outright (see
// decide.go's header: every decision costs its own password, the window is
// never consulted) and spec 08 item 5 asks for an INLINE field on the
// decision form itself, which must also carry two equal-weight answer
// buttons and a hidden plan hash — none of which [StepUp] can express, and a
// nested `<form>` is not valid HTML regardless. So the decision form carries
// its own password field, using the SAME field name, type and autocomplete
// as this component (`password`, `type="password"`,
// `autocomplete="current-password"`) so the two agree on the credential's
// shape even though they are two different forms. [StepUp]'s expected
// consumer remains the composer's standalone mutate apply (#438); it is not
// dead by accident.

// --- Pin to compare ---------------------------------------------------------

// The pin bar's type is pinState in compare.go, beside the builder that
// resolves each pinned id against the registry. Only the MARKUP is here, and
// it is here for the reason at the top of this file: the bar is on three
// screens (fleet, node detail, comparison), and the first version of it was
// duplicated in three templates and had already diverged — the comparison
// screen's "pick another from the fleet" link dropped the pin set, on the one
// screen whose whole purpose is adding a third Node.

// --- Rendering --------------------------------------------------------------

// --- The live region --------------------------------------------------------

// Live is the shell's live-region component (spec 11 line 113 — "incoming
// events for a region a user is reading queue behind an explicit control.
// Build it once").
//
// It is built once because day one built the transport half in its own script
// file and #422 was going to inherit whatever shape that took. Two copies of a
// reconnect loop is two backoff policies, and the second one is the one nobody
// looks at again.
//
// What the client is allowed to do to this region is exactly three things:
// set data-live, set data-queued, and write a number into the queue counter's
// textContent. EVERY WORD HERE IS SERVER-RENDERED — the states are sibling
// elements selected by data-live in CSS, so the script file carries behaviour
// and no product language at all (dayone.js's rule 2).
type Live struct {
	// Wired is whether the event seam exists AND this view has something live
	// to show. The component renders NOTHING when it is false, deliberately:
	// day one's off-state sentence ("Live updates are not available on this
	// Relay") is day one's, and it would be FALSE on a screen whose live lane
	// is off merely because the current filter has no live kind in it. A
	// region that explains itself wrongly is worse than an absent one.
	Wired bool

	// Endpoint is the SSE URL, including its ?kinds=. Read by the client from
	// a data attribute, because no inline script means no server-injected
	// variables (dayone.js's rule 3).
	Endpoint string

	// LastEventID is the resume point: the newest retained event the server
	// already accounted for, so the stream picks up exactly where the render
	// stopped.
	LastEventID string

	// ShowHref is where the explicit queue control leads — the current view,
	// re-fetched. Reloading the region rather than splicing is what makes
	// "one renderer" structural: the client cannot build a row, because
	// building one is not something this component lets it do.
	ShowHref string

	// CountNote says what the counter actually counts. It is a parameter and
	// not fixed copy because the honest sentence is screen-specific, and the
	// honest sentence matters: the live lane is NOT filtered by the view's
	// filter and one Job announces itself more than once, so a counter
	// presented as "rows that will appear" would be wrong twice over.
	CountNote string
}

// componentsTmpl holds every shared component as a named template. Screens
// invoke them with {{template "..." .}} rather than reimplementing any of them.
var componentsTmpl = template.Must(template.New("components").Funcs(template.FuncMap{
	// pct renders a width with one decimal place. A template cannot format a
	// float without help, and the alternative — formatting in Go and passing
	// strings — would put presentation in the component's type.
	"pct": func(f float64) string { return fmt.Sprintf("%.2f", f) },
	// risk renders a risk class as its wire name. Named here rather than
	// precomputed onto Plan so the template reads as the contract does:
	// every Operation declares a risk class (ADR-0012), and the class is what
	// chooses the cap.
	"risk": jobs.RiskClassName,
}).Parse(`
{{define "label-chip"}}<span class="chip lbl" data-ns="{{.Namespace}}"{{if .SecurityLane}} data-lane="security"{{end}}{{if .Attention}} data-sev="attention"{{end}} title="{{.}}"><span class="ns">{{.Namespace}}:</span>{{.Key}}{{if .Value}}<span class="eq">=</span>{{.Value}}{{end}}</span>{{end}}

{{/* kind-label is the word human or machine drawn after a trust chip
     (00-foundations.md, "Kind label"). It is NOT a chip: no pill, no fill, no
     border, so it can never be read as either trust lane. The value is drawn
     only when it is one of the two words a record can hold; anything else,
     including the empty string of a record with no kind, renders nothing
     rather than a guess. Callers pass what the RECORD says (the Job row's
     requester_kind, a Decision's DeciderHuman) and never the Account
     registry's current kind (#540) — except the Accounts screen, whose
     subject is the Account as it is now. */}}
{{define "kind-label"}}{{if or (eq . "human") (eq . "machine")}} <span class="kind" data-kind="{{.}}">{{.}}</span>{{end}}{{end}}

{{define "trust-chip"}}<span class="chip trust" data-trust="{{if .Verified}}verified{{else}}asserted{{end}}" title="{{if .Verified}}The Relay authenticated this identity.{{else}}The caller claimed this. Nothing checked it.{{end}}">{{.Text}}</span>{{end}}

{{define "outcome-bar"}}<div class="obar" role="img" aria-label="{{.Total}} Nodes: {{range .Segments}}{{.Count}} {{.Label}}. {{end}}">
  {{range .Segments}}<span class="oseg" data-outcome="{{.Label}}" data-grow="{{.Grow}}" title="{{.Count}} {{.Label}} ({{pct .Percent}}%)"></span>{{end}}
</div>
<div class="okeys">{{range .Segments}}<span class="okey" data-outcome="{{.Label}}"><b>{{.Count}}</b> {{.Label}}</span>{{end}}</div>{{end}}

{{define "deny-block"}}<div class="deny">
  <div class="denyhead"><span class="chip outcome" data-outcome="denied_by_policy">denied by Policy</span>
    {{with .OperationName}}<span class="denyop">{{.}}</span>{{end}}
    {{with .NodeID}}<span class="denynode">on {{.}}</span>{{end}}</div>
  <pre class="denyrule">{{.Rule}}</pre>
  {{if .RuleClipped}}<p class="denynote">Shown to the first 2 KB of the refusal the daemon reported.</p>{{end}}
  {{with .Location}}<div class="denyloc">{{.}}</div>{{end}}
  <div class="denylinks">
    {{with .PolicyHref}}<a href="{{.}}">See this Node&#39;s effective Policy</a>{{end}}
    {{with .DraftRuleHref}}<a href="{{.}}">Draft the rule that would allow this</a>{{end}}
  </div>
  <p class="denynote">{{.BoundaryExplanation}}</p>
</div>{{end}}

{{define "plan"}}<section class="plan" aria-label="Plan">
  <div class="planhead">
    <span class="chip risk" data-risk="{{.RiskClass | risk}}">{{.RiskClass | risk}}</span>
    {{if .Hash}}<code class="planhash" title="This is what an approval commits to.">{{.Hash}}</code>{{end}}
  </div>
  <div class="planfan">
    <code class="selector">{{if .Selector}}{{.Selector}}{{else}}{{.SelectorNote}}{{end}}</code>
    <span class="fanmath">{{.Matched}} Nodes matched{{if .Cap}} &middot; cap {{.Cap}}{{end}}</span>
    {{if .OverCap}}<span class="overcap">over the {{.RiskClass | risk}} cap &mdash; this Job will not dispatch</span>{{end}}
  </div>
  {{if .Verdicts}}<div class="planverdicts"><b>{{.AllowedCount}}</b> would run &middot; <b>{{.DeniedCount}}</b> would be denied</div>{{end}}
  {{range .Verdicts}}{{if .Deny}}{{template "deny-block" .Deny}}{{end}}{{end}}
</section>{{end}}

{{define "live-region"}}{{if .Wired}}<section class="live" data-live-region data-live="down"
         data-events="{{.Endpoint}}" data-last-event-id="{{.LastEventID}}">
  <div class="livehead">
    <span class="pulse" aria-hidden="true"></span>
    <span class="wmsg" data-when="on">Live.</span>
    <span class="wmsg" data-when="down">The live stream is not connected.</span>
    <span class="wmsg" data-when="gap">The live stream fell behind &mdash; reloading.</span>
    <span class="wmsg" data-when="ended">The live stream has stopped. Your session may have ended;
    reload the page to sign in again.</span>
    <a class="newq" href="{{.ShowHref}}" aria-live="polite">New events on the stream:
    <b id="live-new-count">0</b> &mdash; reload</a>
  </div>
  {{with .CountNote}}<p class="livenote">{{.}}</p>{{end}}
</section>{{end}}{{end}}

{{define "pin-bar"}}<div class="pinbar">
  <span class="pinlbl">Pinned</span>
  {{range .Pins}}<span class="pinchip">
    {{if .Known}}<a href="{{.Href}}"><code>{{.ID}}</code></a>
    {{else}}<code class="dim">{{.ID}}</code><span class="dim" title="A pinned id is whatever the link carried; the Relay resolves each one against the registry.">not in this registry</span>{{end}}
    <a class="unpin" href="{{.UnpinHref}}">unpin</a></span>{{end}}
  {{with .CompareHref}}<a class="act" href="{{.}}">Compare these Nodes</a>{{end}}
  {{with .FleetHref}}<a href="{{.}}">Pick another from the fleet</a>{{end}}
  {{if .Full}}<span class="dim">Three is the maximum &mdash; unpin one to pin another.</span>{{end}}
</div>{{end}}

{{define "step-up"}}<form class="stepup" method="post" action="{{.FormAction}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <h2>Confirm: {{.Action}}</h2>
  {{with .Detail}}<p class="stepupdetail">{{.}}</p>{{end}}
  <label for="stepup-password">Re-enter your password to authorise this</label>
  <input id="stepup-password" name="password" type="password" autocomplete="current-password" required>
  {{with .WindowText}}<p class="stepupwindow">{{.}}</p>{{end}}
  <button type="submit">Authorise</button>
</form>{{end}}

{{define "job-cancel"}}<form class="jobcancel" method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button type="submit">Cancel</button>
  <span class="jcnote">Cancel stops this Job&#39;s in-flight Tasks and nothing future; the incident ladder is for that.</span>
</form>{{end}}
`))
