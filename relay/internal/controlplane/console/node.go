package console

// node.go is everything Relay knows about one machine (spec 02), and the one
// page in the Console where Facts appear.
//
// # Why Facts are confined to this page
//
// OS, kernel, arch, hostname and IP are self-reported by the daemon, and a
// compromised Node can report whatever it likes. That is tolerable on a detail
// page a human is reading about one machine and intolerable as a targeting axis:
// a fleet-wide `os=ubuntu` filter that a Node can opt itself into is a fleet-wide
// filter an attacker can opt into. Targeting is on labels, whose namespaces have
// enforced writers (invariant 7).
//
// The panel is labelled so an implementer does not later "helpfully" surface a
// Fact on a fleet row. If you are reading this because you were about to: that
// is the thing this file exists to prevent.
//
// # The effective-Policy panel
//
// It renders what the Node's own engine REPORTED (policyview, ADR-0011), stamped
// with when. The Relay never evaluates Policy (invariant 12) and never writes it
// (ADR-0002, invariant 2), and the panel says both out loud — not as a
// disclaimer, but because "read-only" here is structural: there is no code path
// from this screen to a Node's Policy file, and an operator who does not know
// that will go looking for the edit button and conclude the product is broken
// when they cannot find it.

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// nodeTaskRows bounds the recent-Task list. Node detail is a page about one
// machine, not its whole history — the Activity screen is where history is
// read, filtered.
const nodeTaskRows = 40

type nodeFact struct{ Key, Value string }

type nodeTask struct {
	When      string
	Operation string
	Args      string
	Outcome   string
	JobID     string
	JobHref   string
	Principal string
	Verified  bool

	// Denied carries the deny block when Policy refused this Task. It is the
	// most informative row on the page and is never styled as a failure.
	Denied *Deny

	// RepeatDeny marks a deny whose rule was already explained further up the
	// list. The row keeps its outcome chip; only the duplicated prose is
	// dropped.
	RepeatDeny bool

	// ReadClass marks a row whose output was deliberately not retained
	// (ADR-0025). Said on the row, because an operator looking for output that
	// is not there needs to know it was never kept rather than lost.
	ReadClass bool
}

type nodeView struct {
	ID       string
	Hostname string

	Connected   bool
	LastSeen    string
	LastSeenAbs string
	Revoked     bool
	RevokedAt   string

	States []Label
	Labels []Label

	CertFingerprint string
	EnrollingToken  string
	DaemonVersion   string
	// CertProvenanceKnown is false until the registry records certificate
	// validity (#440). The panel then says what it does NOT know rather than
	// omitting the rows, because a missing "expires" row reads as "fine".
	CertProvenanceKnown bool

	PolicyFingerprint   string
	TemplateFingerprint string
	TemplateUnloadable  bool
	// PolicyShared and TemplateShared are how many Nodes in the fleet report the
	// same fingerprint. That comparison is the whole value of a fingerprint:
	// confirming a rollout landed is string equality, not trust.
	PolicyShared   int
	TemplateShared int

	Facts []nodeFact

	Policy         *policyview.Snapshot
	PolicyReported bool

	Tasks       []nodeTask
	TasksElided bool
	AuditWired  bool
}

func handleNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Fleet == nil {
			unavailable(w, "the Node registry")
			return
		}
		nodeID := r.PathValue("node_id")
		n, ok := d.Fleet.Get(nodeID)
		if !ok {
			p, ok := page(d, w, r, "Node not found")
			if !ok {
				return
			}
			p.Banner = banner(d, r)
			w.WriteHeader(http.StatusNotFound)
			renderScreen(w, p, nodeMissingTmpl, nodeID)
			return
		}

		p, ok := page(d, w, r, shortHash(n.NodeID))
		if !ok {
			return
		}
		p.Banner = banner(d, r)
		renderScreen(w, p, nodeTmpl, buildNodeView(d, r, n))
	}
}

func buildNodeView(d Deps, r *http.Request, n registry.Node) nodeView {
	connected := d.Liveness != nil && d.Liveness.Connected(n.NodeID)
	in := nodestate.Input{Node: n, Connected: connected}

	v := nodeView{
		ID:                  n.NodeID,
		Hostname:            n.Facts.Hostname,
		Connected:           connected,
		LastSeen:            nodestate.Since(n.LastSeen, d.now()),
		LastSeenAbs:         n.LastSeen.UTC().Format("2006-01-02 15:04:05Z"),
		Revoked:             !n.RevokedAt.IsZero(),
		States:              stateChips(nodestate.Markers(in)),
		Labels:              declaredChips(n),
		CertFingerprint:     n.CertFingerprint,
		EnrollingToken:      n.EnrollingTokenID,
		DaemonVersion:       n.DaemonVersion,
		CertProvenanceKnown: nodestate.CertExpiryKnown(n),
		PolicyFingerprint:   n.PolicyFingerprint,
		TemplateFingerprint: n.TemplateSetFingerprint,
		TemplateUnloadable:  n.TemplateSetFingerprint == nodestate.TemplateUnloadable,
		Facts:               factRows(n),
		AuditWired:          d.Audit != nil,
	}
	if v.Revoked {
		v.RevokedAt = n.RevokedAt.UTC().Format("2006-01-02 15:04:05Z")
	}

	// Fingerprint sharing counts, computed over the fleet the Console can see.
	for _, other := range d.Fleet.List() {
		if n.PolicyFingerprint != "" && other.PolicyFingerprint == n.PolicyFingerprint {
			v.PolicyShared++
		}
		if n.TemplateSetFingerprint != "" && other.TemplateSetFingerprint == n.TemplateSetFingerprint {
			v.TemplateShared++
		}
	}

	if d.Policy != nil {
		if snap, ok := d.Policy.Get(n.NodeID); ok {
			v.Policy = &snap
			v.PolicyReported = true
		}
	}

	if d.Audit != nil {
		if recs, err := d.Audit.ByNode(r.Context(), n.NodeID); err == nil {
			rows, elided := windowed(recs, nodeTaskRows)
			v.TasksElided = elided
			// The same rule denied over and over is ONE fact, not twenty. A
			// Node that has refused the same read every hour for a day would
			// otherwise bury its Policy panel under twenty identical
			// explanations, and the operator would scroll past all of them.
			//
			// So the block renders on the first occurrence of each distinct
			// rule and the repeats keep their outcome chip. The chip is what
			// makes this safe: nothing is hidden, the row is still there, and
			// only the redundant prose is dropped.
			seenRule := map[string]bool{}
			for _, rec := range rows {
				t, ok := nodeTaskFrom(rec)
				if !ok {
					continue
				}
				if t.Denied != nil {
					if seenRule[t.Denied.Rule] {
						t.Denied = nil
						t.RepeatDeny = true
					} else {
						seenRule[t.Denied.Rule] = true
					}
				}
				v.Tasks = append(v.Tasks, t)
			}
		}
	}
	return v
}

// factRows renders the self-reported Facts.
//
// Empty values are omitted rather than rendered blank: a daemon that did not
// report a kernel version has not reported one, and an empty row invites the
// reader to wonder whether the machine has no kernel.
func factRows(n registry.Node) []nodeFact {
	var out []nodeFact
	add := func(k, v string) {
		if v != "" {
			out = append(out, nodeFact{Key: k, Value: v})
		}
	}
	add("hostname", n.Facts.Hostname)
	add("os", n.Facts.OS)
	add("kernel", n.Facts.Kernel)
	add("arch", n.Facts.Arch)
	if len(n.Facts.IPAddresses) > 0 {
		add("ip", strings.Join(n.Facts.IPAddresses, ", "))
	}
	return out
}

// nodeTaskFrom projects one audit record into a recent-Task row, or reports
// that it is not one.
//
// Only dispatch and read records describe something that happened ON this Node.
// A refusal is Relay-side — nothing reached the machine — and belongs on
// Activity, where it is attributed to the principal who was refused rather than
// to the Node that never heard about it.
func nodeTaskFrom(rec audit.Record) (nodeTask, bool) {
	switch rec.Kind {
	case audit.KindDispatch, audit.KindRead:
	default:
		return nodeTask{}, false
	}
	t := nodeTask{
		When:      rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Operation: operationText(rec),
		Args:      argsText(rec),
		Outcome:   OutcomeLabel(rec.Outcome),
		JobID:     rec.JobID,
		Principal: principalText(rec),
		Verified:  rec.Attribution.Verified.AccountID != "",
		ReadClass: rec.Kind == audit.KindRead,
	}
	if rec.JobID != "" {
		t.JobHref = "/console/jobs/" + rec.JobID
	}
	if rec.Outcome == jobs.OutcomeDeniedByPolicy {
		t.Denied = &Deny{
			NodeID:        rec.NodeID,
			OperationName: t.Operation,
			// The daemon's verdict text is what the Relay was told; it is
			// rendered verbatim and never paraphrased. Where the daemon did not
			// supply a rule, the reason field is what there is, and saying so
			// beats inventing a rule that was never quoted.
			Rule:       denyExplanation(rec),
			PolicyHref: "/console/nodes/" + rec.NodeID,
		}
	}
	return t, true
}

func operationText(rec audit.Record) string {
	if rec.OperationName != "" {
		return rec.OperationName
	}
	if len(rec.RawExecArgv) > 0 {
		return "raw_exec"
	}
	return rec.ActionKind
}

func argsText(rec audit.Record) string {
	if len(rec.RawExecArgv) > 0 {
		return strings.Join(rec.RawExecArgv, " ")
	}
	if len(rec.Args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(rec.Args))
	for k := range rec.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+rec.Args[k])
	}
	return strings.Join(parts, " ")
}

// principalText prefers the verified Account name.
//
// Record.Principal is the "name:role" string kept because it is what an operator
// reads at a glance, but the structured Attribution is authoritative — see
// audit's own doc. Reading the structured lane first is what keeps the trust
// chip honest: a name that came from the verified lane is filled, and one that
// did not is dashed.
func principalText(rec audit.Record) string {
	if n := rec.Attribution.Verified.AccountName; n != "" {
		return n
	}
	if rec.Principal != "" {
		return rec.Principal
	}
	return "unattributed"
}

var nodeMissingTmpl = newScreen("nodemissing", `
<div class="placeholder">
  <p>No Node with the id <code>{{.}}</code> is in this Relay's registry.</p>
  <p>A revoked Node keeps its record and stays readable; an id that was never enrolled has none.
  <a href="/console/">Back to the fleet</a>.</p>
</div>
`)

var nodeTmpl = newScreen("node", `
<div class="nodehead">
  <span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}"></span>
  <code class="nodeid big">{{.ID}}</code>
  {{with .Hostname}}<span class="sub">{{.}}</span>{{end}}
  <span class="seen" title="{{.LastSeenAbs}}">{{if .Connected}}connected{{else}}last seen {{.LastSeen}} ago{{end}}</span>
  {{if .Revoked}}<span class="chip outcome" data-outcome="cancelled">revoked {{.RevokedAt}}</span>{{end}}
</div>

<div class="labelrow">
  {{range .Labels}}{{template "label-chip" .}}{{end}}
  {{range .States}}{{template "label-chip" .}}{{end}}
  <span class="labelnote">
    <b>node:</b> set by the machine's config management, immutable to the Relay ·
    <b>relay:</b> set by the Relay, immutable to the Node, and the only namespace the security lane may target ·
    <b>state:</b> derived from this record, set by nobody
  </span>
</div>

<div class="panels">
  <div class="pcol">
    <section class="panel">
      <h3>Identity &amp; enrollment</h3>
      <dl>
        <dt>node id</dt><dd><code>{{.ID}}</code></dd>
        <dt>certificate</dt><dd><code title="{{.CertFingerprint}}">{{short .CertFingerprint}}</code></dd>
        <dt>enrolled via</dt><dd>{{if .EnrollingToken}}<code>{{.EnrollingToken}}</code>{{else}}<span class="dim">not recorded</span>{{end}}</dd>
        <dt>daemon</dt><dd>{{if .DaemonVersion}}<code>{{.DaemonVersion}}</code>{{else}}<span class="dim">not reported</span>{{end}}</dd>
      </dl>
      {{if not .CertProvenanceKnown}}
      <p class="gap"><b>Issued, expiry and renewal count are not recorded yet.</b> The registry
      stores this Node's certificate fingerprint and nothing else, so the Console cannot tell you
      when this identity expires or how many times it has renewed. That is a gap in what is
      stored, not a property of this Node.</p>
      {{end}}
      <p class="note">Renewal is certificate-authenticated and preserves the node id, so this
      identity chains unbroken back to the Enrollment Token above.</p>
    </section>

    <section class="panel">
      <h3>Fingerprints</h3>
      <dl>
        <dt>Policy</dt>
        <dd>{{if .PolicyFingerprint}}<code title="{{.PolicyFingerprint}}">{{short .PolicyFingerprint}}</code>
          <span class="dim">{{.PolicyShared}} {{plural .PolicyShared "Node" "Nodes"}} report this</span>
        {{else}}<span class="dim">not reported</span>{{end}}</dd>
        <dt>Template set</dt>
        <dd>{{if .TemplateUnloadable}}<span class="chip lbl" data-ns="state"><span class="ns">state:</span>template-unloadable</span>
          <span class="dim">the Node's local template set failed to load; its template vocabulary is empty and it fails closed</span>
        {{else if .TemplateFingerprint}}<code title="{{.TemplateFingerprint}}">{{short .TemplateFingerprint}}</code>
          <span class="dim">{{.TemplateShared}} {{plural .TemplateShared "Node" "Nodes"}} report this</span>
        {{else}}<span class="dim">no templates installed</span>{{end}}</dd>
      </dl>
      <p class="note">Confirming a rollout landed is string equality against these, not trust.
      Relay reports what the daemon says it loaded; it never sets either.</p>
    </section>

    <section class="panel">
      <h3>Facts <span class="phint">this page only</span></h3>
      {{if .Facts}}
      <dl>{{range .Facts}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl>
      {{else}}<p class="dim">This Node has not reported any Facts.</p>{{end}}
      <p class="note">Self-reported by the daemon. Facts appear here and nowhere else: they are
      not on a fleet row, not in a facet, and never targetable. A compromised Node can report
      anything it likes, so targeting is on labels, whose namespaces have enforced writers.</p>
    </section>
  </div>

  <div class="pcol wide">
    <section class="panel">
      <h3>Effective Policy</h3>
      {{if .PolicyReported}}
        <p class="note">Answered by <b>this Node's own engine</b> and reported on its last
        connection. The Relay never evaluates Policy and has no code path that writes it.</p>
        <div class="polblock">
          <div class="polrow"><span class="pk">raw exec</span>
            {{if .Policy.RawExecEnabled}}<span class="chip risk" data-risk="mutate">enabled</span>{{else}}<span class="chip risk">disabled</span>{{end}}</div>
          {{if .Policy.RawAllowPatterns}}<div class="polrow"><span class="pk">raw allow</span><pre>{{join "\n" .Policy.RawAllowPatterns}}</pre></div>{{end}}
          {{if .Policy.RawDenyPatterns}}<div class="polrow"><span class="pk">raw deny</span><pre>{{join "\n" .Policy.RawDenyPatterns}}</pre></div>{{end}}
          <div class="polrow"><span class="pk">operations</span>
            <div class="oplist">{{range .Policy.AllowedOperations}}<code>{{.}}</code>{{else}}<span class="dim">none allowed</span>{{end}}</div></div>
          {{range .Policy.OperationRules}}
            <div class="polrow"><span class="pk">allow</span><pre>{{.Name}}{{range .AllowedArgs}} [{{join " | " .}}]{{end}}</pre></div>
          {{end}}
          {{range .Policy.DenyRules}}
            <div class="polrow"><span class="pk">deny</span><pre>{{.Name}}{{range .Args}} [{{join " | " .}}]{{end}}</pre></div>
          {{end}}
        </div>
      {{else}}
        <p class="dim">This Node has not reported its Policy since the Relay last started.</p>
        <p class="note">The Console shows nothing rather than a remembered answer: a Policy view
        that might be stale is worse than none, because it is the thing an operator checks before
        deciding a Task is safe.</p>
      {{end}}
    </section>

    <section class="panel">
      <h3>Recent Tasks</h3>
      {{if .Tasks}}
      <table class="rows">
        <thead><tr><th>When</th><th>Operation</th><th>By</th><th>Outcome</th><th>Job</th></tr></thead>
        <tbody>
        {{range .Tasks}}
          <tr>
            <td class="num">{{.When}}</td>
            <td><code>{{.Operation}}</code>{{with .Args}}<div class="sub mono">{{.}}</div>{{end}}
              {{if .ReadClass}}<div class="sub">read — output not retained</div>{{end}}</td>
            <td>{{template "trust-chip" (trust .Principal .Verified)}}</td>
            <td><span class="chip outcome" data-outcome="{{.Outcome}}">{{.Outcome}}</span></td>
            <td>{{if .JobHref}}<a href="{{.JobHref}}"><code>{{short .JobID}}</code></a>{{end}}</td>
          </tr>
          {{with .Denied}}<tr><td></td><td colspan="4">{{template "deny-block" .}}</td></tr>{{end}}
          {{if .RepeatDeny}}<tr><td></td><td colspan="4" class="repeatdeny">Same rule as above.</td></tr>{{end}}
        {{end}}
        </tbody>
      </table>
      {{if .TasksElided}}<p class="gap">Older Tasks are not shown — this page renders the most
      recent {{len .Tasks}} and the trail has more. Filtered history is on
      <a href="/console/activity">Activity</a>.</p>{{end}}
      {{else if .AuditWired}}
      <p class="dim">No Tasks have run on this Node.</p>
      {{else}}
      <p class="dim">The audit trail is not wired into this Console.</p>
      {{end}}
    </section>
  </div>
</div>
`)
