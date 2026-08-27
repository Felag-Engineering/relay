package console

// reads.go answers the question the architecture itself says is the important
// one, and which nothing in the product could previously answer: what has been
// read, by whom, from where (spec 17).
//
// # Why reading is the exposure that matters
//
// ADR-0021 establishes that reading is exfiltration BY CONSTRUCTION — a read
// result flows to the model provider, and there is no version of that which
// isn't disclosure. ADR-0022 builds a confidentiality deny-list around exactly
// that. ADR-0025 makes every read auditable and fails the read closed when the
// audit write fails.
//
// All of that machinery existed and nothing surfaced any of it. This screen is
// the first place the product admits, out loud, that reading is the risk.
//
// # A map of exposure surface, not a data browser
//
// The trail can say a read HAPPENED, by whom, of what, and when — never what it
// contained (ADR-0025). That is not a gap to be filled later: it is what makes
// this screen structurally incapable of becoming a second copy of the fleet's
// secrets. A screen that showed the bytes would be the largest single
// concentration of confidential data in the deployment, sitting behind a browser
// session.
//
// # Counting two ways, both labelled
//
// One `file.read` across 4,000 Nodes is ONE path and FOUR THOUSAND exposures.
// Which number matters depends on the question — "what did it see" versus "how
// far did it reach" — so both are shown and neither is called "reads".

import (
	"net/http"
	"sort"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

type readPrincipal struct {
	Name     string
	Verified bool
	Calls    int
	Nodes    int
	Targets  int
	Denied   int
	// Enum counts control-plane enumerations, kept in its own column rather
	// than folded into Calls. See readsView.Enumerations.
	Enum int
	Last string
}

type readTarget struct {
	Target string
	Calls  int

	// Nodes is DISTINCT Nodes, not records carrying a Node id. The first build
	// counted records, so `file.read /etc/shadow` run five times across three
	// machines read "15 Nodes" on a three-Node fleet — a number larger than the
	// fleet, on the screen whose entire job is to say how far an agent reached.
	Nodes int
	// Refused counts reads a Node's Policy denied. These are the most
	// interesting rows on the screen: an agent repeatedly asking for something
	// the deny-list refuses is either misconfigured or probing, and both are
	// worth a look.
	Refused int
}

type readsView struct {
	Wired     bool
	Truncated bool
	Window    int

	// Any is whether anything has been read at all. On a fresh Relay the
	// headline row would otherwise render five zeroed statistics, and spec
	// 10's first acceptance criterion is that with zero Nodes no screen
	// renders an empty table or a zeroed statistic — a row of zeros is a
	// measurement, and it says "we measured your exposure and it is nil"
	// where the truth is that nothing has happened yet.
	Any bool

	// Calls, Nodes, Targets and Refused describe reads that reached a NODE —
	// bytes pulled off a machine by a read-class Operation.
	Calls   int
	Nodes   int
	Targets int
	Refused int

	// Enumerations describes the other family: the non-dispatching tools
	// (`list_nodes`, `list_operations`, `describe_node`, `get_job`) that read
	// the Relay's own registry and catalogue and never touch a Node.
	//
	// Both are exposure and both are counted — knowing an agent enumerated a
	// 10,000-Node estate four hundred times is worth a look. They are reported
	// SEPARATELY because blending them makes each number mean less: a
	// headline of "13 read calls / 6 distinct targets" that mixes
	// `file.read /etc/shadow` with `list_operations` softens the one figure
	// this screen's entire argument rests on, and the mixed rows carried
	// "0 Nodes" where every neighbouring row carried a real reach.
	Enumerations int
	EnumTargets  []readTarget

	Principals []readPrincipal
	Targets2   []readTarget
}

func handleReads(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := page(d, w, r, "Read egress")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		v := readsView{Wired: d.Audit != nil, Window: auditWindow}
		if d.Audit == nil {
			renderScreen(w, p, readsTmpl, v)
			return
		}
		recs, err := d.Audit.List(r.Context())
		if err != nil {
			unavailable(w, "the audit trail (it returned an error)")
			return
		}
		renderScreen(w, p, readsTmpl, buildReads(recs))
	}
}

func buildReads(recs []audit.Record) readsView {
	window, truncated := windowed(recs, auditWindow)
	v := readsView{Wired: true, Truncated: truncated, Window: auditWindow}

	type pAgg struct {
		readPrincipal
		nodes   map[string]bool
		targets map[string]bool
		last    string
	}
	byPrincipal := map[string]*pAgg{}
	byTarget := map[string]*readTarget{}
	byEnum := map[string]*readTarget{}
	targetNodes := map[string]map[string]bool{}
	allNodes := map[string]bool{}
	allTargets := map[string]bool{}

	for _, rec := range window {
		if !isRead(rec) {
			continue
		}

		name := principalText(rec)
		p, seen := byPrincipal[name]
		if !seen {
			p = &pAgg{
				readPrincipal: readPrincipal{Name: name, Verified: rec.Attribution.Verified.AccountID != ""},
				nodes:         map[string]bool{},
				targets:       map[string]bool{},
				last:          rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
			}
			byPrincipal[name] = p
		}

		// The two families are tallied apart from here down. An enumeration
		// has no Node and no Operation, so it can contribute neither reach nor
		// a Policy refusal — folding it into the fleet-read counters only ever
		// moved the denominators.
		if isEnumeration(rec) {
			v.Enumerations++
			p.Enum++
			target := readTargetOf(rec)
			t, ok := byEnum[target]
			if !ok {
				t = &readTarget{Target: target}
				byEnum[target] = t
			}
			t.Calls++
			continue
		}

		v.Calls++
		p.Calls++

		target := readTargetOf(rec)
		if target != "" {
			p.targets[target] = true
			allTargets[target] = true
			t, ok := byTarget[target]
			if !ok {
				t = &readTarget{Target: target}
				byTarget[target] = t
			}
			t.Calls++
			if rec.NodeID != "" {
				targetNodes[target] = addNode(targetNodes[target], rec.NodeID)
			}
			if rec.Outcome == jobs.OutcomeDeniedByPolicy {
				t.Refused++
				p.Denied++
				v.Refused++
			}
		}
		if rec.NodeID != "" {
			p.nodes[rec.NodeID] = true
			allNodes[rec.NodeID] = true
		}
	}

	v.Nodes = len(allNodes)
	v.Targets = len(allTargets)
	v.Any = v.Calls+v.Enumerations > 0

	for _, p := range byPrincipal {
		p.Nodes = len(p.nodes)
		p.Targets = len(p.targets)
		p.Last = p.last
		v.Principals = append(v.Principals, p.readPrincipal)
	}
	sort.SliceStable(v.Principals, func(i, j int) bool {
		if v.Principals[i].Calls != v.Principals[j].Calls {
			return v.Principals[i].Calls > v.Principals[j].Calls
		}
		return v.Principals[i].Name < v.Principals[j].Name
	})

	for key, t := range byTarget {
		t.Nodes = len(targetNodes[key])
		v.Targets2 = append(v.Targets2, *t)
	}
	for _, t := range byEnum {
		v.EnumTargets = append(v.EnumTargets, *t)
	}
	sort.SliceStable(v.EnumTargets, func(i, j int) bool {
		if v.EnumTargets[i].Calls != v.EnumTargets[j].Calls {
			return v.EnumTargets[i].Calls > v.EnumTargets[j].Calls
		}
		return v.EnumTargets[i].Target < v.EnumTargets[j].Target
	})
	// Refused first, then volume. The deny-list catching something is the row
	// worth reading; the rest is background.
	sort.SliceStable(v.Targets2, func(i, j int) bool {
		if (v.Targets2[i].Refused > 0) != (v.Targets2[j].Refused > 0) {
			return v.Targets2[i].Refused > 0
		}
		if v.Targets2[i].Calls != v.Targets2[j].Calls {
			return v.Targets2[i].Calls > v.Targets2[j].Calls
		}
		return v.Targets2[i].Target < v.Targets2[j].Target
	})
	return v
}

// isEnumeration reports whether a read was of the Relay's OWN registry or
// catalogue rather than of a Node.
//
// audit.KindRead is exactly the non-dispatching tools — `list_nodes`,
// `describe_node`, `list_operations`, `get_job`. None of them reaches a
// machine, which is why every one of these rows carried "0 Nodes" while
// sitting in the same table as reads that had a real reach.
func isEnumeration(rec audit.Record) bool { return rec.Kind == audit.KindRead }

// isRead reports whether a record describes something leaving a Node or the
// registry for a caller.
//
// Two families qualify, and conflating them would under-count: `KindRead` rows
// are the non-dispatching tools (`list_nodes`, `describe_node`,
// `list_operations`, `get_job`), and read-class dispatches are the catalog
// Operations that actually pull bytes off a machine (`file.read`, `log.tail`).
// Only the second reaches a Node, which is why the Node count and the call
// count are different numbers.
func isRead(rec audit.Record) bool {
	if rec.Kind == audit.KindRead {
		return true
	}
	if rec.Kind != audit.KindDispatch {
		return false
	}
	// Read-class dispatches are identified through the shared inference in
	// vocab.go, which is the one place this package guesses a risk class.
	return riskOf(rec) == jobs.RiskClassRead
}

// readTargetOf names WHAT was read, in the terms an operator would search for.
func readTargetOf(rec audit.Record) string {
	if rec.OperationName == "" {
		if rec.ActionKind != "" {
			return rec.ActionKind
		}
		return "registry read"
	}
	// The path argument is the interesting half of a file read. Where an
	// Operation has one, the target is "operation path" so that two reads of
	// different files do not collapse into one row.
	for _, key := range []string{"path", "file", "unit", "service"} {
		if v, ok := rec.Args[key]; ok && v != "" {
			return rec.OperationName + " " + v
		}
	}
	return rec.OperationName
}

// addNode records nodeID in set, allocating the set on first use.
func addNode(set map[string]bool, nodeID string) map[string]bool {
	if set == nil {
		set = map[string]bool{}
	}
	set[nodeID] = true
	return set
}

var readsTmpl = newScreen("reads", `
<p class="lede">Reading is exfiltration by construction: a read result flows to whoever asked, and
for an AI-agent that means the model provider. This screen is a map of that exposure — <b>who read
what, from where, and when</b>. It cannot show you the contents, at any age, and it is not going
to grow the ability to.</p>

{{if not .Wired}}
<p class="dim">The audit trail is not wired into this Console.</p>
{{else}}

{{if .Any}}
<div class="statrow">
  <div class="stat"><b>{{.Calls}}</b><span>{{plural .Calls "read from a Node" "reads from Nodes"}}</span></div>
  <div class="stat"><b>{{.Targets}}</b><span>distinct {{plural .Targets "target" "targets"}}</span></div>
  <div class="stat"><b>{{.Nodes}}</b><span>{{plural .Nodes "Node touched" "Nodes touched"}}</span></div>
  <div class="stat{{if .Refused}} attn{{end}}"><b>{{.Refused}}</b><span>refused by Policy</span></div>
  <div class="stat"><b>{{.Enumerations}}</b><span>control-plane {{plural .Enumerations "enumeration" "enumerations"}}</span></div>
</div>
<p class="note">Two different numbers on purpose. One <code>file.read</code> across 4,000 Nodes is
one target and four thousand exposures; which one matters depends on whether you are asking what
was seen or how far it reached. Enumerations are counted apart from all three: listing the
registry is exposure — it hands over the shape of your estate — but it is not bytes off a machine,
and a headline that mixes the two makes both softer than they are.</p>
{{else}}
<p class="dim">Nothing has been read yet.</p>
{{end}}

<section class="panel">
  <h3>By principal</h3>
  {{if .Principals}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Account</th><th class="num">Node reads</th><th class="num">Targets</th><th class="num">Nodes</th><th class="num">Refused</th><th class="num">Enumerations</th><th>Most recent</th></tr></thead>
    <tbody>
    {{range .Principals}}
      <tr>
        <td>{{template "trust-chip" (trust .Name .Verified)}}</td>
        <td class="num">{{.Calls}}</td>
        <td class="num">{{.Targets}}</td>
        <td class="num">{{.Nodes}}</td>
        <td class="num{{if .Denied}} attn{{end}}">{{.Denied}}</td>
        <td class="num">{{.Enum}}</td>
        <td class="num">{{.Last}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <p class="note">A machine Account whose read volume jumps against its own baseline is the single
  most useful row this screen can produce. Baselines need per-principal counts by time bucket,
  which is the capability layer's read lane and is not built yet — today this is the window's
  total, not a trend.</p>
  {{else}}<p class="dim">Nothing has been read.</p>{{end}}
</section>

<section class="panel">
  <h3>By target &mdash; read from Nodes</h3>
  {{if .Targets2}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Target</th><th class="num">Calls</th><th class="num">Nodes</th><th class="num">Refused</th></tr></thead>
    <tbody>
    {{range .Targets2}}
      <tr{{if .Refused}} class="attnrow"{{end}}>
        <td><code>{{.Target}}</code></td>
        <td class="num">{{.Calls}}</td>
        <td class="num">{{.Nodes}}</td>
        <td class="num{{if .Refused}} attn{{end}}">{{.Refused}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p class="dim">Nothing has been read from a Node.</p>{{end}}
</section>

<section class="panel">
  <h3>Control-plane enumeration</h3>
  {{if .EnumTargets}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Tool</th><th class="num">Calls</th></tr></thead>
    <tbody>
    {{range .EnumTargets}}
      <tr>
        <td><code>{{.Target}}</code></td>
        <td class="num">{{.Calls}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <p class="note">These read the Relay&#39;s own registry and Operation catalogue, never a Node, so
  they have no reach and no Policy verdict — Policy is a Node&#39;s and there is no Node here. They
  still disclose: the shape of the estate, its labels, and what the fleet will permit. An agent
  that enumerates far more than it reads is mapping rather than working.</p>
  {{else}}<p class="dim">Nothing has been enumerated.</p>{{end}}
</section>

<p class="gap"><b>Read-class dispatches are identified by Operation name.</b> The audit record does
not carry an Operation's risk class, so this screen matches against the read half of the shipped
catalog. A Template Operation a customer added is not in that list and will be counted as a mutate
here — an undercount of exposure, which is the wrong direction for this particular screen to be
wrong in, and worth fixing by putting the class on the record.</p>

{{if .Truncated}}<p class="gap">Computed over the most recent {{.Window}} audit records only. This
is a window, not the whole trail.</p>{{end}}
{{end}}
`)
