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
	Last     string
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

	Calls   int
	Nodes   int
	Targets int
	Refused int

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
	targetNodes := map[string]map[string]bool{}
	allNodes := map[string]bool{}
	allTargets := map[string]bool{}

	for _, rec := range window {
		if !isRead(rec) {
			continue
		}
		v.Calls++

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

<div class="statrow">
  <div class="stat"><b>{{.Calls}}</b><span>{{plural .Calls "read call" "read calls"}}</span></div>
  <div class="stat"><b>{{.Targets}}</b><span>distinct {{plural .Targets "target" "targets"}}</span></div>
  <div class="stat"><b>{{.Nodes}}</b><span>{{plural .Nodes "Node touched" "Nodes touched"}}</span></div>
  <div class="stat{{if .Refused}} attn{{end}}"><b>{{.Refused}}</b><span>refused by Policy</span></div>
</div>
<p class="note">Two different numbers on purpose. One <code>file.read</code> across 4,000 Nodes is
one target and four thousand exposures; which one matters depends on whether you are asking what
was seen or how far it reached.</p>

<section class="panel">
  <h3>By principal</h3>
  {{if .Principals}}
  <table class="rows">
    <thead><tr><th>Account</th><th class="num">Calls</th><th class="num">Targets</th><th class="num">Nodes</th><th class="num">Refused</th><th>Most recent</th></tr></thead>
    <tbody>
    {{range .Principals}}
      <tr>
        <td>{{template "trust-chip" (trust .Name .Verified)}}</td>
        <td class="num">{{.Calls}}</td>
        <td class="num">{{.Targets}}</td>
        <td class="num">{{.Nodes}}</td>
        <td class="num{{if .Denied}} attn{{end}}">{{.Denied}}</td>
        <td class="num">{{.Last}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  <p class="note">A machine Account whose read volume jumps against its own baseline is the single
  most useful row this screen can produce. Baselines need per-principal counts by time bucket,
  which is the capability layer's read lane and is not built yet — today this is the window's
  total, not a trend.</p>
  {{else}}<p class="dim">Nothing has been read.</p>{{end}}
</section>

<section class="panel">
  <h3>By target</h3>
  {{if .Targets2}}
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
  {{else}}<p class="dim">No targets in the window.</p>{{end}}
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
