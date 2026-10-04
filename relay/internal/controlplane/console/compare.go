package console

// compare.go is the second half of spec 02: pin two or three Nodes and put
// them side by side, which is how "why did only that one deny?" is answered
// in one screen instead of four tabs.
//
// # What it diffs, and what it deliberately does not
//
// Fingerprints and reported Policy. No Fact is DIFFED. Facts appear on Node
// detail and nowhere else — that is the v0.6.0 acceptance criterion node.go
// states to the operator's face — and a screen that diffed
// hostname/os/kernel/arch/ip across Nodes would be the second page they live
// on, whatever it was called. What is left is what is actually comparable
// ACROSS machines for a divergence question: the two fingerprints, and what
// each daemon reported its engine would apply.
//
// The one exception is deliberate and is stated on the screen: the hostname
// appears as the HEADING that identifies which Node a column is, the same use
// a fleet row already makes of it (fleet.go's newFleetNode). It is not a row
// being compared, it is not targetable, and it is self-reported like every
// other Fact. TestCompare_RendersNoFact enforces exactly that boundary —
// os/kernel/arch/ip absent entirely, and no Fact as a row key — so the claim
// on the screen is no stronger than the guard behind it.
//
// # It renders only the Nodes it was named, and never enumerates the fleet
//
// Every id comes from the URL and is resolved one at a time through
// Queries.DescribeNode (#680) — one audited record per pinned Node, at most
// maxPins (3). There is no ListNodes call here and there must not be one: an
// enumerating comparison screen is a fleet surface, and the rule above is only
// true while this screen cannot become one.
// TestCompare_ResolvesOnlyThePinnedNodesAndNeverEnumeratesTheFleet is the
// guard.
//
// # Every column it reads is recorded (#680)
//
// This screen used to read FleetReader/PolicyReader directly and record
// nothing — the last gap invariant 10 named against this package. It now
// asks through the SAME audited door node detail does: one describe_node
// read per pinned Node, which is what makes "who compared which Nodes"
// answerable on the trail.
//
// # It states differences; it never adjudicates them
//
// Every cell is a string or a set the daemon REPORTED, compared for equality.
// Nothing here decides whether an Operation would be permitted — that is
// Policy evaluation, it happens in the daemon's live engine (invariant 12,
// ADR-0011), and the Relay has no implementation of it to reach for. The
// screen may say "these two differ here". It may never say "this one would
// deny".

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
)

// maxPins bounds a comparison at spec 02's "2–3 Nodes".
//
// Three columns is the width at which a difference is still visible in one
// glance; beyond it the table becomes the fleet view with Facts on it, which
// is the shape this whole screen is arranged to avoid.
const maxPins = 3

// The two screens the pin bar links onward to, named once so the "empty on the
// screen it points at" rule is a comparison and not a repeated literal.
const (
	fleetPath   = "/console/"
	comparePath = "/console/compare"
)

// notReported is the cell for a Node whose daemon has not reported its Policy
// since the Relay last started.
//
// It is compared like any other value, so a column that has not been heard from
// beside one that has marks the row: a blank column must never read as
// agreement. When NO column has reported — a Relay with no policyview wired,
// or two Nodes that have both been away since the last restart — every value is
// this one, nothing differs, and nothing is marked. That is correct and it is
// also uninformative, so the screen says which case it is in rather than
// letting an unmarked table read as "these two agree".
const notReported = "not reported"

// absent is the cell for a dimension this Node's reported Policy has nothing
// for: no raw-allow patterns, no rule of that name. Never an empty cell — an
// empty cell reads as a rendering bug.
const absent = "—"

// nodePin is one pinned Node as the pin bar draws it.
type nodePin struct {
	ID string

	// Known reports that this id resolved to a Node in the registry. Href is
	// set only when it did — an id that resolves to nothing is not a link to a
	// page about a machine, because there is no machine.
	Known bool
	Href  string

	// UnpinHref returns to the screen the operator is ON with this Node
	// removed. The pin set lives in the query string, so removing one is a
	// link — this surface has no mutating route and no cookie to write
	// (v0.6.0: zero mutating routes).
	UnpinHref string

	// Current marks the Node whose page is being drawn. The bar names it as
	// "this Node" rather than linking to the page the operator is already on.
	Current bool
}

// pinState is the pinned set as one screen sees it.
type pinState struct {
	// Raw is the pin exactly as it travels: the ids, comma-joined.
	Raw string

	Pins []nodePin

	// CompareHref and FleetHref are the bar's two onward links: to the
	// comparison (two or more pinned) and to the fleet, where the next Node is
	// picked. Each is empty on the screen it points at. CompareHref is also
	// empty below two pins, but the bar still DRAWS the Compare action there
	// (disabled) so one pin is never a dead end; see ShowCompare.
	CompareHref string
	FleetHref   string

	// ShowCompare is true on every screen except the comparison itself, which
	// is the screen the Compare action leads to.
	ShowCompare bool

	Full bool
}

// Any reports whether anything is pinned, for the templates.
func (p pinState) Any() bool { return len(p.Pins) > 0 }

// Query renders the pin for a href that has no query string of its own.
func (p pinState) Query() string {
	if p.Raw == "" {
		return ""
	}
	return "?" + url.Values{"pin": {p.Raw}}.Encode()
}

// Param renders the pin for a href that already carries a query string — a
// facet link, which always has a filter and a grouping on it.
func (p pinState) Param() string {
	if p.Raw == "" {
		return ""
	}
	return "&" + url.Values{"pin": {p.Raw}}.Encode()
}

// parsePins reads a pin set from a query value, and reports whether it named
// more Nodes than a comparison holds.
//
// Deduping mirrors appendTerm's idempotence: pinning the same Node twice is a
// double click, not a request for two identical columns.
//
// It stops AT the cap rather than collecting everything and truncating. The
// input is a query string, so the only bound on it is the server's header
// limit — half a million comma-separated entries is a legal request, and
// building a map of them to then keep three is per-request work an unauthorised
// shape of URL should not be able to ask for.
func parsePins(raw string) (ids []string, overflow bool) {
	seen := map[string]bool{}
	for rest := raw; rest != ""; {
		id, tail, more := strings.Cut(rest, ",")
		rest = tail
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			if !more {
				break
			}
			continue
		}
		if len(ids) == maxPins {
			return ids, true
		}
		seen[id] = true
		ids = append(ids, id)
		if !more {
			break
		}
	}
	return ids, false
}

// buildPinState renders the pin bar for the screen at selfPath, which is where
// an unpin link returns the operator. selfParam is the query key that screen
// carries its pin in — "pin" everywhere except the comparison itself, whose
// pin set IS its ?nodes=.
//
// Every id is resolved through known, because a pinned id is whatever the
// link carried and nothing else. An unresolvable one renders as a dead chip
// that says so: the alternative is a crafted URL drawing `node-prod-7` in a
// bar that otherwise only ever holds real machines, which is a screen telling
// an operator a Node exists.
//
// known is a PARAMETER rather than a read off Deps because the answer is a
// registry disclosure and #450 made where a screen gets one matter. The two
// screens on the audited read lane resolve pins from what that lane already
// gave them — the fleet listing from its own audited page, node detail from
// an audited describe per pinned id — so the pin bar never becomes a second,
// unaudited door into the registry. A nil known resolves nothing, which draws
// every chip dead rather than drawing a claim the screen cannot support.
func buildPinState(known func(string) bool, ids []string, selfPath, selfParam string) pinState {
	p := pinState{Raw: strings.Join(ids, ","), Full: len(ids) >= maxPins, ShowCompare: selfPath != comparePath}
	for _, id := range ids {
		unpin := selfPath
		if rest := without(ids, id); len(rest) > 0 {
			unpin += "?" + url.Values{selfParam: {strings.Join(rest, ",")}}.Encode()
		}
		pin := nodePin{ID: id, UnpinHref: unpin}
		if known != nil {
			pin.Known = known(id)
		}
		if pin.Known {
			pin.Href = "/console/nodes/" + id + p.Query()
		}
		p.Pins = append(p.Pins, pin)
	}
	// The two onward links are built HERE, once, rather than in each screen's
	// template: the first version of this bar was three copies, and the copy on
	// the comparison screen — the only screen where "pick another" is the whole
	// point — had already lost the pin set.
	if len(ids) >= 2 && selfPath != comparePath {
		p.CompareHref = comparePath + "?" + url.Values{"nodes": {p.Raw}}.Encode()
	}
	if selfPath != fleetPath {
		p.FleetHref = fleetPath + p.Query()
	}
	return p
}

// pinQuery renders a pin set as the query fragment a link carries it in.
func pinQuery(ids []string) string {
	return pinState{Raw: strings.Join(ids, ",")}.Query()
}

func without(ids []string, drop string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != drop {
			out = append(out, id)
		}
	}
	return out
}

// compareColumn is one Node's column heading.
//
// Hostname is here as the heading that says WHICH machine this column is,
// exactly as node detail's own header uses it. It is not a Fact row being
// diffed, and no other Fact appears on this screen at all.
type compareColumn struct {
	ID        string
	Hostname  string
	Href      string
	Connected bool
	LastSeen  string

	// PolicyReported and PolicyReportedAt are the provenance of this column's
	// Policy cells: whether the daemon has reported since the Relay last
	// started, and when the Relay received it. They sit in the HEADING rather
	// than in a diffed row on purpose — two Nodes reporting at different
	// instants have not diverged, and marking that as a difference would put a
	// mark on the one row that never means anything.
	PolicyReported   bool
	PolicyReportedAt string
}

// compareRow is one compared dimension. Values is positionally aligned with
// compareView.Columns.
type compareRow struct {
	Key    string
	Values []string

	// Differs is set when the columns do not all say the same thing. It is
	// the only judgement this screen makes, and it is string inequality.
	Differs bool
}

type compareView struct {
	Pin pinState

	Columns         []compareColumn
	FingerprintRows []compareRow
	PolicyRows      []compareRow
	Unknown         []string
	Truncated       bool

	// AnyPolicyMissing and AllPolicyMissing distinguish the two shapes of
	// absence. "Some column has not reported" is a difference and marks its
	// rows; "no column has reported" marks nothing at all, because every cell
	// holds the same absence — and an unmarked table that means "the Relay has
	// not been told" must not be read as "these Nodes agree".
	AnyPolicyMissing bool
	AllPolicyMissing bool
}

func handleCompare(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Compare Nodes")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audited read lane")
			return
		}
		d, lane := latched(d)

		ids, overflow := parsePins(r.URL.Query().Get("nodes"))
		v, err := buildCompareView(r.Context(), d, caller, ids)
		if err != nil {
			readFailed(w, err, "the pinned Nodes' registry records")
			return
		}
		if refusedUnaudited(w, lane, "the pinned Nodes' registry records") {
			return
		}
		v.Truncated = overflow
		renderScreen(w, p, compareTmpl, v)
	}
}

// pinnedResolution is one pinned id's DescribeNode result — resolved
// against the audited lane before buildCompareView renders anything, so the
// pin bar (which needs every id's known/unknown answer) and the columns
// (which need the detail) come from the SAME set of reads.
type pinnedResolution struct {
	id     string
	detail capability.NodeDetail
	known  bool
}

// buildCompareView is the whole screen as a function of the ids named in the
// URL, each resolved through the audited read lane (#680): one
// describe_node record per pinned id, at most maxPins (3) — the same honest
// accounting pinsKnown (node.go) already documents. An unknown or malformed
// id resolves to the Unknown list, a dead chip on the pin bar; any OTHER
// error is returned so the page fails closed as a whole.
func buildCompareView(ctx context.Context, d Deps, caller capability.Principal, ids []string) (compareView, error) {
	var resolutions []pinnedResolution
	for _, id := range ids {
		detail, err := d.Queries.DescribeNode(ctx, caller, id)
		switch {
		case err == nil:
			resolutions = append(resolutions, pinnedResolution{id: id, detail: detail, known: true})
		case errors.Is(err, capability.ErrNodeNotFound), errors.Is(err, capability.ErrInvalidFilter):
			resolutions = append(resolutions, pinnedResolution{id: id, known: false})
		default:
			return compareView{}, err
		}
	}

	known := make(map[string]bool, len(resolutions))
	for _, res := range resolutions {
		known[res.id] = res.known
	}
	v := compareView{Pin: buildPinState(func(id string) bool { return known[id] }, ids, comparePath, "nodes")}

	var snaps []*policyview.Snapshot
	for _, res := range resolutions {
		if !res.known {
			// Named rather than dropped: a Node that was revoked out of the
			// registry, or an id that was mistyped, is the answer to the
			// question the operator asked.
			v.Unknown = append(v.Unknown, res.id)
			continue
		}
		n := res.detail.Node
		col := compareColumn{
			ID:        n.NodeID,
			Hostname:  n.Facts.Hostname,
			Href:      "/console/nodes/" + n.NodeID + v.Pin.Query(),
			Connected: n.Connected,
			LastSeen:  nodestate.Since(n.LastSeen, d.now()),
		}

		var snap *policyview.Snapshot
		if res.detail.PolicyReported {
			s := res.detail.Policy
			snap = &s
			col.PolicyReported = true
			if !s.ReportedAt.IsZero() {
				col.PolicyReportedAt = utcStamp(s.ReportedAt)
			}
		}
		if snap == nil {
			v.AnyPolicyMissing = true
		}
		snaps = append(snaps, snap)
		v.Columns = append(v.Columns, col)

		v.FingerprintRows = appendCell(v.FingerprintRows, "Policy fingerprint", fingerprintText(n.PolicyFingerprint))
		v.FingerprintRows = appendCell(v.FingerprintRows, "Template set", templateText(n.TemplateSetFingerprint))
	}

	markDiffs(v.FingerprintRows)
	v.PolicyRows = comparePolicyRows(snaps)
	v.AllPolicyMissing = len(snaps) > 0 && !anyReported(snaps)
	return v, nil
}

// appendCell adds one column's value to the row named key, creating the row on
// the first column that reaches it. Rows stay in first-seen order.
func appendCell(rows []compareRow, key, value string) []compareRow {
	for i := range rows {
		if rows[i].Key == key {
			rows[i].Values = append(rows[i].Values, value)
			return rows
		}
	}
	return append(rows, compareRow{Key: key, Values: []string{value}})
}

func anyReported(snaps []*policyview.Snapshot) bool {
	for _, s := range snaps {
		if s != nil {
			return true
		}
	}
	return false
}

func markDiffs(rows []compareRow) {
	for i := range rows {
		for _, v := range rows[i].Values {
			if v != rows[i].Values[0] {
				rows[i].Differs = true
				break
			}
		}
	}
}

func fingerprintText(v string) string {
	if v == "" {
		return notReported
	}
	return v
}

func templateText(v string) string {
	switch v {
	case "":
		return "no templates installed"
	case nodestate.TemplateUnloadable:
		return "unloadable — the local template set failed to load"
	default:
		return v
	}
}

// comparePolicyRows diffs what each daemon reported its engine holds.
//
// String and set comparison of reported values, nothing else. There is no
// evaluation here and there is nowhere to put one: the Relay has no Policy
// engine (invariant 12), so "differs" is the strongest statement available and
// it is the honest one.
func comparePolicyRows(snaps []*policyview.Snapshot) []compareRow {
	var rows []compareRow

	add := func(key string, cell func(policyview.Snapshot) string) {
		row := compareRow{Key: key}
		for _, s := range snaps {
			if s == nil {
				row.Values = append(row.Values, notReported)
				continue
			}
			row.Values = append(row.Values, orAbsent(cell(*s)))
		}
		rows = append(rows, row)
	}

	add("Raw Exec", func(s policyview.Snapshot) string {
		if s.RawExecEnabled {
			return "enabled"
		}
		return "disabled"
	})
	add("Raw allow", func(s policyview.Snapshot) string { return strings.Join(s.RawAllowPatterns, "\n") })
	add("Raw deny", func(s policyview.Snapshot) string { return strings.Join(s.RawDenyPatterns, "\n") })
	add("Operations", func(s policyview.Snapshot) string { return strings.Join(sortedCopy(s.AllowedOperations), "\n") })

	for _, name := range ruleNames(snaps, func(s policyview.Snapshot) []string {
		var out []string
		for _, r := range s.OperationRules {
			out = append(out, r.Name)
		}
		return out
	}) {
		add("Allow "+name, func(s policyview.Snapshot) string {
			var parts []string
			for _, r := range s.OperationRules {
				if r.Name == name {
					parts = append(parts, argSetsText(r.AllowedArgs))
				}
			}
			return strings.Join(parts, "\n")
		})
	}

	for _, name := range ruleNames(snaps, func(s policyview.Snapshot) []string {
		var out []string
		for _, r := range s.DenyRules {
			out = append(out, r.Name)
		}
		return out
	}) {
		add("Deny "+name, func(s policyview.Snapshot) string {
			var parts []string
			for _, r := range s.DenyRules {
				if r.Name == name {
					parts = append(parts, argSetsText(r.Args))
				}
			}
			return strings.Join(parts, "\n")
		})
	}

	markDiffs(rows)
	return rows
}

// ruleNames is the sorted union of rule names across every reported Snapshot,
// so a rule one Node has and another does not still gets a row.
func ruleNames(snaps []*policyview.Snapshot, names func(policyview.Snapshot) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range snaps {
		if s == nil {
			continue
		}
		for _, n := range names(*s) {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func argSetsText(sets [][]string) string {
	if len(sets) == 0 {
		return "no arguments"
	}
	parts := make([]string, 0, len(sets))
	for _, s := range sets {
		parts = append(parts, "["+strings.Join(s, " | ")+"]")
	}
	return strings.Join(parts, " ")
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func orAbsent(s string) string {
	if s == "" {
		return absent
	}
	return s
}

var compareTmpl = newScreen("compare", `
{{if .Pin.Any}}{{template "pin-bar" .Pin}}{{end}}

{{if .Truncated}}<p class="gap"><b>Only three Nodes can be compared</b>; unpin one to swap in another.</p>{{end}}

{{with .Unknown}}
<p class="gap"><b>Not in this Relay's registry:</b> {{range .}}<code>{{.}}</code> {{end}}</p>
{{end}}

{{if lt (len .Columns) 2}}
<div class="placeholder">
  <p>Pin at least two Nodes to compare them.</p>
  <p>Pin from a row on the <a href="/console/{{.Pin.Query}}">fleet</a> or from a Node's own page.</p>
</div>
{{else}}
<div class="tablescroll">
<table class="cmp">
  <caption class="tcap">What {{len .Columns}} Nodes reported. Rows that differ are marked.</caption>
  <thead>
    <tr>
      <th scope="col"><span class="vh">Dimension</span></th>
      {{range .Columns}}<th scope="col" class="cmpnode">
        <span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}" role="img" aria-label="{{if .Connected}}connected{{else}}not connected{{end}}"></span>
        <a href="{{.Href}}" class="nodeid">{{.ID}}</a>
        {{with .Hostname}}<div class="sub">{{.}}</div>{{end}}
        <div class="sub">{{if .Connected}}connected{{else}}last seen {{.LastSeen}} ago{{end}}</div>
        <div class="sub">{{if .PolicyReported}}Policy received {{if .PolicyReportedAt}}{{.PolicyReportedAt}}{{else}}at a time that was not recorded{{end}}{{else}}Policy not reported{{end}}</div>
      </th>{{end}}
    </tr>
  </thead>
  <tbody>
    {{range .FingerprintRows}}<tr{{if .Differs}} data-diff="1"{{end}}>
      <th scope="row" class="cmpkey">{{.Key}}</th>
      {{range $i, $v := .Values}}<td data-label="{{(index $.Columns $i).ID}}"><code>{{$v}}</code></td>{{end}}
    </tr>{{end}}
    {{range .PolicyRows}}<tr{{if .Differs}} data-diff="1"{{end}}>
      <th scope="row" class="cmpkey">{{.Key}}</th>
      {{range $i, $v := .Values}}<td data-label="{{(index $.Columns $i).ID}}"><pre>{{$v}}</pre></td>{{end}}
    </tr>{{end}}
  </tbody>
</table>
</div>

<p class="note">Each cell is what that Node's daemon <b>reported</b>; this screen never predicts what will run.</p>

{{if .AllPolicyMissing}}
<p class="gap"><b>Neither Node has reported its Policy since the Relay last started</b>, so identical Policy rows mean nothing.</p>
{{else if .AnyPolicyMissing}}
<p class="note">A <b>not reported</b> column is marked as a difference, never read as agreement.</p>
{{end}}

<p class="note">Each column's hostname is self-reported; no other Fact is compared here.</p>
{{end}}
`)
