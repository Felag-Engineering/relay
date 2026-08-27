package console

// fleet.go is the landing screen (spec 01) and, when the registry is empty, day
// one (spec 10).
//
// # The rule this screen is built around
//
// A list is a bug. Fleets run 100–10,000 Nodes, and a screen that renders one
// row per Node has handed the operator the job the computer was supposed to do.
// So this screen computes what is INTERESTING and renders only that: the mode
// as one compressed line, the deviations as rows, sorted by rarity so the
// weirdest Node is row one.
//
// Everything here answers one of the four questions in 00-foundations.md — can I
// reach it, will it take work, what will it permit, who is it and who vouched.
// There is no CPU, no memory, no load, no latency and no uptime graph, and their
// absence is a product decision rather than an unfinished backlog: this is not a
// monitoring product and the moment it imitates one, the four questions stop
// being the contract.
//
// # Filtering is targeting
//
// The filter box speaks Selector syntax — literally capability.ParseSelector,
// the same parser a dispatch resolves through — because browsing trains
// targeting. An operator who filters to a set and then asks "what would a Job
// hit?" must get the same answer, and the only way to guarantee that is to run
// the same code. A second, Console-local parser that agreed today would drift.

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// wallBucket is one of the four colours in the pixel wall.
//
// FOUR, and not five. Preattentive vision — the "pop-out" that lets you find
// the odd cell in four thousand without reading anything — handles about four
// categories and then collapses. A fifth bucket does not add information; it
// destroys the property the wall exists for. The deviation table beneath names
// which is which, and the wall's only job is to make the one quarantined Node in
// a 4,000-Node group findable without reading a word.
type wallBucket string

const (
	wallNormal    wallBucket = "normal"
	wallDrift     wallBucket = "drift"
	wallAttention wallBucket = "attention"

	// wallFenced is "a person deliberately took this Node out of the fleet" —
	// BOTH lower rungs of the incident ladder, quarantine and revoke.
	//
	// One bucket for two rungs because the wall may hold exactly four, and
	// because at wall distance the useful distinction is human-act versus
	// machine-condition: an amber cell is something that happened TO a Node, an
	// indigo one is something somebody DID to it. Which rung it was is named in
	// the deviation table a few inches below — the wall finds it, the table
	// says what it is.
	//
	// Filing revoked under wallAttention instead would put a deliberate,
	// irreversible act in the same colour as "the daemon is down".
	wallFenced wallBucket = "fenced"
)

// fleetNode is one Node as this screen sees it.
type fleetNode struct {
	ID       string
	Hostname string
	Href     string

	Connected bool
	LastSeen  string

	// States are the derived `state:` labels (nodestate). Rendered as chips,
	// never as an edit affordance — nobody sets these, including admins.
	States []Label

	// Labels are the declared namespaces: node:, tag:, relay:. Separate from
	// States because the difference between an observation and a declaration is
	// the whole point of the namespace model.
	Labels []Label

	Quarantined bool

	// Revoked is the middle rung of the incident ladder, and the irreversible
	// one. The registry RETAINS the record after revocation — deliberately, so
	// the Node stays investigable and its audit history stays answerable — so
	// it belongs on this screen rather than vanishing from it.
	//
	// Dropping it was the first build's worst omission: a revoked Node rendered
	// identically to `state:offline`, so an operator would raise a ticket
	// against a machine nobody will ever reach again.
	Revoked   bool
	RevokedAt string

	PolicyFingerprint   string
	TemplateFingerprint string
	DaemonVersion       string

	Bucket wallBucket

	// BucketLabel is the legend's wording for Bucket. The hover title said
	// `attention`, an internal token an operator has never seen; the key three
	// inches above says "needs attention". Two names for one colour on one
	// screen is how a key stops being a key.
	BucketLabel string

	// rarity is how many Nodes in the group share this Node's deviation
	// signature. Not rendered; it is the sort key that puts the weird Node
	// first.
	rarity    int
	signature string
}

// facetValue is one row in the facet rail.
type facetValue struct {
	Label string
	Term  string // the Selector term clicking this fills into the filter

	// Href is the full link, precomputed server-side. It carries the CURRENT
	// grouping and APPENDS to the current filter rather than replacing it.
	//
	// Both halves were bugs. Dropping `group` made a facet click silently
	// re-default the grouping, so the filter box and the group control — one
	// GET form — disagreed with the links beside them. Replacing the filter
	// made `node:env=prod, node:role=web` unreachable by clicking, which is
	// exactly the Selector composition this screen exists to teach: browsing
	// trains targeting, and a filter you can only ever set one term of trains
	// nothing.
	Href string

	Count int

	// Chip renders this value through the shared label-chip component when the
	// value IS a label. The State facet listed `offline` and
	// `quarantine (relay:)` as bare strings under one heading — a derived
	// observation and a declared act, told apart by a parenthetical, on a
	// screen whose entire chip grammar exists to keep those two apart by hue,
	// glyph and mono prefix.
	Chip *Label

	// Fenced renders this value as a declared act — the same chip the deviation
	// table uses — rather than as a label.
	//
	// Revocation is not a label at all. Rendering it as `state:revoked` in the
	// facet while the table three inches away rendered it as a fenced act meant
	// one screen described one fact two ways, and in the two grammars that most
	// need to stay apart: an observation the Relay derived, versus an
	// irreversible thing a person did.
	Fenced string
	// Targetable is false for a value the Selector parser cannot express yet
	// (a `state:` or `tag:` term — #414, #430). Rendered as text rather than a
	// link, because a filter link that produced a parse error would teach an
	// operator that the filter box is unreliable.
	Targetable bool
}

// facet is one distribution in the facet rail. The facets ARE the summary
// statistics — there is no separate stats panel, because a count of Nodes
// sharing a value is both the statistic and the way to select them.
type facet struct {
	Title  string
	Values []facetValue

	// Hint is one VISIBLE line explaining why this facet's values are not
	// links. It replaced a per-row `title` attribute, which a keyboard user
	// never sees and a touch user cannot reach — an explanation nobody can read
	// is not an explanation.
	Hint string
}

// fleetGroup is one rollup card: every Node sharing one value of the grouping
// key.
type fleetGroup struct {
	Key   string
	Count int

	Offline     int
	Outdated    int
	Quarantined int
	Revoked     int
	Unloadable  int
	OffMode     int

	Facets     []facet
	Deviations []fleetNode

	// ModeLine is the calm sentence beneath the deviations: how many Nodes
	// carry nothing at all. It is deliberately the last thing on the card —
	// most Nodes are normal, and normal is not what anyone came to read.
	ModeLine string

	// ListsWholeFleet is true when the table below is every Node in the group
	// rather than only its deviations. It changes what the table MEANS, so the
	// card says which it is showing instead of leaving the reader to infer it
	// from the row count.
	ListsWholeFleet bool

	// Elided is how many rows the table dropped at deviationRows.
	Elided int

	// Open is whether this card renders its detail. A group with no deviations
	// compresses to one line: healthy groups should cost one line of screen,
	// not a screenful of green.
	Open bool
}

// fleetView is the whole screen.
type fleetView struct {
	Total    int
	Matched  int
	Filter   string
	FilterOK bool
	// FilterError explains a rejected filter in the operator's terms, naming
	// the namespace that is not targetable yet rather than echoing a parser
	// error.
	FilterError string

	GroupBy   string
	GroupKeys []string

	// Now is when this page was rendered.
	//
	// "Can I reach it?" is answered from a socket state read at render time,
	// and live updates are not built. Without a stamp, a tab left open
	// overnight shows a confidently green fleet from twelve hours ago, with
	// relative last-seen values stale in the same direction. When #416 lands,
	// the live indicator goes here.
	Now time.Time

	Groups []fleetGroup

	// Wall is the WHOLE matched fleet as one block, above the groups: system
	// state at a glance, before any question about a particular group.
	//
	// One wall, not one per group. The acceptance criterion is "one segmented
	// summary, one pixel wall, and the deviating rows" — singular — and the
	// first build got this wrong in a way only visible on a real fleet: a
	// per-group wall of three cells is three specks nobody can see, and at
	// 10,000 Nodes across forty groups it is forty walls nobody can compare.
	// The whole point of the wall is that it is ONE image of the system.
	Wall []wallGroup

	// CellSize buckets the fleet size into a cell scale. It is an attribute,
	// never an inline style: the content security policy discards those.
	CellSize string

	// Legend is the four buckets with their counts — what the colours mean,
	// beside the thing they colour.
	Legend []wallLegend

	WallTotal  int
	WallCap    int
	WallElided int

	// GroupsElided is how many rollup cards were not drawn. Said out loud: a
	// truncated page that looks complete is how an operator concludes a group
	// has no Nodes in it.
	GroupsElided int

	// CertExpiryKnown is false until the registry records certificate validity
	// (#440). The screen SAYS so rather than rendering a clean State column,
	// which reads as "no Node is near losing its identity" when the truth is
	// "the Relay cannot tell".
	CertExpiryKnown bool
}

// groupCards bounds how many rollup cards the page draws. Forty is well past
// any taxonomy a human reads at a glance and far short of the thousand a
// high-cardinality label key produces.
const groupCards = 40

// wallGroup is one run of cells in the fleet-wide wall, kept together and
// labelled.
//
// The wall preserves the fleet's STRUCTURE rather than sorting by bucket.
// Sorting by bucket would make the counts trivially readable and destroy the
// thing the wall is for: an operator learns where their groups sit in the
// block, and then a colour appearing in an unusual place is itself information.
// The legend carries the counts, which is the readable form.
type wallGroup struct {
	Key   string
	Nodes []fleetNode
}

// wallLegend is one bucket in the wall's key.
//
// Counts only, no Selector term. The legend once carried one and never rendered
// it; then `fenced` grew to span two rungs of the incident ladder and no single
// term could select the bucket at all. Filtering is the facet rail's job — "one
// pixel wall, one facet rail", and the specification is explicit that clicking
// a facet is the interaction. A key explains the colours; it is not a second,
// weaker filter.
type wallLegend struct {
	Bucket wallBucket
	Label  string
	Count  int
}

// wallCap bounds the pixel wall. At 10,000 cells the wall is still cheap to
// render and useful to look at; past that the cells are sub-pixel and the wall
// has stopped being information. The cap is stated on screen when it binds.
const wallCap = 10000

// deviationRows bounds how many deviating Nodes a group lists before the
// "N more deviate the same way" ladder takes over.
const deviationRows = 25

// legibleGroup is the size at or below which a group lists EVERY Node rather
// than only its deviations.
//
// "A list is a bug" is a claim about ten thousand Nodes, not about three. Spec
// 01 says it in the small-fleet clause — "the deviation table simply IS the
// fleet. Nothing special-cased" — and the first build of this screen missed it:
// a healthy three-Node fleet compressed to two one-line cards and showed the
// operator nothing at all. A screen that computes what is interesting still has
// to show you your fleet when the interesting set is empty and the fleet fits.
//
// Fifty is where a table stops being readable in one glance. Above it the
// deviations are the answer; at or below it, the fleet is.
const legibleGroup = 50

func handleFleet(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Fleet == nil {
			unavailable(w, "the Node registry")
			return
		}
		p, ok := page(d, w, r, "Fleet")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		nodes := d.Fleet.List()

		// An empty registry is not an empty table. Spec 10: a Console with zero
		// Nodes is a distinct screen with a distinct job — it is watching for
		// the first enrollment, and rendering column headings over nothing
		// would say "this works and you have no machines" when what is true is
		// "you have not started yet".
		if len(nodes) == 0 {
			renderDayOne(w, p, d)
			return
		}

		v := buildFleetView(d, nodes, r.URL.Query().Get("filter"), r.URL.Query().Get("group"))
		renderScreen(w, p, fleetTmpl, v)
	}
}

// buildFleetView is the whole screen as a pure function of the fleet, the
// filter and the grouping. Kept separate from the handler so it is testable
// against a slice of registry.Node with no HTTP anywhere.
func buildFleetView(d Deps, nodes []registry.Node, filter, groupBy string) fleetView {
	v := fleetView{
		Now:      d.now(),
		Total:    len(nodes),
		Filter:   filter,
		FilterOK: true,
		WallCap:  wallCap,
	}

	matched := nodes
	if strings.TrimSpace(filter) != "" {
		sel, err := parseFleetFilter(filter)
		if err != nil {
			v.FilterOK = false
			v.FilterError = err.Error()
			// A rejected filter shows the WHOLE fleet with the error stated,
			// not an empty screen. An operator who mistypes a term is still
			// looking at their fleet, and blanking the page makes a typo feel
			// like an outage.
			matched = nodes
		} else {
			matched = matched[:0:0]
			for _, n := range nodes {
				if sel.Matches(n) {
					matched = append(matched, n)
				}
			}
		}
	}
	v.Matched = len(matched)

	v.GroupKeys = groupKeys(nodes)
	v.GroupBy = chooseGroupBy(groupBy, v.GroupKeys)

	fns := make([]fleetNode, 0, len(matched))
	for _, n := range matched {
		fns = append(fns, newFleetNode(d, n))
	}

	groups := groupNodes(fns, v.GroupBy)

	// "A list is a bug" is a claim about THE PAGE, not about one card. Deciding
	// it per group meant grouping 10,000 Nodes by a thousand-valued label key
	// produced a thousand open cards of ten rows each — ten thousand rows, and
	// verbatim the acceptance criterion this screen exists to satisfy.
	listWhole := v.Matched <= legibleGroup
	link := linkContext{Filter: v.Filter, GroupBy: v.GroupBy}

	if len(groups) > groupCards {
		v.GroupsElided = len(groups) - groupCards
		groups = groups[:groupCards]
	}
	for _, g := range groups {
		v.Groups = append(v.Groups, buildGroup(g.key, g.nodes, listWhole, link))
	}
	buildWall(&v, groups)
	return v
}

// buildWall assembles the fleet-wide block: every matched Node as one cell, in
// group order, with the legend beside it.
func buildWall(v *fleetView, groups []namedGroup) {
	counts := map[wallBucket]int{}
	remaining := wallCap
	for _, g := range groups {
		if remaining <= 0 {
			break
		}
		nodes := g.nodes
		if len(nodes) > remaining {
			nodes = nodes[:remaining]
		}
		remaining -= len(nodes)
		v.Wall = append(v.Wall, wallGroup{Key: g.key, Nodes: nodes})
		v.WallTotal += len(nodes)
	}
	for _, g := range groups {
		for _, n := range g.nodes {
			counts[n.Bucket]++
		}
	}
	if total := len(v.Wall); total > 0 {
		v.WallElided = v.Matched - v.WallTotal
	}
	v.CellSize = cellSize(v.Matched)

	// Ordered by how much they should draw the eye, not by count: the
	// quarantined Node is the reason the wall exists, and it must not sort
	// itself to the bottom by being rare.
	for _, b := range []struct {
		bucket wallBucket
		label  string
	}{
		{wallFenced, bucketLabel(wallFenced)},
		{wallAttention, bucketLabel(wallAttention)},
		{wallDrift, bucketLabel(wallDrift)},
		{wallNormal, bucketLabel(wallNormal)},
	} {
		if counts[b.bucket] == 0 {
			continue
		}
		v.Legend = append(v.Legend, wallLegend{Bucket: b.bucket, Label: b.label, Count: counts[b.bucket]})
	}
}

// cellSize picks a cell scale for the fleet size.
//
// A fixed cell size cannot serve both ends of the range this product targets.
// At three Nodes a 10px cell is a speck an operator does not notice is there;
// at ten thousand it is a wall four screens tall. The scale is a class name
// rather than a computed style because `style-src 'self'` discards inline
// styles — see console.css.
func cellSize(n int) string {
	switch {
	case n <= 24:
		return "lg"
	case n <= 150:
		return "md"
	case n <= 1500:
		return "sm"
	default:
		return "xs"
	}
}

// newFleetNode projects one registry record into a row.
func newFleetNode(d Deps, n registry.Node) fleetNode {
	connected := false
	if d.Liveness != nil {
		connected = d.Liveness.Connected(n.NodeID)
	}
	in := nodestate.Input{Node: n, Connected: connected}

	fn := fleetNode{
		ID:                  n.NodeID,
		Hostname:            n.Facts.Hostname,
		Href:                "/console/nodes/" + n.NodeID,
		Connected:           connected,
		LastSeen:            nodestate.Since(n.LastSeen, d.now()),
		States:              stateChips(nodestate.Markers(in)),
		Labels:              declaredChips(n),
		Quarantined:         nodestate.Quarantined(n),
		Revoked:             !n.RevokedAt.IsZero(),
		PolicyFingerprint:   n.PolicyFingerprint,
		TemplateFingerprint: n.TemplateSetFingerprint,
		DaemonVersion:       n.DaemonVersion,
	}

	if fn.Revoked {
		fn.RevokedAt = n.RevokedAt.UTC().Format("2006-01-02 15:04:05Z")
	}

	switch {
	// Revoke outranks quarantine: it is the higher rung and the one that cannot
	// be undone, so it is what the row should say first.
	case fn.Revoked, fn.Quarantined:
		fn.Bucket = wallFenced
	case nodestate.Attention(in):
		fn.Bucket = wallAttention
	case n.TemplateSetFingerprint == nodestate.TemplateUnloadable:
		fn.Bucket = wallDrift
	default:
		fn.Bucket = wallNormal
	}

	fn.BucketLabel = bucketLabel(fn.Bucket)

	// The signature is what "deviates the same way" means: two Nodes collapse
	// into one ladder rung only if their state chips AND their quarantine
	// status match. Fingerprint is deliberately NOT part of it — a fingerprint
	// difference is drift, drift is an observation rather than a deviation, and
	// folding it in here would make every rollout look like an incident.
	var sig []string
	for _, s := range fn.States {
		sig = append(sig, s.Key)
	}
	if fn.Quarantined {
		sig = append(sig, "quarantine")
	}
	if fn.Revoked {
		sig = append(sig, "revoked")
	}
	fn.signature = strings.Join(sig, "+")
	return fn
}

// bucketLabel is the single source of the operator-facing word for a bucket,
// shared by the legend and by every cell's hover title.
func bucketLabel(b wallBucket) string {
	switch b {
	case wallFenced:
		return "fenced by a person"
	case wallAttention:
		return "needs attention"
	case wallDrift:
		return "drift"
	default:
		return "normal"
	}
}

// stateChips converts derived nodestate labels into rendered chips.
func stateChips(ls []nodestate.Label) []Label {
	out := make([]Label, 0, len(ls))
	for _, l := range ls {
		out = append(out, Label{
			Namespace: NamespaceState,
			Key:       l.Key,
			Value:     l.Value,
			// nodestate already decided which markers demand attention. The
			// first build computed it there and threw it away here, so every
			// state chip rendered the same inert grey.
			Attention: l.Attention,
		})
	}
	return out
}

// declaredChips returns the labels somebody SET: node:, tag: and relay:.
//
// `tag:` is DELIBERATELY ABSENT. It has no storage until #430, so this screen
// has no source for one, and the honest rendering is none.
//
// An earlier version of this comment claimed tags were read from a `tag.` key
// prefix inside the relay-label map. They were not, and if #430's interim
// storage ever does land them there, the loop below would render an operator's
// ad-hoc grouping label as a `relay:` chip — lock glyph, security hue,
// data-lane="security" — which is the single confusion the four-namespace
// grammar exists to prevent (invariant 7: `tag:` is never a valid security-lane
// target). When #430 lands, split on the prefix HERE, in one place, and assert
// that a tag never renders with the security lane.
func declaredChips(n registry.Node) []Label {
	var out []Label
	for _, k := range sortedKeys(n.NodeLabels) {
		out = append(out, Label{Namespace: NamespaceNode, Key: k, Value: n.NodeLabels[k]})
	}
	for _, k := range sortedKeys(n.RelayLabels) {
		out = append(out, Label{Namespace: NamespaceRelay, Key: k, Value: n.RelayLabels[k]})
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// parseFleetFilter runs the filter through the real Selector parser, refusing
// namespaces it cannot yet express with a message that names the reason.
//
// `tag:` and `state:` are in the model (invariant 7, ADR-0034) and not in the
// parser: #430 gives `tag:` its storage and #414 makes `state:` resolvable at
// Selector time. Until then a filter on either would match nothing, and a
// filter box that silently returns zero rows for a valid-looking term is worse
// than one that refuses.
func parseFleetFilter(s string) (capability.Selector, error) {
	for _, term := range strings.Split(s, ",") {
		term = strings.TrimSpace(term)
		switch {
		case strings.HasPrefix(term, "tag:"):
			return capability.Selector{}, filterErr("tag: labels are not resolvable yet — operator-set grouping lands with label management (#430). Filter on node: or relay: for now.")
		case strings.HasPrefix(term, "state:"):
			return capability.Selector{}, filterErr("state: labels are derived and rendered, but not yet resolvable as Selector terms (#414). They appear as chips on every row.")
		}
	}
	sel, err := capability.ParseSelector(s)
	if err != nil {
		return capability.Selector{}, filterErr("every term needs a namespace prefix and a value, like node:role=web. " + strings.TrimPrefix(err.Error(), "capability: "))
	}
	return sel, nil
}

type filterErr string

func (e filterErr) Error() string { return string(e) }

// groupKeys returns every label key the fleet can be grouped by, most-used
// first.
//
// Only `node:` keys: the grouping axis is the customer's own taxonomy, stamped
// on the machine by their config management. Relay's own bookkeeping is "group
// by nothing", which is the empty string and always offered.
func groupKeys(nodes []registry.Node) []string {
	counts := map[string]int{}
	for _, n := range nodes {
		for k := range n.NodeLabels {
			counts[k]++
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// chooseGroupBy honours an explicit choice, falls back to the conventional
// taxonomy keys, and otherwise groups by nothing.
//
// "env" then "role" is a guess about the customer's taxonomy and is only a
// DEFAULT — the per-Account saved view (#442) is what makes an operator land on
// their own slice. Until that lands, guessing well beats landing on an
// undifferentiated wall.
func chooseGroupBy(requested string, available []string) string {
	if requested == "-" {
		return ""
	}
	for _, k := range available {
		if k == requested {
			return requested
		}
	}
	for _, preferred := range []string{"env", "environment", "role", "cluster"} {
		for _, k := range available {
			if k == preferred {
				return preferred
			}
		}
	}
	if len(available) > 0 {
		return available[0]
	}
	return ""
}

type namedGroup struct {
	key   string
	nodes []fleetNode
}

// groupNodes partitions rows by the value of key, ordered largest group first.
func groupNodes(nodes []fleetNode, key string) []namedGroup {
	if key == "" {
		return []namedGroup{{key: "all Nodes", nodes: nodes}}
	}
	byValue := map[string][]fleetNode{}
	for _, n := range nodes {
		v := "(unset)"
		for _, l := range n.Labels {
			if l.Namespace == NamespaceNode && l.Key == key {
				v = l.Value
				break
			}
		}
		byValue[v] = append(byValue[v], n)
	}
	out := make([]namedGroup, 0, len(byValue))
	for k, ns := range byValue {
		out = append(out, namedGroup{key: k, nodes: ns})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].nodes) != len(out[j].nodes) {
			return len(out[i].nodes) > len(out[j].nodes)
		}
		return out[i].key < out[j].key
	})
	return out
}

// buildGroup computes one rollup card: the counts, the wall, the facets and the
// anomaly-first deviation table.
func buildGroup(key string, nodes []fleetNode, listWhole bool, link linkContext) fleetGroup {
	g := fleetGroup{Key: key, Count: len(nodes)}

	modeFingerprint := modalValue(nodes, func(n fleetNode) string { return n.PolicyFingerprint })

	sigCount := map[string]int{}
	for _, n := range nodes {
		sigCount[n.signature]++
	}

	for i := range nodes {
		n := &nodes[i]
		n.rarity = sigCount[n.signature]
		for _, s := range n.States {
			switch s.Key {
			case string(nodestate.MarkerOffline):
				g.Offline++
			case string(nodestate.MarkerOutdated):
				g.Outdated++
			case string(nodestate.MarkerTemplateUnloadable):
				g.Unloadable++
			}
		}
		if n.Quarantined {
			g.Quarantined++
		}
		if n.Revoked {
			g.Revoked++
		}
		if modeFingerprint != "" && n.PolicyFingerprint != modeFingerprint {
			g.OffMode++
		}
	}

	g.Facets = buildFacets(nodes, link)

	// Anomaly-first by RARITY, never alphabetically. Sorting a deviation table
	// by name is how the one quarantined Node ends up on page nine.
	//
	// Below legibleGroup every Node is a row and the rarity sort still applies,
	// so the weird one is row one whether the table is the deviations or the
	// whole fleet. That is what "nothing special-cased" means: one sort, one
	// table, and the only thing that changes with size is how much of the group
	// reaches it.
	var dev []fleetNode
	deviating := 0
	for _, n := range nodes {
		if n.signature != "" {
			deviating++
		}
	}
	g.ListsWholeFleet = listWhole
	for _, n := range nodes {
		if g.ListsWholeFleet || n.signature != "" {
			dev = append(dev, n)
		}
	}
	sort.SliceStable(dev, func(i, j int) bool {
		// Deviating before normal, ALWAYS — before rarity is even consulted.
		//
		// Rarity alone inverts the table whenever the deviating Nodes are the
		// majority: a normal Node's rarity is the count of normal Nodes, so in
		// a group of 50 with 40 offline, the ten healthy machines sort to the
		// top of a table captioned "oddest first". Every fixture had the
		// deviations in the minority, which is the one case where rarity and
		// oddness happen to agree.
		iDev, jDev := dev[i].signature != "", dev[j].signature != ""
		if iDev != jDev {
			return iDev
		}
		if dev[i].rarity != dev[j].rarity {
			return dev[i].rarity < dev[j].rarity
		}
		return dev[i].ID < dev[j].ID
	})
	g.Deviations = dev
	if len(g.Deviations) > deviationRows {
		g.Elided = len(g.Deviations) - deviationRows
		g.Deviations = g.Deviations[:deviationRows]
	}

	normal := len(nodes) - deviating
	switch {
	case deviating == 0:
		g.ModeLine = "every Node here is reachable, current and permitted — no state label anywhere in this group."
	case normal == 0:
		g.ModeLine = "every Node in this group carries at least one state label."
	default:
		g.ModeLine = plural(normal, "Node carries", "Nodes carry") +
			" no state label at all — reachable, current, permitted."
	}

	// A group opens when it has something to show: a deviation, drift, or few
	// enough Nodes that the fleet itself is the thing worth showing. Only a
	// LARGE, uniformly healthy group compresses to one line — which is the case
	// the compression was for.
	g.Open = deviating > 0 || g.OffMode > 0 || g.ListsWholeFleet
	return g
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

// modalValue returns the most common non-empty value of f across nodes, or ""
// when nothing is reported.
//
// The mode is used ONLY to count how many Nodes differ from it, and that count
// is rendered as an observation ("12 on a different Policy fingerprint"), never
// as a state label. See nodestate's package doc for why a fleet-relative label
// would be wrong.
func modalValue(nodes []fleetNode, f func(fleetNode) string) string {
	counts := map[string]int{}
	for _, n := range nodes {
		if v := f(n); v != "" {
			counts[v]++
		}
	}
	best, bestN := "", 0
	for v, c := range counts {
		if c > bestN || (c == bestN && v < best) {
			best, bestN = v, c
		}
	}
	return best
}

// buildFacets renders the distributions, in the specified order: state, daemon
// version, Policy fingerprint, template set, node:role.
//
// The daemon-version facet is the upgrade dashboard (ADR-0014) and it offers
// nothing — no push, no copyable inventory, no install shortcut. The Relay
// never pushes binaries; the distribution is the whole feature.
// linkContext is the view state every facet link must preserve.
type linkContext struct {
	Filter  string
	GroupBy string
}

// href builds the link for a facet value: the current grouping kept, the term
// appended to the current filter.
func (c linkContext) href(term string) string {
	q := url.Values{}
	q.Set("filter", appendTerm(c.Filter, term))
	if c.GroupBy == "" {
		q.Set("group", "-")
	} else {
		q.Set("group", c.GroupBy)
	}
	return "/console/?" + q.Encode()
}

// appendTerm adds term to a Selector-syntax filter, unless it is already there.
//
// Idempotent on purpose: clicking the same facet twice must not produce
// `node:role=web, node:role=web`, which parses to a redundant predicate and
// reads as a bug in the product.
func appendTerm(filter, term string) string {
	term = strings.TrimSpace(term)
	if term == "" {
		return filter
	}
	for _, existing := range strings.Split(filter, ",") {
		if strings.TrimSpace(existing) == term {
			return filter
		}
	}
	if strings.TrimSpace(filter) == "" {
		return term
	}
	return filter + ", " + term
}

func buildFacets(nodes []fleetNode, link linkContext) []facet {
	var out []facet

	// The State facet mixes two namespaces on purpose — an operator scanning for
	// "what is wrong here" wants derived conditions and declared fences in one
	// list — so each row renders as its own CHIP and the namespace stays
	// visible. `relay:quarantine=on` is the one term here a Selector can
	// actually resolve today.
	stateFacet := facet{Title: "State"}
	stateCounts := map[string]int{}
	stateChip := map[string]Label{}
	for _, n := range nodes {
		for _, sc := range n.States {
			stateCounts[sc.String()]++
			stateChip[sc.String()] = sc
		}
		if n.Quarantined {
			q := Label{Namespace: NamespaceRelay, Key: registry.QuarantineKey, Value: registry.QuarantineOn}
			stateCounts[q.String()]++
			stateChip[q.String()] = q
		}
		if n.Revoked {
			stateCounts[fencedRevoked]++
		}
	}
	for term, count := range stateCounts {
		if term == fencedRevoked {
			stateFacet.Values = append(stateFacet.Values,
				facetValue{Label: term, Count: count, Fenced: term})
			continue
		}
		chip := stateChip[term]
		v := facetValue{Label: term, Count: count, Term: term, Chip: &chip}
		// Only the relay: fence resolves as a Selector term today; `state:` is
		// #414 and `revoked` is not a label at all.
		if chip.Namespace == NamespaceRelay {
			v.Targetable = true
			v.Href = link.href(term)
		}
		stateFacet.Values = append(stateFacet.Values, v)
	}
	if len(stateFacet.Values) > 0 {
		sortFacet(&stateFacet)
		stateFacet.Hint = "only relay: terms resolve as a Selector today"
		out = append(out, stateFacet)
	}

	versions := map[string]int{}
	for _, n := range nodes {
		if n.DaemonVersion != "" {
			versions[n.DaemonVersion]++
		}
	}
	if f := facetFrom("Daemon version", versions, link, noTerm); len(f.Values) > 0 {
		out = append(out, f)
	}

	policies := map[string]int{}
	for _, n := range nodes {
		if n.PolicyFingerprint != "" {
			policies[shortHash(n.PolicyFingerprint)]++
		}
	}
	if f := facetFrom("Policy fingerprint", policies, link, noTerm); len(f.Values) > 0 {
		f.Hint = "not resolvable as a Selector term yet — #414"
		out = append(out, f)
	}

	// The template-set facet, in its specified slot. Omitting it left question
	// two of the four ("will it take work?") with no fleet-level answer for
	// template vocabulary: `state:template-unloadable` was countable, but the
	// fingerprint that says WHICH set is installed — and therefore whether a
	// rollout is half-landed — was nowhere.
	templates := map[string]int{}
	for _, n := range nodes {
		switch {
		case n.TemplateFingerprint == nodestate.TemplateUnloadable:
			templates["unloadable"]++
		case n.TemplateFingerprint != "":
			templates[shortHash(n.TemplateFingerprint)]++
		default:
			templates["none installed"]++
		}
	}
	if f := facetFrom("Template set", templates, link, noTerm); len(f.Values) > 0 {
		out = append(out, f)
	}

	roles := map[string]int{}
	for _, n := range nodes {
		for _, l := range n.Labels {
			if l.Namespace == NamespaceNode && l.Key == "role" {
				roles[l.Value]++
			}
		}
	}
	if f := facetFrom("node:role", roles, link, func(k string) (string, bool) {
		return "node:role=" + k, true
	}); len(f.Values) > 0 {
		out = append(out, f)
	}

	return out
}

func noTerm(string) (string, bool) { return "", false }

// fencedRevoked is how the State facet names revocation. Not a label — a
// revoked Node carries no label at all — so it is spelled once here and
// rendered through the same declared-act chip the deviation table uses.
const fencedRevoked = "revoked"

// sortFacet orders a facet's values, largest bucket first.
func sortFacet(f *facet) {
	sort.Slice(f.Values, func(i, j int) bool {
		if f.Values[i].Count != f.Values[j].Count {
			return f.Values[i].Count > f.Values[j].Count
		}
		return f.Values[i].Label < f.Values[j].Label
	})
}

// facetFrom builds one facet, largest bucket first.
func facetFrom(title string, counts map[string]int, link linkContext, term func(string) (string, bool)) facet {
	f := facet{Title: title}
	for k, c := range counts {
		t, targetable := term(k)
		v := facetValue{Label: k, Count: c, Term: t, Targetable: targetable}
		if targetable {
			v.Href = link.href(t)
		}
		f.Values = append(f.Values, v)
	}
	sortFacet(&f)
	return f
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var fleetTmpl = newScreen("fleet", `
<form class="viewbar" method="get" action="/console/">
  <label class="vlabel" for="filter">Filter</label>
  <input id="filter" name="filter" value="{{.Filter}}" placeholder="node:role=web, relay:quarantine=on" spellcheck="false" autocomplete="off">
  <label class="vlabel" for="group">Group by</label>
  <select id="group" name="group">
    <option value="-"{{if eq .GroupBy ""}} selected{{end}}>nothing</option>
    {{range .GroupKeys}}<option value="{{.}}"{{if eq $.GroupBy .}} selected{{end}}>node:{{.}}</option>{{end}}
  </select>
  <button type="submit">Apply</button>
  <span class="vcount">{{.Matched}} of {{.Total}} {{plural .Total "Node" "Nodes"}}</span>
</form>

{{if not .FilterOK}}<div class="filtererr"><b>That filter was not applied.</b> {{.FilterError}}</div>{{end}}

{{if .Wall}}
<section class="systemstate">
  <div class="sshead">
    <h2>System state</h2>
    <span class="ssline">{{.WallTotal}} {{plural .WallTotal "Node" "Nodes"}}, one cell each{{if .GroupBy}}, grouped by <code>node:{{.GroupBy}}</code>{{end}}</span>
    <span class="asat" title="This page does not update on its own. Reload to re-read the fleet.">as at {{stamp .Now}}</span>
    <div class="sskey">
      {{range .Legend}}<span class="sskeyitem"><i class="cell" data-bucket="{{.Bucket}}" aria-hidden="true"></i><b>{{.Count}}</b> {{.Label}}</span>{{end}}
    </div>
  </div>
  <div class="wall" data-size="{{.CellSize}}" role="img" aria-label="{{.WallTotal}} Nodes: {{range .Legend}}{{.Count}} {{.Label}}. {{end}}Individual Nodes are listed in the tables below.">
    {{range .Wall}}<div class="wallgroup">
      {{if $.GroupBy}}<span class="walllabel" aria-hidden="true">{{.Key}}</span>{{end}}
      <div class="wallcells">{{range .Nodes}}<a class="cell" data-bucket="{{.Bucket}}" href="{{.Href}}" tabindex="-1" aria-hidden="true" title="{{.ID}}{{with .Hostname}} — {{.}}{{end}} · {{.BucketLabel}}"></a>{{end}}</div>
    </div>{{end}}
  </div>
  {{if .WallElided}}<p class="mode">{{.WallElided}} more {{plural .WallElided "Node is" "Nodes are"}} not drawn — the wall caps at {{.WallCap}} cells.</p>{{end}}
</section>
{{end}}

{{range .Groups}}
<section class="group{{if .Open}} open{{end}}">
  <header class="ghead">
    <h2>{{.Key}}</h2>
    <span class="gcount">{{.Count}} {{plural .Count "Node" "Nodes"}}</span>
    {{if .Offline}}<span class="gdev attn">{{.Offline}} offline</span>{{end}}
    {{if .Outdated}}<span class="gdev attn">{{.Outdated}} outdated</span>{{end}}
    {{if .Unloadable}}<span class="gdev drift">{{.Unloadable}} template-unloadable</span>{{end}}
    {{if .Quarantined}}<span class="gdev quar">{{.Quarantined}} quarantined</span>{{end}}
    {{if .Revoked}}<span class="gdev quar">{{.Revoked}} revoked</span>{{end}}
    {{if .OffMode}}<span class="gdev drift">{{.OffMode}} on a different Policy fingerprint</span>{{end}}
    {{if not .Open}}<span class="gdev calm">no deviations</span>{{end}}
  </header>

  {{if .Open}}
  <div class="gbody">
    <div class="facets">
      {{range .Facets}}
      <div class="facet">
        <div class="ftitle">{{.Title}}</div>
        {{range .Values}}
        <div class="frow">
          {{if .Fenced}}<span class="chip fenced">{{.Fenced}}</span>
          {{else if .Targetable}}<a href="{{.Href}}">{{if .Chip}}{{template "label-chip" .Chip}}{{else}}{{.Label}}{{end}}</a>
          {{else}}<span>{{if .Chip}}{{template "label-chip" .Chip}}{{else}}{{.Label}}{{end}}</span>{{end}}
          <b>{{.Count}}</b>
        </div>
        {{end}}
        {{with .Hint}}<div class="fhint">{{.}}</div>{{end}}
      </div>
      {{end}}
    </div>

    <div class="devtable">
      <table>
        <caption class="tcap">{{if .ListsWholeFleet}}Every Node in {{.Key}}, oddest first.{{else}}Deviating Nodes in {{.Key}}, rarest first.{{end}}</caption>
        <thead><tr>
          <th scope="col"><span class="vh">Reachable</span></th>
          <th scope="col">Node</th><th scope="col">State</th><th scope="col">Labels</th>
          <th scope="col">Policy</th><th scope="col">Last seen</th>
        </tr></thead>
        <tbody>
        {{range .Deviations}}
          <tr>
            <td><span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}" role="img" aria-label="{{if .Connected}}connected{{else}}not connected{{end}}"></span></td>
            <td><a href="{{.Href}}" class="nodeid">{{.ID}}</a>{{with .Hostname}}<div class="sub">{{.}}</div>{{end}}</td>
            <td class="statecell">{{if .Revoked}}<span class="chip fenced" title="Revoked {{.RevokedAt}}. The record is kept so the Node stays investigable.">revoked</span>{{end}}
              {{if .Quarantined}}<span class="chip fenced" title="Quarantined by an admin. Reversible.">quarantined</span>{{end}}
              {{range .States}}{{template "label-chip" .}}{{end}}</td>
            <td class="lblcell">{{range .Labels}}{{template "label-chip" .}}{{end}}</td>
            <td><code title="{{.PolicyFingerprint}}">{{short .PolicyFingerprint}}</code></td>
            <td class="num">{{.LastSeen}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
      {{if .Elided}}<p class="mode">{{.Elided}} more {{plural .Elided "Node deviates" "Nodes deviate"}} and are not listed.</p>{{end}}
      <p class="mode">{{.ModeLine}}</p>
    </div>
  </div>
  {{end}}
</section>
{{end}}

{{if .GroupsElided}}<p class="gap"><b>{{.GroupsElided}} more {{plural .GroupsElided "group is" "groups are"}} not shown.</b>
This page draws the {{len .Groups}} largest. Narrow the filter, or group by a coarser label key —
a grouping with hundreds of values is a list of Nodes wearing a different hat.</p>{{end}}

{{if not .CertExpiryKnown}}
<p class="gap"><b>Certificate expiry is not recorded yet.</b> No Node here can show
<code>state:cert-expiring</code> — including one whose identity certificate lapses tomorrow. A
clear State column means the Relay has nothing to report, not that nothing is wrong: the registry
stores each Node&#39;s certificate fingerprint and nothing else, so there is no expiry to compare a
clock against. A Node that quietly stops renewing drops off the fleet with no warning here.</p>
{{end}}

<p class="scopenote">This screen answers only what Relay can honestly answer about a Node: whether
it is reachable, whether it will take work, what it will permit, and who vouched for it. There are
no host metrics here and there will not be — reads are pulled as Jobs with a Plan and a blast cap,
never collected on a schedule.</p>
`)
