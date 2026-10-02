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
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// wallBucket is one bucket of the pixel wall: four colours, plus one hollow
// cell for a Node that has not reported.
//
// FOUR colours, and not five. Preattentive vision — the "pop-out" that lets you find
// the odd cell in four thousand without reading anything — handles about four
// categories and then collapses. A fifth bucket does not add information; it
// destroys the property the wall exists for. The deviation table beneath names
// which is which, and the wall's only job is to make the one quarantined Node in
// a 4,000-Node group findable without reading a word.
//
// "Not reported" is not a fifth hue. It is a hollow cell — an outline with no
// fill — on the fill-versus-outline channel, which is separate from hue, so
// the four-hue pop-out argument survives. Without it an unreported Node is
// drawn as a filled green "normal" cell, which is the false reassurance #833
// reported.
type wallBucket string

const (
	wallNormal    wallBucket = "normal"
	wallDrift     wallBucket = "drift"
	wallAttention wallBucket = "attention"

	// wallUnreported is a Node with no recorded Hello: no daemon version or no
	// Policy fingerprint. A Console presentation bucket only — not a state:
	// value and not a Selector term (owner decision on #833, 2026-10-01).
	wallUnreported wallBucket = "unreported"

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

	// Unreported is true when the registry holds no recorded Hello for this
	// Node (see unreported). Such a Node is never counted as current or
	// permitted.
	Unreported bool

	PolicyFingerprint   string
	TemplateFingerprint string
	DaemonVersion       string

	// policyTerm, templateTerm and versionTerm are the Selector terms the
	// facet rail links to for the three fields above — never the raw values
	// themselves. Unexported because no template may render them (precedent:
	// rarity, signature): the only writer is nodestate.Facts, in
	// newFleetNode, mirroring buildNodeView (node.go:234-251). Empty means
	// nodestate refused the raw value (validFactValue rejected a comma,
	// whitespace or a namespace prefix), and buildFacets must then produce an
	// unlinkable row rather than a term built by concatenation — the bug this
	// change exists to close.
	policyTerm   string
	templateTerm string
	versionTerm  string

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

// hasStateCell reports whether the State cell for n renders anything. It must
// change whenever the statecell template does.
func (n fleetNode) hasStateCell() bool {
	return n.Revoked || n.Quarantined || n.Unreported || len(n.States) > 0
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

	// key is the map key this value was built from — the FULL self-reported
	// value for the fingerprint/version facets and a discriminated key for
	// the template-set facet's sentinels, never the shortHash Label. Never
	// rendered; it exists solely as sortFacet's final tiebreak. Two distinct
	// full values can render the same Label (a shared 12-character prefix, or
	// a self-reported string landing beside a sentinel's LABEL though never
	// its key), and without a deterministic tiebreak, sort.Slice is not
	// stable and facetFrom ranges a map — the page order would flap between
	// renders.
	key string
}

// facet is one distribution in the facet rail. The facets ARE the summary
// statistics — there is no separate stats panel, because a count of Nodes
// sharing a value is both the statistic and the way to select them.
type facet struct {
	Title  string
	Values []facetValue

	// LabelKey is true when Title is a label key (an identifier) rather than
	// a facet name, and so renders as code, verbatim.
	LabelKey bool

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
	// Fingerprinted and Fingerprints are the drift chip's display counts: Nodes
	// in the group that reported a Policy fingerprint, and the distinct
	// fingerprints among them. Unreported Nodes stay out of both.
	Fingerprinted int
	Fingerprints  int
	// Unreported counts Nodes with no recorded Hello (see unreported). They
	// are counted here once and never in OffMode.
	Unreported int
	// Expiring counts state:cert-expiring — the identity-alarm marker #414
	// adds a threshold for. A marker no rollup counts is a half-landed
	// marker: it would render on the row but never surface in the card's
	// header line.
	Expiring int

	Facets     []facet
	Deviations []fleetNode

	// ShowState is false when no row in this group's table draws anything in
	// the State cell (hasStateCell), so an all-empty State column does not
	// take width on every row.
	ShowState bool

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
	// NoMatch is true when a valid filter matched no Node: the empty state.
	NoMatch bool

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

	// Legend is the five buckets with their counts — what the colours mean,
	// beside the thing they colour.
	Legend []wallLegend

	WallTotal  int
	WallCap    int
	WallElided int

	// GroupsElided is how many rollup cards were not drawn. Said out loud: a
	// truncated page that looks complete is how an operator concludes a group
	// has no Nodes in it.
	GroupsElided int

	// CertExpiryKnown reports whether the registry holds certificate validity
	// for EVERY matched Node (#440), and CertExpiryUnknown counts the ones it
	// does not — Nodes that enrolled before the Relay began recording validity
	// and have not renewed since.
	//
	// The threshold now exists (#414, ADR-0034): a Node with under 25% of its
	// certificate's remaining lifetime shows state:cert-expiring like any
	// other marker, counted in Expiring above and chipped on its row. What
	// these two fields still gate is narrower — whether the judgement can be
	// COMPLETE: a Node with no recorded validity at all cannot be judged
	// either way, so a clean State column has two possible causes (nothing is
	// close to lapsing, or the Relay cannot yet say), and the banner names
	// which Nodes fall in the second bucket rather than letting a clean
	// column read as "no Node is near losing its identity".
	CertExpiryKnown   bool
	CertExpiryUnknown int

	// Pin is the pinned-Node set this request carried, set by the handler
	// after the view is built. It only ever travels through this screen —
	// every row and facet link appends it so a click does not lose the pins.
	Pin pinState
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
		// The read lane takes a capability.Principal, so this screen reads
		// the one the Authenticator injected as well as the Page the shell
		// needs. Both are context reads; page() resolves the same principal
		// itself.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Fleet")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audited read lane")
			return
		}
		// Every read this page makes goes through the latch, so the "a page
		// whose read cannot be audited is not served" rule is one call at the
		// end rather than a branch per read (screen.go).
		d, lane := latched(d)

		// THE FLEET ENUMERATION IS AN AUDITED READ (#450, ADR-0025). This
		// screen discloses every Node's name, Labels, Facts and certificate
		// provenance in one page, which is the disclosure ADR-0025 names
		// first — so it asks the capability layer, which writes the
		// list_nodes access record BEFORE it touches the registry and returns
		// the failure instead of the fleet when it cannot.
		//
		// Fail closed, with no exception for this screen or any other: a
		// Console page whose read cannot be audited refuses to render.
		listing, err := d.Queries.ListNodes(r.Context(), caller, "")
		if err != nil {
			readFailed(w, err, "this Relay's Node registry")
			return
		}
		if refusedUnaudited(w, lane, "this Relay's Node registry") {
			return
		}
		// listing.Nodes may be a NIL slice when the whole fleet is empty —
		// buildFleetView and knownIn both range over it, so both already
		// tolerate that; stated here so the next reader does not have to
		// re-derive it (#680).
		nodes := listing.Nodes

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
		// The pin is carried, not computed: this screen is where an operator
		// picks the second and third Node of a comparison, and a fleet view
		// that dropped the pin on the way through would make pinning one Node
		// the only thing possible.
		pins, _ := parsePins(r.URL.Query().Get("pin"))
		// Pins resolve against the page this screen ALREADY read and already
		// audited, not through a second door into the registry: one screen,
		// one disclosure, one record.
		v.Pin = buildPinState(knownIn(nodes), pins, fleetPath, "pin")
		renderScreen(w, p, fleetTmpl, v)
	}
}

// ClearHref is the fleet with the filter dropped and the grouping and pin
// kept. An explicit "group by nothing" travels as "-", as in linkContext.href,
// so it survives instead of falling back to the default grouping.
func (v fleetView) ClearHref() string {
	q := url.Values{}
	if v.GroupBy == "" {
		q.Set("group", "-")
	} else {
		q.Set("group", v.GroupBy)
	}
	if v.Pin.Raw != "" {
		q.Set("pin", v.Pin.Raw)
	}
	return fleetPath + "?" + q.Encode()
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
			ev := capability.StateEval{Now: d.now(), CertExpiringWithin: d.CertExpiringWithin}
			matched = matched[:0:0]
			for _, n := range nodes {
				if sel.Matches(n, ev) {
					matched = append(matched, n)
				}
			}
		}
	}
	v.Matched = len(matched)
	v.NoMatch = v.FilterOK && strings.TrimSpace(filter) != "" && v.Matched == 0

	v.GroupKeys = groupKeys(nodes)
	v.GroupBy = chooseGroupBy(groupBy, v.GroupKeys)

	fns := make([]fleetNode, 0, len(matched))
	for _, n := range matched {
		fns = append(fns, newFleetNode(d, n))
	}

	groups := groupNodes(fns, v.GroupBy)
	if v.NoMatch {
		// The empty state stands alone: a group card or all-clear line
		// beneath "No Nodes match" would contradict it.
		groups = nil
	}

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

	// Counted over the MATCHED set, not the whole fleet: the sentence the
	// banner renders is about the Nodes on this page.
	for _, n := range matched {
		if !nodestate.CertExpiryKnown(n) {
			v.CertExpiryUnknown++
		}
	}
	v.CertExpiryKnown = v.CertExpiryUnknown == 0

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
		{wallUnreported, bucketLabel(wallUnreported)},
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

// unreported reports whether the registry holds no recorded Hello for n: no
// daemon version or no Policy fingerprint. A Node with no recorded version
// cannot be called current, and one with no recorded fingerprint cannot be
// called permitted.
//
// A Console presentation bucket only. It is NOT a state: value, not a
// Selector term, and never placed in nodestate — the owner's decision of
// 2026-10-01 on #833, which leaves the closed state: vocabulary (invariant 7)
// untouched. Node detail uses this same function.
func unreported(n registry.Node) bool {
	return n.DaemonVersion == "" || n.PolicyFingerprint == ""
}

// newFleetNode projects one registry record into a row.
func newFleetNode(d Deps, n registry.Node) fleetNode {
	in := nodestate.Input{Node: n, Now: d.now(), CertExpiringWithin: d.CertExpiringWithin}

	fn := fleetNode{
		ID:       n.NodeID,
		Hostname: primaryHostname(n.Facts.Hostname),
		// Href carries NO query string, and must not start: the template
		// appends the pin with fleetView.Pin.Query, which begins with "?".
		// A parameter added here would silently produce "...?a=b?pin=...".
		Href:                "/console/nodes/" + n.NodeID,
		Connected:           n.Connected,
		LastSeen:            nodestate.Since(n.LastSeen, d.now()),
		States:              stateChips(nodestate.Markers(in)),
		Labels:              declaredChips(n),
		Quarantined:         nodestate.Quarantined(n),
		Revoked:             !n.RevokedAt.IsZero(),
		PolicyFingerprint:   n.PolicyFingerprint,
		TemplateFingerprint: n.TemplateSetFingerprint,
		DaemonVersion:       n.DaemonVersion,
		Unreported:          unreported(n),
	}

	if fn.Revoked {
		fn.RevokedAt = n.RevokedAt.UTC().Format("2006-01-02 15:04:05Z")
	}

	// Selector terms for the three self-reported facts, derived through
	// nodestate.Facts rather than concatenated here — the same seam
	// buildNodeView uses (node.go:234-242) and for the identical reason: the
	// raw fields above arrive with no validation at the wire ingress, and
	// nodestate.Facts is the only place permitted to turn one into a
	// Selector-syntax string. A key nodestate refused is simply absent from
	// the loop, leaving the matching term field at its zero value.
	for _, l := range nodestate.Facts(in) {
		switch l.Key {
		case string(nodestate.FactPolicyFingerprint):
			fn.policyTerm = l.String()
		case string(nodestate.FactTemplateFingerprint):
			fn.templateTerm = l.String()
		case string(nodestate.FactDaemonVersion):
			fn.versionTerm = l.String()
		}
	}

	switch {
	// Revoke outranks quarantine: it is the higher rung and the one that cannot
	// be undone, so it is what the row should say first.
	case fn.Revoked, fn.Quarantined:
		fn.Bucket = wallFenced
	case nodestate.Attention(in):
		fn.Bucket = wallAttention
	// Unreported sits BELOW attention: offline comes from the tunnel and
	// cert-expiring from the certificate, neither depends on Hello, and both
	// are live alarms the hollow cell must never mask. An unreported Node that
	// also raises an attention marker stays amber; it is still counted in
	// fleetGroup.Unreported and still carries the "not reported" chip. It sits
	// above drift because it is the larger unknown: no recorded Hello means no
	// basis to call the Node current or permitted at all.
	case fn.Unreported:
		fn.Bucket = wallUnreported
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
	if fn.Unreported {
		sig = append(sig, "unreported")
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
	case wallUnreported:
		return "not reported"
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
	for _, k := range slices.Sorted(maps.Keys(n.NodeLabels)) {
		out = append(out, Label{Namespace: NamespaceNode, Key: k, Value: n.NodeLabels[k]})
	}
	for _, k := range slices.Sorted(maps.Keys(n.RelayLabels)) {
		out = append(out, Label{Namespace: NamespaceRelay, Key: k, Value: n.RelayLabels[k]})
	}
	return out
}

// parseFleetFilter runs the filter through the real Selector parser, refusing
// `tag:` — the one namespace it still cannot express — with a message that
// names the reason.
//
// `tag:` is in the model (invariant 7, ADR-0020) and not resolvable: it has no
// storage on registry.Node until #430 gives it one. The REFUSAL now lives in
// capability.ParseSelector (#560), not here. This screen used to guard it
// itself, which meant MCP's list_nodes answered the same term with 200 and an
// empty list while this box refused it — the surface-local guard was how the
// two drifted. What is left here is rendering: recognise the sentinel and say
// it in this screen's register, never re-decide it.
//
// `state:` is NOT special-cased at all (#414, ADR-0034): it resolves through
// capability.ParseSelector/Matches exactly like node: and relay:, so a
// `state:offline` filter narrows the table the same way a facet click does
// — one resolver, no surface-local evaluation.
func parseFleetFilter(s string) (capability.Selector, error) {
	sel, err := capability.ParseSelector(s)
	switch {
	case errors.Is(err, capability.ErrSelectorTagUnsupported):
		// Rendered in this screen's own words: the term DOES carry a prefix, so
		// the generic arm below would name the wrong problem.
		return capability.Selector{}, filterErr("This Relay cannot filter on tag: labels yet, because it has nowhere to store them. Filter on node:, relay: or state: instead.")
	case err != nil:
		msg := sentenceCase(strings.TrimPrefix(err.Error(), "capability: "))
		return capability.Selector{}, filterErr(msg + ". A term looks like node:role=web or state:offline.")
	}
	return sel, nil
}

// sentenceCase upper-cases a leading ASCII lower-case letter. A message that
// opens with a quoted term is left as it is.
func sentenceCase(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
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
	distinctFingerprints := map[string]struct{}{}
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
			case string(nodestate.MarkerCertExpiring):
				g.Expiring++
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
		if n.Unreported {
			g.Unreported++
		}
		// A Node with no recorded fingerprint is not "on a different Policy
		// fingerprint". It is not reported, and it is counted once, in
		// g.Unreported.
		if modeFingerprint != "" && n.PolicyFingerprint != "" && n.PolicyFingerprint != modeFingerprint {
			g.OffMode++
		}
		if n.PolicyFingerprint != "" {
			g.Fingerprinted++
			distinctFingerprints[n.PolicyFingerprint] = struct{}{}
		}
	}
	g.Fingerprints = len(distinctFingerprints)

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
	for _, n := range g.Deviations {
		if n.hasStateCell() {
			g.ShowState = true
			break
		}
	}

	normal := len(nodes) - deviating
	switch {
	case deviating == 0:
		g.ModeLine = "every Node here is reachable, current and permitted — no state label anywhere in this group."
	case normal == 0 && g.Unreported > 0:
		g.ModeLine = "no Node in this group can be called reachable, current and permitted: " +
			countOf(g.Unreported, "Node has", "Nodes have") + " not reported a daemon version or Policy fingerprint."
	case normal == 0:
		g.ModeLine = "every Node in this group carries at least one state label."
	case g.Unreported > 0:
		not := "so it is not counted as current or permitted."
		if g.Unreported > 1 {
			not = "so they are not counted as current or permitted."
		}
		g.ModeLine = countOf(normal, "other Node carries", "other Nodes carry") +
			" no state label at all — reachable, current, permitted. " +
			countOf(g.Unreported, "Node has", "Nodes have") + " not reported, " + not
	default:
		g.ModeLine = countOf(normal, "Node carries", "Nodes carry") +
			" no state label at all — reachable, current, permitted."
	}

	// A group opens when it has something to show: a deviation, drift, or few
	// enough Nodes that the fleet itself is the thing worth showing. Only a
	// LARGE, uniformly healthy group compresses to one line — which is the case
	// the compression was for.
	g.Open = deviating > 0 || g.OffMode > 0 || g.ListsWholeFleet
	return g
}

// countOf renders a count AND its noun: "1 Node", "3 Nodes". It is the Go-side
// counterpart to the template funcMap's "plural" (screen.go), which returns
// ONLY the word and leaves the number to the template.
//
// The two are deliberately named differently because they once were not. Both
// took (int, string, string) and returned string, so nothing at either
// definition revealed that a sibling with the opposite contract existed, and
// which one you got depended purely on whether you were inside a template or
// inside Go. That cost three wrong conclusions in a single session (#550): a
// double-prefixed "1 1 Account" written in Go from the template's contract, a
// correct template line reported as a double-render bug from this contract,
// and a reviewer who believed the report and nearly filed ~25 phantom bugs.
// No code was ever wrong; only readers were. Hence a name that states the
// contract instead of a comment asking people to remember it.
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
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
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	}
}

// modalValue returns the most common non-empty value of f across nodes, or ""
// when nothing is reported.
//
// The mode is used ONLY to count how many Nodes differ from it, and that count
// is rendered as an observation ("4 Nodes on 3 Policy fingerprints"), never
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
	for _, build := range []func([]fleetNode, linkContext) (facet, bool){
		stateFacet,
		daemonVersionFacet,
		policyFingerprintFacet,
		templateSetFacet,
		nodeRoleFacet,
	} {
		if f, ok := build(nodes, link); ok {
			out = append(out, f)
		}
	}
	return out
}

// stateFacet builds the State facet; false when no Node contributes a value.
//
// The State facet mixes two namespaces on purpose — an operator scanning for
// "what is wrong here" wants derived conditions and declared fences in one
// list — so each row renders as its own CHIP and the namespace stays
// visible. Both `relay:` fences and `state:` markers resolve as a Selector
// term (#414); `revoked` alone does not, because it is not a label at all.
func stateFacet(nodes []fleetNode, link linkContext) (facet, bool) {
	stateRows := facet{Title: "State"}
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
			stateRows.Values = append(stateRows.Values,
				facetValue{Label: term, Count: count, Fenced: term})
			continue
		}
		chip := stateChip[term]
		v := facetValue{Label: term, Count: count, Term: term, Chip: &chip}
		if chip.Namespace == NamespaceRelay || chip.Namespace == NamespaceState {
			v.Targetable = true
			v.Href = link.href(term)
		}
		stateRows.Values = append(stateRows.Values, v)
	}
	if len(stateRows.Values) == 0 {
		return facet{}, false
	}
	sortFacet(&stateRows)
	return stateRows, true
}

// daemonVersionFacet builds the Daemon version facet; false when no Node contributes a value.
//
// Daemon version is self-reported (registry.Node.DaemonVersion, copied
// straight out of Hello — tunnel.go) and has the IDENTICAL bypass the
// fingerprint facets below had: no short hash, so the raw value went
// straight into the href. It is also validFactValue's own documented
// example of the injection (nodestate.go's doc comment uses
// `"1.4.2, tag:x=y"`), so leaving it out would leave the exemplar live.
// The map is already keyed by the full value with no sentinels, so no
// re-keying is needed here — only routing the term through nodestate.Facts
// instead of concatenating it.
func daemonVersionFacet(nodes []fleetNode, link linkContext) (facet, bool) {
	versions := map[string]int{}
	versionTerms := map[string]string{}
	versionRefused := false
	for _, n := range nodes {
		if n.DaemonVersion == "" {
			// Counted, not skipped, so the facet sums to the group's Node count.
			versions[factSentinelUnreported]++
			continue
		}
		key := facetValueKey(n.DaemonVersion)
		versions[key]++
		// Harmless last-writer-wins: every Node reporting the same version
		// produces the same term, because nodestate.Facts is a pure function
		// of the value.
		versionTerms[key] = n.versionTerm
		if n.versionTerm == "" {
			versionRefused = true
		}
	}
	f := facetFrom("Daemon version", versions, link, func(k string) (string, string, bool) {
		if k == factSentinelUnreported {
			// Absence is not a label — there is nothing to target.
			return "not reported", "", false
		}
		term := versionTerms[k]
		return strings.TrimPrefix(k, facetValuePrefix), term, term != ""
	})
	if len(f.Values) == 0 {
		return facet{}, false
	}
	if versionRefused {
		f.Hint = facetRefusalHint
	}
	return f, true
}

// policyFingerprintFacet builds the Policy fingerprint facet; false when no Node contributes a value.
//
// Policy fingerprint is BUCKETED by the FULL self-reported value, not the
// short hash — the short hash is only ever a display convenience
// (shortHash, in render below). Bucketing by the truncated form let a
// hostile value sharing twelve characters with an honest one either
// hijack the honest bucket's link (last-writer-wins over the nodes slice)
// or poison its count; keying by the full value makes both impossible,
// because a Node can only ever share a bucket with another Node reporting
// the SAME full value. The facet has one sentinel, "not reported", for a Node
// with no recorded fingerprint; real values are keyed through facetValueKey so
// a Node self-reporting the literal "not reported" never joins the sentinel row.
func policyFingerprintFacet(nodes []fleetNode, link linkContext) (facet, bool) {
	policies := map[string]int{}
	policyTerms := map[string]string{}
	policyRefused := false
	for _, n := range nodes {
		if n.PolicyFingerprint == "" {
			policies[factSentinelUnreported]++
			continue
		}
		key := facetValueKey(n.PolicyFingerprint)
		policies[key]++
		policyTerms[key] = n.policyTerm
		if n.policyTerm == "" {
			policyRefused = true
		}
	}
	f := facetFrom("Policy fingerprint", policies, link, func(k string) (string, string, bool) {
		if k == factSentinelUnreported {
			return "not reported", "", false
		}
		term := policyTerms[k]
		return shortHash(strings.TrimPrefix(k, facetValuePrefix)), term, term != ""
	})
	if len(f.Values) == 0 {
		return facet{}, false
	}
	if policyRefused {
		f.Hint = facetRefusalHint
	}
	return f, true
}

// templateSetFacet builds the Template set facet; false when no Node contributes a value.
//
// The template-set facet, in its specified slot. Omitting it left question
// two of the four ("will it take work?") with no fleet-level answer for
// template vocabulary: `state:template-unloadable` was countable, but the
// fingerprint that says WHICH set is installed — and therefore whether a
// rollout is half-landed — was nowhere.
//
// This map mixes real values with two closed-vocabulary sentinels, so —
// unlike the Policy fingerprint facet above — bucketing by the raw full
// value is NOT safe on its own: the sentinel literal "no templates installed" is
// itself a legal (if unlikely) self-reported string, and a Node reporting
// it verbatim would key into the genuine "no templates installed" bucket
// and inflate its count. facetValueKey and the sentinel consts
// below give the two kinds of key disjoint PREFIXES, so that collision is
// structurally unreachable rather than merely unlikely.
func templateSetFacet(nodes []fleetNode, link linkContext) (facet, bool) {
	templates := map[string]int{}
	templateTerms := map[string]string{}
	templateRefused := false
	for _, n := range nodes {
		switch {
		case n.TemplateFingerprint == nodestate.TemplateUnloadable:
			templates[templateSentinelUnloadable]++
		case n.TemplateFingerprint != "":
			key := facetValueKey(n.TemplateFingerprint)
			templates[key]++
			templateTerms[key] = n.templateTerm
			if n.templateTerm == "" {
				templateRefused = true
			}
		default:
			templates[templateSentinelNoneInstalled]++
		}
	}
	f := facetFrom("Template set", templates, link, func(k string) (string, string, bool) {
		switch k {
		case templateSentinelUnloadable:
			// "unloadable" maps to the marker term, not a fact: the fingerprint
			// field holds the literal "unloadable" rather than a hash (ADR-0021).
			return "unloadable", "state:template-unloadable", true
		case templateSentinelNoneInstalled:
			// Absence is not a label — there is nothing to target.
			return "no templates installed", "", false
		default:
			full := strings.TrimPrefix(k, facetValuePrefix)
			return shortHash(full), templateTerms[k], templateTerms[k] != ""
		}
	})
	if len(f.Values) == 0 {
		return facet{}, false
	}
	if templateRefused {
		f.Hint = facetRefusalHint
	}
	return f, true
}

// nodeRoleFacet builds the node:role facet; false when no Node contributes a value.
//
// node:role's value is now well-formed BY CONSTRUCTION at ingress
// (registry.WellFormedLabel, applied by protoconv.ParseNodeLabel —
// #504): every node: label stored in the registry has already been
// refused if it could render as more than one Selector term, so
// "node:role=" + k below is safe for exactly that reason, at the one
// gate that protects the registry, the Control API and MCP too, not just
// this renderer. Naming the predicate here rather than re-deriving the
// argument is deliberate — a second, Console-local validation path is
// precisely the fork #488 exists to remove.
func nodeRoleFacet(nodes []fleetNode, link linkContext) (facet, bool) {
	roles := map[string]int{}
	for _, n := range nodes {
		for _, l := range n.Labels {
			if l.Namespace == NamespaceNode && l.Key == "role" {
				roles[l.Value]++
			}
		}
	}
	f := facetFrom("node:role", roles, link, func(k string) (string, string, bool) {
		return k, "node:role=" + k, true
	})
	f.LabelKey = true
	return f, len(f.Values) > 0
}

// facetRefusalHint is the facet rail's one visible line explaining why some
// of a facet's values render as text instead of a link (facet.Hint,
// :195-ish, styled .fhint in assets/console.css).
//
// Driven by a REFUSAL bool at each of the three facet builders above, never by
// `!Targetable`: "no templates installed" is also unlinkable, and there is nothing
// wrong with that value — this hint would be a lie about it. It is only ever
// true when nodestate rejected a self-reported value outright.
const facetRefusalHint = "One reported value is not a link: it carries a comma, whitespace or a namespace prefix, so a Selector cannot express it."

// facetValuePrefix and the sentinel consts below key the counts map of the
// three self-reported value facets: Daemon version, Policy fingerprint and
// Template set. A facet's real values and its sentinels are DISJOINT KEY
// SPACES BY CONSTRUCTION: every real key is built by facetValueKey, the ONLY
// place a self-reported value becomes a key, and begins with facetValuePrefix;
// every sentinel key is one of the literals below and begins with
// sentinelPrefix instead. Whatever a Node sends — including the literals
// "no templates installed" or "not reported" — it can only ever reach the value space,
// never the sentinel space, because nothing outside this file ever builds a
// key with anything but facetValuePrefix in front of it. Both sides are
// prefixed, not only the sentinels, so the invariant survives someone later
// editing one constant without noticing the other.
const (
	facetValuePrefix = "v:"

	sentinelPrefix                = "s:"
	templateSentinelUnloadable    = sentinelPrefix + "unloadable"
	templateSentinelNoneInstalled = sentinelPrefix + "none-installed"
	// factSentinelUnreported is a Node with no recorded daemon version or
	// Policy fingerprint, in the facet for that field.
	factSentinelUnreported = sentinelPrefix + "unreported"
)

// facetValueKey is the ONLY way a self-reported value becomes a key in a
// value facet's counts map — see the key-space comment above.
func facetValueKey(value string) string {
	return facetValuePrefix + value
}

// fencedRevoked is how the State facet names revocation. Not a label — a
// revoked Node carries no label at all — so it is spelled once here and
// rendered through the same declared-act chip the deviation table uses.
const fencedRevoked = "revoked"

// sortFacet orders a facet's values, largest bucket first.
//
// key is the LAST tiebreak, after Count then Label. It is REQUIRED, not
// cosmetic: the fingerprint and template-set facets now key by the full
// self-reported value while displaying only a shortHash Label, so two
// distinct keys can share a Label. facetFrom ranges a map to build Values, so
// without a deterministic final tiebreak the order among same-Label rows
// would be Go's map-iteration order — different on every render, on a screen
// this file's own comment says exists so the operator can browse it as a
// stable page.
func sortFacet(f *facet) {
	sort.Slice(f.Values, func(i, j int) bool {
		if f.Values[i].Count != f.Values[j].Count {
			return f.Values[i].Count > f.Values[j].Count
		}
		if f.Values[i].Label != f.Values[j].Label {
			return f.Values[i].Label < f.Values[j].Label
		}
		return f.Values[i].key < f.Values[j].key
	})
}

// facetFrom builds one facet, largest bucket first.
//
// render is keyed by the map's FULL-value key, not the display string: the
// fingerprint and template-set facets bucket by the full self-reported value
// while displaying a shortHash label, so label and key are no longer the
// same string. render returns the label, the recorded Selector term, and
// whether the value is targetable; a refused value MUST come back with an
// empty term — facetFrom uses targetable, never term itself, to decide
// whether to compute an Href, so a caller cannot smuggle a term through
// without also setting targetable.
func facetFrom(title string, counts map[string]int, link linkContext, render func(key string) (label, term string, targetable bool)) facet {
	f := facet{Title: title}
	for k, c := range counts {
		label, term, targetable := render(k)
		v := facetValue{Label: label, key: k, Count: c, Targetable: targetable}
		if targetable {
			v.Term = term
			v.Href = link.href(term)
		}
		f.Values = append(f.Values, v)
	}
	sortFacet(&f)
	return f
}

var fleetTmpl = newScreen("fleet", `
<form class="viewbar" method="get" action="/console/">
  <div class="vfield wide">
    <label class="vlabel" for="filter">Filter</label>
    <input id="filter" name="filter" value="{{.Filter}}" placeholder="e.g. node:role=web, state:offline" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="group">Group by</label>
    <select id="group" name="group">
      <option value="-"{{if eq .GroupBy ""}} selected{{end}}>nothing</option>
      {{range .GroupKeys}}<option value="{{.}}"{{if eq $.GroupBy .}} selected{{end}}>node:{{.}}</option>{{end}}
    </select>
  </div>
  {{with .Pin.Raw}}<input type="hidden" name="pin" value="{{.}}">{{end}}
  <button type="submit">Apply</button>
  <span class="vcount">{{.Matched}} of {{.Total}} {{plural .Total "Node" "Nodes"}}</span>
</form>

{{if .Pin.Any}}{{template "pin-bar" .Pin}}{{end}}

{{if not .FilterOK}}<div class="filtererr"><b>That filter was not applied.</b> {{.FilterError}}</div>{{end}}
{{if .NoMatch}}
<div class="empty">
  <h2>No Nodes match this Selector.</h2>
  <p>No Node in this fleet matches every term of <code>{{.Filter}}</code>.
  <a href="{{.ClearHref}}">Clear the filter</a>.</p>
</div>
{{end}}

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
      {{if $.GroupBy}}<span class="walllabel" aria-hidden="true"><span class="ident">{{.Key}}</span></span>{{end}}
      <div class="wallcells">{{range .Nodes}}<a class="cell" data-bucket="{{.Bucket}}" href="{{.Href}}{{$.Pin.Query}}" tabindex="-1" aria-hidden="true" title="{{.ID}}{{with .Hostname}} — {{.}}{{end}} · {{.BucketLabel}}"></a>{{end}}</div>
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
    {{if .Expiring}}<span class="gdev attn">{{.Expiring}} certificate expiring</span>{{end}}
    {{if .Unloadable}}<span class="gdev drift">{{.Unloadable}} template-unloadable</span>{{end}}
    {{if .Quarantined}}<span class="gdev quar">{{.Quarantined}} quarantined</span>{{end}}
    {{if .Revoked}}<span class="gdev quar">{{.Revoked}} revoked</span>{{end}}
    {{if .Unreported}}<span class="gdev">{{.Unreported}} not reported</span>{{end}}
    {{if .OffMode}}<span class="gdev drift">{{.Fingerprinted}} {{plural .Fingerprinted "Node" "Nodes"}} on {{.Fingerprints}} Policy {{plural .Fingerprints "fingerprint" "fingerprints"}}</span>{{end}}
    {{if not .Open}}<span class="gdev calm">no deviations</span>{{end}}
  </header>

  {{if .Open}}
  <div class="gbody">
    <div class="facets">
      {{range .Facets}}
      <div class="facet">
        <div class="ftitle">{{if .LabelKey}}<code>{{.Title}}</code>{{else}}{{.Title}}{{end}}</div>
        {{range .Values}}
        <div class="frow">
          {{if .Fenced}}<span class="chip fenced">{{.Fenced}}</span>
          {{else if .Targetable}}<a href="{{.Href}}{{$.Pin.Param}}">{{if .Chip}}{{template "label-chip" .Chip}}{{else}}{{.Label}}{{end}}</a>
          {{else}}<span>{{if .Chip}}{{template "label-chip" .Chip}}{{else}}{{.Label}}{{end}}</span>{{end}}
          <b>{{.Count}}</b>
        </div>
        {{end}}
        {{with .Hint}}<div class="fhint">{{.}}</div>{{end}}
      </div>
      {{end}}
    </div>

    <div class="devtable">
      <table class="cards">
        <caption class="tcap">{{if .ListsWholeFleet}}Every Node in <span class="ident">{{.Key}}</span>, oddest first.{{else}}Deviating Nodes in <span class="ident">{{.Key}}</span>, rarest first.{{end}}</caption>
        <thead><tr>
          <th scope="col"><span class="vh">Reachable</span></th>
          <th scope="col">Node <span class="selfreptag">hostname self-reported</span></th>{{if .ShowState}}<th scope="col">State</th>{{end}}<th scope="col">Labels</th>
          <th scope="col">Policy</th><th scope="col">Last seen</th>
        </tr></thead>
        <tbody>
        {{$showState := .ShowState}}
        {{range .Deviations}}
          <tr>
            <td class="livecell"><span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}" role="img" aria-label="{{if .Connected}}connected{{else}}not connected{{end}}"></span></td>
            <td data-label="Node{{if .Hostname}} · hostname self-reported{{end}}"><a href="{{.Href}}{{$.Pin.Query}}" class="noderef">{{with .Hostname}}<span class="selfrep" title="{{selfReportedTitle}}">{{.}}<span class="vh"> (self-reported)</span></span> {{end}}<code class="nodeid">{{.ID}}</code></a></td>
            {{if $showState}}<td data-label="State"><div class="statecell">{{if .Revoked}}<span class="chip fenced" title="Revoked {{.RevokedAt}}. The record is kept so the Node stays investigable.">revoked</span>{{end}}
              {{if .Quarantined}}<span class="chip fenced" title="Quarantined by an admin. Reversible.">quarantined</span>{{end}}
              {{if .Unreported}}<span class="chip unreported" title="The Relay holds no recorded Hello for this Node: no daemon version or no Policy fingerprint. Not a state: label, and not targetable.">not reported</span>{{end}}
              {{range .States}}{{template "label-chip" .}}{{end}}</div></td>{{end}}
            <td data-label="Labels"><div class="lblcell">{{range .Labels}}{{template "label-chip" .}}{{end}}</div></td>
            <td data-label="Policy">{{if .PolicyFingerprint}}<code title="{{.PolicyFingerprint}}">{{short .PolicyFingerprint}}</code>{{else}}<span class="dim">not reported</span>{{end}}</td>
            <td class="num" data-label="Last seen">{{.LastSeen}}</td>
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
This page draws the {{len .Groups}} largest. Narrow the filter, or group by a label key with fewer
values. A grouping with hundreds of values is only a list of Nodes by another name.</p>{{end}}

{{if not .CertExpiryKnown}}
<p class="gap"><b>{{.CertExpiryUnknown}} {{plural .CertExpiryUnknown "Node" "Nodes"}} here
{{plural .CertExpiryUnknown "has" "have"}} no recorded validity at all.</b>
{{if eq .CertExpiryUnknown 1}}It{{else}}They{{end}} enrolled before the Relay began storing certificate validity, so
<code>state:cert-expiring</code> cannot say whether {{if eq .CertExpiryUnknown 1}}it is{{else}}they are{{end}}
close to lapsing. A clean State column for {{if eq .CertExpiryUnknown 1}}this Node{{else}}these Nodes{{end}}
means unknown, not all-clear. This fills in at the next certificate renewal, at most one
certificate lifetime away.</p>
{{end}}

<details class="about">
<summary>About this screen</summary>
<p class="gap"><b>There are no host metrics here, and there will not be.</b> This screen answers
only what Relay can honestly answer about a Node: whether it is reachable, whether it will take
work, what it will permit, and who vouched for it. Host data is read on demand as a Job, with a
Plan and a blast cap, and never collected on a schedule.</p>
</details>
`)

// knownIn is the pin resolver over a Node page a screen has already read.
//
// It closes over the slice rather than re-querying, which is the whole point:
// the ids in a pin bar are whatever a link carried, and resolving them must
// not be a fresh, unrecorded look at the registry.
func knownIn(nodes []registry.Node) func(string) bool {
	set := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		set[n.NodeID] = true
	}
	return func(id string) bool { return set[id] }
}
