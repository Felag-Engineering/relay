package console

import (
	"sort"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// NavGroup is one of the navigation's two headings. The grouping is
// load-bearing rather than decorative: it makes the model legible (observe,
// then administer) and it makes the ABSENCE of a settings section, and of any
// execution surface, visible (00-foundations.md "Navigation"). Invariant 11
// depends on nobody quietly adding a settings section.
type NavGroup string

const (
	NavObserve    NavGroup = "Observe"
	NavAdminister NavGroup = "Administer"
)

// navGroupOrder fixes the order the headings render in. It is not alphabetical
// and must not become alphabetical: the sequence is the teaching.
var navGroupOrder = []NavGroup{NavObserve, NavAdminister}

// NavEntry describes a route's place in the navigation. The zero value means
// the route is reachable but not advertised — node detail and job detail are
// reached from a row, not from a menu.
type NavEntry struct {
	Group NavGroup
	Label string
	Order int

	// Under lists the path roots of screens reached from this destination
	// rather than from the menu (node detail from a Fleet row, Job detail from
	// an Activity row). A request at a root, or beneath it, marks this item
	// current. Roots of different destinations must not overlap: exactly one
	// item is current on any screen. The slice makes NavEntry, and so Route,
	// non-comparable: never compare one with ==.
	Under []string
}

// NavItem is one rendered navigation link.
type NavItem struct {
	Label   string
	Path    string
	Current bool
}

// NavSection is one rendered heading and its links. A section with no items is
// dropped rather than rendered empty.
type NavSection struct {
	Group NavGroup
	Items []NavItem
}

// Slug is the section's id-safe name, used to point each list's
// aria-labelledby at its own heading. Without it the two lists are announced
// as two anonymous lists, and the grouping — which nav.go calls the teaching
// — reaches a sighted operator and nobody else.
func (s NavSection) Slug() string { return strings.ToLower(string(s.Group)) }

// Nav projects the mounted route table into the navigation a principal with
// role should see, marking the destination currentPath is, or was reached from
// (NavEntry.Under).
//
// It is a PROJECTION, and that is the whole design. Both of the properties the
// specification cares about fall out of it rather than being maintained by
// hand:
//
//   - No route in the table executes, so no Run item can be projected
//     (ADR-0052).
//   - A viewer's navigation is structurally smaller, because a route whose
//     MinRole they do not meet is not projected.
//
// Nav draws no role comparison of its own: it consumes [routesFor], the same
// projection Register's mount-time gate applies to every request. A drawn
// link and a reachable route are one fact, computed once, not two
// implementations that happen to agree today. Nav still decides nothing by
// itself — the capability layer's RoleGate is what a request meets when it
// arrives, for this surface exactly as for MCP and the Control API — but a
// link that is not drawn is now also a route that is not there to visit.
func Nav(d Deps, role accounts.Role, currentPath string) []NavSection {
	byGroup := map[NavGroup][]Route{}
	for _, r := range routesFor(d, role) {
		if r.Nav.Label == "" {
			continue
		}
		byGroup[r.Nav.Group] = append(byGroup[r.Nav.Group], r)
	}

	var out []NavSection
	for _, g := range navGroupOrder {
		rs := byGroup[g]
		if len(rs) == 0 {
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Nav.Order < rs[j].Nav.Order })
		items := make([]NavItem, 0, len(rs))
		for _, r := range rs {
			items = append(items, NavItem{
				Label:   r.Nav.Label,
				Path:    r.Link(),
				Current: navCurrent(r, currentPath),
			})
		}
		out = append(out, NavSection{Group: g, Items: items})
	}
	return out
}

// navCurrent reports whether path is the screen r advertises or one reached from
// it. The Link comparison is exact, never a prefix: Fleet's link is "/console/",
// which prefixes every path. Under roots match on a segment boundary, so
// "/console/accountsx" is not under "/console/accounts".
func navCurrent(r Route, path string) bool {
	if path == "" {
		return false
	}
	if path == r.Link() {
		return true
	}
	for _, root := range r.Nav.Under {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}
