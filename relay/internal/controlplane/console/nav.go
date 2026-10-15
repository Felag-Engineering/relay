package console

import (
	"sort"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// NavGroup is one of the navigation's three headings. The grouping is
// load-bearing rather than decorative: it makes the model legible (observe,
// then act, then administer) and it makes the ABSENCE of a settings section
// visible, which invariant 11 depends on nobody quietly adding.
type NavGroup string

const (
	NavObserve    NavGroup = "Observe"
	NavAct        NavGroup = "Act"
	NavAdminister NavGroup = "Administer"
)

// navGroupOrder fixes the order the headings render in. It is not alphabetical
// and must not become alphabetical: the sequence is the teaching.
var navGroupOrder = []NavGroup{NavObserve, NavAct, NavAdminister}

// NavEntry describes a route's place in the navigation. The zero value means
// the route is reachable but not advertised — node detail and job detail are
// reached from a row, not from a menu.
type NavEntry struct {
	Group NavGroup
	Label string
	Order int
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
// aria-labelledby at its own heading. Without it the three lists are announced
// as three anonymous lists, and the grouping — which nav.go calls the teaching
// — reaches a sighted operator and nobody else.
func (s NavSection) Slug() string { return strings.ToLower(string(s.Group)) }

// Nav projects the mounted route table into the navigation a principal with
// role should see, marking currentPath.
//
// It is a PROJECTION, and that is the whole design. Both of the properties the
// specification cares about fall out of it rather than being maintained by
// hand:
//
//   - With console_execution off, Routes never returns the execution routes, so
//     Run cannot appear here. Absent, not disabled (ADR-0026 decision 5).
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
				Current: r.Link() == currentPath,
			})
		}
		out = append(out, NavSection{Group: g, Items: items})
	}
	return out
}
