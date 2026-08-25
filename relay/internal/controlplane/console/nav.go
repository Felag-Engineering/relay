package console

import (
	"sort"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
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
// What this is NOT is an authorization decision. A link that is not drawn is
// not a permission that was checked; the capability layer's RoleGate answers
// that when the request arrives, for this surface exactly as for MCP and the
// Control API. Drawing fewer links is a courtesy to the operator, not a control.
func Nav(d Deps, role accounts.Role, currentPath string) []NavSection {
	byGroup := map[NavGroup][]Route{}
	for _, r := range Routes(d) {
		if r.Nav.Label == "" {
			continue
		}
		if !accounts.Role(role).AtLeast(r.MinRole) {
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
