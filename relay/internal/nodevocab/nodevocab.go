// Package nodevocab holds the Relay's in-memory, thread-safe, DISPLAY-ONLY
// cache of each Node's daemon-reported Template Operation vocabulary
// (relayv1.TemplateSnapshot; ADR-0021).
//
// Display and discovery only. Templates are locally rooted on the Node and
// remotely-immutable (ADR-0002 applies to them verbatim), and only the
// daemon's live engine decides whether a given Operation may run (ADR-0011,
// invariant 12). Nothing in this package validates a parameter, renders a
// template body, or makes an allow/deny decision — it records what a daemon
// reported so list_operations/describe_node can tell a caller which
// Operations a given Node actually has. The template BODY never crosses the
// wire at all (see relay.proto's TemplateDescriptor), so it cannot be cached
// here even by accident.
//
// Proto-free domain mirror, following the policyview / registry.Facts
// precedent: this package carries no proto dependency. The caller
// (relay/cmd/relay's tunnel handler) converts relayv1.TemplateSnapshot into
// Snapshot before calling Set.
//
// In-memory, not registry/store — the policyview precedent again: a snapshot
// is refreshed on every (re)connect, and a Relay restart empties the cache
// until each Node reconnects, so a caller correctly sees reported=false for a
// Node that has not reported yet rather than a stale vocabulary. The Node's
// template-set FINGERPRINT is persisted (registry.Node.TemplateSetFingerprint,
// from Hello) — that is the durable drift signal; this is the detail view.
package nodevocab

import "sync"

// Slot is a proto-free mirror of relayv1.TemplateSlot: one typed parameter
// slot of a Template Operation. Type is the daemon's slot-type name
// ("identifier", "integer", "path", "enum"); EnumValues is populated only for
// "enum". Display-only — the daemon validates, never this package.
type Slot struct {
	Name       string
	Type       string
	EnumValues []string
}

// Template is a proto-free mirror of relayv1.TemplateDescriptor: one Template
// Operation as reported by one Node. RiskClass is the ADR-0012 class the
// template's author declared (mandatory), carried here as the raw wire enum
// value so the renderer can map it with the same helper it uses for Native
// Operations. Slots are in declaration order — which is the positional order
// Policy evaluates the args in.
type Template struct {
	Name      string
	RiskClass int32
	Slots     []Slot
}

// Snapshot is a proto-free mirror of relayv1.TemplateSnapshot: the Template
// Operation vocabulary one Node reported, at the time it reported it.
//
// Fingerprint is the same value that Node's Hello carried (registry.Node
// .TemplateSetFingerprint): empty means "no templates installed", the literal
// "unloadable" means the Node's local template set failed to load and its
// template vocabulary is empty (fail closed, daemon-side).
type Snapshot struct {
	Fingerprint string
	Templates   []Template
}

// clone returns a deep copy so Set/Get never let a caller mutate cached state
// through a shared slice (policyview.Snapshot.clone precedent).
func (s Snapshot) clone() Snapshot {
	out := s
	if s.Templates != nil {
		out.Templates = make([]Template, len(s.Templates))
		for i, t := range s.Templates {
			ct := Template{Name: t.Name, RiskClass: t.RiskClass}
			if t.Slots != nil {
				ct.Slots = make([]Slot, len(t.Slots))
				for j, sl := range t.Slots {
					ct.Slots[j] = Slot{
						Name:       sl.Name,
						Type:       sl.Type,
						EnumValues: append([]string(nil), sl.EnumValues...),
					}
				}
			}
			out.Templates[i] = ct
		}
	}
	return out
}

// Cache is an in-memory, thread-safe store of the most recently reported
// Snapshot per node_id.
type Cache struct {
	mu sync.RWMutex
	m  map[string]Snapshot
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{m: make(map[string]Snapshot)}
}

// Set records the latest Snapshot reported for nodeID, replacing any previous
// value. s is deep-copied on entry so a later mutation by the caller cannot
// reach the cached value.
func (c *Cache) Set(nodeID string, s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[nodeID] = s.clone()
}

// Get returns a deep copy of the most recently reported Snapshot for nodeID,
// or (Snapshot{}, false) if none has been captured yet — e.g. the Node has not
// (re)connected since the Relay last started, or it runs a daemon predating
// the template tier. Absence is never "this Node has no templates": that is
// what a reported snapshot with no Templates says.
func (c *Cache) Get(nodeID string) (Snapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.m[nodeID]
	if !ok {
		return Snapshot{}, false
	}
	return s.clone(), true
}
