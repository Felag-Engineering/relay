// Package hostfile decides whether the Relay could write a file it reads, or another
// account could read it, on the descriptor it then reads from (ADR-0043, invariant 11).
// It imports nothing from relay/internal and only ever refuses: no flag, environment
// variable or build tag makes it pass.
//
// Decide is pure over gathered Facts; Open and OpenDir (Linux) gather the Facts from the
// descriptor they return, so the decision and the read share one file (RC-16). Where the
// check is not defined, Open and OpenDir refuse.
package hostfile

import (
	"fmt"
	"strings"
)

// Rule says what a path is for, and so which clauses apply to it.
type Rule int

const (
	// Named is a file the configuration names: refused if the Relay could write it.
	Named Rule = iota + 1
	// Secret is the configuration file or any file holding a secret: Named, plus refused
	// if any account but the Relay and root could read it.
	Secret
	// GeneratedFile is key material the Relay generates (RC-17), on a regular file.
	GeneratedFile
	// GeneratedDir is the state directory the Relay generates material in (RC-17).
	GeneratedDir
)

// Kind is the file type of a Node.
type Kind int

const (
	KindRegular Kind = iota + 1
	KindDir
	KindSymlink
	// KindOther is a FIFO, socket or device.
	KindOther
)

// Process is the identity the Relay runs as.
type Process struct {
	UIDs   [3]uint32 // real, effective, saved
	GIDs   [3]uint32 // real, effective, saved
	Groups []uint32  // supplementary groups plus the effective gid, deduplicated

	CapInh, CapPrm, CapEff, CapAmb uint64
}

// Node is one component of the path, as read from its own descriptor.
type Node struct {
	Name string // the component; the root directory is "/"
	Kind Kind
	Dev  uint64
	Ino  uint64
	UID  uint32
	GID  uint32
	Mode uint32 // permission bits plus S_ISVTX

	ACL        []byte // raw system.posix_acl_access; nil when absent
	ForeignACL string // system.nfs4_acl or system.richacl when present, else empty
	FSType     uint32
	ReadOnly   bool
}

// Facts is everything Decide looks at. Path[0] is the root directory, the last element is
// the leaf, and everything between is an ancestor in walk order.
type Facts struct {
	Process Process
	Path    []Node
}

// Clause names the reason for a refusal.
type Clause int

const (
	ClauseUnsupportedOS Clause = iota + 1
	ClauseNotAbsolute
	ClauseSymlink
	ClauseRoot
	ClauseSplitIdentity
	ClauseCapability
	ClauseFilesystem
	ClauseForeignACL
	ClauseACLMalformed
	ClauseAncestorOwned
	ClauseAncestorWritable
	ClauseStickyNextNotRoot
	ClauseNotRegular
	ClauseNotDirectory
	ClauseOwnedOnWritableFS
	ClauseWriteGrant
	ClauseReadableByOther
	ClauseGeneratedNotOwned
	ClauseGeneratedAccessByOther
	ClauseInvalidRule
)

// String is a one-line reason, never file content.
func (c Clause) String() string {
	switch c {
	case ClauseUnsupportedOS:
		return "the file-safety check is defined only on Linux"
	case ClauseNotAbsolute:
		return "the path is not absolute and clean"
	case ClauseSymlink:
		return "a symbolic link is on the path"
	case ClauseRoot:
		return "the Relay runs as root (a real, effective or saved user id is 0)"
	case ClauseSplitIdentity:
		return "real, effective and saved user or group ids differ; the Relay could switch to another of them and write as it"
	case ClauseCapability:
		return "the Relay holds a capability"
	case ClauseFilesystem:
		return "the filesystem is not one whose reported owner and mode can be trusted"
	case ClauseForeignACL:
		return "an NFSv4 or richacl access-control list is present"
	case ClauseACLMalformed:
		return "the POSIX access-control list is malformed"
	case ClauseAncestorOwned:
		return "a directory above it is owned by the Relay"
	case ClauseAncestorWritable:
		return "a directory above it is writable by the Relay"
	case ClauseStickyNextNotRoot:
		return "a sticky directory above it contains an entry not owned by root"
	case ClauseNotRegular:
		return "it is not a regular file"
	case ClauseNotDirectory:
		return "it is not a directory"
	case ClauseOwnedOnWritableFS:
		return "the Relay owns it on a filesystem mounted writable"
	case ClauseWriteGrant:
		return "a mode bit or access-control list grants the Relay, or one of its groups, write"
	case ClauseReadableByOther:
		return "an account other than the Relay and root could read it"
	case ClauseGeneratedNotOwned:
		return "generated material is not owned by the Relay"
	case ClauseGeneratedAccessByOther:
		return "generated material grants access to an account other than the Relay"
	case ClauseInvalidRule:
		return "the rule is not one of Named, Secret, GeneratedFile or GeneratedDir"
	}
	return "unknown"
}

// Refusal is the error every refusal returns. It names the path and component, never
// file content. Process-level refusals have an empty Component.
type Refusal struct {
	Path      string
	Component string
	Clause    Clause
	Detail    string // extra, content-free reason text; may be empty
}

func (r *Refusal) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "hostfile: refusing %s: ", r.Path)
	if r.Component != "" {
		fmt.Fprintf(&b, "%s: ", r.Component)
	}
	b.WriteString(r.Clause.String())
	if r.Detail != "" {
		fmt.Fprintf(&b, " (%s)", r.Detail)
	}
	return b.String()
}

// Filesystems whose reported owner and mode are the kernel's own.
const (
	fsExt  uint32 = 0xEF53
	fsXFS  uint32 = 0x58465342
	fsBtrf uint32 = 0x9123683E
	fsTmp  uint32 = 0x01021994
	fsOver uint32 = 0x794C7630
)

func trustedFS(t uint32) bool {
	switch t {
	case fsExt, fsXFS, fsBtrf, fsTmp, fsOver:
		return true
	}
	return false
}

// Capability bits that mean "could write".
const (
	capChown       = 0
	capDACOverride = 1
	capFowner      = 3
	capSysAdmin    = 21
)

const sticky = 0o1000

// Decide returns nil, or the first *Refusal in the order of the steps below. The order is
// part of the contract: tests assert the clause.
func Decide(f Facts, r Rule) error {
	p := f.Process
	path := pathOf(f.Path)
	refuse := func(component string, c Clause) error {
		return &Refusal{Path: path, Component: component, Clause: c}
	}

	switch r {
	case Named, Secret, GeneratedFile, GeneratedDir:
	default:
		return refuse("", ClauseInvalidRule)
	}

	// a. The process.
	for _, u := range p.UIDs {
		if u == 0 {
			return refuse("", ClauseRoot)
		}
	}
	if p.UIDs[0] != p.UIDs[1] || p.UIDs[1] != p.UIDs[2] ||
		p.GIDs[0] != p.GIDs[1] || p.GIDs[1] != p.GIDs[2] {
		return refuse("", ClauseSplitIdentity)
	}
	if caps := p.CapInh | p.CapPrm | p.CapEff | p.CapAmb; caps != 0 {
		var named []string
		for _, c := range []struct {
			bit  uint
			name string
		}{{capChown, "CAP_CHOWN"}, {capDACOverride, "CAP_DAC_OVERRIDE"}, {capFowner, "CAP_FOWNER"}, {capSysAdmin, "CAP_SYS_ADMIN"}} {
			if caps&(1<<c.bit) != 0 {
				named = append(named, c.name)
			}
		}
		return &Refusal{Path: path, Clause: ClauseCapability, Detail: strings.Join(named, ", ")}
	}

	// b. The path.
	if len(f.Path) == 0 || f.Path[0].Name != "/" || f.Path[0].Kind != KindDir {
		return refuse("", ClauseNotAbsolute)
	}

	// c. Every descriptor on the path.
	for _, n := range f.Path {
		if !trustedFS(n.FSType) {
			return refuse(n.Name, ClauseFilesystem)
		}
		if n.ForeignACL != "" {
			return refuse(n.Name, ClauseForeignACL)
		}
		if n.ACL != nil {
			if _, err := parsePOSIXACL(n.ACL); err != nil {
				return refuse(n.Name, ClauseACLMalformed)
			}
		}
		if n.Kind == KindSymlink {
			return refuse(n.Name, ClauseSymlink)
		}
	}

	uid := p.UIDs[1]
	generated := r == GeneratedFile || r == GeneratedDir

	// d. The ancestors.
	for i := 0; i < len(f.Path)-1; i++ {
		n, next := f.Path[i], f.Path[i+1]
		isSticky := n.Mode&sticky != 0
		if isSticky && next.UID != 0 {
			return refuse(n.Name, ClauseStickyNextNotRoot)
		}
		if generated {
			continue
		}
		if n.UID == uid {
			return refuse(n.Name, ClauseAncestorOwned)
		}
		// A sticky directory the Relay can write is refused like any other: the sticky bit
		// only adds the next-component rule above, never a waiver.
		if writableBy(n, p) {
			return refuse(n.Name, ClauseAncestorWritable)
		}
	}

	// e. The leaf kind.
	leaf := f.Path[len(f.Path)-1]
	if r == GeneratedDir {
		if leaf.Kind != KindDir {
			return refuse(leaf.Name, ClauseNotDirectory)
		}
	} else if leaf.Kind != KindRegular {
		return refuse(leaf.Name, ClauseNotRegular)
	}

	switch r {
	case Named, Secret:
		// f. Could the Relay write it.
		if leaf.UID == uid && !leaf.ReadOnly {
			return refuse(leaf.Name, ClauseOwnedOnWritableFS)
		}
		if writableBy(leaf, p) {
			return refuse(leaf.Name, ClauseWriteGrant)
		}
		// g. Could another account read it.
		if r == Secret && readableByOther(leaf, p) {
			return refuse(leaf.Name, ClauseReadableByOther)
		}
	case GeneratedFile, GeneratedDir:
		// h. Generated material belongs to the Relay alone.
		if leaf.UID != uid {
			return refuse(leaf.Name, ClauseGeneratedNotOwned)
		}
		if accessByOther(leaf, p) {
			return refuse(leaf.Name, ClauseGeneratedAccessByOther)
		}
	}
	return nil
}

func pathOf(nodes []Node) string {
	if len(nodes) == 0 {
		return ""
	}
	names := make([]string, 0, len(nodes))
	for _, n := range nodes[1:] {
		names = append(names, n.Name)
	}
	return "/" + strings.Join(names, "/")
}

func inGroups(g uint32, p Process) bool {
	for _, x := range p.Groups {
		if x == g {
			return true
		}
	}
	return false
}

// parsedACL returns the node's POSIX ACL (nil when it has none), and false when the ACL
// does not parse. Decide refuses a malformed ACL before it calls the helpers below, but
// that ordering is not relied on: each helper treats an unparsable ACL as granting
// everything it looks for, so reordering Decide cannot make one pass.
func parsedACL(n Node) (*posixACL, bool) {
	if n.ACL == nil {
		return nil, true
	}
	a, err := parsePOSIXACL(n.ACL)
	if err != nil {
		return nil, false
	}
	return &a, true
}

// writableBy is the union of every grant, deliberately more conservative than the
// kernel's first-match evaluation.
func writableBy(n Node, p Process) bool {
	uid := p.UIDs[1]
	if n.UID == uid && n.Mode&0o200 != 0 {
		return true
	}
	if n.Mode&0o002 != 0 {
		return true
	}
	a, ok := parsedACL(n)
	if !ok {
		return true
	}
	if a == nil {
		return n.Mode&0o020 != 0 && inGroups(n.GID, p)
	}
	for _, e := range a.users {
		if e.id == uid && a.effective(e.perm)&permW != 0 {
			return true
		}
	}
	if inGroups(n.GID, p) && a.effective(a.groupObj)&permW != 0 {
		return true
	}
	for _, e := range a.groups {
		if inGroups(e.id, p) && a.effective(e.perm)&permW != 0 {
			return true
		}
	}
	return false
}

// readableByOther reports whether any account but root and the Relay (user and group)
// could read n. The Relay group is the effective gid and never gid 0.
func readableByOther(n Node, p Process) bool {
	uid, egid := p.UIDs[1], p.GIDs[1]
	if n.UID != 0 && n.UID != uid {
		return true
	}
	if n.Mode&0o004 != 0 {
		return true
	}
	foreignGroup := func(g uint32) bool { return g != egid || egid == 0 }
	a, ok := parsedACL(n)
	if !ok {
		return true
	}
	if a == nil {
		return n.Mode&0o040 != 0 && foreignGroup(n.GID)
	}
	if a.effective(a.groupObj)&permR != 0 && foreignGroup(n.GID) {
		return true
	}
	for _, e := range a.users {
		if a.effective(e.perm)&permR != 0 && e.id != 0 && e.id != uid {
			return true
		}
	}
	for _, e := range a.groups {
		if a.effective(e.perm)&permR != 0 && foreignGroup(e.id) {
			return true
		}
	}
	return false
}

// accessByOther reports whether n grants any permission bit to anyone but its owner.
func accessByOther(n Node, p Process) bool {
	uid := p.UIDs[1]
	if n.Mode&0o007 != 0 {
		return true
	}
	a, ok := parsedACL(n)
	if !ok {
		return true
	}
	if a == nil {
		return n.Mode&0o070 != 0
	}
	if a.effective(a.groupObj) != 0 {
		return true
	}
	for _, e := range a.users {
		if e.id != uid && a.effective(e.perm) != 0 {
			return true
		}
	}
	for _, e := range a.groups {
		if a.effective(e.perm) != 0 {
			return true
		}
	}
	return false
}
