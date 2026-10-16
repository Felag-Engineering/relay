package hostfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

const relayID = 990

// acl builds a system.posix_acl_access value. Entries are {tag, perm, id}.
func acl(version uint32, entries ...[3]uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, uint16(e[0]))
		b = binary.LittleEndian.AppendUint16(b, uint16(e[1]))
		b = binary.LittleEndian.AppendUint32(b, e[2])
	}
	return b
}

// baseACL is the three required entries plus a mask and the given named entries.
func baseACL(groupObj uint32, mask uint32, named ...[3]uint32) []byte {
	es := [][3]uint32{{tagUserObj, 6, 0}, {tagGroupObj, groupObj, 0}, {tagOther, 0, 0}, {tagMask, mask, 0}}
	return acl(2, append(es, named...)...)
}

func dir(name string, mode uint32) Node {
	return Node{Name: name, Kind: KindDir, UID: 0, GID: 0, Mode: mode, FSType: fsExt}
}

// baseFacts is a passing path for the rule: root-owned directories on ext4 and a leaf the
// Relay (990, no capabilities) cannot write.
func baseFacts(r Rule) Facts {
	f := Facts{
		Process: Process{
			UIDs:   [3]uint32{relayID, relayID, relayID},
			GIDs:   [3]uint32{relayID, relayID, relayID},
			Groups: []uint32{relayID},
		},
		Path: []Node{dir("/", 0o755), dir("etc", 0o755), dir("relay", 0o755)},
	}
	leaf := Node{Name: "relay.toml", Kind: KindRegular, Mode: 0o644, FSType: fsExt}
	switch r {
	case Secret:
		leaf.GID, leaf.Mode = relayID, 0o640
	case GeneratedFile:
		leaf.UID, leaf.GID, leaf.Mode = relayID, relayID, 0o600
	case GeneratedDir:
		leaf = Node{Name: "state", Kind: KindDir, UID: relayID, GID: relayID, Mode: 0o700, FSType: fsExt}
	}
	f.Path = append(f.Path, leaf)
	return f
}

func (f *Facts) leaf() *Node     { return &f.Path[len(f.Path)-1] }
func (f *Facts) ancestor() *Node { return &f.Path[len(f.Path)-2] }

type decideCase struct {
	name   string
	rule   Rule
	mutate func(*Facts)
	want   Clause // 0 passes
}

func runCases(t *testing.T, cases []decideCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := baseFacts(c.rule)
			if c.mutate != nil {
				c.mutate(&f)
			}
			err := Decide(f, c.rule)
			if c.want == 0 {
				if err != nil {
					t.Fatalf("want pass, got %v", err)
				}
				return
			}
			var ref *Refusal
			if !errors.As(err, &ref) {
				t.Fatalf("want refusal %v, got %v", c.want, err)
			}
			if ref.Clause != c.want {
				t.Fatalf("want clause %v, got %v (%v)", c.want, ref.Clause, err)
			}
		})
	}
}

// TestDecide_Table is RC-15's proof: every could-write and could-read clause, the ACL
// cases, each filesystem, capability and root slot, and the sticky rule, one group per subtest.
func TestDecide_Table(t *testing.T) {
	groups := []struct {
		name string
		run  func(*testing.T)
	}{
		{"CouldWrite", tableCouldWrite},
		{"SplitIdentity", tableSplitIdentity},
		{"CouldRead", tableCouldRead},
		{"ACL", tableACL},
		{"Filesystem", tableFilesystem},
		{"Capabilities", tableCapabilities},
		{"Root", tableRoot},
		{"Sticky", tableSticky},
		{"Kind", tableKind},
		{"InvalidRule", tableInvalidRule},
	}
	for _, g := range groups {
		t.Run(g.name, g.run)
	}
}

func tableInvalidRule(t *testing.T) {
	for _, r := range []Rule{0, 99} {
		runCases(t, []decideCase{{fmt.Sprintf("rule %d", r), r, nil, ClauseInvalidRule}})
	}
}

func TestDecide_Baselines(t *testing.T) {
	for _, r := range []Rule{Named, Secret, GeneratedFile, GeneratedDir} {
		if err := Decide(baseFacts(r), r); err != nil {
			t.Errorf("rule %d: %v", r, err)
		}
	}
}

func tableCouldWrite(t *testing.T) {
	runCases(t, []decideCase{
		{"leaf owned by the Relay on a writable fs", Named, func(f *Facts) { f.leaf().UID = relayID; f.leaf().Mode = 0o400 }, ClauseOwnedOnWritableFS},
		{"read-only fs 0400 passes", Named, func(f *Facts) { f.leaf().UID = relayID; f.leaf().Mode = 0o400; f.leaf().ReadOnly = true }, 0},
		{"read-only fs 0600 refuses", Named, func(f *Facts) { f.leaf().UID = relayID; f.leaf().Mode = 0o600; f.leaf().ReadOnly = true }, ClauseWriteGrant},
		{"other write", Named, func(f *Facts) { f.leaf().Mode = 0o646 }, ClauseWriteGrant},
		{"group write, egid", Named, func(f *Facts) { f.leaf().GID = relayID; f.leaf().Mode = 0o664 }, ClauseWriteGrant},
		{"group write, supplementary", Named, func(f *Facts) { f.Process.Groups = []uint32{relayID, 40}; f.leaf().GID = 40; f.leaf().Mode = 0o664 }, ClauseWriteGrant},
		{"group write, group not the Relay's", Named, func(f *Facts) { f.leaf().GID = 41; f.leaf().Mode = 0o664 }, 0},
		{"ancestor owned by the Relay", Named, func(f *Facts) { f.ancestor().UID = relayID }, ClauseAncestorOwned},
		{"ancestor group-writable by a Relay group", Named, func(f *Facts) { f.ancestor().GID = relayID; f.ancestor().Mode = 0o775 }, ClauseAncestorWritable},
		{"ancestor other-writable", Named, func(f *Facts) { f.ancestor().Mode = 0o757 }, ClauseAncestorWritable},
		{"ancestor writable through a named-user entry", Named, func(f *Facts) {
			f.ancestor().ACL = baseACL(5, 6, [3]uint32{tagUser, 2, relayID})
		}, ClauseAncestorWritable},
		{"secret rule also refuses", Secret, func(f *Facts) { f.leaf().Mode = 0o646 }, ClauseWriteGrant},
	})
}

func tableSplitIdentity(t *testing.T) {
	slots := map[string]func(*Process){
		"real uid":      func(p *Process) { p.UIDs[0] = 1000 },
		"effective uid": func(p *Process) { p.UIDs[1] = 1000 },
		"saved uid":     func(p *Process) { p.UIDs[2] = 1000 },
		"real gid":      func(p *Process) { p.GIDs[0] = 1000 },
		"effective gid": func(p *Process) { p.GIDs[1] = 1000 },
		"saved gid":     func(p *Process) { p.GIDs[2] = 1000 },
	}
	for name, mut := range slots {
		for _, r := range []Rule{Named, Secret} {
			runCases(t, []decideCase{{fmt.Sprintf("%s/rule %d", name, r), r, func(f *Facts) { mut(&f.Process) }, ClauseSplitIdentity}})
		}
	}
	runCases(t, []decideCase{
		{"refusal is process-level", Named, func(f *Facts) {
			f.Process.UIDs[2] = 1000
			*f.leaf() = Node{Name: "relay.toml", Kind: KindRegular, UID: 1000, GID: 1000, Mode: 0o644, FSType: fsExt}
		}, ClauseSplitIdentity},
		{"uid 0 in a split slot reports root", Named, func(f *Facts) { f.Process.UIDs[0] = 0 }, ClauseRoot},
	})
}

func tableCouldRead(t *testing.T) {
	runCases(t, []decideCase{
		{"other read", Secret, func(f *Facts) { f.leaf().Mode = 0o644 }, ClauseReadableByOther},
		{"foreign owner", Secret, func(f *Facts) { f.leaf().UID = 1000; f.leaf().Mode = 0o400; f.leaf().ReadOnly = true }, ClauseReadableByOther},
		{"group read, not the Relay group", Secret, func(f *Facts) { f.leaf().GID = 4 }, ClauseReadableByOther},
		{"group read, supplementary group", Secret, func(f *Facts) { f.Process.Groups = []uint32{relayID, 4}; f.leaf().GID = 4 }, ClauseReadableByOther},
		{"root:relay 0640 passes", Secret, nil, 0},
		{"root:root 0640 refuses", Secret, func(f *Facts) { f.leaf().GID = 0 }, ClauseReadableByOther},
		{"gid 0 process, group 0 refuses", Secret, func(f *Facts) { f.Process.GIDs = [3]uint32{}; f.leaf().GID = 0 }, ClauseReadableByOther},
		{"named user r for another uid", Secret, func(f *Facts) { f.leaf().ACL = baseACL(0, 4, [3]uint32{tagUser, 4, 1000}) }, ClauseReadableByOther},
		{"named user r for the Relay passes", Secret, func(f *Facts) { f.leaf().ACL = baseACL(4, 4, [3]uint32{tagUser, 4, relayID}) }, 0},
		{"named user r for root passes", Secret, func(f *Facts) { f.leaf().ACL = baseACL(4, 4, [3]uint32{tagUser, 4, 0}) }, 0},
		{"named group r, not the egid", Secret, func(f *Facts) { f.leaf().ACL = baseACL(4, 4, [3]uint32{tagGroup, 4, 4}) }, ClauseReadableByOther},
		{"the same rows pass under Named", Named, func(f *Facts) { f.leaf().Mode = 0o644; f.leaf().UID = 1000; f.leaf().GID = 4 }, 0},
	})
}

func tableACL(t *testing.T) {
	relayRW := [3]uint32{tagUser, 6, relayID}
	runCases(t, []decideCase{
		{"named user w, mask rw-", Named, func(f *Facts) { f.leaf().ACL = baseACL(4, 6, relayRW) }, ClauseWriteGrant},
		{"named user w, mask r--", Named, func(f *Facts) { f.leaf().ACL = baseACL(4, 4, relayRW) }, 0},
		{"group-obj w, mask r--", Named, func(f *Facts) { f.leaf().GID = relayID; f.leaf().ACL = baseACL(6, 4) }, 0},
		{"group-obj w, mask rw-", Named, func(f *Facts) { f.leaf().GID = relayID; f.leaf().ACL = baseACL(6, 6) }, ClauseWriteGrant},
		{"named group w in Groups, mask rw-", Named, func(f *Facts) { f.leaf().ACL = baseACL(4, 6, [3]uint32{tagGroup, 6, relayID}) }, ClauseWriteGrant},
		{"named group w in Groups, mask r--", Named, func(f *Facts) { f.leaf().ACL = baseACL(4, 4, [3]uint32{tagGroup, 6, relayID}) }, 0},
		{"named entries without a mask", Named, func(f *Facts) {
			f.leaf().ACL = acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagUser, 4, 5}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0})
		}, ClauseACLMalformed},
		{"version 1", Named, func(f *Facts) {
			f.leaf().ACL = acl(1, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0})
		}, ClauseACLMalformed},
		{"version 3", Named, func(f *Facts) {
			f.leaf().ACL = acl(3, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0})
		}, ClauseACLMalformed},
		{"truncated", Named, func(f *Facts) { f.leaf().ACL = baseACL(4, 4)[:10] }, ClauseACLMalformed},
		{"unknown tag", Named, func(f *Facts) { f.leaf().ACL = acl(2, [3]uint32{0x40, 6, 0}) }, ClauseACLMalformed},
		{"malformed on an ancestor", Named, func(f *Facts) { f.ancestor().ACL = []byte{1} }, ClauseACLMalformed},
		{"NFSv4 ACL on the leaf", Named, func(f *Facts) { f.leaf().ForeignACL = "system.nfs4_acl" }, ClauseForeignACL},
		{"NFSv4 ACL on an ancestor", Named, func(f *Facts) { f.ancestor().ForeignACL = "system.nfs4_acl" }, ClauseForeignACL},
		{"richacl", Named, func(f *Facts) { f.leaf().ForeignACL = "system.richacl" }, ClauseForeignACL},
	})
}

func tableFilesystem(t *testing.T) {
	for name, magic := range map[string]uint32{"nfs": 0x6969, "fuse": 0x65735546, "9p": 0x01021997, "zfs": 0x2FC12FC1} {
		runCases(t, []decideCase{
			{name + " leaf", Named, func(f *Facts) { f.leaf().FSType = magic }, ClauseFilesystem},
			{name + " ancestor", Named, func(f *Facts) { f.ancestor().FSType = magic }, ClauseFilesystem},
			{name + " root directory", Named, func(f *Facts) { f.Path[0].FSType = magic }, ClauseFilesystem},
		})
	}
	for name, magic := range map[string]uint32{"ext": fsExt, "xfs": fsXFS, "btrfs": fsBtrf, "tmpfs": fsTmp, "overlay": fsOver} {
		runCases(t, []decideCase{{name + " passes", Named, func(f *Facts) { f.leaf().FSType = magic }, 0}})
	}
}

func tableCapabilities(t *testing.T) {
	for _, bit := range []uint{capChown, capDACOverride, capFowner, capSysAdmin, 10} {
		for slot, set := range map[string]func(*Process, uint64){
			"inheritable": func(p *Process, v uint64) { p.CapInh = v },
			"permitted":   func(p *Process, v uint64) { p.CapPrm = v },
			"effective":   func(p *Process, v uint64) { p.CapEff = v },
			"ambient":     func(p *Process, v uint64) { p.CapAmb = v },
		} {
			runCases(t, []decideCase{{fmt.Sprintf("bit %d %s", bit, slot), Named, func(f *Facts) { set(&f.Process, 1<<bit) }, ClauseCapability}})
		}
	}
}

func tableRoot(t *testing.T) {
	for i, slot := range []string{"real", "effective", "saved"} {
		runCases(t, []decideCase{{slot, Named, func(f *Facts) { f.Process.UIDs[i] = 0 }, ClauseRoot}})
	}
}

func tableSticky(t *testing.T) {
	tmp := func(nextUID, tmpUID, mode uint32) func(*Facts) {
		return func(f *Facts) {
			f.ancestor().Mode = mode
			f.ancestor().UID = tmpUID
			f.leaf().UID = nextUID
			f.leaf().Mode = 0o400
			f.leaf().ReadOnly = true
		}
	}
	runCases(t, []decideCase{
		{"sticky 1755 ancestor the Relay cannot write, root-owned next", Named, tmp(0, 0, 0o1755), 0},
		{"sticky 1777 ancestor, root-owned next", Named, tmp(0, 0, 0o1777), ClauseAncestorWritable},
		{"sticky 1775 ancestor writable by a Relay group", Named, func(f *Facts) {
			tmp(0, 0, 0o1775)(f)
			f.ancestor().GID = relayID
		}, ClauseAncestorWritable},
		{"sticky 1755 ancestor, Relay-owned next", Named, tmp(relayID, 0, 0o1755), ClauseStickyNextNotRoot},
		{"sticky 1755 ancestor, other-owned next", Named, tmp(1000, 0, 0o1755), ClauseStickyNextNotRoot},
		{"sticky 1777 ancestor, other-owned next", Named, tmp(1000, 0, 0o1777), ClauseStickyNextNotRoot},
		{"Relay-owned sticky ancestor", Named, tmp(0, relayID, 0o1755), ClauseAncestorOwned},
	})
}

func tableKind(t *testing.T) {
	runCases(t, []decideCase{
		{"fifo leaf", Named, func(f *Facts) { f.leaf().Kind = KindOther }, ClauseNotRegular},
		{"directory leaf under Named", Named, func(f *Facts) { f.leaf().Kind = KindDir }, ClauseNotRegular},
		{"symlink leaf", Named, func(f *Facts) { f.leaf().Kind = KindSymlink }, ClauseSymlink},
		{"symlink ancestor", Named, func(f *Facts) { f.ancestor().Kind = KindSymlink }, ClauseSymlink},
		{"empty path", Named, func(f *Facts) { f.Path = nil }, ClauseNotAbsolute},
		{"path not from the root", Named, func(f *Facts) { f.Path = f.Path[1:] }, ClauseNotAbsolute},
	})
}

func TestDecide_GeneratedMaterialRule(t *testing.T) {
	root := func(f *Facts) { f.leaf().UID = 0 }
	runCases(t, []decideCase{
		{"file 0640", GeneratedFile, func(f *Facts) { f.leaf().Mode = 0o640 }, ClauseGeneratedAccessByOther},
		{"file 0604", GeneratedFile, func(f *Facts) { f.leaf().Mode = 0o604 }, ClauseGeneratedAccessByOther},
		{"file 0620", GeneratedFile, func(f *Facts) { f.leaf().Mode = 0o620 }, ClauseGeneratedAccessByOther},
		{"file 0601", GeneratedFile, func(f *Facts) { f.leaf().Mode = 0o601 }, ClauseGeneratedAccessByOther},
		{"file root-owned 0600", GeneratedFile, root, ClauseGeneratedNotOwned},
		{"file named user r, mask r", GeneratedFile, func(f *Facts) { f.leaf().ACL = baseACL(0, 4, [3]uint32{tagUser, 4, 1000}) }, ClauseGeneratedAccessByOther},
		{"file named user r, mask ---", GeneratedFile, func(f *Facts) { f.leaf().ACL = baseACL(0, 0, [3]uint32{tagUser, 4, 1000}) }, 0},
		{"file named user for the Relay", GeneratedFile, func(f *Facts) { f.leaf().ACL = baseACL(0, 6, [3]uint32{tagUser, 6, relayID}) }, 0},
		{"dir 0750", GeneratedDir, func(f *Facts) { f.leaf().Mode = 0o750 }, ClauseGeneratedAccessByOther},
		{"dir 0701", GeneratedDir, func(f *Facts) { f.leaf().Mode = 0o701 }, ClauseGeneratedAccessByOther},
		{"dir on a regular file", GeneratedDir, func(f *Facts) { f.leaf().Kind = KindRegular }, ClauseNotDirectory},
		{"file under Relay-owned ancestors", GeneratedFile, func(f *Facts) {
			f.ancestor().UID = relayID
			f.ancestor().Mode = 0o700
		}, 0},
		{"dir under a sticky ancestor, Relay-owned next", GeneratedDir, func(f *Facts) { f.ancestor().Mode = 0o1777 }, ClauseStickyNextNotRoot},
		{"dir under a sticky ancestor, root-owned next", GeneratedDir, func(f *Facts) { f.Path[1].Mode = 0o1777 }, 0},
	})
}

func TestRefusal_Message(t *testing.T) {
	f := baseFacts(Named)
	f.Process.CapEff = 1 << capDACOverride
	err := Decide(f, Named)
	want := "hostfile: refusing /etc/relay/relay.toml: the Relay holds a capability (CAP_DAC_OVERRIDE)"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	f = baseFacts(Named)
	f.leaf().Mode = 0o646
	want = "hostfile: refusing /etc/relay/relay.toml: relay.toml: a mode bit or access-control list grants the Relay, or one of its groups, write"
	if err := Decide(f, Named); err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}

// The helpers fail closed on an ACL that does not parse, whatever order Decide calls them in.
func TestHelpers_UnparsableACLFailsClosed(t *testing.T) {
	p := baseFacts(Named).Process
	n := Node{Name: "x", Kind: KindRegular, Mode: 0o600, GID: relayID, ACL: []byte{1}}
	if !writableBy(n, p) || !readableByOther(n, p) || !accessByOther(n, p) {
		t.Fatal("an unparsable ACL must read as granting everything")
	}
}
