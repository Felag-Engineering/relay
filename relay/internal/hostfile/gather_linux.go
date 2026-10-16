package hostfile

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxXattr = 64 << 10

// Open checks path under r (Named, Secret or GeneratedFile) and returns the descriptor the
// facts were gathered from. Any non-nil error must be treated as a refusal, whether or not
// errors.As finds a *Refusal in it: a failure to gather facts also means the file was not
// decided on. The caller never reads a file that was not the one decided on.
func Open(path string, r Rule) (*os.File, error) {
	switch r {
	case Named, Secret, GeneratedFile:
		return open(path, r, false)
	}
	return nil, errors.New("hostfile: Open needs a file rule")
}

// OpenDir checks the directory at path under GeneratedDir and returns its descriptor.
func OpenDir(path string, r Rule) (*os.File, error) {
	if r != GeneratedDir {
		return nil, errors.New("hostfile: OpenDir needs the GeneratedDir rule")
	}
	return open(path, r, true)
}

func open(path string, r Rule, wantDir bool) (*os.File, error) {
	facts, f, err := gather(path, wantDir)
	if err != nil {
		return nil, err
	}
	if err := Decide(facts, r); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// gatherProcess reads the Relay's identity.
//
// Linux credentials and capability sets are per thread. /proc/self/status reports the
// thread-group leader, which stands for every thread on the premise that each holds the
// leader's sets: Go applies the set*id family to every thread, threads inherit their
// creator's sets, and the Relay makes no per-thread capset call. One added anywhere in the
// Relay would break this. /proc/thread-self is no better for a Go process, whose goroutines
// migrate between threads.
func gatherProcess() (Process, error) {
	var p Process
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	ids := []int{ruid, euid, suid, rgid, egid, sgid}
	out := make([]uint32, len(ids))
	for i, id := range ids {
		v, ok := toUint32(id)
		if !ok {
			return p, fmt.Errorf("hostfile: process id %d out of range", id)
		}
		out[i] = v
	}
	copy(p.UIDs[:], out[:3])
	copy(p.GIDs[:], out[3:])

	supp, err := unix.Getgroups()
	if err != nil {
		return p, fmt.Errorf("hostfile: reading supplementary groups: %w", err)
	}
	seen := map[uint32]bool{}
	for _, g := range append(supp, egid) {
		v, ok := toUint32(g)
		if !ok {
			return p, fmt.Errorf("hostfile: group id %d out of range", g)
		}
		if !seen[v] {
			seen[v] = true
			p.Groups = append(p.Groups, v)
		}
	}

	st, err := os.Open("/proc/self/status")
	if err != nil {
		return p, fmt.Errorf("hostfile: reading process capabilities: %w", err)
	}
	defer func() { _ = st.Close() }()
	if p.CapInh, p.CapPrm, p.CapEff, p.CapAmb, err = parseCapabilities(st); err != nil {
		return p, err
	}
	return p, nil
}

func toUint32(v int) (uint32, bool) {
	if v < 0 || int64(v) > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

// gather walks path from "/" one component at a time, never following a symbolic link, and
// takes each component's facts from its own descriptor. It returns the leaf's descriptor,
// open and positioned for reading. It applies no policy beyond symbolic links and
// absoluteness; Decide owns every other refusal.
func gather(path string, wantDir bool) (Facts, *os.File, error) {
	var facts Facts
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return facts, nil, &Refusal{Path: path, Clause: ClauseNotAbsolute}
	}
	if path == "/" {
		// The root directory is never a Named or Secret file, and never the Relay's.
		c := ClauseNotRegular
		if wantDir {
			c = ClauseGeneratedNotOwned
		}
		return facts, nil, &Refusal{Path: path, Clause: c}
	}
	proc, err := gatherProcess()
	if err != nil {
		return facts, nil, err
	}
	facts.Process = proc

	dfd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return facts, nil, fmt.Errorf("hostfile: opening /: %w", err)
	}
	root, err := nodeFacts(dfd, "/")
	if err != nil {
		_ = unix.Close(dfd)
		return facts, nil, err
	}
	facts.Path = append(facts.Path, root)

	parts := strings.Split(path[1:], "/")
	for i, name := range parts {
		last := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if !last || wantDir {
			flags |= unix.O_DIRECTORY
		}
		if last {
			// A device node at the configured path is opened before Decide refuses it, and
			// open(2) on a device can have driver side effects that O_NONBLOCK and O_NOCTTY
			// limit but cannot exclude. The path comes from configuration only the host
			// administrator writes, and the open is read-only.
			flags |= unix.O_NONBLOCK | unix.O_NOCTTY
		}
		fd, err := unix.Openat(dfd, name, flags, 0)
		if err != nil {
			err = classifyOpenError(dfd, path, name, last && wantDir, err)
			_ = unix.Close(dfd)
			return facts, nil, err
		}
		_ = unix.Close(dfd)
		dfd = fd

		node, err := nodeFacts(dfd, name)
		if err != nil {
			_ = unix.Close(dfd)
			return facts, nil, err
		}
		facts.Path = append(facts.Path, node)
	}

	if err := unix.SetNonblock(dfd, false); err != nil {
		_ = unix.Close(dfd)
		return facts, nil, fmt.Errorf("hostfile: %s: %w", parts[len(parts)-1], err)
	}
	return facts, os.NewFile(uintptr(dfd), path), nil
}

// classifyOpenError turns a failed openat into a refusal when a symbolic link caused it,
// and otherwise into an error naming the component only.
func classifyOpenError(dfd int, path, name string, leafDir bool, err error) error {
	if errors.Is(err, unix.ELOOP) {
		return &Refusal{Path: path, Component: name, Clause: ClauseSymlink}
	}
	if errors.Is(err, unix.ENOTDIR) {
		var st unix.Stat_t
		if unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return &Refusal{Path: path, Component: name, Clause: ClauseSymlink}
			}
			if leafDir {
				return &Refusal{Path: path, Component: name, Clause: ClauseNotDirectory}
			}
		}
	}
	return fmt.Errorf("hostfile: %s: %w", name, err)
}

func nodeFacts(fd int, name string) (Node, error) {
	n := Node{Name: name}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return n, fmt.Errorf("hostfile: %s: %w", name, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		n.Kind = KindRegular
	case unix.S_IFDIR:
		n.Kind = KindDir
	case unix.S_IFLNK:
		n.Kind = KindSymlink
	default:
		n.Kind = KindOther
	}
	n.Dev, n.Ino = st.Dev, st.Ino
	n.UID, n.GID = st.Uid, st.Gid
	n.Mode = st.Mode & 0o7777

	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return n, fmt.Errorf("hostfile: %s: %w", name, err)
	}
	// f_type is a 32-bit magic number; on a 32-bit kernel int32 sign-extends, so mask first.
	n.FSType = uint32(int64(fs.Type) & math.MaxUint32)
	n.ReadOnly = fs.Flags&unix.ST_RDONLY != 0

	var err error
	if n.ACL, err = readXattr(fd, "system.posix_acl_access"); err != nil {
		return n, fmt.Errorf("hostfile: %s: %w", name, err)
	}
	for _, attr := range []string{"system.nfs4_acl", "system.richacl"} {
		v, err := readXattr(fd, attr)
		if err != nil {
			return n, fmt.Errorf("hostfile: %s: %w", name, err)
		}
		if v != nil {
			n.ForeignACL = attr
			break
		}
	}
	return n, nil
}

// readXattr returns nil when the attribute is absent or the filesystem has no xattrs, and a
// non-nil empty slice when it is present and empty.
func readXattr(fd int, attr string) ([]byte, error) {
	for range 2 {
		size, err := unix.Fgetxattr(fd, attr, nil)
		if err != nil {
			if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
				return nil, nil
			}
			return nil, fmt.Errorf("reading %s: %w", attr, err)
		}
		if size > maxXattr {
			return nil, fmt.Errorf("%s too large", attr)
		}
		if size == 0 {
			// An empty buffer makes the kernel answer a size query, so a second
			// call could report a nonzero length that buf cannot hold.
			return []byte{}, nil
		}
		buf := make([]byte, size)
		n, err := unix.Fgetxattr(fd, attr, buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			if errors.Is(err, unix.ENODATA) {
				return nil, nil
			}
			return nil, fmt.Errorf("reading %s: %w", attr, err)
		}
		if n > len(buf) {
			return nil, fmt.Errorf("%s changed while reading", attr)
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("%s changed while reading", attr)
}
