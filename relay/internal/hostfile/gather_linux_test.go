package hostfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// base returns a temp directory whose path contains no symbolic link.
func base(t *testing.T) string {
	t.Helper()
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantRefusal(t *testing.T, err error, c Clause, component string) {
	t.Helper()
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if ref.Clause != c || ref.Component != component {
		t.Fatalf("got clause %v component %q, want %v %q", ref.Clause, ref.Component, c, component)
	}
}

func TestGather_SymlinkedAncestorRefused(t *testing.T) {
	b := base(t)
	if err := os.Mkdir(filepath.Join(b, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(b, "real", "f"), "x")
	if err := os.Symlink(filepath.Join(b, "real"), filepath.Join(b, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(b, "real", "f"), filepath.Join(b, "leaflink")); err != nil {
		t.Fatal(err)
	}

	_, f, err := gather(filepath.Join(b, "link", "f"), false)
	wantRefusal(t, err, ClauseSymlink, "link")
	if f != nil {
		t.Fatal("a file was returned with the refusal")
	}
	_, _, err = gather(filepath.Join(b, "leaflink"), false)
	wantRefusal(t, err, ClauseSymlink, "leaflink")
	_, _, err = gather(filepath.Join(b, "leaflink"), true)
	wantRefusal(t, err, ClauseSymlink, "leaflink")

	f2, err := Open(filepath.Join(b, "link", "f"), Named)
	wantRefusal(t, err, ClauseSymlink, "link")
	if f2 != nil {
		t.Fatal("a file was returned with the refusal")
	}
}

func TestGather_FIFOLeafDoesNotBlock(t *testing.T) {
	b := base(t)
	fifo := filepath.Join(b, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	type result struct {
		facts Facts
		err   error
	}
	done := make(chan result, 1)
	go func() {
		facts, f, err := gather(fifo, false)
		if f != nil {
			_ = f.Close()
		}
		done <- result{facts, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gather blocked on a FIFO")
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	leaf := res.facts.Path[len(res.facts.Path)-1]
	if leaf.Kind != KindOther {
		t.Fatalf("leaf kind %v, want KindOther", leaf.Kind)
	}

	synthetic := baseFacts(Named)
	synthetic.Path = append(synthetic.Path[:3], Node{Kind: leaf.Kind, Name: leaf.Name, FSType: fsExt})
	wantRefusal(t, Decide(synthetic, Named), ClauseNotRegular, "fifo")

	opened := make(chan error, 1)
	go func() {
		f, err := Open(fifo, Named)
		if f != nil {
			_ = f.Close()
			opened <- errors.New("a file was returned")
			return
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		var ref *Refusal
		if !errors.As(err, &ref) {
			t.Fatalf("want a refusal, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Open blocked on a FIFO")
	}
}

// TestGather_DecisionAndReadShareDescriptor: ReadSecretFile opens the webhook
// secret with Open under the Secret rule, and Open decides on the facts gather
// took from one descriptor and returns that same descriptor for the read. A file
// swapped in after gather is never what is read.
//
// Proves RC-48.
func TestGather_DecisionAndReadShareDescriptor(t *testing.T) {
	b := base(t)
	path := filepath.Join(b, "f")
	write(t, path, "original")
	facts, f, err := gather(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	other := filepath.Join(b, "other")
	write(t, other, "replaced")
	var replacement unix.Stat_t
	if err := unix.Stat(other, &replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("read %q, want the file the facts came from", got)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	leaf := facts.Path[len(facts.Path)-1]
	if leaf.Dev != st.Dev || leaf.Ino != st.Ino {
		t.Fatalf("facts are for %d/%d, the descriptor is %d/%d", leaf.Dev, leaf.Ino, st.Dev, st.Ino)
	}
	if leaf.Ino == replacement.Ino {
		t.Fatal("facts describe the replacement")
	}
}

func TestGather_RecordsDescriptorFacts(t *testing.T) {
	b := base(t)
	path := filepath.Join(b, "f")
	write(t, path, "x")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	facts, f, err := gather(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	leaf := facts.Path[len(facts.Path)-1]
	if leaf.Kind != KindRegular || leaf.Mode&0o777 != 0o640 || int(leaf.UID) != os.Getuid() || leaf.Name != "f" {
		t.Fatalf("leaf %+v", leaf)
	}
	root := facts.Path[0]
	if root.Name != "/" || root.Kind != KindDir {
		t.Fatalf("root %+v", root)
	}
	if want := strings.Count(path, "/") + 1; len(facts.Path) != want {
		t.Fatalf("%d nodes, want %d", len(facts.Path), want)
	}
	r, e, s := unix.Getresuid()
	gr, ge, gs := unix.Getresgid()
	p := facts.Process
	if int(p.UIDs[0]) != r || int(p.UIDs[1]) != e || int(p.UIDs[2]) != s ||
		int(p.GIDs[0]) != gr || int(p.GIDs[1]) != ge || int(p.GIDs[2]) != gs {
		t.Fatalf("process %+v", p)
	}
}

func TestGather_RefusesRelativeAndUnclean(t *testing.T) {
	for _, p := range []string{"relay.toml", "/etc/../etc/x", "/etc//x"} {
		_, _, err := gather(p, false)
		wantRefusal(t, err, ClauseNotAbsolute, "")
	}
}

func TestFSMagicMatchesUnix(t *testing.T) {
	for name, pair := range map[string][2]uint32{
		"ext":     {fsExt, unix.EXT4_SUPER_MAGIC},
		"xfs":     {fsXFS, unix.XFS_SUPER_MAGIC},
		"btrfs":   {fsBtrf, unix.BTRFS_SUPER_MAGIC},
		"tmpfs":   {fsTmp, unix.TMPFS_MAGIC},
		"overlay": {fsOver, unix.OVERLAYFS_SUPER_MAGIC},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: %#x != %#x", name, pair[0], pair[1])
		}
	}
}

// Whatever user runs the tests, a file that user owns is one the Relay could write, and
// root is refused as root: the default everywhere is a refusal.
func TestOpen_RefusesTestUsersOwnFile(t *testing.T) {
	path := filepath.Join(base(t), "f")
	write(t, path, "x")
	f, err := Open(path, Named)
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if f != nil {
		t.Fatal("a file was returned with the refusal")
	}
}

func TestOpen_RuleMismatch(t *testing.T) {
	if _, err := Open("/", GeneratedDir); err == nil {
		t.Fatal("Open accepted a directory rule")
	}
	if _, err := OpenDir("/", Named); err == nil {
		t.Fatal("OpenDir accepted a file rule")
	}
}

func TestGather_RootPathRefused(t *testing.T) {
	_, _, err := gather("/", false)
	wantRefusal(t, err, ClauseNotRegular, "")
	_, _, err = gather("/", true)
	wantRefusal(t, err, ClauseGeneratedNotOwned, "")
}

// TestDecide_EmptyACLRefuses: a present but zero-length ACL value is non-nil and
// does not parse, so it refuses rather than reading as "no ACL".
func TestDecide_EmptyACLRefuses(t *testing.T) {
	f := baseFacts(Named)
	f.leaf().ACL = []byte{}
	wantRefusal(t, Decide(f, Named), ClauseACLMalformed, "relay.toml")
}
