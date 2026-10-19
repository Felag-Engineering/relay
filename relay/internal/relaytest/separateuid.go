package relaytest

// The separate-uid real-binary harness. A test that starts a real Relay binary starts it
// through a RelayLayout, so the Relay runs as TestUser over fixtures root owns: it can write
// neither its configuration nor its binary, which is the property the Relay's start-time check
// enforces on the files it reads (ADR-0043). No binary carries a way round that check; the
// harness is the only way a test meets it.
//
// The layout is in two places. The files the check reads are under /run, because the check
// refuses a file below any directory the Relay can write and /tmp is world-writable; /run is
// root-owned and writable by nobody else. The binaries are under /tmp, because /run is often
// mounted noexec (it is on GitHub's runners) and the check never looks at the binary:
//
//	<base>/        root:root              0755  /run/relaytest.*
//	  etc/         root:relaytest         0750  the configuration, root:relaytest 0640
//	  state/       relaytest:relaytest    0700  the CA directory and the store
//	  io/          relaytest:relaytest-io 2770  the devharness socket and the Relay's log
//	<bin>/         root:root              0755  /tmp/relaytest-bin.*: root-owned copies of
//	                                            the binaries under test
//
// The test is in TestIOGroup and in nothing else the Relay owns, so it reaches the socket and
// the log only through that group, and no member of that group can read or write the
// configuration, the CA or the store. A public file the test needs from state/ (the CA
// certificate) is copied out through sudo.
//
// Without passwordless sudo, setpriv, the accounts (scripts/relaytest-user.sh) or the group
// membership the test cannot run at all: the Relay refuses to start over files its own uid
// could write. The test is skipped and the skip recorded in make verify's skip ledger, never
// passed over; SudoRequiredEnv set to "1" (CI only) makes it a failure instead.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	// SudoRequiredEnv names the switch CI sets to "1": under it, a real-binary test that
	// cannot run the Relay as a separate uid fails instead of recording a skip.
	SudoRequiredEnv = "RELAY_E2E_SUDO_REQUIRED"
	// TestUser is the account the Relay under test runs as.
	TestUser = "relaytest"
	// TestIOGroup is the Relay's one supplementary group, shared with the test, and the only
	// way the test reaches the Relay's socket and log.
	TestIOGroup = "relaytest-io"

	// verifySkipsEnv is make verify's skip ledger (the Makefile's RELAY_VERIFY_SKIPS).
	verifySkipsEnv = "RELAY_VERIFY_SKIPS"
	// relayStartTimeout bounds how long sudo may take to hand over to the Relay.
	relayStartTimeout = 10 * time.Second
	// layoutParent holds every layout's checked files: root-owned and writable by nobody
	// else, so nothing above them is a directory the Relay could write.
	layoutParent = "/run"
	// binParent holds every layout's binaries: a filesystem that allows exec, which /run
	// often does not. Each layout's bin directory is root-owned under it.
	binParent = "/tmp"
)

// setprivArgs drops sudo's root to TestUser: its own uid and gid, every supplementary group
// cleared except TestIOGroup (setpriv refuses --clear-groups beside --groups, so naming the one
// group is how the rest are cleared), and no inheritable capabilities.
func setprivArgs() []string {
	return []string{"setpriv", "--reuid=" + TestUser, "--regid=" + TestUser,
		"--groups=" + TestIOGroup, "--inh-caps=-all"}
}

// separateUID is a probed, usable TestUser.
type separateUID struct {
	uid, ioGID int
}

var (
	probeOnce   sync.Once
	probedUID   *separateUID
	probeReason string
)

// probe reports, once per process, whether the Relay can run as TestUser here, and why not.
func probe() (*separateUID, string) {
	probeOnce.Do(func() { probedUID, probeReason = probeSeparateUID() })
	return probedUID, probeReason
}

// probeSeparateUID checks every prerequisite of the separate uid in the order a developer
// would fix them, and names the first one missing.
func probeSeparateUID() (*separateUID, string) {
	if _, err := exec.LookPath("sudo"); err != nil {
		return nil, "sudo is not installed"
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		return nil, "sudo -n is not passwordless here"
	}
	if err := exec.Command("sudo", "-n", "setpriv", "--version").Run(); err != nil {
		return nil, "setpriv is not installed"
	}
	u, err := user.Lookup(TestUser)
	if err != nil {
		return nil, "no " + TestUser + " user (sudo scripts/relaytest-user.sh \"$USER\" creates it)"
	}
	g, err := user.LookupGroup(TestIOGroup)
	if err != nil {
		return nil, "no " + TestIOGroup + " group (sudo scripts/relaytest-user.sh \"$USER\" creates it)"
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Sprintf("%s has a non-numeric uid %q", TestUser, u.Uid)
	}
	ioGID, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil, fmt.Sprintf("%s has a non-numeric gid %q", TestIOGroup, g.Gid)
	}
	if os.Getuid() == uid {
		return nil, "this test already runs as " + TestUser
	}
	if !canUseGroup(ioGID) {
		return nil, "this process is not in " + TestIOGroup +
			" (start a new login after relaytest-user.sh, or run under sg " + TestIOGroup + ")"
	}
	return &separateUID{uid: uid, ioGID: ioGID}, ""
}

// canUseGroup reports whether this process can reach a gid-owned 2770 directory: as root, or
// with the group as its effective or a supplementary group.
func canUseGroup(gid int) bool {
	if os.Geteuid() == 0 || os.Getegid() == gid {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

// logFataler is the slice of testing.TB requireSeparateUID uses, narrowed so both branches can
// be proven against a recorder rather than by failing a real test.
type logFataler interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// recordedSkips dedupes ledger lines within one test process: every Relay a suite starts asks,
// and the ledger should say once per suite that the separate uid did not run.
var recordedSkips sync.Map

// requireSeparateUID is the one way a test reacts to the separate uid being unavailable: under
// SudoRequiredEnv=1 it fails; otherwise it records the skip, named for gate, in make verify's
// skip ledger (when there is one) and returns, and the caller skips the test.
func requireSeparateUID(t logFataler, gate, reason string) {
	t.Helper()
	if os.Getenv(SudoRequiredEnv) == "1" {
		t.Fatalf("%s: the Relay cannot run as a separate uid: %s — and %s=1, so this is a failure, not a skip",
			gate, reason, SudoRequiredEnv)
		return
	}
	line := gate + ": the Relay as a separate uid (" + reason + ")"
	t.Logf("SKIPPING %s; the Relay refuses to start as this test's own uid", line)
	ledger := os.Getenv(verifySkipsEnv)
	if ledger == "" {
		return
	}
	if _, dup := recordedSkips.LoadOrStore(ledger+"\x00"+line, true); dup {
		return
	}
	f, err := os.OpenFile(ledger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.WriteString(line + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		// A skip that cannot be recorded would read as a pass.
		t.Fatalf("record the skip in %s: %v", ledger, err)
	}
}

// RelayLayout is the set of directories one Relay under test uses, across restarts.
type RelayLayout struct {
	sep                              *separateUID
	confDir, binDir, stateDir, ioDir string
	configs                          atomic.Int64
	binsMu                           sync.Mutex
	bins                             map[string]string
}

// NewRelayLayout builds the layout for one Relay, or skips the test (failing it under
// SudoRequiredEnv=1) where the Relay cannot run as TestUser. gate names the make target the
// calling test runs under, for the skip ledger. Every directory is removed when the test ends.
func NewRelayLayout(t *testing.T, gate string) *RelayLayout {
	t.Helper()
	sep, reason := probe()
	if sep == nil {
		requireSeparateUID(t, gate, reason)
		t.Skipf("the Relay cannot run as a separate uid here (%s)", reason)
	}

	base := strings.TrimSpace(string(sudo(t, "mktemp", "-d", layoutParent+"/relaytest.XXXXXXXX")))
	if filepath.Dir(base) != layoutParent || !strings.HasPrefix(filepath.Base(base), "relaytest.") {
		t.Fatalf("sudo mktemp returned an unexpected path %q", base)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("sudo", "-n", "rm", "-rf", "--", base).CombinedOutput(); err != nil {
			t.Errorf("remove the separate-uid layout %s: %v: %s", base, err, out)
		}
	})
	sudo(t, "chmod", "0755", base)
	binDir := strings.TrimSpace(string(sudo(t, "mktemp", "-d", binParent+"/relaytest-bin.XXXXXXXX")))
	if filepath.Dir(binDir) != binParent || !strings.HasPrefix(filepath.Base(binDir), "relaytest-bin.") {
		t.Fatalf("sudo mktemp returned an unexpected path %q", binDir)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("sudo", "-n", "rm", "-rf", "--", binDir).CombinedOutput(); err != nil {
			t.Errorf("remove the separate-uid bin directory %s: %v: %s", binDir, err, out)
		}
	})
	sudo(t, "chmod", "0755", binDir)
	l := &RelayLayout{
		sep:      sep,
		confDir:  filepath.Join(base, "etc"),
		binDir:   binDir,
		stateDir: filepath.Join(base, "state"),
		ioDir:    filepath.Join(base, "io"),
		bins:     map[string]string{},
	}
	sudo(t, "install", "-d", "-o", "root", "-g", TestUser, "-m", "0750", l.confDir)
	sudo(t, "install", "-d", "-o", TestUser, "-g", TestUser, "-m", "0700", l.stateDir)
	sudo(t, "install", "-d", "-o", TestUser, "-g", TestIOGroup, "-m", "2770", l.ioDir)
	return l
}

// sudo runs `sudo -n <args>` and returns its stdout, failing the test on any error.
func sudo(t *testing.T, args ...string) []byte {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command("sudo", append([]string{"-n"}, args...)...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sudo -n %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// RelayUID is TestUser's uid.
func (l *RelayLayout) RelayUID() int { return l.sep.uid }

// IOGID is TestIOGroup's gid.
func (l *RelayLayout) IOGID() int { return l.sep.ioGID }

// ConfigDir holds the configuration files WriteConfig writes.
func (l *RelayLayout) ConfigDir() string { return l.confDir }

// StateDir is where the Relay's CA directory and store belong. The test cannot read it;
// CopyOut is how a public file leaves it.
func (l *RelayLayout) StateDir() string { return l.stateDir }

// IODir is where the devharness socket and the Relay's log belong.
func (l *RelayLayout) IODir() string { return l.ioDir }

// InstallBinary returns the path the Relay should be started from: a root-owned copy of src in
// the layout's bin directory (TestUser could neither reach nor be trusted with a binary under
// the test user's home).
func (l *RelayLayout) InstallBinary(t *testing.T, src string) string {
	t.Helper()
	l.binsMu.Lock()
	defer l.binsMu.Unlock()
	if dst, ok := l.bins[src]; ok {
		return dst
	}
	dst := filepath.Join(l.binDir, filepath.Base(src))
	for other, d := range l.bins {
		if d == dst {
			t.Fatalf("InstallBinary %s: %s already installs as %s", src, other, dst)
		}
	}
	sudo(t, "install", "-o", "root", "-g", "root", "-m", "0755", "--", src, dst)
	l.bins[src] = dst
	return dst
}

// WriteConfig writes body as a fresh configuration file and returns its path: root:TestUser
// 0640, so the Relay can read it and nobody but root can write it.
func (l *RelayLayout) WriteConfig(t *testing.T, body string) string {
	t.Helper()
	return l.WriteFile(t, fmt.Sprintf("relay-%d.toml", l.configs.Add(1)), body, "root", TestUser, "0640")
}

// WriteFile writes body to name in ConfigDir with the given owner, group and octal mode, and
// returns its path: how a test places a secret or gate file, or a configuration file the
// start-time check must refuse.
func (l *RelayLayout) WriteFile(t *testing.T, name, body, owner, group, mode string) string {
	t.Helper()
	if strings.Contains(name, "/") {
		t.Fatalf("WriteFile %q: a name, not a path", name)
	}
	src := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", src, err)
	}
	dst := filepath.Join(l.confDir, name)
	sudo(t, "install", "-o", owner, "-g", group, "-m", mode, "--", src, dst)
	return dst
}

// Symlink makes name in ConfigDir a symbolic link to target, as root, and returns its path.
func (l *RelayLayout) Symlink(t *testing.T, target, name string) string {
	t.Helper()
	if strings.Contains(name, "/") {
		t.Fatalf("Symlink %q: a name, not a path", name)
	}
	link := filepath.Join(l.confDir, name)
	sudo(t, "ln", "-s", "--", target, link)
	return link
}

// MakeStateDir creates name under StateDir, owned by TestUser with the given octal mode, and
// returns its path: how a test hands the Relay a state location it must refuse.
func (l *RelayLayout) MakeStateDir(t *testing.T, name, mode string) string {
	t.Helper()
	if strings.Contains(name, "/") {
		t.Fatalf("MakeStateDir %q: a name, not a path", name)
	}
	dir := filepath.Join(l.stateDir, name)
	sudo(t, "install", "-d", "-o", TestUser, "-g", TestUser, "-m", mode, dir)
	return dir
}

// ChmodState sets the octal mode of path, under StateDir, as TestUser (never as root, so
// nothing the Relay planted there can redirect root).
func (l *RelayLayout) ChmodState(t *testing.T, path, mode string) {
	t.Helper()
	if rel, err := filepath.Rel(l.stateDir, path); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("ChmodState %s: not under the state directory %s", path, l.stateDir)
	}
	sudo(t, "-u", TestUser, "chmod", mode, "--", path)
}

// CopyOut returns a path the test can read holding the contents of path, a public file under
// StateDir such as the CA certificate: a copy read as TestUser — never as root, so nothing the
// Relay plants in its own directory (a symlink) can make root read for it.
func (l *RelayLayout) CopyOut(t *testing.T, path string) string {
	t.Helper()
	if rel, err := filepath.Rel(l.stateDir, path); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("CopyOut %s: not under the state directory %s", path, l.stateDir)
	}
	out := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(out, sudo(t, "-u", TestUser, "cat", "--", path), 0o600); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	return out
}

// Stat reports path's owner, group and octal mode (setgid included, as stat's %a prints it),
// read through sudo: the test may not traverse the configuration directory itself.
func (l *RelayLayout) Stat(t *testing.T, path string) (uid, gid int, mode string) {
	t.Helper()
	fields := strings.Fields(string(sudo(t, "stat", "-c", "%u %g %a", "--", path)))
	if len(fields) != 3 {
		t.Fatalf("stat %s: unexpected output %q", path, fields)
	}
	var err error
	if uid, err = strconv.Atoi(fields[0]); err == nil {
		gid, err = strconv.Atoi(fields[1])
	}
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return uid, gid, fields[2]
}

// Start launches bin (a path InstallBinary returned) with args, in exactly the environment env,
// its stdout and stderr written to a fresh log file in IODir. It runs as TestUser through
// `sudo -n setpriv`. It returns once the Relay's own process exists, not once it is
// ready; readiness is the caller's (its log). The process is killed and reaped when the test
// ends if the caller has not done so.
func (l *RelayLayout) Start(t *testing.T, bin string, env []string, args ...string) (*RelayProcess, error) {
	t.Helper()
	logFile, err := os.CreateTemp(l.ioDir, "relay-*.log")
	if err != nil {
		return nil, fmt.Errorf("create the Relay's log in %s: %w", l.ioDir, err)
	}
	argv := append([]string{"-n"}, setprivArgs()...)
	argv = append(argv, "env", "-i")
	argv = append(argv, env...)
	argv = append(argv, bin)
	argv = append(argv, args...)
	cmd := exec.Command("sudo", argv...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err = cmd.Start()
	// The child holds its own descriptor; the test reads the log by path.
	logFile.Close()
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}

	p := &RelayProcess{layout: l, cmd: cmd, logPath: logFile.Name(), done: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()

	pid, err := p.findRelayPID()
	if err != nil {
		// sudo runs as root, which the test may not signal itself.
		_ = exec.Command("sudo", "-n", "kill", "-s", "9", strconv.Itoa(cmd.Process.Pid)).Run() // it may already have exited
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
		return nil, fmt.Errorf("%w\n%s", err, p.Log())
	}
	p.pid = pid
	t.Cleanup(func() {
		_ = p.Kill() // best effort: the caller may already have ended it
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Errorf("relay pid %d did not exit within 5s of SIGKILL", p.pid)
		}
	})
	return p, nil
}

// runTimeout bounds a one-shot command Run starts.
const runTimeout = 60 * time.Second

// Run runs bin (a path InstallBinary returned) with args to completion as TestUser, through
// `sudo -n setpriv` exactly as Start does, in exactly the environment env, with stdin as its
// standard input. It returns the command's stdout and stderr, kept apart, and its exit code:
// how a test runs a one-shot Relay command such as `relay init`.
func (l *RelayLayout) Run(t *testing.T, bin string, env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	argv := append([]string{"-n"}, setprivArgs()...)
	return runToCompletion(t, append(argv, l.envArgv(env, bin, args)...), stdin)
}

// RunAsRoot is Run as root rather than TestUser: how a test shows the Relay's start-time check
// refuses to run as root. Nothing else in the harness runs a Relay binary as root.
func (l *RelayLayout) RunAsRoot(t *testing.T, bin string, env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runToCompletion(t, append([]string{"-n"}, l.envArgv(env, bin, args)...), stdin)
}

// envArgv is `env -i <env> bin <args>`.
func (l *RelayLayout) envArgv(env []string, bin string, args []string) []string {
	argv := append([]string{"env", "-i"}, env...)
	argv = append(argv, bin)
	return append(argv, args...)
}

// runToCompletion runs `sudo argv` with stdin and returns stdout, stderr and the exit code,
// failing the test if it cannot be started or does not finish within runTimeout.
func runToCompletion(t *testing.T, argv []string, stdin string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command("sudo", argv...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sudo %s: %v", strings.Join(argv, " "), err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(runTimeout):
		// sudo runs as root, which the test may not signal itself.
		_ = exec.Command("sudo", "-n", "kill", "-s", "9", strconv.Itoa(cmd.Process.Pid)).Run()
		<-done
		t.Fatalf("sudo %s did not finish within %v\nstderr: %s", strings.Join(argv, " "), runTimeout, errOut.String())
	}
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run sudo %s: %v", strings.Join(argv, " "), err)
		}
		code = exitErr.ExitCode()
	}
	return out.String(), errOut.String(), code
}

// ExistsInState reports whether path, under StateDir, exists, asked as TestUser: the test
// may not traverse the state directory itself.
func (l *RelayLayout) ExistsInState(t *testing.T, path string) bool {
	t.Helper()
	if rel, err := filepath.Rel(l.stateDir, path); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("ExistsInState %s: not under the state directory %s", path, l.stateDir)
	}
	err := exec.Command("sudo", "-n", "-u", TestUser, "test", "-e", path).Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return true
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		return false
	default:
		t.Fatalf("sudo -n -u %s test -e %s: %v", TestUser, path, err)
		return false
	}
}

// RelayProcess is one running Relay under test.
type RelayProcess struct {
	layout  *RelayLayout
	cmd     *exec.Cmd
	pid     int
	logPath string
	done    chan struct{}
	waitErr error
}

// findRelayPID waits for the Relay's own process: the descendant of sudo running as TestUser.
func (p *RelayProcess) findRelayPID() (int, error) {
	deadline := time.After(relayStartTimeout)
	for {
		if pid, ok := descendantWithUID(p.cmd.Process.Pid, p.layout.sep.uid); ok {
			return pid, nil
		}
		select {
		case <-p.done:
			return 0, fmt.Errorf("sudo exited before the Relay started as %s: %v", TestUser, p.waitErr)
		case <-deadline:
			return 0, fmt.Errorf("no process running as %s under sudo pid %d within %v",
				TestUser, p.cmd.Process.Pid, relayStartTimeout)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// descendantWithUID finds, breadth-first, a descendant of root whose real uid is uid.
func descendantWithUID(root, uid int) (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	children := map[int][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, ok := procPPid(pid); ok {
			children[ppid] = append(children[ppid], pid)
		}
	}
	queue := children[root]
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if ids, err := procStatusInts(pid, "Uid:"); err == nil && len(ids) > 0 && ids[0] == uid {
			return pid, true
		}
		queue = append(queue, children[pid]...)
	}
	return 0, false
}

// procPPid reads pid's parent from /proc/<pid>/stat, whose second field (the command name)
// may itself contain spaces and parentheses, so fields are counted after the last ')'.
func procPPid(pid int) (int, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

// procStatusField returns the whitespace-separated values of key in /proc/<pid>/status.
func procStatusField(pid int, key string) ([]string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, key); ok {
			return strings.Fields(rest), nil
		}
	}
	return nil, fmt.Errorf("no %s line in /proc/%d/status", key, pid)
}

// procStatusInts is procStatusField with decimal values.
func procStatusInts(pid int, key string) ([]int, error) {
	fields, err := procStatusField(pid, key)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("/proc/%d/status %s %q: %w", pid, key, f, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// PID is the Relay's own process id (not sudo's).
func (p *RelayProcess) PID() int { return p.pid }

// UIDs returns the Relay's real, effective, saved and filesystem uids.
func (p *RelayProcess) UIDs() ([]int, error) { return procStatusInts(p.pid, "Uid:") }

// Groups returns the Relay's supplementary groups.
func (p *RelayProcess) Groups() ([]int, error) { return procStatusInts(p.pid, "Groups:") }

// Capabilities returns the Relay's inheritable, permitted, effective and ambient capability
// sets, keyed by their /proc status names (CapInh, CapPrm, CapEff, CapAmb), as hex strings.
func (p *RelayProcess) Capabilities() (map[string]string, error) {
	caps := map[string]string{}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		v, err := procStatusField(p.pid, k+":")
		if err != nil {
			return nil, err
		}
		if len(v) != 1 {
			return nil, fmt.Errorf("/proc/%d/status %s: %v", p.pid, k, v)
		}
		caps[k] = v[0]
	}
	return caps, nil
}

// Signal delivers sig to the Relay itself, through `sudo -n -u relaytest kill`: the test may not
// signal another uid, and sudo cannot relay SIGKILL. As TestUser and not root, so a pid reused
// after the Relay exited is refused, never killed.
func (p *RelayProcess) Signal(sig syscall.Signal) error {
	select {
	case <-p.done:
		return fmt.Errorf("relay pid %d has exited", p.pid)
	default:
	}
	out, err := exec.Command("sudo", "-n", "-u", TestUser, "kill", "-s", strconv.Itoa(int(sig)), strconv.Itoa(p.pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo -n -u %s kill -s %d %d: %w: %s", TestUser, int(sig), p.pid, err, out)
	}
	return nil
}

// Kill sends the Relay SIGKILL: a crash, not a shutdown.
func (p *RelayProcess) Kill() error { return p.Signal(syscall.SIGKILL) }

// Done is closed once the process the test started (sudo) has exited.
func (p *RelayProcess) Done() <-chan struct{} { return p.done }

// Err is the exit error of the process the test started; meaningful once Done is closed.
func (p *RelayProcess) Err() error {
	<-p.done
	return p.waitErr
}

// Log returns everything the Relay has written to stdout and stderr so far.
func (p *RelayProcess) Log() string {
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		return fmt.Sprintf("(read relay log %s: %v)", p.logPath, err)
	}
	return string(data)
}
