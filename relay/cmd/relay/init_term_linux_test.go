//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns a pseudo-terminal's controller and terminal ends.
func openPTY(t *testing.T) (controller, term *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	t.Cleanup(func() { controller.Close() })
	fd := int(controller.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("pty number: %v", err)
	}
	term, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("cannot open the pty's terminal end: %v", err)
	}
	t.Cleanup(func() { term.Close() })
	return controller, term
}

// echoes pumps everything the terminal sends back to the controller into a
// channel, from one reader for the whole test, so no stray read can swallow output
// a later check is waiting for.
func echoes(controller *os.File) <-chan string {
	out := make(chan string, 64)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := controller.Read(buf)
			if n > 0 {
				out <- string(buf[:n])
			}
			if err != nil {
				close(out)
				return
			}
		}
	}()
	return out
}

// within collects what arrives on ch for d.
func within(ch <-chan string, d time.Duration) string {
	var sb strings.Builder
	deadline := time.After(d)
	for {
		select {
		case s, ok := <-ch:
			if !ok {
				return sb.String()
			}
			sb.WriteString(s)
		case <-deadline:
			return sb.String()
		}
	}
}

// The first admin's password is read from the terminal with echo off (RC-28): typed
// on a real pseudo-terminal, nothing of it comes back, and the terminal's echo is on
// again afterwards. The positive control shows the same pty does echo a line read
// normally, so the absence is the setting and not the harness.
func TestReadNoEcho_ThePasswordIsNotEchoedAndEchoIsRestored(t *testing.T) {
	controller, term := openPTY(t)
	back := echoes(controller)
	if !isTerminal(term) {
		t.Fatal("isTerminal is false for a pseudo-terminal")
	}

	const secret = "correct horse battery staple"
	done := make(chan string, 1)
	go func() {
		line, err := readNoEcho(term)
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- line
	}()
	time.Sleep(50 * time.Millisecond) // let the read turn echo off first
	if _, err := controller.Write([]byte(secret + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-done:
		if line != secret {
			t.Fatalf("readNoEcho = %q, want the typed line", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readNoEcho did not return")
	}
	if echoed := within(back, 300*time.Millisecond); strings.Contains(echoed, "horse") {
		t.Errorf("the password was echoed: %q", echoed)
	}

	tio, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ECHO == 0 {
		t.Error("echo is still off after readNoEcho returned")
	}

	// Positive control: a plain read on the same pty echoes.
	go func() {
		buf := make([]byte, 64)
		_, _ = term.Read(buf)
	}()
	if _, err := controller.Write([]byte("visible line\n")); err != nil {
		t.Fatal(err)
	}
	if echoed := within(back, 2*time.Second); !strings.Contains(echoed, "visible") {
		t.Errorf("positive control: the pty did not echo a normal read (%q), so the test above proves nothing", echoed)
	}
}

func TestIsTerminal_FalseForAFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("isTerminal is true for a regular file")
	}
}

// typeLines writes each line to the terminal once the reader is waiting.
func typeLines(t *testing.T, controller *os.File, lines ...string) {
	t.Helper()
	for _, l := range lines {
		time.Sleep(100 * time.Millisecond)
		if _, err := controller.Write([]byte(l + "\n")); err != nil {
			t.Errorf("type a line: %v", err)
			return
		}
	}
}

// On a terminal the password is asked for twice; two different entries create
// nothing.
func TestInitFirstAdmin_TwoDifferentEntriesCreateNothing(t *testing.T) {
	controller, term := openPTY(t)
	_ = echoes(controller)
	st := openInitStore(t)
	io := newInitIO(t, "")
	go typeLines(t, controller, "correct horse battery staple", "correct horse battery stapler")
	code := initFirstAdmin(context.Background(), st, "alice", 0, term, io.stdout, io.stderr, nil)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	out, errOut := io.read(t)
	if out != "" || !strings.Contains(errOut, "the two passwords differ") {
		t.Errorf("stdout %q, stderr %q: want nothing, and the mismatch", out, errOut)
	}
	if all, _ := st.Accounts().List(context.Background()); len(all) != 0 {
		t.Errorf("accounts = %+v, want none", all)
	}
}

// An interrupt at the prompt restores the terminal's echo before the process
// exits with 130, and the handler is gone once the read returns.
func TestReadNoEcho_AnInterruptRestoresEchoThenExits130(t *testing.T) {
	controller, term := openPTY(t)
	_ = echoes(controller)
	exited := make(chan bool, 1)
	exitOnInterrupt = func(code int) {
		tio, err := unix.IoctlGetTermios(int(term.Fd()), unix.TCGETS)
		exited <- code == interruptedExitCode && err == nil && tio.Lflag&unix.ECHO != 0
	}
	t.Cleanup(func() { exitOnInterrupt = os.Exit })

	done := make(chan struct{})
	go func() {
		_, _ = readNoEcho(term)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // let the read install its handler and turn echo off
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-exited:
		if !ok {
			t.Error("the interrupt exited with echo still off, or with a code other than 130")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the interrupt was not handled")
	}
	if _, err := controller.Write([]byte("end\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readNoEcho did not return")
	}

	// The handler is removed with the prompt: an interrupt now reaches a
	// channel of the test's own, and exitOnInterrupt is not called again.
	own := make(chan os.Signal, 1)
	signal.Notify(own, syscall.SIGINT)
	defer signal.Stop(own)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	<-own
	select {
	case <-exited:
		t.Error("the prompt's interrupt handler outlived the prompt")
	case <-time.After(200 * time.Millisecond):
	}
}

// A pasted line longer than the terminal's line buffer is cut short by the
// terminal itself; it is refused, never taken as a shorter password.
func TestReadNoEcho_RefusesALineAtTheTerminalLimit(t *testing.T) {
	controller, term := openPTY(t)
	_ = echoes(controller)
	type result struct {
		line string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		line, err := readNoEcho(term)
		got <- result{line, err}
	}()
	time.Sleep(100 * time.Millisecond)
	go func() { _, _ = controller.Write([]byte(strings.Repeat("x", 5000) + "\n")) }()
	select {
	case r := <-got:
		if r.err == nil {
			t.Fatalf("a %d-byte line was accepted as a password", len(r.line))
		}
		if !strings.Contains(r.err.Error(), "limit") {
			t.Errorf("err = %v, want the terminal-limit refusal", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readNoEcho did not return")
	}
}

// Proves EN-39: init offers the mint form only with a terminal on both stdin and stdout.
func TestInitInteractive_NeedsATerminalOnStdinAndStdout(t *testing.T) {
	_, term := openPTY(t)
	file, err := os.CreateTemp(t.TempDir(), "stdio")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for name, c := range map[string]struct {
		stdin, stdout *os.File
		want          bool
	}{
		"both terminals":   {term, term, true},
		"stdin is a file":  {file, term, false},
		"stdout is a file": {term, file, false},
	} {
		if got := initInteractive(c.stdin, c.stdout); got != c.want {
			t.Errorf("%s: initInteractive = %v, want %v", name, got, c.want)
		}
	}
}
