//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
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
