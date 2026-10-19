//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// terminalLineLimit is the longest line a Linux terminal in canonical mode
// hands a reader: its line buffer holds 4096 bytes, the newline included, and
// it silently drops what is typed or pasted past that. A line that reaches it
// may have been cut short, so it is refused rather than taken as a different
// password than the one entered.
const terminalLineLimit = 4095

// interruptedExitCode is the shell's code for a process ended by SIGINT.
const interruptedExitCode = 130

// exitOnInterrupt ends the process after an interrupted prompt has restored the
// terminal. A variable so a test can observe it without exiting.
var exitOnInterrupt = os.Exit

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// readNoEcho reads one line from the terminal f with echo turned off, and
// restores the terminal's settings before it returns. An interrupt or a
// termination signal while it waits restores them too, then exits with code
// 130: the signal would otherwise end the process with echo still off. It
// reads a byte at a time, so nothing past the line is consumed.
func readNoEcho(f *os.File) (string, error) {
	fd := int(f.Fd())
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}

	// Watch for the signals before echo goes off, and stop watching before
	// this returns, so the handler exists only while the prompt does.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	defer func() {
		signal.Stop(signals)
		close(done)
	}()
	go func() {
		select {
		case <-signals:
			_ = unix.IoctlSetTermios(fd, unix.TCSETS, saved)
			fmt.Fprintln(os.Stderr)
			exitOnInterrupt(interruptedExitCode)
		case <-done:
		}
	}()

	quiet := *saved
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, saved) //nolint:errcheck // best effort: the read's own error matters more

	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				if len(line) >= terminalLineLimit {
					return "", fmt.Errorf("the line reached the terminal's %d-byte limit, so the password may have been cut short; choose a shorter one, or give it on a stdin that is not a terminal", terminalLineLimit)
				}
				return string(line), nil
			}
			line = append(line, buf[0])
			if len(line) > maxPromptBytes {
				return "", errors.New("the password is too long")
			}
			continue
		}
		if err != nil {
			if len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
	}
}
