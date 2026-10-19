//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// readNoEcho reads one line from the terminal f with echo turned off, and
// restores the terminal's settings before it returns. It reads a byte at a
// time, so nothing past the line is consumed.
func readNoEcho(f *os.File) (string, error) {
	fd := int(f.Fd())
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
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
