//go:build !linux

package main

import (
	"errors"
	"os"
)

// isTerminal reports whether f is a character device, which init treats as a
// terminal so it never reads a password with echo on.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readNoEcho refuses: turning echo off is implemented for Linux only, where
// the start-time check that init runs first is defined.
func readNoEcho(*os.File) (string, error) {
	return "", errors.New("reading a password with echo off is not supported on this platform")
}
