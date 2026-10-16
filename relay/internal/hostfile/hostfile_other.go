//go:build !linux

package hostfile

import "os"

// The check is defined only on Linux, so elsewhere the Relay refuses.

// Open refuses.
func Open(path string, _ Rule) (*os.File, error) {
	return nil, &Refusal{Path: path, Clause: ClauseUnsupportedOS}
}

// OpenDir refuses.
func OpenDir(path string, _ Rule) (*os.File, error) {
	return nil, &Refusal{Path: path, Clause: ClauseUnsupportedOS}
}
