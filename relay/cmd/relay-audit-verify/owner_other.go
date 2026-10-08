//go:build !unix

package main

import (
	"fmt"
	"os"
)

// realEnv is the real osEnv. Without file ownership the UID guard is skipped.
type realEnv struct{}

func (realEnv) Geteuid() int { return os.Geteuid() }

func (realEnv) FileOwner(path string) (int, bool, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, false, fmt.Errorf("audit store: %w", err)
	}
	return 0, false, nil
}
