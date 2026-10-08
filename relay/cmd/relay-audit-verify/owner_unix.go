//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// realEnv is the real osEnv.
type realEnv struct{}

func (realEnv) Geteuid() int { return os.Geteuid() }

func (realEnv) FileOwner(path string) (int, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false, fmt.Errorf("audit store: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false, nil
	}
	return int(st.Uid), true, nil
}
