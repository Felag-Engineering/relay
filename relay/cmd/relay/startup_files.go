package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
)

// startupFiles is what the composition root reads from the host before it
// builds anything: the CA and the approval gate, each read from the descriptor
// hostfile checked (ADR-0043). newServer takes them as values and opens
// neither, so nothing it builds reads a file the check did not decide on.
type startupFiles struct {
	ca   *ca.CA
	gate *approval.Gate
	// recheckStore checks the store's directory again; newServer calls it immediately
	// before it opens the store. SQLite opens the store and its journal files by path, and
	// resolves symbolic links itself, so the store cannot be opened from the checked
	// descriptor: what remains is the window between this check and those opens, against
	// an account that could already write the Relay's own directory.
	recheckStore func() error
}

// openStartupFiles is the start-time check on everything the configuration
// names apart from the file itself and its secrets, which loadConfig reads:
// the approval-gate file (RC-15, RC-16), then the state locations — the
// store's directory, and the CA directory and private key (RC-17). Any
// refusal refuses start.
func openStartupFiles(cfg Config) (startupFiles, error) {
	gate, err := approval.Load(cfg.ApprovalGatePath)
	if err != nil {
		return startupFiles{}, fmt.Errorf("load approval gate config: %w", err)
	}
	if err := checkStoreDir(cfg.StorePath); err != nil {
		return startupFiles{}, err
	}
	relayCA, err := ca.Open(cfg.CADir)
	if err != nil {
		return startupFiles{}, fmt.Errorf("open CA: %w", err)
	}
	return startupFiles{ca: relayCA, gate: gate, recheckStore: func() error { return checkStoreDir(cfg.StorePath) }}, nil
}

// checkStoreDir creates the store's directory owner-only if it is absent, as
// the store would, and refuses unless it is the Relay's alone (RC-17).
func checkStoreDir(storePath string) error {
	dir := filepath.Dir(storePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store directory: create: %w", err)
	}
	d, err := hostfile.OpenDir(dir, hostfile.GeneratedDir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	return d.Close()
}
