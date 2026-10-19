// Package startup is the Relay's start-time file check on everything its configuration names
// apart from the file itself and its secrets (ADR-0043): the approval-gate file, then the
// state locations. Its result, Files, can only be made by Open, or by the test-only
// startuptest that depguard keeps out of production code; the composition root takes a Files
// and opens none of these files itself.
package startup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
	"github.com/Felag-Engineering/relay/relay/internal/startup/internal/sealed"
)

// Files is what the start-time check read: the CA and the approval gate, each read from the
// descriptor hostfile checked, and the store's path with a recheck of its directory. Its one
// field is unexported and of a type no package outside the startup tree can name.
type Files struct {
	v sealed.Files
}

// Open checks and reads the approval-gate file at gatePath (RC-15, RC-16; empty means no
// gate), the store's directory, and the CA directory and private key at caDir (RC-17). Any
// refusal refuses start.
func Open(gatePath, caDir, storePath string) (Files, error) {
	gate, err := approval.Load(gatePath)
	if err != nil {
		return Files{}, fmt.Errorf("load approval gate config: %w", err)
	}
	recheck := func() error { return checkStoreDir(storePath) }
	if err := recheck(); err != nil {
		return Files{}, err
	}
	relayCA, err := ca.Open(caDir)
	if err != nil {
		return Files{}, fmt.Errorf("open CA: %w", err)
	}
	return Files{v: sealed.Files{CA: relayCA, Gate: gate, StorePath: storePath, RecheckStore: recheck}}, nil
}

// FromSealed wraps v. Its parameter's type is internal to the startup tree, so only the
// test-only constructor can pass it anything but a zero value; it refuses any part missing.
func FromSealed(v sealed.Files) (Files, error) {
	if v.CA == nil || v.Gate == nil || v.StorePath == "" || v.RecheckStore == nil {
		return Files{}, errors.New("startup: incomplete start-time files")
	}
	return Files{v: v}, nil
}

// Valid reports whether f came from Open or FromSealed rather than being the zero value.
func (f Files) Valid() bool { return f.v.CA != nil && f.v.Gate != nil && f.v.RecheckStore != nil }

// CA is the Relay's CA, read from the checked directory.
func (f Files) CA() *ca.CA { return f.v.CA }

// Gate is the approval gate, read from the checked file; empty when no file is configured.
func (f Files) Gate() *approval.Gate { return f.v.Gate }

// StorePath is the store's path, whose directory Open checked. The store is opened at
// exactly this path.
func (f Files) StorePath() string { return f.v.StorePath }

// RecheckStore checks the store's directory again; the composition root calls it immediately
// before it opens the store. SQLite opens the store and its journal files by path, and
// resolves symbolic links itself, so the store cannot be opened from the checked descriptor:
// what remains is the window between this check and those opens, against an account that
// could already write the Relay's own directory.
func (f Files) RecheckStore() error { return f.v.RecheckStore() }

// checkStoreDir creates the store's directory owner-only if it is absent, as the store would,
// and refuses unless it is the Relay's alone (RC-17).
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
