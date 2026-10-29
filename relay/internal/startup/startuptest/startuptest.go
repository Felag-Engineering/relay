// Package startuptest builds startup.Files for the in-process suites, from a CA a
// test made and a store path in a test directory, with no file check: the real check refuses
// every temporary directory a test can make. depguard keeps this package out of every
// non-test file; the Relay's own Files always come from startup.Open.
package startuptest

import (
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
	"github.com/Felag-Engineering/relay/relay/internal/startup/internal/sealed"
)

// Files returns startup.Files holding c and storePath, whose store recheck passes.
func Files(c *ca.CA, storePath string) (startup.Files, error) {
	return startup.FromSealed(sealed.New(c, storePath, func() error { return nil }))
}
