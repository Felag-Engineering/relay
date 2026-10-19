// Package startuptest builds startup.Files for the in-process suites, from a CA and gate a
// test made and a store path in a test directory, with no file check: the real check refuses
// every temporary directory a test can make. depguard keeps this package out of every
// non-test file; the Relay's own Files always come from startup.Open.
package startuptest

import (
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
	"github.com/Felag-Engineering/relay/relay/internal/startup/internal/sealed"
)

// Files returns startup.Files holding c, g and storePath, whose store recheck passes.
func Files(c *ca.CA, g *approval.Gate, storePath string) (startup.Files, error) {
	return startup.FromSealed(sealed.New(c, g, storePath, func() error { return nil }))
}
