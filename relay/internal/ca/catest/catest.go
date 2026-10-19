// Package catest builds in-memory CAs for tests. A CA from here was read from no file and
// decided on by no file check, so depguard keeps this package out of every non-test file; the
// Relay's own CA always comes from ca.Open.
package catest

import (
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/ca/internal/material"
)

// Generate returns a new CA held only in memory.
func Generate() (*ca.CA, error) {
	m, err := material.New()
	if err != nil {
		return nil, err
	}
	return ca.FromMaterial(m)
}
