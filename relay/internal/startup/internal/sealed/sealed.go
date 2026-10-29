// Package sealed is the plain contents of a startup.Files. It is internal to the startup
// tree, so only startup and its test-only constructor (startuptest) can import it, and Files
// carries an unexported field, so no struct literal written anywhere else has its type: Go
// assigns an unnamed look-alike struct to a named one, which is why unnameable is not enough.
// Together they keep startup.FromSealed callable from nowhere else with anything but a zero
// value.
package sealed

import (
	"github.com/Felag-Engineering/relay/relay/internal/ca"
)

// Files is what the start-time file check read.
type Files struct {
	CA           *ca.CA
	StorePath    string
	RecheckStore func() error

	// A non-exported field: field names that are not exported are never the same across
	// packages, so a look-alike literal written outside this package has another type.
	_ struct{}
}

// New returns Files holding its arguments.
func New(c *ca.CA, storePath string, recheck func() error) Files {
	return Files{CA: c, StorePath: storePath, RecheckStore: recheck}
}
