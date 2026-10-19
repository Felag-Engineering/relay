// Package sealed is the plain contents of a startup.Files. It is internal to the startup
// tree, so only startup and its test-only constructor (startuptest) can name it, which is what
// keeps startup.FromSealed callable from nowhere else with anything but a zero value.
package sealed

import (
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
)

// Files is what the start-time file check read.
type Files struct {
	CA           *ca.CA
	Gate         *approval.Gate
	StorePath    string
	RecheckStore func() error
}
