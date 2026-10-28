package capability

import (
	"errors"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// HumanAPITokenDefaultTTL is the lifetime of a human Account's API Token when
// the mint names none. An answer given on a human's token session counts as
// that human's decision (ADR-0047, amended 2026-10-23), so the credential is
// short-lived unless a longer life is chosen explicitly.
const HumanAPITokenDefaultTTL = 7 * 24 * time.Hour

// APITokenLifetime is what a mint path asks for: the default, or an explicit
// lifetime. A typed value rather than a sentinel duration, so "0 means no
// expiry" and "use the default" cannot be confused.
type APITokenLifetime struct {
	ttl      time.Duration
	explicit bool
}

// DefaultAPITokenLifetime asks for the capability layer's default. It is the
// zero value.
func DefaultAPITokenLifetime() APITokenLifetime { return APITokenLifetime{} }

// ExplicitAPITokenLifetime asks for exactly ttl; 0 means no expiry.
func ExplicitAPITokenLifetime(ttl time.Duration) APITokenLifetime {
	return APITokenLifetime{ttl: ttl, explicit: true}
}

// Explicit returns the named lifetime and whether one was named.
func (l APITokenLifetime) Explicit() (time.Duration, bool) { return l.ttl, l.explicit }

// ErrAPITokenTTLRequired is returned when a machine Account's mint names no
// lifetime: a forgotten field must never silently mint an immortal credential.
var ErrAPITokenTTLRequired = errors.New("capability: a machine Account's API Token has no default lifetime; name one explicitly (0 means no expiry)")

// ResolveAPITokenTTL turns a requested lifetime into the TTL to mint with. It
// is the one function every mint path calls. An explicit lifetime is returned
// unchanged (a negative one is left for accounts.ErrInvalidTTL to reject); the
// default is seven days for a human Account and a refusal for any other kind.
func ResolveAPITokenTTL(kind accounts.Kind, l APITokenLifetime) (time.Duration, error) {
	if l.explicit {
		return l.ttl, nil
	}
	if kind == accounts.KindHuman {
		return HumanAPITokenDefaultTTL, nil
	}
	return 0, ErrAPITokenTTLRequired
}
