// Package relayconfig loads and validates the Relay's one configuration file
// (ADR-0043, invariant 11). It performs no file I/O and reads no environment:
// the caller supplies the bytes, a reader for secret files, and the
// environment, so every read goes through the caller's file check.
package relayconfig

import (
	"errors"
	"log/slog"
	"net"
	"slices"
	"time"
)

// DefaultPath is where the Relay reads its configuration when --config is not
// given.
const DefaultPath = "/etc/relay/relay.toml"

// Defaults this package owns; the rest are imported from the package that
// owns the behaviour they set.
const (
	defaultNodeAddress     = ":7654"
	defaultControlAddress  = ":9443"
	defaultAccountClaim    = "email"
	defaultIPRate          = 5
	defaultIPBurst         = 3
	defaultGlobalRate      = 50
	defaultGlobalBurst     = 10
	defaultMaxTrackedIPs   = 100000
	defaultMaxNodes        = 110000
	defaultLogLevel        = slog.LevelInfo
	defaultLogFormat       = LogText
	defaultNodePort        = "7654"
	maxPort                = 65535
	maxHostnameLength      = 253
	maxHostnameLabelLength = 63

	// maxExtraNames caps tls.extra_names (RC-47). With the composition root's
	// cap on detected addresses it bounds the certificate's SAN list.
	maxExtraNames = 32
)

// LogFormat is how the Relay renders its log.
type LogFormat string

const (
	LogText LogFormat = "text"
	LogJSON LogFormat = "json"
)

// Config is the validated configuration, shaped by section.
type Config struct {
	NodePlane    NodePlane
	ControlPlane ControlPlane
	Console      Console
	CA           CA
	Store        Store
	TLS          TLS
	OAuth        OAuth
	Approval     Approval
	Log          Log
	Reach        Reach
	Enrollment   Enrollment
}

// NodePlane is the mTLS gRPC listener every relay-daemon connects to.
type NodePlane struct {
	ListenAddress string
	// AdvertisedAddress is empty when unset; see EffectiveAdvertisedAddress.
	AdvertisedAddress string
}

// ControlPlane is the MCP and /api/v1 listener.
type ControlPlane struct {
	Enabled       bool
	ListenAddress string
}

// Console is the Admin Console served on the control-plane listener.
type Console struct {
	Enabled       bool
	SessionMaxAge time.Duration
	SessionIdle   time.Duration
	StepUpWindow  time.Duration
}

// CA holds the directory of the Relay's CA key and certificate.
type CA struct{ Dir string }

// Store holds the path of the SQLite store.
type Store struct{ Path string }

// TLS holds the certificate hostname: a name on the one server certificate
// both listeners present, and the host a join string carries by default.
// ExtraNames are the further names that certificate carries (RC-46, RC-47);
// nil when unset.
type TLS struct {
	Hostname   string
	ExtraNames []string
}

// OAuth is the human sign-in through an external identity provider; an empty
// Issuer means OAuth is off.
type OAuth struct {
	Issuer        string
	Audience      string
	AccountClaim  string
	RequiredScope string
	PublicURL     string
}

// Approval is the approval gate and its notification path. An empty
// GateRulesPath means no gate; an unset WebhookURL means no notification.
type Approval struct {
	GateRulesPath  string
	WebhookURL     Secret
	WebhookSecret  Secret
	WebhookTimeout time.Duration
}

// Log is the log level and format.
type Log struct {
	Level  slog.Level
	Format LogFormat
}

// Reach is the configuration that bounds how far one dispatch reaches.
type Reach struct {
	ReadBlastCap        int
	MutateBlastCap      int
	DispatchConcurrency int
	// MinDaemonVersion is empty when the gate is off.
	MinDaemonVersion string
}

// Enrollment is the Enrollment rate limiting, the registry cap, and the
// Node identity certificate expiry window.
type Enrollment struct {
	IPRatePerMinute      int
	IPBurst              int
	GlobalRatePerMinute  int
	GlobalBurst          int
	MaxTrackedIPs        int
	MaxNodes             int // 0 means no cap
	CertExpiringFraction float64
}

// EffectiveAdvertisedAddress is the address a join string carries: the
// configured one, or the certificate hostname on the Node plane's port.
func (c Config) EffectiveAdvertisedAddress() string {
	if c.NodePlane.AdvertisedAddress != "" {
		return c.NodePlane.AdvertisedAddress
	}
	_, port, err := net.SplitHostPort(c.NodePlane.ListenAddress)
	if err != nil {
		port = defaultNodePort
	}
	return net.JoinHostPort(c.TLS.Hostname, port)
}

// Load decodes data strictly, applies defaults, and validates every value. On
// failure it returns the zero Config and every problem at once, ordered by
// line. Warnings are settings that are accepted and likely wrong.
func Load(data []byte) (Config, []Warning, error) {
	doc, errs := decode(data)
	if len(errs) > 0 {
		return Config{}, nil, joinErrors(errs)
	}
	v := &validator{idx: keyLines(data)}
	cfg := v.build(doc)
	if len(v.errs) > 0 {
		return Config{}, nil, joinErrors(v.errs)
	}
	return cfg, v.warns, nil
}

func joinErrors(errs []*Error) error {
	slices.SortStableFunc(errs, func(a, b *Error) int {
		// Absent-key errors (line 0) follow the ones that point into the file.
		if (a.Line == 0) != (b.Line == 0) {
			if a.Line == 0 {
				return 1
			}
			return -1
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		switch {
		case a.Key < b.Key:
			return -1
		case a.Key > b.Key:
			return 1
		}
		return 0
	})
	joined := make([]error, len(errs))
	for i, e := range errs {
		joined[i] = e
	}
	return errors.Join(joined...)
}
