package main

// reload_live.go holds the live configuration the Relay runs on, which a
// reload (reload.go) replaces whole. The snapshot, the approval gate and the
// log handler are the three things a reload swaps (RC-21). Pull-on-use from one
// atomic pointer: nothing is notified on a reload, so there is no point at which
// it can half-apply.
//
// Adapters never receive any of these. Only the capability constructors, the
// store, the rate limiter and the reloader do (invariant 10).

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/approvalnotify"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// running is one configuration the Relay runs on: the operator settings and the
// approval notifier built from the same file. It is replaced whole, never
// mutated.
type running struct {
	settings capability.OperatorSettings
	notifier capability.ApprovalNotifier // nil when no webhook is configured
}

// newRunning is the single validation and build path for start and for reload.
// A value no run may use refuses here, so a reload never swaps in a snapshot
// that start would have refused.
func newRunning(cfg Config, logger *slog.Logger) (*running, error) {
	// A malformed min_daemon_version refuses rather than leaving the outdated
	// gate in an unpredictable state (ADR-0014). Empty is valid: the gate is off.
	if cfg.MinDaemonVersion != "" && !registry.ValidVersion(cfg.MinDaemonVersion) {
		return nil, fmt.Errorf("invalid min-daemon-version %q: not a valid semver version", cfg.MinDaemonVersion)
	}
	// There is deliberately no "off" value for the cert-expiring fraction
	// (ADR-0034): a silently disabled alarm is exactly the failure
	// state:cert-expiring exists to catch.
	if cfg.CertExpiringFraction <= 0 || cfg.CertExpiringFraction > 1 {
		return nil, fmt.Errorf("invalid cert-expiring-fraction %v: must be in (0, 1]", cfg.CertExpiringFraction)
	}
	// The per-Job dispatch bound has no "off" value: zero would dispatch nothing.
	if cfg.DispatchConcurrency < 1 {
		return nil, fmt.Errorf("invalid dispatch-concurrency %d: must be at least 1", cfg.DispatchConcurrency)
	}
	r := &running{settings: capability.OperatorSettings{
		ReadBlastCap:        cfg.ReadBlastCap,
		MutateBlastCap:      cfg.MutateBlastCap,
		DispatchConcurrency: cfg.DispatchConcurrency,
		MinDaemonVersion:    cfg.MinDaemonVersion,
		// A Duration, never the fraction itself, so capability needs no
		// import of internal/ca to make sense of it.
		CertExpiringWithin:        nodestate.CertExpiringWindow(ca.LeafValidity, cfg.CertExpiringFraction),
		EnrollIPRatePerMinute:     cfg.EnrollIPRate,
		EnrollIPBurst:             cfg.EnrollIPBurst,
		EnrollGlobalRatePerMinute: cfg.EnrollGlobalRate,
		EnrollGlobalBurst:         cfg.EnrollGlobalBurst,
		EnrollMaxTrackedIPs:       cfg.EnrollMaxTrackedIPs,
		MaxNodes:                  cfg.MaxNodes,
	}}

	// The out-of-band notification envelope (ADR-0027). Optional: with no URL
	// configured nothing is pushed. Configured but unusable refuses, on the gate
	// config's precedent: a notifier the operator asked for and did not get is a
	// silent gap in how they learn a fleet action is waiting.
	if webhookURL, ok := cfg.ApprovalWebhookURL.Reveal(); ok && webhookURL != "" {
		var secretBytes []byte
		if v, ok := cfg.ApprovalWebhookSecret.Reveal(); ok {
			secretBytes = []byte(v)
		}
		n, err := approvalnotify.New(approvalnotify.Config{
			URL:     webhookURL,
			Secret:  secretBytes,
			Timeout: cfg.ApprovalWebhookTimeout,
		}, approvalnotify.WithLogger(logger))
		if err != nil {
			return nil, fmt.Errorf("configure approval webhook: %w", err)
		}
		r.notifier = n
	}
	return r, nil
}

// liveConfig is the Relay's current configuration snapshot. Always used as a
// *liveConfig: it is the capability.OperatorSettingsSource the layer is built
// over, and NewExecution compares sources by identity.
type liveConfig struct {
	cur atomic.Pointer[running]
}

// OperatorSettings implements capability.OperatorSettingsSource.
func (l *liveConfig) OperatorSettings() capability.OperatorSettings {
	return l.cur.Load().settings
}

// notifier is the current approval notifier, or nil.
func (l *liveConfig) notifier() capability.ApprovalNotifier {
	return l.cur.Load().notifier
}

func (l *liveConfig) swap(r *running) { l.cur.Store(r) }

// liveNotifier delegates to the notifier of the current snapshot, so a rotated
// webhook URL or secret applies to the next park.
type liveNotifier struct{ live *liveConfig }

func (n liveNotifier) NotifyParked(ctx context.Context, notice capability.ApprovalNotice) {
	if cur := n.live.notifier(); cur != nil {
		cur.NotifyParked(ctx, notice)
	}
}

// liveGate is the approval gate, replaceable whole by a reload. It implements
// capability.ApprovalGate and loads once per evaluation.
type liveGate struct {
	cur atomic.Pointer[approval.Gate]
}

func (g *liveGate) Evaluate(d approval.Dispatch) (approval.Requirement, []string, bool) {
	return g.cur.Load().Evaluate(d)
}

func (g *liveGate) rules() []approval.Rule { return g.cur.Load().Rules() }

func (g *liveGate) swap(next *approval.Gate) { g.cur.Store(next) }

// rateConfig is the enrollment rate limiter's parameters from the settings.
func rateConfig(s capability.OperatorSettings) ratelimit.Config {
	return ratelimit.Config{
		PerIPRatePerMin:  float64(s.EnrollIPRatePerMinute),
		PerIPBurst:       float64(s.EnrollIPBurst),
		GlobalRatePerMin: float64(s.EnrollGlobalRatePerMinute),
		GlobalBurst:      float64(s.EnrollGlobalBurst),
		MaxTrackedIPs:    s.EnrollMaxTrackedIPs,
	}
}
