package relayconfig

import (
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approvalnotify"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const (
	keyHostname       = "tls.hostname"
	keyWebhookURL     = "approval.webhook_url"
	keyWebhookURLFile = "approval.webhook_url_file"
	keyWebhookSecret  = "approval.webhook_secret"
	keyWebhookSecFile = "approval.webhook_secret_file"
	keyWebhookTimeout = "approval.webhook_timeout"
	keyOAuthIssuer    = "oauth.issuer"

	reasonEmpty = "must not be empty; omit the key instead"
)

// validator builds a Config from a decoded document, collecting every refusal
// and warning. A Reason is written from schema facts only: it never includes a
// value from the file.
type validator struct {
	idx   lineIndex
	errs  []*Error
	warns []Warning
}

func (v *validator) fail(key, reason string) {
	v.errs = append(v.errs, &Error{Key: key, Line: v.idx.of(key), Reason: reason})
}

// failAbsent reports a setting that is missing from the file, so no line.
func (v *validator) failAbsent(key, reason string) {
	v.errs = append(v.errs, &Error{Key: key, Reason: reason})
}

func (v *validator) build(d document) Config {
	var c Config

	c.NodePlane.ListenAddress = v.address("node_plane.listen_address", d.NodePlane.ListenAddress, defaultNodeAddress, false)
	c.NodePlane.AdvertisedAddress = v.address("node_plane.advertised_address", d.NodePlane.AdvertisedAddress, "", true)

	c.ControlPlane.Enabled = boolOr(d.ControlPlane.Enabled, false)
	c.ControlPlane.ListenAddress = v.address("control_plane.listen_address", d.ControlPlane.ListenAddress, defaultControlAddress, false)

	c.Console.Enabled = boolOr(d.Console.Enabled, false)
	c.Console.SessionMaxAge = v.duration("console.session_max_age", d.Console.SessionMaxAge, consoleauth.DefaultAbsoluteLifetime, 0)
	c.Console.SessionIdle = v.duration("console.session_idle", d.Console.SessionIdle, consoleauth.DefaultIdleTimeout, 0)
	c.Console.StepUpWindow = v.duration("console.step_up_window", d.Console.StepUpWindow, consoleauth.DefaultStepUpWindow, consoleauth.MaxStepUpWindow)

	c.CA.Dir = v.requiredPath("ca.dir", d.CA.Dir)
	c.Store.Path = v.requiredPath("store.path", d.Store.Path)
	c.TLS.Hostname = v.hostname(d.TLS.Hostname)

	v.buildOAuth(&c, d.OAuth)
	v.buildApproval(&c, d.Approval)
	v.buildLog(&c, d.Log)
	v.buildReach(&c, d.Reach)
	v.buildEnrollment(&c, d.Enrollment)

	if c.Console.Enabled && !c.ControlPlane.Enabled {
		v.fail("console.enabled", "requires control_plane.enabled = true; the Console has no listener of its own")
	}
	v.checkAdvertised(c, d.NodePlane.AdvertisedAddress)
	return c
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// text returns a present, non-empty string; ok is false for an absent key or
// an empty one (which is reported).
func (v *validator) text(key string, p *string) (string, bool) {
	if p == nil {
		return "", false
	}
	if *p == "" {
		v.fail(key, reasonEmpty)
		return "", false
	}
	return *p, true
}

func (v *validator) requiredPath(key string, p *string) string {
	if p == nil {
		v.failAbsent(key, "must be set; it has no default")
		return ""
	}
	return v.path(key, p)
}

// path returns a present absolute, clean path.
func (v *validator) path(key string, p *string) string {
	s, ok := v.text(key, p)
	if !ok {
		return ""
	}
	if !filepath.IsAbs(s) || filepath.Clean(s) != s {
		v.fail(key, "must be an absolute, clean path")
		return ""
	}
	return s
}

func (v *validator) address(key string, p *string, def string, needHost bool) string {
	s, ok := v.text(key, p)
	if !ok {
		return def
	}
	host, port, err := net.SplitHostPort(s)
	n, perr := strconv.Atoi(port)
	if err != nil || perr != nil || n < 1 || n > maxPort || (needHost && host == "") {
		reason := "must be host:port with a port from 1 to 65535"
		if needHost {
			reason = "must be a host and port, host:port, with a port from 1 to 65535"
		}
		v.fail(key, reason)
		return def
	}
	return s
}

func (v *validator) hostname(p *string) string {
	s, ok := v.text(keyHostname, p)
	if p == nil {
		v.failAbsent(keyHostname, "must be set; it has no default")
		return ""
	}
	if !ok {
		return ""
	}
	if net.ParseIP(s) == nil && !validDNSName(s) {
		v.fail(keyHostname, "must be a DNS name or an IP address")
		return ""
	}
	return s
}

func validDNSName(s string) bool {
	if s == "" || len(s) > maxHostnameLength {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > maxHostnameLabelLength || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

// duration parses a positive duration; max, when non-zero, is the upper bound.
func (v *validator) duration(key string, p *string, def, max time.Duration) time.Duration {
	s, ok := v.text(key, p)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		v.fail(key, "must be a positive duration such as 5m")
		return def
	}
	if max > 0 && d > max {
		v.fail(key, "must be at most "+max.String())
		return def
	}
	return d
}

func (v *validator) integer(key string, p *int, def, min int) int {
	if p == nil {
		return def
	}
	if *p < min {
		v.fail(key, "must be at least "+strconv.Itoa(min))
		return def
	}
	return *p
}

func (v *validator) buildOAuth(c *Config, d oauthDoc) {
	present := []struct {
		key string
		p   *string
	}{
		{"oauth.audience", d.Audience},
		{"oauth.account_claim", d.AccountClaim},
		{"oauth.required_scope", d.RequiredScope},
		{"oauth.public_url", d.PublicURL},
	}

	if issuer, ok := v.text(keyOAuthIssuer, d.Issuer); ok {
		c.OAuth.Issuer = v.issuerURL(issuer)
	}
	if d.Issuer == nil {
		for _, f := range present {
			if f.p != nil {
				v.fail(f.key, "requires oauth.issuer")
			}
		}
		return
	}
	if !c.ControlPlane.Enabled {
		v.fail(keyOAuthIssuer, "has no effect unless control_plane.enabled = true; OAuth is served on the control plane")
	}

	c.OAuth.AccountClaim = defaultAccountClaim
	if s, ok := v.text("oauth.account_claim", d.AccountClaim); ok {
		c.OAuth.AccountClaim = s
	}
	if s, ok := v.text("oauth.audience", d.Audience); ok {
		c.OAuth.Audience = s
	} else if d.Audience == nil {
		v.failAbsent("oauth.audience", "must be set when oauth.issuer is set")
	}
	if s, ok := v.text("oauth.public_url", d.PublicURL); ok {
		c.OAuth.PublicURL = v.httpURL("oauth.public_url", s)
	} else if d.PublicURL == nil {
		v.failAbsent("oauth.public_url", "must be set when oauth.issuer is set")
	}
	if s, ok := v.text("oauth.required_scope", d.RequiredScope); ok {
		if strings.ContainsAny(s, " \t\r\n") {
			v.fail("oauth.required_scope", "must be one scope, with no whitespace")
		} else {
			c.OAuth.RequiredScope = s
		}
	}
}

func (v *validator) httpURL(key, s string) string {
	if reason := httpURLProblem(s); reason != "" {
		v.fail(key, "must be "+reason)
		return ""
	}
	return s
}

// issuerURL requires https unless the host is loopback: the issuer's discovery
// document names the signing keys, so over plaintext a network attacker can
// substitute them. The reason never carries any part of the value.
func (v *validator) issuerURL(s string) string {
	if reason := httpURLProblem(s); reason != "" {
		v.fail(keyOAuthIssuer, "must be "+reason)
		return ""
	}
	u, _ := url.Parse(s) // httpURLProblem parsed it
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		v.fail(keyOAuthIssuer, "must be an https URL; http is accepted only for a loopback host")
		return ""
	}
	return s
}

// loopbackHost reports whether host is the name localhost or a loopback IP
// literal. It never resolves names.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const absoluteHTTPURL = "an absolute http or https URL"

// httpURLProblem returns what a URL must be when s is not it, or "".
func httpURLProblem(s string) string {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return absoluteHTTPURL
	}
	return ""
}

// webhookURLProblem checks only the shape. The https-unless-loopback rule is
// approvalnotify's, which still runs when the notifier is built.
func webhookURLProblem(s string) string { return httpURLProblem(s) }

func (v *validator) buildApproval(c *Config, d approvalDoc) {
	c.Approval.GateRulesPath = v.path("approval.gate_rules_path", d.GateRulesPath)
	c.Approval.WebhookURL = v.secret(keyWebhookURL, keyWebhookURLFile, d.WebhookURL, d.WebhookURLFile, true)
	c.Approval.WebhookSecret = v.secret(keyWebhookSecret, keyWebhookSecFile, d.WebhookSecret, d.WebhookSecretFile, false)
	c.Approval.WebhookTimeout = v.duration(keyWebhookTimeout, d.WebhookTimeout, approvalnotify.DefaultTimeout, 0)

	if c.Approval.WebhookURL.IsSet() {
		return
	}
	if d.WebhookURL != nil || d.WebhookURLFile != nil {
		return // already reported
	}
	for _, f := range []struct {
		key string
		set bool
	}{
		{keyWebhookSecret, d.WebhookSecret != nil},
		{keyWebhookSecFile, d.WebhookSecretFile != nil},
		{keyWebhookTimeout, d.WebhookTimeout != nil},
	} {
		if f.set {
			v.fail(f.key, "requires approval.webhook_url or approval.webhook_url_file; it would apply to no notification")
		}
	}
}

// secret folds a secret's two spellings, x and x_file, into one Secret. Giving
// both is refused (ADR-0043 decision 2).
func (v *validator) secret(key, fileKey string, inline, file *string, isURL bool) Secret {
	switch {
	case inline != nil && file != nil:
		v.fail(fileKey, "set "+key+" or "+fileKey+", not both")
	case inline != nil:
		s, ok := v.text(key, inline)
		if !ok {
			return Secret{}
		}
		if s = strings.TrimSpace(s); s == "" {
			v.fail(key, reasonEmpty)
			return Secret{}
		}
		if isURL && webhookURLProblem(s) != "" {
			v.fail(key, "must be "+absoluteHTTPURL)
			return Secret{}
		}
		return inlineSecret(s)
	case file != nil:
		if p := v.path(fileKey, file); p != "" {
			return fileSecret(p, fileKey, v.idx.of(fileKey))
		}
	}
	return Secret{}
}

func (v *validator) buildLog(c *Config, d logDoc) {
	c.Log.Level, c.Log.Format = defaultLogLevel, defaultLogFormat
	if s, ok := v.text("log.level", d.Level); ok {
		levels := map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}
		if l, known := levels[s]; known {
			c.Log.Level = l
		} else {
			v.fail("log.level", "must be one of debug, info, warn, error")
		}
	}
	if s, ok := v.text("log.format", d.Format); ok {
		switch LogFormat(s) {
		case LogText, LogJSON:
			c.Log.Format = LogFormat(s)
		default:
			v.fail("log.format", "must be one of text, json")
		}
	}
}

func (v *validator) buildReach(c *Config, d reachDoc) {
	c.Reach.ReadBlastCap = v.integer("reach.read_blast_cap", d.ReadBlastCap, capability.DefaultReadCap, 1)
	c.Reach.MutateBlastCap = v.integer("reach.mutate_blast_cap", d.MutateBlastCap, capability.DefaultMutateCap, 1)
	c.Reach.DispatchConcurrency = v.integer("reach.dispatch_concurrency", d.DispatchConcurrency, capability.DefaultDispatchConcurrency, 1)
	if s, ok := v.text("reach.min_daemon_version", d.MinDaemonVersion); ok {
		if registry.ValidVersion(s) {
			c.Reach.MinDaemonVersion = s
		} else {
			v.fail("reach.min_daemon_version", "must be a semantic version such as 0.1.0")
		}
	}

	if c.Reach.MutateBlastCap > c.Reach.ReadBlastCap {
		key := "reach.read_blast_cap"
		if d.MutateBlastCap != nil {
			key = "reach.mutate_blast_cap"
		}
		v.warns = append(v.warns, Warning{Key: key, Line: v.idx.of(key),
			Reason: "the mutate cap is above the read cap; a mutate normally reaches fewer Nodes than a read"})
	}
}

func (v *validator) buildEnrollment(c *Config, d enrollmentDoc) {
	e := &c.Enrollment
	e.IPRatePerMinute = v.integer("enrollment.ip_rate_per_minute", d.IPRatePerMinute, defaultIPRate, 1)
	e.IPBurst = v.integer("enrollment.ip_burst", d.IPBurst, defaultIPBurst, 1)
	e.GlobalRatePerMinute = v.integer("enrollment.global_rate_per_minute", d.GlobalRatePerMinute, defaultGlobalRate, 1)
	e.GlobalBurst = v.integer("enrollment.global_burst", d.GlobalBurst, defaultGlobalBurst, 1)
	e.MaxTrackedIPs = v.integer("enrollment.max_tracked_ips", d.MaxTrackedIPs, defaultMaxTrackedIPs, 1)
	e.MaxNodes = v.integer("enrollment.max_nodes", d.MaxNodes, defaultMaxNodes, 0)

	e.CertExpiringFraction = nodestate.DefaultCertExpiringFraction
	if f := d.CertExpiringFraction; f != nil {
		// Written as a negation so NaN is refused with the out-of-range values.
		if !(*f > 0 && *f <= 1) {
			v.fail("enrollment.cert_expiring_fraction", "must be greater than 0 and at most 1; there is no off value")
		} else {
			e.CertExpiringFraction = *f
		}
	}
}

// checkAdvertised refuses an advertised address whose host is not the
// certificate hostname: a daemon dialling it would fail TLS verification
// (RC-36). Only key names appear in the Reason, never either host.
func (v *validator) checkAdvertised(c Config, p *string) {
	if p == nil || c.NodePlane.AdvertisedAddress == "" || c.TLS.Hostname == "" {
		return
	}
	host, _, err := net.SplitHostPort(c.NodePlane.AdvertisedAddress)
	if err != nil || !strings.EqualFold(host, c.TLS.Hostname) {
		v.fail("node_plane.advertised_address", "host must be the certificate hostname (tls.hostname)")
	}
}
