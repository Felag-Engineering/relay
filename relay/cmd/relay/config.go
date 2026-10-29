// Config loading: how the Relay's one configuration file becomes the Config
// newServer takes (ADR-0043).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"

	"github.com/Felag-Engineering/relay/relay/internal/approvalnotify"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
)

// parseArgs accepts exactly one flag, --config. Anything else is refused: the
// Relay takes no setting from its command line (invariant 11). The refusals
// never echo a flag's value or a positional argument, which may be a secret.
func parseArgs(args []string, stderr io.Writer) (string, error) {
	set := flag.NewFlagSet("relay", flag.ContinueOnError)
	set.SetOutput(stderr)
	path := set.String("config", relayconfig.DefaultPath, "path of the Relay's configuration file")
	set.Usage = func() {
		_, _ = fmt.Fprint(stderr, `Usage:
  relay [--config PATH]
  relay --version
  relay init [--config PATH] (--admin NAME | --recover NAME)

Every setting is in the configuration file; the Relay reads none from flags or the environment.
`)
	}
	if err := set.Parse(args); err != nil {
		return "", err
	}
	if set.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "relay: takes no positional arguments; settings belong in the configuration file")
		return "", errors.New("positional arguments are not accepted")
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "relay: --config must name a file")
		return "", errors.New("empty --config")
	}
	return *path, nil
}

// startupConfig is everything main needs from a loaded configuration file.
type startupConfig struct {
	Config Config
	Log    relayconfig.Log
	// File is the validated configuration with its secrets resolved: what a
	// reload diffs the next file against.
	File     relayconfig.Config
	Warnings []relayconfig.Warning
}

// maxConfigBytes bounds the configuration file, so a pathological file is
// refused before it is read into memory.
const maxConfigBytes = 1 << 20

// loadConfig reads and validates the configuration file at path. The file is
// opened through hostfile's check as a file holding secrets (RC-15, RC-16) and
// read from the descriptor that was checked, and every file-backed secret it
// names is read through the same check (approvalnotify.ReadSecretFile). Every
// refusal names the path, a key or a line — never a value.
func loadConfig(path string) (startupConfig, error) {
	f, err := hostfile.Open(path, hostfile.Secret)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return startupConfig{}, fmt.Errorf("configuration: the configuration file %s does not exist: %w", path, fs.ErrNotExist)
	case errors.Is(err, fs.ErrPermission):
		return startupConfig{}, fmt.Errorf("configuration: the configuration file %s cannot be read: %w", path, fs.ErrPermission)
	case errors.As(err, new(*hostfile.Refusal)):
		// The refusal names the path itself.
		return startupConfig{}, fmt.Errorf("configuration: %w", err)
	case err != nil:
		return startupConfig{}, fmt.Errorf("configuration: the configuration file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return startupConfig{}, fmt.Errorf("configuration: the configuration file %s could not be read", path)
	}
	if len(data) > maxConfigBytes {
		return startupConfig{}, fmt.Errorf("configuration: the configuration file %s is larger than %d bytes", path, maxConfigBytes)
	}
	return parseConfig(data, approvalnotify.ReadSecretFile)
}

// errSecretFileUnread marks a load that failed because a file-backed secret
// could not be read, so a reload can name that stage without the error's text.
var errSecretFileUnread = errors.New("a secret file could not be read")

// parseConfig decodes and validates data, the configuration file's contents,
// reading each file-backed secret through readSecret.
func parseConfig(data []byte, readSecret func(string) ([]byte, error)) (startupConfig, error) {
	rc, warns, err := relayconfig.Load(data)
	if err != nil {
		return startupConfig{}, err
	}

	var readerErrs []error
	read := func(p string) ([]byte, error) {
		b, err := readSecret(p)
		if err != nil {
			readerErrs = append(readerErrs, err)
		}
		return b, err
	}
	if err := rc.ResolveSecrets(read); err != nil {
		errs := append([]error{err}, readerErrs...)
		if len(readerErrs) > 0 {
			errs = append(errs, errSecretFileUnread)
		}
		return startupConfig{}, errors.Join(errs...)
	}
	return startupConfig{Config: fromFile(rc), Log: rc.Log, File: rc, Warnings: warns}, nil
}

// fromFile maps the validated file onto the Config newServer takes. The values
// no file key reaches are built-in constants (RC-38 to RC-43).
func fromFile(rc relayconfig.Config) Config {
	enroll := ratelimit.Enrollment()
	return Config{
		ConsoleSessionMaxAge:   consoleauth.DefaultAbsoluteLifetime,
		ConsoleStepUpWindow:    consoleauth.DefaultStepUpWindow,
		ApprovalWebhookTimeout: approvalnotify.DefaultTimeout,
		DispatchConcurrency:    capability.DefaultDispatchConcurrency,
		EnrollIPRate:           int(enroll.PerIPRatePerMin),
		EnrollIPBurst:          int(enroll.PerIPBurst),
		EnrollGlobalRate:       int(enroll.GlobalRatePerMin),
		EnrollGlobalBurst:      int(enroll.GlobalBurst),
		EnrollMaxTrackedIPs:    enroll.MaxTrackedIPs,
		CertExpiringFraction:   nodestate.DefaultCertExpiringFraction,
		Addr:                   rc.NodePlane.ListenAddress,
		AdvertisedAddress:      rc.NodePlane.AdvertisedAddress,
		ControlEnabled:         rc.ControlPlane.Enabled,
		ControlAddr:            rc.ControlPlane.ListenAddress,
		ConsoleEnabled:         rc.Console.Enabled,
		ConsoleSessionIdle:     rc.Console.SessionIdle,
		CADir:                  rc.CA.Dir,
		StorePath:              rc.Store.Path,
		Hostname:               rc.TLS.Hostname,
		ExtraNames:             rc.TLS.ExtraNames,
		OAuthIssuer:            rc.OAuth.Issuer,
		OAuthAudience:          rc.OAuth.Audience,
		OAuthAccountClaim:      rc.OAuth.AccountClaim,
		OAuthRequiredScope:     rc.OAuth.RequiredScope,
		OAuthPublicURL:         rc.OAuth.PublicURL,
		ApprovalRules:          rc.Approval.Rules,
		ApprovalWebhookURL:     rc.Approval.WebhookURL,
		ApprovalWebhookSecret:  rc.Approval.WebhookSecret,
		ReadBlastCap:           rc.Reach.ReadBlastCap,
		MutateBlastCap:         rc.Reach.MutateBlastCap,
		MinDaemonVersion:       rc.Reach.MinDaemonVersion,
		MaxNodes:               rc.Enrollment.MaxNodes,
	}
}

// newLogHandler renders the log as JSON at the configured level (RC-42).
func newLogHandler(w io.Writer, l relayconfig.Log) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l.Level})
}
