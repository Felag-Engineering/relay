package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config.go resolves how relayctl reaches a Relay: which endpoint, which
// credential, and which CA to trust.
//
// Resolution order is flag > environment > profile file > default, so an
// explicit flag always wins and a scripted invocation can override a saved
// profile without editing it. Nothing is ever written back: relayctl reads
// configuration, it does not manage it. A credential in particular is only ever
// read — the CLI has no "login" that stashes a token somewhere the operator did
// not choose.

const (
	envEndpoint = "RELAY_ENDPOINT"
	envToken    = "RELAY_TOKEN"
	envTokenTag = "RELAY_TOKEN_FILE"
	envCACert   = "RELAY_CA_CERT"
	envProfile  = "RELAY_PROFILE"

	defaultEndpoint = "https://localhost:9443"
	defaultTimeout  = 60 * time.Second
)

// Config is a resolved connection to one Relay.
type Config struct {
	// Endpoint is the control-plane base URL, e.g. https://relay.example:9443.
	Endpoint string
	// Token is the Account API Token presented as a bearer credential.
	Token string
	// CACertPath, when set, is a PEM bundle to trust INSTEAD of the system
	// roots. A Relay's control-plane certificate is issued by its own CA
	// (ADR-0005/0006), so an operator normally points this at that CA's bundle.
	CACertPath string
	// Timeout bounds a single request.
	Timeout time.Duration
}

// profile is one named entry in the profile file.
type profile struct {
	Endpoint   string `json:"endpoint"`
	Token      string `json:"token"`
	TokenFile  string `json:"token_file"`
	CACertPath string `json:"ca_cert"`
}

// profilePath returns the profile file's location: $RELAY_CONFIG if set,
// else ~/.config/relay/config.json. Absent is not an error — a fully
// flag/env-driven invocation is a first-class way to use this tool.
func profilePath() string {
	if p := os.Getenv("RELAY_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "relay", "config.json")
}

// resolveConfig merges flags, environment, and the named profile.
//
// The credential is resolved LAST and separately (see resolveToken) because it
// is the one value that must never be logged and the one with a file-based
// alternative: putting a token in argv exposes it in the process table to every
// user on the machine, so RELAY_TOKEN_FILE / a profile's token_file exist as
// the safer default and the flag is deliberately not the documented path.
func resolveConfig(f *globalFlags) (Config, error) {
	prof, err := loadProfile(firstNonEmpty(f.profile, os.Getenv(envProfile)))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Endpoint:   firstNonEmpty(f.endpoint, os.Getenv(envEndpoint), prof.Endpoint, defaultEndpoint),
		CACertPath: firstNonEmpty(f.caCert, os.Getenv(envCACert), prof.CACertPath),
		Timeout:    defaultTimeout,
	}
	if f.timeout > 0 {
		cfg.Timeout = f.timeout
	}

	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		// Fail closed rather than silently downgrading: the control plane
		// carries credentials and command output, and a plaintext endpoint
		// would expose both. This mirrors the daemon's own refusal to dial a
		// non-https Relay (invariant 6).
		return Config{}, fmt.Errorf("endpoint %q must use https:// — refusing to send a credential over plaintext", cfg.Endpoint)
	}

	token, err := resolveToken(f, prof)
	if err != nil {
		return Config{}, err
	}
	cfg.Token = token
	return cfg, nil
}

// resolveToken finds the API Token, preferring file-based sources.
func resolveToken(f *globalFlags, prof profile) (string, error) {
	if f.token != "" {
		return f.token, nil
	}
	if v := os.Getenv(envToken); v != "" {
		return v, nil
	}
	for _, path := range []string{f.tokenFile, os.Getenv(envTokenTag), prof.TokenFile} {
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read token file %q: %w", path, err)
		}
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("token file %q is empty", path)
	}
	if prof.Token != "" {
		return prof.Token, nil
	}
	return "", errNoCredential
}

// errNoCredential is returned when no token could be resolved. It is a distinct
// value so main can render the one error an operator hits most often with an
// actionable message rather than a bare failure.
var errNoCredential = errors.New("no API Token found")

// httpClient builds the HTTP client for cfg: the Relay's own CA when one is
// configured, the system roots otherwise.
//
// There is deliberately no insecure-skip-verify flag. The control plane is the
// path a credential and captured command output travel; an escape hatch that
// disables verification is the kind of thing that starts as a debugging
// convenience and ends up in a runbook (invariant 6 — the daemon refuses an
// untrusted Relay, and the operator's tool should hold the same line).
func httpClient(cfg Config) (*http.Client, error) {
	transport := &http.Transport{}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %q: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %q contains no usable certificate", cfg.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: cfg.Timeout}, nil
}

// loadProfile reads the named profile from the profile file. A missing file is
// not an error (flags/env alone are a complete configuration); a named profile
// that does not exist IS an error, because the operator asked for something
// specific and silently falling back would run the command against the wrong
// Relay.
func loadProfile(name string) (profile, error) {
	path := profilePath()
	if path == "" {
		return profile{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if name != "" {
			return profile{}, fmt.Errorf("profile %q requested but no config file at %s", name, path)
		}
		return profile{}, nil
	}
	if err != nil {
		return profile{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var file struct {
		DefaultProfile string             `json:"default_profile"`
		Profiles       map[string]profile `json:"profiles"`
	}
	if err := jsonUnmarshal(data, &file); err != nil {
		return profile{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	want := firstNonEmpty(name, file.DefaultProfile)
	if want == "" {
		return profile{}, nil
	}
	p, ok := file.Profiles[want]
	if !ok {
		return profile{}, fmt.Errorf("profile %q not found in %s", want, path)
	}
	return p, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
