package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// Steps of newServerWithHooks that need nothing from the rest of the
// composition root, named so the root reads as a sequence.

// runDeclinedScans runs the one-shot declined-Label and declined-self-report
// startup scans (threat model R13) under the shared declinedScanBudget. A
// failed scan is logged and tolerated: a detector must not become a gate, and
// the absence of its signal is itself visible.
//
// The budget is shared, not per scan, because both hold the process's only
// SQLite connection ahead of the listener. A label scan that spends it leaves
// the self-report scan to fail, which warns and continues the same way.
func runDeclinedScans(st *store.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), declinedScanBudget)
	defer cancel()
	if _, err := st.ScanDeclinedLabels(ctx); err != nil {
		slog.Warn("declined-label startup scan failed", "err", err)
	}
	if _, err := st.ScanDeclinedSelfReports(ctx); err != nil {
		slog.Warn("declined self-report startup scan failed", "err", err)
	}
}

// revokedNodeLister is the slice of the registry that rehydrateDenylist reads.
type revokedNodeLister interface {
	RevokedNodeIDs() ([]string, error)
}

// rehydrateDenylist loads every persisted revocation into the Denylist. The
// Denylist is a derived cache of the registry, which is the authority, so this
// runs before any listener accepts a connection (ADR-0006: revocation is
// instant, and must also hold across a restart).
func rehydrateDenylist(reg revokedNodeLister, denylist *revocation.Denylist) error {
	revokedIDs, err := reg.RevokedNodeIDs()
	if err != nil {
		return fmt.Errorf("load revoked node ids: %w", err)
	}
	for _, id := range revokedIDs {
		denylist.Add(id)
	}
	return nil
}

// advertisedNodePlaneAddress is the one derivation the server certificate, the
// server's enrollment minter and relay init's mint form all use (RC-36, RC-46).
func advertisedNodePlaneAddress(cfg Config) (string, error) {
	addr, err := enroll.AdvertisedAddress(cfg.AdvertisedAddress, cfg.Hostname, cfg.Addr)
	if err != nil {
		return "", fmt.Errorf("advertised node-plane address: %w", err)
	}
	return addr, nil
}

// issueServerCertificate resolves the node-plane address a join string will
// carry and issues the Relay's one TLS server certificate naming it, which
// both listeners present (ADR-0031 §1). It returns the advertised address
// beside the certificate because the enrollment minter must receive the same
// one (RC-46).
//
// Failing to list the host's addresses is a warning, not a refusal: they are a
// convenience on top of the configured names, and a detector must not become
// an outage.
func issueServerCertificate(cfg Config, relayCA *ca.CA, appMetrics *metrics.Metrics) (cert *ca.ServerCertificate, advertisedAddress string, err error) {
	advertisedAddress, err = advertisedNodePlaneAddress(cfg)
	if err != nil {
		return nil, "", err
	}
	advertisedHost, _, err := net.SplitHostPort(advertisedAddress)
	if err != nil {
		return nil, "", fmt.Errorf("advertised node-plane address: %w", err)
	}
	names, err := serverCertificateNames(cfg.Hostname, advertisedHost, cfg.ExtraNames, net.InterfaceAddrs)
	if err != nil {
		slog.Warn("server certificate names only tls.hostname, the advertised host, tls.extra_names and loopback: this host's addresses could not be listed; a systemd unit whose RestrictAddressFamilies omits AF_NETLINK prevents it",
			"err", err)
	}
	if names.Omitted > 0 {
		slog.Warn("server certificate omits some of this host's addresses",
			"omitted", names.Omitted, "kept", maxDetectedAddresses)
	}
	presentedOn := []metrics.ServerCertListener{metrics.ListenerNodePlane}
	if cfg.ControlEnabled {
		presentedOn = append(presentedOn, metrics.ListenerControlPlane)
	}
	cert, err = relayCA.NewServerCertificate(names.DNSNames, names.IPAddresses,
		ca.WithRotationObserver(serverCertObserver(appMetrics, presentedOn...)))
	if err != nil {
		return nil, "", fmt.Errorf("issue server certificate: %w", err)
	}
	slog.Info("relay server certificate",
		"server_cert_fingerprint", cert.Fingerprint(),
		"dns_names", names.DNSNames,
		"ip_addresses", ipStrings(names.IPAddresses))
	return cert, advertisedAddress, nil
}
