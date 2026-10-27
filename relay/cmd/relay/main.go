package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/eventsink"
	"github.com/Felag-Engineering/relay/relay/internal/harnesssetup"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/logctx"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
	"github.com/Felag-Engineering/relay/relay/internal/store"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"github.com/Felag-Engineering/relay/relay/internal/version"
	"google.golang.org/grpc"
)

// Config holds the Relay's startup parameters, converted from the configuration
// file by fromFile.
type Config struct {
	Addr      string
	CADir     string
	StorePath string
	Hostname  string
	// ExtraNames are the further names the server certificate carries
	// (tls.extra_names, RC-47). They are read from the configuration file at
	// start and no API reaches them (invariant 11).
	ExtraNames []string
	// AdvertisedAddress is the node-plane address a join string tells Nodes to
	// dial (RC-36). Unset, it is the certificate hostname plus the gRPC listen
	// port. It is read from the configuration file at startup
	// (node_plane.advertised_address) and no API reaches it (ADR-0043,
	// invariant 11).
	AdvertisedAddress   string
	EnrollIPRate        int
	EnrollIPBurst       int
	EnrollGlobalRate    int
	EnrollGlobalBurst   int
	EnrollMaxTrackedIPs int
	MaxNodes            int
	// ReadBlastCap and MutateBlastCap are the blast-radius caps by risk class
	// (ADR-0004, ADR-0012).
	//
	// Read from the configuration file at start and on a host reload (RC-21),
	// and reachable from no API — which is invariant 11's requirement
	// (ADR-0043).
	//
	// What must stay true: no code path from a request to these values. A
	// stolen API Token cannot raise its own blast cap, and an API that could
	// would not be a cap.
	ReadBlastCap   int
	MutateBlastCap int

	// DispatchConcurrency is the per-Job bound on Tasks in flight at once.
	// It bounds reach, so invariant 11 allows it as runtime-shaped
	// configuration; it is not the blast cap (how many Nodes a Job may touch)
	// and not a security-floor value. It is read from the configuration file at
	// start and on a host reload (RC-21) and is reachable from no API; it is
	// planned to move to the store-backed settings object (ADR-0010 amendment
	// 2026-09-15), where invariant 11's "human with step-up, audited" rule
	// applies. Zero or negative refuses startup.
	DispatchConcurrency int

	// MinDaemonVersion is the minimum relay-daemon version (ADR-0014); empty
	// means the gate is off and no Node is ever Outdated. Same file-only,
	// never-API-settable mechanism as ReadBlastCap/MutateBlastCap above
	// (invariant 11, ADR-0010). A malformed value refuses start and a reload —
	// see newRunning.
	MinDaemonVersion string

	// CertExpiringFraction sets the state:cert-expiring warning window
	// (ADR-0034): a Node fires the marker once less than this fraction
	// of its identity certificate's lifetime remains. Same file-only,
	// never-API-settable mechanism as the fields above (invariant 11) — a
	// fraction rather than an absolute duration, so it tracks any future
	// change to ca.LeafValidity instead of going stale against it. There is
	// deliberately no "off" value: newRunning refuses outside (0, 1],
	// because a silently disabled alarm is exactly the failure this marker
	// exists to catch.
	CertExpiringFraction float64

	// ApprovalGatePath is the approval-gate config (ADR-0027): which dispatches
	// must park for a human. Same file-only mechanism as the blast caps, and the
	// gate file is re-read on a host reload (RC-21) — a path read from the
	// configuration file, never settable through any API, since
	// a stolen credential that could edit its own approval requirements would
	// make the mechanism decorative.
	//
	// EMPTY means no approval gates, which is safe because a gate can only add a reason to stop. A NON-EMPTY path that
	// cannot be loaded refuses startup — a Relay that silently decided nothing
	// needs approval because it could not read its own config is the exact
	// failure this mechanism exists to prevent (approval.Load).
	ApprovalGatePath string

	// ApprovalWebhook* configure the out-of-band notification envelope
	// (ADR-0027): where to push a Relay-authored notice that a dispatch has
	// parked. Empty URL disables it.
	//
	// Notification is DELIVERY, never the decision. The webhook is
	// fire-and-forget and unauthenticated in the inbound direction — a decision
	// only ever lands on the authenticated /api/v1 endpoint. A deployment whose
	// webhook is down loses a notification, not the guarantee.
	//
	// ApprovalWebhookURL may carry a token: it is a secret and is never logged
	// or put in an error. ApprovalWebhookSecret signs the outbound body
	// (HMAC-SHA256); it prints as a placeholder under every verb.
	ApprovalWebhookURL     relayconfig.Secret
	ApprovalWebhookSecret  relayconfig.Secret
	ApprovalWebhookTimeout time.Duration

	// ControlEnabled and ControlAddr configure the control-plane HTTP listener
	// (MCP + /api/v1, ADR-0009/0010) — separate from the node-plane gRPC
	// listener (Addr above). Default disabled (ControlEnabled=false) for
	// backward compatibility.
	//
	// There is deliberately no credential field: the control plane
	// authenticates per-Account API Tokens held in the store, not a shared
	// secret configured here (ADR-0023). The first one is minted by
	// `relay init`.
	ControlEnabled bool
	ControlAddr    string

	// Console* configure the Admin Console (ADR-0009, ADR-0026), served on the
	// control-plane listener above rather than one of its own — the Console is
	// internal-only and shares that listener's exposure posture.
	//
	// The two duration fields are configuration-file settings in the
	// invariant-11 sense: operator-set at startup, and there is no code path
	// from any request to either of them. That matters most for
	// ConsoleStepUpWindow — an Account that could widen its own step-up window
	// has removed the strongest per-action control in the system (spec 11).
	// The loader refuses a value above consoleauth.MaxStepUpWindow. It governs the
	// privilege-granting Account acts.
	ConsoleEnabled       bool
	ConsoleSessionMaxAge time.Duration
	ConsoleSessionIdle   time.Duration
	ConsoleStepUpWindow  time.Duration

	// OAuth* configure the OAuth 2.1 protected-resource half of the control
	// plane (ADR-0024): humans authenticate through an external IdP and
	// resolve to Accounts. Empty OAuthIssuer disables it entirely, and the
	// Relay then advertises no flow rather than one it cannot complete.
	//
	// Relay is never an authorization server. Like every other field here this
	// is startup configuration, unreachable through the Control API
	// (invariant 11) — an API that could repoint its own issuer could
	// authenticate anyone.
	OAuthIssuer        string
	OAuthAudience      string
	OAuthAccountClaim  string
	OAuthRequiredScope string
	// OAuthMetadataURL is this Relay's externally-reachable base URL, used to
	// build the RFC 9728 resource_metadata pointer a harness follows. It must
	// be the URL clients actually dial, not the listen address.
	OAuthPublicURL string
}

// appDeps holds the constructed collaborators that tests and lifecycle hooks need
// to reach without starting a listener.
type appDeps struct {
	// logger is the process logger every internal package is handed; it adds
	// the request, principal and Job ids from the context (logctx).
	logger *slog.Logger
	ca     *ca.CA
	// serverCert is the one server certificate both listeners present
	// (ADR-0031 §1); held for tests.
	serverCert *ca.ServerCertificate
	store      *store.Store
	registry   registry.Repository
	jobs       jobs.JobRepository
	tasks      jobs.TaskRepository
	audit      audit.Repository
	tokens     *enroll.Service
	// minter is the one enrollment Minter the Control API mints through; the
	// devharness and tests mint join strings through it too, never by hand.
	minter     *enroll.Minter
	denylist   *revocation.Denylist
	conns      *revocation.Connections
	revocation *revocation.Service
	limiter    *ratelimit.Limiter
	// live is the configuration snapshot the operator settings are read from,
	// and gate the approval gate; a reload (reload.go) swaps both. Held here for
	// the reloader and tests only: no adapter receives either (invariant 10).
	live *liveConfig
	gate *liveGate
	// freezeControl is the Freeze and its role floor — the part of the
	// capability layer the SIGUSR1/SIGUSR2 host lever (watchFreezeSignals)
	// drives. Always built, independent of ControlEnabled.
	freezeControl *capability.Control
	// execution is the Relay's execution service (ADR-0009/0010), built over
	// freezeControl, the read lane and the Approvals by capability.NewExecution
	// with the real Job engine over the real mTLS tunnel and the real
	// role-gated Authorizer (authz.NewRoleGate), so MCP/Control API
	// dispatch runs on the fleet. Built only when
	// Config.ControlEnabled; nil otherwise (nothing is mounted to call it).
	execution *capability.Execution
	// tunnel is the registered tunnelServer. Its sink is set by newServer
	// ONLY when Config.ControlEnabled (production execution), by
	// installDevHarness in a devharness-tagged build, or injected directly by
	// tests; nil when the control plane is disabled.
	tunnel *tunnelServer
	// control is the control-plane HTTP server (MCP + /api/v1, ADR-0009/0010),
	// nil when Config.ControlEnabled is false (default; backward-compatible).
	// It has its own listener and lifecycle, independent of the node-plane
	// gRPC server above.
	control *controlplane.Server
	// dispatch is the real dispatch.Router newServer builds when
	// Config.ControlEnabled — the same Conduit execution's Job engine dispatches
	// through — exposed so integration tests can block on a live Tunnel via Router.WaitForAny/
	// Connected before dispatching, rather than racing the offline
	// fail-fast (ADR-0004). Nil when the control plane is disabled.
	dispatch *dispatch.Router
	// metrics is the real capability.MetricsSink/enroll.EnrollmentObserver,
	// exposed so tests can assert on its counters/gauges directly.
	metrics *metrics.Metrics
	// events is the Relay's one in-process event seam: registry
	// transitions, Job transitions, MCP tool calls, and enrollment
	// attempts. Exposed so integration tests can Subscribe without going
	// through the Console's SSE route.
	events *events.Bus
	// hooks is what newServer threaded into the surfaces as serverHooks
	// — recorded so a test can assert the production entry point
	// (newServer) leaves it empty, while a test calling newServerWithHooks
	// directly can prove its own hooks reached surfaceDeps.
	hooks serverHooks
}

// opvocabLister adapts opvocab.Operations (a package-level func) to the
// mcp.OperationLister interface mcp.New expects, without opvocab needing to
// export a type of its own for this one call.
type opvocabLister struct{}

func (opvocabLister) Operations() []opvocab.Descriptor { return opvocab.Operations() }

// jobResultReader adapts st.Jobs()/st.Tasks() to mcp.JobResultReader — the
// tiny per-Job read surface the execution tools use to render
// per-Node results (exit code, output, duration) and get_job's polling
// re-read.
type jobResultReader struct {
	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
}

func (r jobResultReader) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	return r.jobsRepo.GetJob(ctx, id)
}

func (r jobResultReader) TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	return r.tasksRepo.ByJob(ctx, jobID)
}

// serverCertObserver returns the callback that makes rotation of the Relay's
// one server certificate observable: the log line an operator reads after the
// fact, and the counter they can alert on. internal/ca deliberately logs
// nothing itself, so this — the composition root — is where a rotation becomes
// visible. Both listeners present the certificate (ADR-0031 §1), so a re-issue
// moves the counter series of every listener given.
//
// The fingerprint is the new leaf's, and it is not a secret: it identifies a
// certificate, never authenticates one. Nothing here touches key material.
//
// A failed re-issue with a still-valid certificate in hand is an error, not a
// warning: rotation stopping is the first act of the outage this whole
// mechanism exists to prevent, and the leaf's remaining lifetime is all the
// warning there is.
func serverCertObserver(m *metrics.Metrics, listeners ...metrics.ServerCertListener) func(ca.Rotation) {
	return func(r ca.Rotation) {
		if r.Err != nil {
			slog.Error("server certificate re-issue failed; still serving the current certificate",
				"err", r.Err)
			return
		}
		for _, l := range listeners {
			m.IncServerCertRotation(l)
		}
		slog.Info("server certificate rotated",
			"not_after", r.NotAfter.Format(time.RFC3339),
			"renew_at", r.RenewAt.Format(time.RFC3339),
			"fingerprint", r.Fingerprint,
		)
	}
}

// newServer constructs and wires the gRPC server and all its dependencies from
// cfg. It does not create a listener or call Serve — those belong to main so
// that tests can construct the server without binding a port.
// declinedScanBudget bounds the boot-time declined-label scan. Generous rather
// than tight: it exists so a pathological label population cannot hold the
// startup path open indefinitely, not to police a slow disk. Exceeding it
// downgrades the signal to "scan failed" — which is logged — rather than
// refusing to start, because a detector must never be a gate.
const declinedScanBudget = 30 * time.Second

// approvalsWaitingTimeout bounds the approvals-waiting count a scrape runs, so
// a scrape never holds the single store connection longer than this.
const approvalsWaitingTimeout = 2 * time.Second

// newServer is the one production entry point: it builds the composition
// root with an empty serverHooks, so no test-only seam is ever populated on
// the path main takes. See newServerWithHooks and serverHooks
// (control_surfaces.go). files is what startup.Open read through the
// start-time file check; newServer opens neither the CA nor the gate itself,
// and opens the store at the path whose directory the check decided on.
func newServer(cfg Config, files startup.Files) (*grpc.Server, *appDeps, error) {
	return newServerWithHooks(cfg, files, serverHooks{})
}

func newServerWithHooks(cfg Config, files startup.Files, hooks serverHooks) (*grpc.Server, *appDeps, error) {
	if !files.Valid() {
		// Never a default: an absent gate would read as "nothing needs
		// approval", the failure approval.Load exists to prevent.
		return nil, nil, errors.New("build server: the CA, the approval gate and the store directory were not read through the start-time file check")
	}
	relayCA := files.CA()

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(relayCA.Bundle()) {
		return nil, nil, fmt.Errorf("parse CA bundle into cert pool")
	}

	// The number an operator checks a daemon's configured trust root against
	// (ADR-0031): it identifies the certificate authority every Node's
	// certificate chains to, so it survives the server leaf's daily
	// re-issue, and the Console's day-one screen renders the same value.
	// It is the fingerprint a join string carries and a daemon pins
	// (ADR-0031 decision 3, EN-7). A digest over a public certificate — no key
	// material, nothing secret, and safe to log.
	slog.Info("relay certificate authority", "ca_fingerprint", relayCA.Fingerprint())

	// An injected logger, not slog.SetDefault: installing a wrapper around the
	// default handler as the default would recurse through the log package
	// (logctx.Handler). It reads the default now, so a test that captures
	// internal log lines must set the default before newServer.
	logger := slog.New(logctx.NewHandler(slog.Default().Handler()))

	// The operator settings and the notifier, validated by the one path a
	// reload also takes. live is the snapshot every reach-bounding consumer
	// below reads on use, so a reload applies to the next request.
	r, err := newRunning(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	live := &liveConfig{}
	live.swap(r)
	if r.notifier != nil {
		slog.Info("approval webhook enabled", "signed", cfg.ApprovalWebhookSecret.IsSet())
	}

	if err := files.RecheckStore(); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(files.StorePath(),
		store.WithMaxNodesSource(func() int { return live.OperatorSettings().MaxNodes }),
		store.WithMinDaemonVersionSource(func() string { return live.OperatorSettings().MinDaemonVersion }),
		store.WithLogger(logger))
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}

	// The one-shot declined-Label startup scan (threat model R13) runs
	// here: immediately after Open, before anything else touches the store,
	// so the signal fires even if a later startup step fails. A failed scan
	// is a diagnostic failure, never a startup refusal — logged and
	// tolerated rather than returned, so the ABSENCE of the signal is itself
	// visible instead of silently taking the whole Relay down with it. Not
	// called from store.Open itself: Open's other caller is `relay init`, and
	// a fleet-wide warning dump in the middle of minting a token is noise in
	// the wrong place.
	// Bounded, because the scan holds the process's ONLY SQLite connection
	// (SetMaxOpenConns(1)) for O(total label rows) ahead of the listener, and
	// nothing caps how many labels a Node may report. A hundred Nodes each
	// holding ~10^5 well-formed labels is tens of millions of rows — invisible
	// to the scan's OUTPUT but not to its cost, and on the startup critical
	// path there is no request to cancel and no operator to wait for it. The
	// failure path below is already "warn and continue", so a deadline
	// degrades exactly as designed rather than adding a new outcome.
	scanCtx, cancelScan := context.WithTimeout(context.Background(), declinedScanBudget)
	defer cancelScan()
	if _, err := st.ScanDeclinedLabels(scanCtx); err != nil {
		slog.Warn("declined-label startup scan failed", "err", err)
	}
	// The same signal for the self-reported fields getNode declines on read
	// (the Policy fingerprint, Facts, and the rest), on the same terms and
	// within the same budget: O(Nodes), after the label scan. A label scan
	// that spends the budget leaves this one to fail, which warns and
	// continues like the label scan's own failure.
	if _, err := st.ScanDeclinedSelfReports(scanCtx); err != nil {
		slog.Warn("declined self-report startup scan failed", "err", err)
	}

	// denylist and conns implement immediate Node revocation (ADR-0006).
	// denylist.Add is reached at runtime by revocationSvc.RevokeNode (the
	// post-enroll revocation recheck and the Control API revoke path both call
	// it), which now ALSO persists the revocation to the registry. The registry
	// is the authority; the denylist is a derived cache, rehydrated from
	// registry.RevokedNodeIDs() below so a revoked Node stays refused across a
	// Relay restart.
	denylist := revocation.NewDenylist()
	conns := revocation.NewConnections()

	// Enrollment_Enroll is the only certless RPC: daemons call it before they have
	// a client certificate. All other RPCs (including Tunnel and Enrollment_Renew)
	// remain mTLS-required. Renew is intentionally absent here: it is authenticated
	// by the caller's existing mTLS client cert, not a token.
	certless := map[string]struct{}{
		relayv1.Enrollment_Enroll_FullMethodName: {},
	}

	limiter := ratelimit.New(rateConfig(live.OperatorSettings()),
		ratelimit.WithConfigSource(func() ratelimit.Config { return rateConfig(live.OperatorSettings()) }))

	// eventBus is the Relay's one in-process event seam: registry
	// transitions, Job transitions, MCP tool calls, and enrollment
	// attempts. Built here — before reg, which wraps it below — because it
	// depends on nothing and reg's ObserveRegistry decorator needs it.
	eventBus := events.NewBus()

	// st.Registry() is memoised (store.go) and this is its only non-test
	// caller, so wrapping it ONCE here covers every caller in the process —
	// including tunnel.go's SetConnected and enroll's SetRelayLabels —
	// without an edit to either file (eventsink.ObserveRegistry's doc
	// comment).
	reg := eventsink.ObserveRegistry(st.Registry(), eventBus)

	// appMetrics is the real capability.MetricsSink/enroll.EnrollmentObserver:
	// its counters are always live (wired into enrollSrv and base
	// below), independent of Config.ControlEnabled; only the /metrics HTTP
	// surface itself is gated on ControlEnabled (no control listener
	// otherwise), mirroring every other control-plane surface.
	// serverCert is assigned below, before any listener serves; the
	// scrape-time certificate closure reads it.
	var serverCert *ca.ServerCertificate
	appMetrics := metrics.New(metrics.GaugeSources{
		Connected: conns.Count,
		Nodes:     reg.Count,
		Frozen:    func() (bool, error) { return st.Freeze().Frozen(context.Background()) },
		// This binary's own build stamp — the composition root is the
		// only place that knows it; internal/metrics never imports
		// internal/version.
		Build: metrics.BuildInfo{
			Version:   version.Version,
			Commit:    version.Commit,
			BuildDate: version.BuildDate,
		},
		// The read-back label filter's live counters, read straight
		// off the Store rather than duplicated here — see
		// Store.LabelsDeclined and metrics.GaugeSources.LabelsDeclined.
		LabelsDeclined: st.LabelsDeclined,
		// One indexed count per scrape, bounded by approvalsWaitingTimeout. A
		// Request past its deadline cannot be answered; the sweeper retires it
		// within approval.DefaultSweepInterval, so it is not counted as waiting.
		ApprovalsWaiting: func() (int, error) {
			ctx, cancel := context.WithTimeout(context.Background(), approvalsWaitingTimeout)
			defer cancel()
			return st.Approvals().CountWaiting(ctx, time.Now())
		},
		CertificateRemaining: func(c metrics.Certificate) (time.Duration, bool) {
			var notAfter time.Time
			switch c {
			case metrics.CertificateRelayCA:
				notAfter = relayCA.NotAfter()
			case metrics.CertificateServer:
				// The leaf is re-issued at the next handshake, so on an idle
				// Relay this can fall toward zero: alert on the relay_ca series.
				if serverCert == nil {
					return 0, false
				}
				notAfter = serverCert.NotAfter()
			}
			if notAfter.IsZero() {
				return 0, false
			}
			return time.Until(notAfter), true
		},
	})

	// The Relay's one TLS server certificate, presented on both listeners
	// (ADR-0031 §1) and re-issued in-process before it expires so the fleet
	// never fail-closes on an expired leaf (ADR-0031 §5). The listeners share
	// the certificate and nothing else: each builds its own tls.Config, and
	// only the node plane asks for a client certificate (EN-9). Sharing a
	// tls.Config would share ClientAuth, so never share one.
	//
	// Failing to list the host's addresses is a warning, not a refusal: they
	// are a convenience on top of the configured names (tls.hostname, the
	// advertised host, tls.extra_names), and a detector must not become an
	// outage.
	//
	// The certificate names the advertised host and tls.extra_names so that no
	// join string carries a host it does not name (RC-46): the minter below
	// receives the same advertisedAddress.
	advertisedAddress, err := enroll.AdvertisedAddress(cfg.AdvertisedAddress, cfg.Hostname, cfg.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("advertised node-plane address: %w", err)
	}
	advertisedHost, _, err := net.SplitHostPort(advertisedAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("advertised node-plane address: %w", err)
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
	serverCert, err = relayCA.NewServerCertificate(names.DNSNames, names.IPAddresses,
		ca.WithRotationObserver(serverCertObserver(appMetrics, presentedOn...)))
	if err != nil {
		return nil, nil, fmt.Errorf("issue server certificate: %w", err)
	}
	slog.Info("relay server certificate",
		"server_cert_fingerprint", serverCert.Fingerprint(),
		"dns_names", names.DNSNames,
		"ip_addresses", ipStrings(names.IPAddresses))

	// The real adapter to the SQLite-backed audit trail is the Recorder
	// below, and the real persisted Relay-wide emergency stop (ADR-0013 —
	// see watchFreezeSignals in freeze_signal.go for the local engage/release
	// lever) is the Control.
	// One audit sink, shared by the capability layer and the MCP read surface
	// (ADR-0025): read-access records land in the same trail as dispatches, via
	// the same writer.
	auditSink := auditsink.New(st.Audit(), auditsink.WithLogger(logger))

	// A revoked Node's refused dial is recorded, throttled per Node (DI-23). The
	// record says a revoked Node's chain-verified certificate was presented; key
	// possession is not yet proven at the refusal point. The recorder writes the
	// audit trail and holds no handle on the Node, so the Relay never reaches
	// back to it (DI-21).
	revokedDials := auditsink.NewRevokedDialRecorder(auditSink, hooks.testRevokedDialClock)

	// Every handshake asks serverCert for the certificate to present, which
	// is what makes the guarantee unconditional: rotation is driven by
	// connections, not by a timer that a sleeping process could miss.
	creds := transport.ServerCredentials(serverCert.GetCertificate, clientCAs, denylist, revokedDials)

	// Rehydrate the denylist from the persisted authority before the listener
	// accepts any connection: the Denylist is a derived cache of
	// registry.RevokedNodeIDs(); the store is the source of truth (ADR-0006
	// "revocation is instant" must also hold across a restart).
	revokedIDs, err := reg.RevokedNodeIDs()
	if err != nil {
		return nil, nil, fmt.Errorf("load revoked node ids: %w", err)
	}
	for _, id := range revokedIDs {
		denylist.Add(id)
	}

	tokenSvc := enroll.NewService(st.Tokens())
	enrollmentMinter, err := enroll.NewMinter(tokenSvc, relayCA, advertisedAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment minter: %w", err)
	}
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc, revocation.WithLogger(logger))

	// policyCache is the display-only effective-Policy cache (invariant 12 /
	// ADR-0002): the tunnel handler records what a daemon reports in
	// DaemonMessage.policy, and describe_node (mounted below when
	// ControlEnabled) reads it. It always exists — independent of
	// ControlEnabled — so a daemon's PolicySnapshot is captured whether or not
	// the control-plane listener is on.
	policyCache := policyview.New()

	// vocabCache is policyCache's sibling for the per-Node Template Operation
	// vocabulary (ADR-0021): the tunnel handler records what a daemon
	// reports in DaemonMessage.templates, and describe_node/list_operations
	// read it. Display-only, and likewise independent of ControlEnabled.
	vocabCache := nodevocab.New()

	ts := &tunnelServer{conns: conns, reg: reg, policy: policyCache, vocab: vocabCache}
	// ts.sink is set below, ONLY inside the cfg.ControlEnabled branch:
	// execution is on if and only if the control plane (its only consumer
	// surface, MCP + /api/v1) is on. Disabled: ts.sink stays nil. Integration tests, or
	// installDevHarness in a devharness-tagged build, may also inject a
	// taskSink directly.

	// The read lane: filtered, paginated queries over the audit trail
	// and over Jobs/Tasks, adapted onto capability.AuditQuery/JobQuery by
	// internal/auditquery — auditsink's twin, for the same import-boundary
	// reason (capability's allowlist bars internal/audit).
	queries := auditquery.New(st.AuditQueries(), st.JobQueries())

	// The approval gate (ADR-0027), loaded by startup.Open before anything
	// here was built: a load failure refuses start rather than degrading, so an
	// empty Gate only ever means "no rules configured", never "the rules could
	// not be read".
	// The gate is held behind a swappable pointer so a reload replaces it whole.
	approvalGate := &liveGate{}
	approvalGate.swap(files.Gate())
	if n := len(files.Gate().Rules()); n > 0 {
		slog.Info("approval gating enabled", "rules", n, "config", cfg.ApprovalGatePath)
	}

	// ONE RoleGate for the whole process. It answers both "who may dispatch
	// this Action" and "who may decide an approval for one", and those
	// two must be the same ladder read from the same object: an approver who
	// could release what they could not request would be a side door around
	// ADR-0001's admin-only Raw Exec.
	roleGate := authz.NewRoleGate()

	// The one TokenService in the process: the authenticator VERIFIES through
	// it and the Control API MINTS through it (via capability.NewAccountAdmin
	// below), but each is handed a narrow interface exposing only its half
	// (controlplane.TokenVerifier / capability.APITokenStore), so neither
	// surface holds the other's power. Constructed here, above the shared
	// capability objects, because NewAccountAdmin needs it and both
	// branches below share the AccountAdmin it builds.
	apiTokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)

	// The ONE Recorder: audit trail, metrics and log, shared by the Control,
	// the read lane and the Approvals, and so the whole capability layer
	// (capability.NewExecution refuses a read lane or an Approvals over a different one).
	rec := capability.NewRecorder(auditSink, appMetrics, logger)

	// The Freeze and its role floor (ADR-0013) over the real RoleGate:
	// both branches below carry a real Authorizer, not just the
	// ControlEnabled one, which is what makes NewAccountAdmin below
	// satisfiable — its fail-open guard requires a real Authorizer. On the
	// disabled branch this changes no caller's outcome: nothing
	// is mounted on that path (see the ControlEnabled==false branch's comment
	// below).
	freezeControl := capability.NewControl(rec, roleGate, st.Freeze())

	// Account and API-Token administration: the same Accounts store and
	// TokenService the authenticator and `relay init` use, so identity
	// administration inherits one floor (invariant 10) instead of the Control
	// API deciding role itself per handler. Built over the Control, so it
	// shares its Authorizer and trail.
	accountAdmin := capability.NewAccountAdmin(freezeControl, st.Accounts(), apiTokenSvc)

	// The tag write (ADR-0050): the one writer of tag: labels, over the same
	// Control and so the same Recorder, RoleGate and trail. The Control API and
	// the Console hold it for tag writes, and the Enrollment service for a
	// token's initial tags (WriteInitialTags); MCP is never handed it.
	tagWriter := capability.NewTagWriter(freezeControl, reg)
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter),
		enroll.WithEnrollmentObserver(appMetrics),
		enroll.WithAttemptObserver(eventsink.Enrollment(eventBus)),
		enroll.WithServerLogger(logger),
		enroll.WithInitialTagWriter(initialTagWriter{tags: tagWriter}))

	// The Policy alias write: the one alias writer, over the same Control,
	// Recorder and trail. Only the Console holds it (QRY-36).
	policyAliasAdmin := capability.NewPolicyAliasAdmin(freezeControl, st.PolicyAliases())

	// The read lane: filtered, paginated queries over the audit trail
	// and over Jobs/Tasks — one seam, shared by every surface (invariant 10).
	// live supplies state:cert-expiring's warning window (ADR-0034), read per
	// request, and is the one source the BlastCap and the Execution below share. The
	// Policy-view and Template-vocabulary reads (QRY-28) are the same
	// policyCache/vocabCache the Tunnel handler writes into below (ts),
	// Get-only from this side. Wiring them here is what lets
	// describe_node/list_operations disclose a Node's Policy and Template
	// vocabulary through the ONE capability layer, on every surface, instead
	// of each surface holding its own cache reference — and, for vocabCache,
	// what lets a Template Operation be dispatched at all: the capability
	// layer resolves its fan-out and class from it (ADR-0042). Without it
	// every Template dispatch is refused. A nil clock is the real one. The
	// Policy alias source is the store's read-only view of the aliases.
	readLane := capability.NewReadLane(rec, reg, queries, queries, policyCache, vocabCache, live, nil, capability.WithPolicyAliasSource(st.PolicyAliases()))

	// The approval callout (ADR-0027), over the one Recorder and the same
	// RoleGate as dispatch. Batch/window grants (ADR-0027 decision
	// 12) are wired unconditionally alongside the gate: a Grant can only ever be
	// created through an approval Request the gate itself required, so with no
	// rules configured nothing is gated, nothing can be granted, and the store
	// simply holds no rows. MCP task handles (ADR-0028) are wired for the
	// same reason: a handle is only ever minted for a dispatch the gate parked,
	// so with no rules configured nothing parks and the table stays empty. A nil
	// clock is the real one.
	approvals := capability.NewApprovals(rec, approvalGate, st.Approvals(), roleGate, st.Grants(), st.MCPTasks(), liveNotifier{live}, nil)

	var execution *capability.Execution
	var controlSrv *controlplane.Server
	var dispatchRouter *dispatch.Router
	if cfg.ControlEnabled {
		// This is THE production execution flip: the Relay becomes
		// remote-code-execution-as-a-service over the control surfaces
		// mounted below. newDispatchStack (dispatch_wiring.go) is the SAME
		// tested assembly installDevHarness uses — no parallel production
		// wiring path — over the real mTLS Tunnel (tunnelServer.Open,
		// tunnel.go). The guardrails are unchanged and all already enforced
		// through this one capability pipeline (invariant 10): mTLS
		// authenticates every Node (ADR-0005/0006); the daemon's live Policy
		// engine remains the sole, last-word verdict on every Task
		// (ADR-0002/0011) — nothing added here evaluates or mutates Policy;
		// the blast-radius cap (ADR-0004/0012) and the real, deny-by-default
		// authz.NewRoleGate Authorizer (ADR-0010) both run before any
		// dispatch; Freeze (ADR-0013) can stop all of it instantly; every
		// dispatch and refusal is audited. This flip adds no new
		// bypass — it only turns on the same pipeline every other surface
		// already dispatches through.
		router, reconciler, sink := newDispatchStack(st.Tasks(), violationRecorder{audit: auditSink, metrics: appMetrics}, logger)
		// reconciler is captured by router's onConnect closure
		// (dispatch_wiring.go) and fires on every Node (re)connect — this is
		// what makes crash-mid-Job restart reconciliation happen; it is not
		// called directly from here.
		_ = reconciler
		ts.sink = sink
		dispatchRouter = router

		execution = capability.NewExecution(freezeControl, readLane, approvals,
			// The real BlastCap (ADR-0004/0012; see the ReadBlastCap/MutateBlastCap
			// doc comment on Config for the file-vs-flag deviation flagged for
			// human review).
			capability.NewBlastCap(live),
			// Dispatch idempotency keys: the MCP execution tools forward an
			// optional key so a call re-issued after a lost response re-attaches to
			// its Job. Without this a keyed call is refused, never run unkeyed.
			st.IdempotencyKeys(),
			st.Jobs(), st.Tasks(), router,
			live,
			nil, // newID: the production default
			// The event seam's Job-grained publisher.
			eventsink.Jobs(eventBus))

		// No Account is seeded: the first admin is created by `relay init`
		// (ADR-0030, amended 2026-10-16).

		// apiTokenSvc is constructed above, before the shared capability
		// objects (NewAccountAdmin needs it), and reused here.

		// OAuth 2.1 protected-resource support (ADR-0024). Discovery
		// happens ONCE, here at startup, so a misconfigured issuer fails the
		// Relay's boot loudly rather than every request quietly.
		var authOpts []controlplane.AuthOption
		if cfg.OAuthIssuer != "" {
			oauthCfg := controlplane.OAuthConfig{
				Issuer:        cfg.OAuthIssuer,
				Audience:      cfg.OAuthAudience,
				AccountClaim:  cfg.OAuthAccountClaim,
				RequiredScope: cfg.OAuthRequiredScope,
			}
			if oauthCfg.Audience == "" {
				return nil, nil, fmt.Errorf("-oauth-audience is required with -oauth-issuer: without the audience check, a token minted for any other service sharing the IdP would authenticate here")
			}
			if cfg.OAuthPublicURL == "" {
				return nil, nil, fmt.Errorf("-oauth-public-url is required with -oauth-issuer: it is how a harness is told where to find this Relay's protected-resource metadata")
			}
			verifier, err := controlplane.NewOIDCVerifier(context.Background(), oauthCfg)
			if err != nil {
				return nil, nil, fmt.Errorf("oauth resource server: %w", err)
			}
			metadataURL := strings.TrimSuffix(cfg.OAuthPublicURL, "/") + controlplane.ProtectedResourceMetadataPath
			// A read-only Account view: resolving a session must never be able
			// to create one (ADR-0024, no auto-provisioning).
			authOpts = append(authOpts, controlplane.WithOAuth(oauthCfg, verifier, st.Accounts(), metadataURL))
			slog.Info("oauth resource server enabled",
				"issuer", cfg.OAuthIssuer,
				"audience", cfg.OAuthAudience,
				"account_claim", oauthCfg.AccountClaim,
				"metadata_url", metadataURL,
			)
		}

		// The Admin Console's human authentication lane (ADR-0009).
		//
		// Built BEFORE the authenticator because it is one of its credential
		// lanes: browser sessions sit beside API Tokens and OAuth at the one
		// authentication boundary (invariant 10), rather than the Console
		// authenticating its own requests, which would be a second control
		// path and the first one to be forgotten.
		var consoleAuthSvc *consoleauth.Service
		if cfg.ConsoleEnabled {
			consoleSessions := consoleauth.NewStore(
				consoleauth.WithLifetimes(cfg.ConsoleSessionMaxAge, cfg.ConsoleSessionIdle),
			)
			// auditSink, not a nil Auditor: consoleauth FAILS a sign-in it
			// cannot record, and handing it nothing to record with would turn
			// that fail-closed property into a silent no-op, as a nil sink
			// would for every read record. The counter wraps it and always
			// delegates.
			consoleAuthSvc = consoleauth.NewService(
				st.Accounts(), st.Passwords(), consoleSessions,
				consoleauth.NewThrottle(), loginAuditCounter{next: auditSink, metrics: appMetrics},
				consoleauth.WithStepUpWindow(cfg.ConsoleStepUpWindow),
				consoleauth.WithLogger(logger),
			)
			authOpts = append(authOpts, controlplane.WithConsoleSessions(
				consoleAuthSvc,
				controlplane.ConsoleSessionOptions{
					// The ONE hole this punches in the auth wrapper: the
					// sign-in page and its stylesheet. The predicate is owned
					// by the package that owns those routes, and its exact
					// extent is asserted there.
					Public: console.Unauthenticated,
					// And the reach of the credential this lane resolves
					// (ADR-0010): a Console session authenticates the Console,
					// not /api/v1 and not /mcp. Owned by the same package for
					// the same reason — it is a statement about which routes
					// exist, and consoleSurface below mounts every one of
					// them under this prefix.
					Scope:        console.SessionScope,
					Unauthorized: console.UnauthorizedHandler(),
				},
			))
			slog.Info("admin console enabled",
				"path", console.HomePath,
				"session_max_age", cfg.ConsoleSessionMaxAge,
				"session_idle", cfg.ConsoleSessionIdle,
				"step_up_window", cfg.ConsoleStepUpWindow,
			)
		}

		authOpts = append(authOpts, controlplane.WithAuthFailureCounter(appMetrics))
		authn := controlplane.NewAuthenticator(apiTokenSvc, authOpts...)
		controlCfg := controlplane.Config{Addr: cfg.ControlAddr, GetCertificate: serverCert.GetCertificate}
		if cfg.ConsoleEnabled {
			// A browser opened on the bare host lands on the Console. Off with
			// the Console, so / stays the authenticated mux's 401.
			controlCfg.RootRedirect = console.HomePath
		}
		controlSrv = controlplane.New(
			controlCfg,
			// Two credential kinds, routed by prefix: per-Account API Tokens
			// verified against the store, and OAuth sessions verified against
			// the IdP. No shared secret and no digest held in memory
			// (ADR-0023, ADR-0024).
			authn,
		)

		// Every input is already validated by relayconfig, so an error here is a
		// composition bug, not an operator mistake.
		harnessTarget, err := harnesssetup.NewTarget(advertisedAddress, cfg.ControlAddr, relayCA.Bundle())
		if err != nil {
			return nil, nil, fmt.Errorf("harness setup: %w", err)
		}

		// sd bundles every collaborator a control surface's Mount may need,
		// assembled exactly once (invariant 10: execution above is a single
		// instance, delivered to every surface below — no surface constructs
		// its own capability.Execution or dispatcher). See control_surfaces.go
		// for the ControlSurface seam this replaces the two inline
		// mount stanzas with.
		sd := surfaceDeps{
			logger:    logger,
			ops:       opvocabLister{},
			execution: execution,
			// The predicate that gates WithOAuth above.
			oauthConfigured: cfg.OAuthIssuer != "",
			harnessSetup:    harnessTarget,
			// The leaf capability services (invariant 10): each surface is
			// handed the narrow one it uses, not the Execution — see
			// surfaceDeps. A field forgotten here is a nil pointer behind a
			// non-nil interface, so the Console's account routes and the
			// read-lane routes are exercised end to end by the e2e tests.
			freezeControl:    freezeControl,
			readLane:         readLane,
			accountAdmin:     accountAdmin,
			tagWriter:        tagWriter,
			policyAliasAdmin: policyAliasAdmin,
			approvals:        approvals,
			jobs:             st.Jobs(),
			tasks:            st.Tasks(),
			enrollmentMinter: enrollmentMinter,
			revocation:       revocationSvc,
			audit:            st.Audit(),
			// The read-access sink (ADR-0025), for the MCP read tools and the
			// Control API's Job-read route. Left nil, readAuditor's defensive
			// `sink == nil` skip would silently disable every read-access
			// record. TestSurfaceDeps_AuditSinkIsWired is the regression
			// guard, because a nil here fails silently by design.
			auditSink: auditSink,
			// The same RoleGate the capability layer authorizes with:
			// the Control API's administrative routes never reach the
			// capability layer, so they read their floor from this object
			// directly rather than from a second table.
			roleGate: roleGate,
			now:      func() time.Time { return time.Now().UTC() },
			metrics:  appMetrics,

			// The Console's read seams (v0.6.0 screens). Every one is an object
			// already assembled above and already handed to another surface —
			// the registry the MCP read tools list, the policyview cache
			// describe_node renders, the trail the Control API appends to. The
			// Console narrows each to a read-only interface at the boundary
			// (console/seams.go); nothing new is constructed for it.
			//
			// There is no separate liveness seam: connectedness comes off
			// registry.Node.Connected, the same fact every other surface reads,
			// fed by the same tunnel handler that registers the dispatch sink
			// above — see nodestate.Input's doc comment.
			//
			// freeze is the read half of the Relay-wide emergency stop, for the
			// control-plane banner. The store's repository, not the capability
			// layer: the Console must be able to SEE the Freeze and must not be
			// able to touch it, and handing it an object with Engage on it
			// would make that a matter of discipline instead of type.
			freeze: st.Freeze(),

			consoleAuth: consoleAuthSvc,

			// The event seam — the Console's one live-read route
			// mounts over this, narrowed to a reader with no Publish
			// method on it (console/seams.go).
			events: eventBus,

			// The two fingerprints day one renders. The CA's is
			// fixed for the life of the process; the server leaf's is read
			// live because it is re-issued about daily.
			//
			// The one server certificate both listeners present, so the leaf
			// this screen shows is the one the browser reading it is talking
			// to (ADR-0031 §1).
			trust: consoleTrustReader{
				caFingerprint: relayCA.Fingerprint(),
				serverCert:    serverCert,
			},
			// Test-only (serverHooks): empty on the production path,
			// since newServer always calls newServerWithHooks with an empty
			// serverHooks. See mcpSurface.Mount.
			testMCPOptions: hooks.testMCPOptions,
		}
		surfaces := defaultControlSurfaces()
		if cfg.ConsoleEnabled {
			// Appended only when enabled, so with the Console off there is no
			// /console/ route on the listener at all. Absent, not refusing (ADR-0009).
			surfaces = append(surfaces, consoleSurface{})
		}
		for _, s := range surfaces {
			s.Mount(controlSrv.Mux(), sd)
		}
	}
	// With ControlEnabled off no consumer surface is mounted (MCP and API
	// require it), so no Execution is built. The Control (a real RoleGate),
	// AccountAdmin, read lane and Approvals above are still built, and
	// SIGUSR1/2 drives freezeControl.

	serverOpts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, denylist)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, denylist)),
	}
	serverOpts = append(serverOpts, transport.KeepaliveServerOptions(transport.ProductionKeepalive())...)
	srv := grpc.NewServer(serverOpts...)
	relayv1.RegisterTunnelServer(srv, ts)
	relayv1.RegisterEnrollmentServer(srv, enrollSrv)

	deps := &appDeps{
		ca:         relayCA,
		serverCert: serverCert,
		store:      st,
		registry:   reg,
		jobs:       st.Jobs(),
		tasks:      st.Tasks(),
		audit:      st.Audit(),
		tokens:     tokenSvc,
		minter:     enrollmentMinter,
		denylist:   denylist,
		conns:      conns,
		revocation: revocationSvc,
		limiter:    limiter,
		live:       live,
		gate:       approvalGate,
		execution:  execution,

		freezeControl: freezeControl,
		tunnel:        ts,
		control:       controlSrv,
		dispatch:      dispatchRouter,
		metrics:       appMetrics,
		events:        eventBus,
		hooks:         hooks,
		logger:        logger,
	}
	return srv, deps, nil
}

func main() {
	// Retired RELAY_* names are refused by the server and by init alike
	// (ADR-0043). Read once, here; each path reports it in its own order.
	envErr := relayconfig.RefuseRetiredEnv(os.Environ())

	// `relay init` (init.go) is the binary's one local act (ADR-0030). It
	// loads the configuration through the same check as the server below,
	// acts on the store the Relay created, and never starts a server.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		os.Exit(runInitCommand(os.Args[2:], envErr, os.Stdin, os.Stdout, os.Stderr))
	}

	// `relay --version` prints the build stamp and exits. Checked here,
	// alongside init and before argument parsing, because the
	// flag package would otherwise reject it as an unknown flag: an operator
	// must be able to identify a binary without a valid startup config.
	//
	// All three spellings are accepted, and relay-daemon accepts exactly the
	// same three (daemon/src/main.rs) — the two binaries are operated together
	// and must not disagree about how to ask them what they are.
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "-V") {
		fmt.Println(version.String())
		return
	}

	// Startup order follows ADR-0043: refuse retired RELAY_* names, open and
	// check the file, decode strictly, validate, open and check every file it
	// names, check the state locations, and only then build the server.
	path, err := parseArgs(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	// Registered before the file is read: until a handler is installed SIGHUP's
	// default action ends the process, and a signal sent during start is queued
	// and served once the watcher starts (reload_signal.go).
	hup := notifyReload()
	if envErr != nil {
		fmt.Fprintf(os.Stderr, "relay: %v\n", envErr)
		os.Exit(1)
	}
	sc, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay: %v\n", err)
		os.Exit(1)
	}
	// The base handler is swappable so a reload can change the level and format
	// (RC-21); slog.SetDefault is called once.
	logs := newSwapHandler(newLogHandler(os.Stderr, sc.Log))
	slog.SetDefault(slog.New(logs))
	for _, w := range sc.Warnings {
		slog.Warn(w.String())
	}
	cfg := sc.Config
	files, err := startup.Open(cfg.ApprovalGatePath, cfg.CADir, cfg.StorePath)
	if err != nil {
		slog.Error("start-time file check refused", "err", err)
		os.Exit(1)
	}
	srv, deps, err := newServer(cfg, files)
	if err != nil {
		slog.Error("build server failed", "err", err)
		os.Exit(1)
	}
	defer deps.store.Close() //nolint:errcheck
	// installDevHarness is a no-op in every build except `devharness`
	// (relay/cmd/relay/devharness_stub.go vs devharness.go); it must run
	// before Serve so deps.tunnel.sink is set before any tunnel handler starts.
	stop, err := installDevHarness(cfg, deps)
	if err != nil {
		slog.Error("install dev harness failed", "err", err)
		os.Exit(1)
	}
	defer stop()
	// watchFreezeSignals is the local engage/release lever for the Relay-wide
	// Freeze (ADR-0013) — see freeze_signal.go for the asymmetric-
	// activation rationale. It must start before Serve so a signal sent
	// immediately after startup is never missed.
	go watchFreezeSignals(context.Background(), deps.freezeControl)
	// SIGHUP reloads the configuration file (reload_signal.go).
	go watchReload(context.Background(), hup, newReloader(path, sc, deps, logs, os.Stderr))
	lis := mustListen(cfg.Addr, "listen failed")
	slog.Info("relay listening",
		"version", version.Version,
		"commit", version.Commit,
		"build_date", version.BuildDate,
		"addr", cfg.Addr,
		"config_file", path,
		"mtls", true,
		"ca_dir", cfg.CADir,
		"store_path", cfg.StorePath,
		"enroll_ip_rate_per_min", cfg.EnrollIPRate,
		"enroll_ip_burst", cfg.EnrollIPBurst,
		"enroll_global_rate_per_min", cfg.EnrollGlobalRate,
		"enroll_global_burst", cfg.EnrollGlobalBurst,
		"enroll_max_tracked_ips", cfg.EnrollMaxTrackedIPs,
		"max_nodes", cfg.MaxNodes,
		"read_blast_cap", cfg.ReadBlastCap,
		"mutate_blast_cap", cfg.MutateBlastCap,
		"dispatch_concurrency", cfg.DispatchConcurrency,
		"min_daemon_version", cfg.MinDaemonVersion,
		"cert_expiring_fraction", cfg.CertExpiringFraction,
	)

	// The control-plane listener (MCP + /api/v1, ADR-0009/0010) is separate
	// from the node-plane gRPC listener above: its own address, its own
	// goroutine, its own lifecycle. deps.control is nil unless
	// cfg.ControlEnabled, so this is a no-op on the default (disabled) path.
	if deps.control != nil {
		listenAndServeControl(deps.control, cfg.ControlAddr)
	}
	if deps.store != nil {
		startHousekeeping(deps)
	}

	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}

// mustListen opens a process-lifetime TCP listener, logging failMsg and
// exiting when the address cannot be bound.
func mustListen(addr, failMsg string) net.Listener {
	lis, err := net.Listen("tcp", addr) //nolint:noctx // process-lifetime listener opened at startup; there is no context to bound it
	if err != nil {
		slog.Error(failMsg, "addr", addr, "err", err)
		os.Exit(1)
	}
	return lis
}

// listenAndServeControl binds the control-plane listener and serves it in its own
// goroutine; a serve failure other than a clean close ends the process.
func listenAndServeControl(control *controlplane.Server, addr string) {
	lis := mustListen(addr, "control-plane listen failed")
	slog.Info("control-plane listening",
		"addr", addr,
		"credential_configured", true,
	)
	go func() {
		if err := control.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("control-plane serve failed", "err", err)
			os.Exit(1)
		}
	}()
}

// startHousekeeping starts the background loops that read the store.
//
// The approval expiry sweeper (ADR-0027) retires parked Requests whose TTL has
// passed, so the queue does not fill with zombies. It is HOUSEKEEPING, not the
// expiry guarantee. A lapsed Request is already undecidable and unredeemable
// by the clock alone (approval.Request.PastDeadline), so a sweeper that stalls
// cannot make a stale approval usable — it only leaves the stored state
// looking live for longer than it is. That is why a sweep error logs and
// continues rather than taking the process down.
//
// The audit chain checkpointer logs a metadata-only line an operator keeps as
// an anchor for relay-audit-verify -expect.
func startHousekeeping(deps *appDeps) {
	sweeper := approval.NewSweeper(deps.store.Approvals(), approval.DefaultSweepInterval, nil,
		func(ctx context.Context, r approval.Request) {
			slog.Info("approval request expired",
				"request_id", r.ID, "requested_by", r.RequestedBy,
				"plan_hash", r.PlanHash, "expires_at", r.ExpiresAt)
			if err := auditExpiry(ctx, deps, r); err != nil {
				slog.Error("record approval expiry in audit", "request_id", r.ID, "err", err)
			}
		})
	go sweeper.Run(context.Background(), func(err error) {
		slog.Error("approval sweep failed", "err", err)
	})

	go auditsink.NewCheckpointer(deps.store.AuditChain(), auditsink.DefaultCheckpointInterval, deps.logger).
		Run(context.Background(), func(err error) {
			slog.Error("audit chain checkpoint failed", "err", err)
		})
}

// auditExpiry records a lapsed approval Request in the audit trail. An approval
// that ran out of time is a fact the trail must carry: without it, a parked
// dispatch simply vanishes from the record, and "what happened to that request"
// has no answer.
func auditExpiry(ctx context.Context, deps *appDeps, r approval.Request) error {
	return deps.audit.Append(ctx, audit.Record{
		Timestamp: r.ResolvedAt,
		Kind:      audit.KindApprovalExpired,
		Principal: r.RequestedBy,
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: r.RequestedByID, AccountName: r.RequestedBy},
		},
		Reason: fmt.Sprintf("approval request %s expired at %s without reaching %s (plan %s): %s",
			r.ID, r.ExpiresAt.UTC().Format(time.RFC3339), r.Progress(), r.PlanHash, r.Summary),
	})
}
