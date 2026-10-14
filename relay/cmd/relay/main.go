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
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approvalnotify"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/console"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/eventsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/metrics"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/version"
	"google.golang.org/grpc"
)

// Config holds all Relay startup parameters resolved from flags and environment.
type Config struct {
	Addr                string
	CADir               string
	StorePath           string
	Hostname            string
	EnrollIPRate        int
	EnrollIPBurst       int
	EnrollGlobalRate    int
	EnrollGlobalBurst   int
	EnrollMaxTrackedIPs int
	MaxNodes            int
	// ReadBlastCap and MutateBlastCap are the blast-radius caps by risk class
	// (ADR-0004, ADR-0012).
	//
	// Set at startup by flag or RELAY_* environment variable, and reachable
	// from no API — which is invariant 11's actual requirement, settled in
	// #362. An earlier reading of that invariant expected a config-file
	// loader and these comments called flags+env an "interim" deviation
	// pending one; the invariant now states the property rather than a file
	// format, and the delivered mechanism is the root-owned systemd unit and
	// EnvironmentFile in relay/packaging/.
	//
	// What must stay true: no code path from a request to these values. A
	// stolen API Token cannot raise its own blast cap, and an API that could
	// would not be a cap. Secrets stay PATHS rather than values (the
	// control-plane credential, the approval-webhook secret below), so
	// nothing sensitive reaches a process listing or a crash dump.
	ReadBlastCap   int
	MutateBlastCap int

	// DispatchConcurrency is the per-Job bound on Tasks in flight at once
	// (#886). It bounds reach, so invariant 11 allows it as runtime-shaped
	// configuration; it is not the blast cap (how many Nodes a Job may touch)
	// and not a security-floor value. It is startup-only today and reachable
	// from no API; it is planned to move to the store-backed settings object
	// under #596, where invariant 11's "human with step-up, audited" rule
	// applies. Zero or negative refuses startup.
	DispatchConcurrency int

	// MinDaemonVersion is the minimum relay-daemon version (ADR-0014); empty
	// means the gate is off and no Node is ever Outdated. Same startup-only,
	// never-API-settable mechanism as ReadBlastCap/MutateBlastCap above
	// (invariant 11, ADR-0010). A malformed value refuses startup — see
	// newServer.
	MinDaemonVersion string

	// CertExpiringFraction sets the state:cert-expiring warning window
	// (ADR-0034, #414): a Node fires the marker once less than this fraction
	// of its identity certificate's lifetime remains. Same startup-only,
	// never-API-settable mechanism as the fields above (invariant 11) — a
	// fraction rather than an absolute duration, so it tracks any future
	// change to ca.LeafValidity instead of going stale against it. There is
	// deliberately no "off" value: newServer refuses startup outside (0, 1],
	// because a silently disabled alarm is exactly the failure this marker
	// exists to catch.
	CertExpiringFraction float64

	// ApprovalGatePath is the root-owned approval-gate config (#269,
	// ADR-0027): which dispatches must park for a human. Same startup-only
	// mechanism as the blast caps and the control-plane credential — a path,
	// never settable through any API, since
	// a stolen credential that could edit its own approval requirements would
	// make the mechanism decorative.
	//
	// EMPTY means no approval gates, which is the pre-#269 behaviour and is
	// safe because a gate can only add a reason to stop. A NON-EMPTY path that
	// cannot be loaded refuses startup — a Relay that silently decided nothing
	// needs approval because it could not read its own config is the exact
	// failure this mechanism exists to prevent (approval.Load).
	ApprovalGatePath string

	// ApprovalWebhook* configure the out-of-band notification envelope (#270,
	// ADR-0027): where to push a Relay-authored notice that a dispatch has
	// parked. Empty URL disables it.
	//
	// Notification is DELIVERY, never the decision. The webhook is
	// fire-and-forget and unauthenticated in the inbound direction — a decision
	// only ever lands on the authenticated /api/v1 endpoint. A deployment whose
	// webhook is down loses a notification, not the guarantee.
	//
	// ApprovalWebhookSecretPath names a root-owned file holding the shared
	// secret used to sign the outbound body (HMAC-SHA256). It is a path rather
	// than a value for the same reason the control-plane credential is: a
	// secret passed as a flag or an environment variable is a secret in every
	// process listing and every crash dump.
	ApprovalWebhookURL        string
	ApprovalWebhookSecretPath string
	ApprovalWebhookTimeout    time.Duration

	// ControlEnabled and ControlAddr configure the control-plane HTTP listener
	// (MCP + /api/v1, ADR-0009/0010) — separate from the node-plane gRPC
	// listener (Addr above). Default disabled (ControlEnabled=false) for
	// backward compatibility.
	//
	// There is deliberately no credential field: since #298 the control plane
	// authenticates per-Account API Tokens held in the store, not a shared
	// secret configured here (ADR-0023). Bootstrap the first one with
	// `relay bootstrap-token`.
	ControlEnabled bool
	ControlAddr    string

	// Console* configure the Admin Console (ADR-0009, ADR-0026), served on the
	// control-plane listener above rather than one of its own — the Console is
	// internal-only and shares that listener's exposure posture.
	//
	// The two duration fields are file-only Relay configuration in the
	// invariant-11 sense: operator-set at startup, and there is no code path
	// from any request to either of them. That matters most for
	// ConsoleStepUpWindow — an Account that could widen its own step-up window
	// has removed the strongest per-action control in the system (spec 11).
	// It is clamped to consoleauth.MaxStepUpWindow at parse. It governs the
	// privilege-granting Account acts, and never approval decisions, which
	// always ask for the password.
	ConsoleEnabled       bool
	ConsoleSessionMaxAge time.Duration
	ConsoleSessionIdle   time.Duration
	ConsoleStepUpWindow  time.Duration

	// OAuth* configure the OAuth 2.1 protected-resource half of the control
	// plane (#299, ADR-0024): humans authenticate through an external IdP and
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
	logger     *slog.Logger
	ca         *ca.CA
	store      *store.Store
	registry   registry.Repository
	jobs       jobs.JobRepository
	tasks      jobs.TaskRepository
	audit      audit.Repository
	tokens     *enroll.Service
	denylist   *revocation.Denylist
	conns      *revocation.Connections
	revocation *revocation.Service
	limiter    *ratelimit.Limiter
	// freezeControl is the Freeze and its role floor — the part of the
	// capability layer the SIGUSR1/SIGUSR2 host lever (watchFreezeSignals)
	// drives. Always built, independent of ControlEnabled.
	freezeControl *capability.Control
	// execution is the Relay's execution service (ADR-0009/0010), built over
	// freezeControl, the read lane and the Approvals by capability.NewExecution
	// with the real Job engine over the real mTLS tunnel and the real
	// role-gated Authorizer (authz.NewRoleGate) — this is the "#154 flip": MCP/
	// Control API dispatch actually runs on the fleet. Built only when
	// Config.ControlEnabled; nil otherwise (nothing is mounted to call it).
	execution *capability.Execution
	// tunnel is the registered tunnelServer. Its sink is set by newServer
	// ONLY when Config.ControlEnabled (production execution, #154), by
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
	// through — exposed so integration tests (and a later real-fleet e2e
	// surface, #121) can block on a live Tunnel via Router.WaitForAny/
	// Connected before dispatching, rather than racing the offline
	// fail-fast (ADR-0004). Nil when the control plane is disabled.
	dispatch *dispatch.Router
	// metrics is the real capability.MetricsSink/enroll.EnrollmentObserver
	// (#182), exposed so tests can assert on its counters/gauges directly.
	metrics *metrics.Metrics
	// events is the Relay's one in-process event seam (#416): registry
	// transitions, Job transitions, MCP tool calls, and enrollment
	// attempts. Exposed so integration tests can Subscribe without a route
	// (the SSE route itself is #422).
	events *events.Bus
	// hooks is what newServer threaded into the surfaces as serverHooks
	// (#721) — recorded so a test can assert the production entry point
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
// tiny per-Job read surface the execution tools (#118) use to render
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

// envOr returns the value of environment variable key if it is non-empty, or
// fallback otherwise.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseConfig resolves all Relay startup parameters from CLI flags and
// environment. RELAY_-prefixed env vars override the corresponding CLI flags
// for string fields. For integer fields, non-integer env values are silently
// ignored and the flag default is kept.
func parseConfig() Config {
	addr := flag.String("addr", ":7654", "gRPC listen address")
	caDir := flag.String("ca-dir", "./ca-data", "directory for CA key and certificate")
	storePath := flag.String("store-path", "./relay-data/relay.db", "path to the Relay's SQLite store file")
	hostname := flag.String("hostname", "localhost", "hostname for the server certificate SAN")

	// Rate-limit and registry-cap flags. Env overrides follow the RELAY_ prefix
	// convention; non-integer env values are silently ignored (flag default kept).
	enrollIPRate := flag.Int("enroll-ip-rate", 5, "per-IP Enrollment rate (tokens/min)")
	enrollIPBurst := flag.Int("enroll-ip-burst", 3, "per-IP Enrollment burst capacity")
	enrollGlobalRate := flag.Int("enroll-global-rate", 50, "global Enrollment rate (tokens/min)")
	enrollGlobalBurst := flag.Int("enroll-global-burst", 10, "global Enrollment burst capacity")
	enrollMaxTrackedIPs := flag.Int("enroll-max-tracked-ips", 100000, "cap on per-IP rate-limit bucket map")
	maxNodes := flag.Int("max-nodes", 110000, "registry insert cap (0 = unlimited)")
	readBlastCap := flag.Int("read-blast-cap", capability.DefaultReadCap,
		"blast-radius cap for read Operations (max Nodes per Job)")
	mutateBlastCap := flag.Int("mutate-blast-cap", capability.DefaultMutateCap,
		"blast-radius cap for mutate Operations and Raw Exec (max Nodes per Job)")
	dispatchConcurrency := flag.Int("dispatch-concurrency", capability.DefaultDispatchConcurrency,
		"max Tasks of one Job dispatched at once (per-Job fan-out bound); must be at least 1")
	approvalGatePath := flag.String("approval-gate-config", "",
		"path to the root-owned approval-gate config (ADR-0027); empty disables approval gating. "+
			"A configured path that cannot be loaded refuses startup.")
	approvalWebhookURL := flag.String("approval-webhook-url", "",
		"HTTPS endpoint notified (fire-and-forget) when a dispatch parks for approval (ADR-0027); "+
			"empty disables notification. Decisions never arrive this way — they land on /api/v1.")
	approvalWebhookSecret := flag.String("approval-webhook-secret-file", "",
		"path to a root-owned file holding the shared secret used to sign approval webhook bodies "+
			"(HMAC-SHA256); empty sends unsigned notifications")
	approvalWebhookTimeout := flag.Duration("approval-webhook-timeout", approvalnotify.DefaultTimeout,
		"total time budget for one approval webhook delivery attempt")
	minDaemonVersion := flag.String("min-daemon-version", "",
		"minimum relay-daemon semver version (ADR-0014); empty disables the outdated gate")
	certExpiringFraction := flag.Float64("cert-expiring-fraction", nodestate.DefaultCertExpiringFraction,
		"fraction of a Node identity certificate's LeafValidity remaining below which state:cert-expiring "+
			"fires (ADR-0034); must be in (0, 1] — there is no off value")

	controlEnabled := flag.Bool("control-enabled", false,
		"enable the control-plane listener (MCP + /api/v1); disabled by default")
	controlAddr := flag.String("control-addr", ":9443",
		"control-plane HTTPS listen address (distinct from -addr, the node-plane gRPC listener)")
	consoleEnabled := flag.Bool("console-enabled", false,
		"serve the Admin Console on the control-plane listener (ADR-0009); requires -control-enabled")
	consoleSessionMaxAge := flag.Duration("console-session-max-age", consoleauth.DefaultAbsoluteLifetime,
		"absolute lifetime of a Console session, never extended by activity")
	consoleSessionIdle := flag.Duration("console-session-idle", consoleauth.DefaultIdleTimeout,
		"idle timeout of a Console session")
	consoleStepUpWindow := flag.Duration("console-step-up-window", consoleauth.DefaultStepUpWindow,
		"how recently a human must have re-authenticated for a step-up-gated action; file-only, no Account of any role can extend it")
	oauthIssuer := flag.String("oauth-issuer", "",
		"OIDC issuer URL for human MCP sessions (ADR-0024); empty disables OAuth")
	oauthAudience := flag.String("oauth-audience", "",
		"this Relay's OAuth resource identifier, checked against each token's aud; required with -oauth-issuer")
	oauthAccountClaim := flag.String("oauth-account-claim", "email",
		"token claim whose value names the Account a session resolves to")
	oauthRequiredScope := flag.String("oauth-required-scope", "",
		"scope every OAuth token must carry; empty requires none")
	oauthPublicURL := flag.String("oauth-public-url", "",
		"externally-reachable base URL of the control plane, used to advertise protected-resource metadata")

	flag.Parse()

	var cfg Config
	cfg.Addr = envOr("RELAY_ADDR", *addr)
	cfg.CADir = envOr("RELAY_CA_DIR", *caDir)
	cfg.StorePath = envOr("RELAY_STORE_PATH", *storePath)
	cfg.Hostname = envOr("RELAY_HOSTNAME", *hostname)

	cfg.EnrollIPRate = intEnvOr("RELAY_ENROLL_IP_RATE", *enrollIPRate)
	cfg.EnrollIPBurst = intEnvOr("RELAY_ENROLL_IP_BURST", *enrollIPBurst)
	cfg.EnrollGlobalRate = intEnvOr("RELAY_ENROLL_GLOBAL_RATE", *enrollGlobalRate)
	cfg.EnrollGlobalBurst = intEnvOr("RELAY_ENROLL_GLOBAL_BURST", *enrollGlobalBurst)
	cfg.EnrollMaxTrackedIPs = intEnvOr("RELAY_ENROLL_MAX_TRACKED_IPS", *enrollMaxTrackedIPs)
	cfg.MaxNodes = intEnvOr("RELAY_MAX_NODES", *maxNodes)
	cfg.ReadBlastCap = intEnvOr("RELAY_READ_BLAST_CAP", *readBlastCap)
	cfg.MutateBlastCap = intEnvOr("RELAY_MUTATE_BLAST_CAP", *mutateBlastCap)
	cfg.DispatchConcurrency = intEnvOr("RELAY_DISPATCH_CONCURRENCY", *dispatchConcurrency)

	cfg.MinDaemonVersion = envOr("RELAY_MIN_DAEMON_VERSION", *minDaemonVersion)
	cfg.CertExpiringFraction = certExpiringFractionFromEnv(
		os.Getenv("RELAY_CERT_EXPIRING_FRACTION"), *certExpiringFraction)
	cfg.ApprovalGatePath = envOr("RELAY_APPROVAL_GATE_CONFIG", *approvalGatePath)
	cfg.ApprovalWebhookURL = envOr("RELAY_APPROVAL_WEBHOOK_URL", *approvalWebhookURL)
	cfg.ApprovalWebhookSecretPath = envOr("RELAY_APPROVAL_WEBHOOK_SECRET_FILE", *approvalWebhookSecret)
	cfg.ApprovalWebhookTimeout = durationEnvOr("RELAY_APPROVAL_WEBHOOK_TIMEOUT", *approvalWebhookTimeout)

	cfg.ControlEnabled = boolEnvOr("RELAY_CONTROL_ENABLED", *controlEnabled)
	cfg.ControlAddr = envOr("RELAY_CONTROL_ADDR", *controlAddr)

	cfg.ConsoleEnabled = boolEnvOr("RELAY_CONSOLE_ENABLED", *consoleEnabled)
	cfg.ConsoleSessionMaxAge = durationEnvOr("RELAY_CONSOLE_SESSION_MAX_AGE", *consoleSessionMaxAge)
	cfg.ConsoleSessionIdle = durationEnvOr("RELAY_CONSOLE_SESSION_IDLE", *consoleSessionIdle)
	cfg.ConsoleStepUpWindow = clampedStepUpWindow(durationEnvOr("RELAY_CONSOLE_STEP_UP_WINDOW", *consoleStepUpWindow))
	cfg.OAuthIssuer = envOr("RELAY_OAUTH_ISSUER", *oauthIssuer)
	cfg.OAuthAudience = envOr("RELAY_OAUTH_AUDIENCE", *oauthAudience)
	cfg.OAuthAccountClaim = envOr("RELAY_OAUTH_ACCOUNT_CLAIM", *oauthAccountClaim)
	cfg.OAuthRequiredScope = envOr("RELAY_OAUTH_REQUIRED_SCOPE", *oauthRequiredScope)
	cfg.OAuthPublicURL = envOr("RELAY_OAUTH_PUBLIC_URL", *oauthPublicURL)

	return cfg
}

// serverCertObserver returns the callback that makes one listener's server
// certificate rotation observable (#403): the log line an operator reads after
// the fact, and the counter they can alert on. internal/ca deliberately logs
// nothing itself, so this — the composition root — is where a rotation becomes
// visible.
//
// The fingerprint is the new leaf's, and it is not a secret: it identifies a
// certificate, never authenticates one. Nothing here touches key material.
//
// A failed re-issue with a still-valid certificate in hand is an error, not a
// warning: rotation stopping is the first act of the outage this whole
// mechanism exists to prevent, and the leaf's remaining lifetime is all the
// warning there is.
func serverCertObserver(listener string, l metrics.ServerCertListener, m *metrics.Metrics) func(ca.Rotation) {
	return func(r ca.Rotation) {
		if r.Err != nil {
			slog.Error("server certificate re-issue failed; still serving the current certificate",
				"listener", listener, "err", r.Err)
			return
		}
		m.IncServerCertRotation(l)
		slog.Info("server certificate rotated",
			"listener", listener,
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

// newServer is the one production entry point: it builds the composition
// root with an empty serverHooks, so no test-only seam is ever populated on
// the path main takes. See newServerWithHooks and serverHooks
// (control_surfaces.go, #721).
func newServer(cfg Config) (*grpc.Server, *appDeps, error) {
	return newServerWithHooks(cfg, serverHooks{})
}

func newServerWithHooks(cfg Config, hooks serverHooks) (*grpc.Server, *appDeps, error) {
	relayCA, err := ca.Open(cfg.CADir)
	if err != nil {
		return nil, nil, fmt.Errorf("open CA: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(relayCA.Bundle()) {
		return nil, nil, fmt.Errorf("parse CA bundle into cert pool")
	}

	// The number an operator checks a daemon's configured trust root against
	// (ADR-0031): it identifies the certificate authority every Node's
	// certificate chains to, so it survives the server leaf's daily
	// re-issue, and the Console's day-one screen renders the same value.
	// ADR-0031 decision 3 will have a daemon PIN it through a join string;
	// neither exists yet, so this is a value to compare, not yet a value
	// anything enforces. A digest over a public certificate — no key
	// material, nothing secret, and safe to log.
	slog.Info("relay certificate authority", "ca_fingerprint", relayCA.Fingerprint())

	// A malformed min_daemon_version refuses startup rather than silently
	// leaving the outdated gate in an unpredictable state (ADR-0014). Empty
	// is valid — it means the gate is off.
	if cfg.MinDaemonVersion != "" && !registry.ValidVersion(cfg.MinDaemonVersion) {
		return nil, nil, fmt.Errorf("invalid min-daemon-version %q: not a valid semver version", cfg.MinDaemonVersion)
	}

	// There is deliberately no "off" value for the cert-expiring fraction
	// (ADR-0034): a silently disabled alarm is exactly the failure
	// state:cert-expiring exists to catch, so an out-of-range value refuses
	// startup rather than degrading to "never fires".
	if cfg.CertExpiringFraction <= 0 || cfg.CertExpiringFraction > 1 {
		return nil, nil, fmt.Errorf("invalid cert-expiring-fraction %v: must be in (0, 1]", cfg.CertExpiringFraction)
	}
	// The per-Job dispatch bound has no "off" value (#886): zero would
	// dispatch nothing, so it refuses startup.
	if cfg.DispatchConcurrency < 1 {
		return nil, nil, fmt.Errorf("invalid dispatch-concurrency %d: must be at least 1", cfg.DispatchConcurrency)
	}
	// Computed once, from the CA's own LeafValidity constant, and handed to
	// every surface below (invariant 11) — a Duration, never the fraction
	// itself, so capability/mcp/api never need to import internal/ca to make
	// sense of it (nodestate's own package doc explains why).
	certExpiringWithin := nodestate.CertExpiringWindow(ca.LeafValidity, cfg.CertExpiringFraction)

	// An injected logger, not slog.SetDefault: installing a wrapper around the
	// default handler as the default would recurse through the log package
	// (logctx.Handler). It reads the default now, so a test that captures
	// internal log lines must set the default before newServer.
	logger := slog.New(logctx.NewHandler(slog.Default().Handler()))

	st, err := store.Open(cfg.StorePath, store.WithMaxNodes(cfg.MaxNodes), store.WithMinDaemonVersion(cfg.MinDaemonVersion), store.WithLogger(logger))
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}

	// The one-shot declined-Label startup scan (#565, threat model R13) runs
	// here: immediately after Open, before anything else touches the store,
	// so the signal fires even if a later startup step fails. A failed scan
	// is a diagnostic failure, never a startup refusal — logged and
	// tolerated rather than returned, so the ABSENCE of the signal is itself
	// visible instead of silently taking the whole Relay down with it. Not
	// called from store.Open itself: two of Open's other callers are the
	// `relay bootstrap-token` and `relay console-password` CLIs, and a
	// fleet-wide warning dump in the middle of minting a token is noise in
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

	// denylist and conns implement immediate Node revocation (ADR-0006).
	// denylist.Add is reached at runtime by revocationSvc.RevokeNode (the
	// post-enroll revocation recheck and the Control API revoke path both call
	// it), which now ALSO persists the revocation to the registry. The registry
	// is the authority; the denylist is a derived cache, rehydrated from
	// registry.RevokedNodeIDs() below so a revoked Node stays refused across a
	// Relay restart (issue #133).
	denylist := revocation.NewDenylist()
	conns := revocation.NewConnections()

	// Enrollment_Enroll is the only certless RPC: daemons call it before they have
	// a client certificate. All other RPCs (including Tunnel and Enrollment_Renew)
	// remain mTLS-required. Renew is intentionally absent here: it is authenticated
	// by the caller's existing mTLS client cert, not a token.
	certless := map[string]struct{}{
		relayv1.Enrollment_Enroll_FullMethodName: {},
	}

	limiter := ratelimit.New(ratelimit.Config{
		PerIPRatePerMin:  float64(cfg.EnrollIPRate),
		PerIPBurst:       float64(cfg.EnrollIPBurst),
		GlobalRatePerMin: float64(cfg.EnrollGlobalRate),
		GlobalBurst:      float64(cfg.EnrollGlobalBurst),
		MaxTrackedIPs:    cfg.EnrollMaxTrackedIPs,
	})

	// eventBus is the Relay's one in-process event seam (#416): registry
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

	// appMetrics is the real capability.MetricsSink/enroll.EnrollmentObserver
	// (#182): its counters are always live (wired into enrollSrv and base
	// below), independent of Config.ControlEnabled; only the /metrics HTTP
	// surface itself is gated on ControlEnabled (no control listener
	// otherwise), mirroring every other control-plane surface.
	appMetrics := metrics.New(metrics.GaugeSources{
		Connected: conns.Count,
		Nodes:     reg.Count,
		Frozen:    func() (bool, error) { return st.Freeze().Frozen(context.Background()) },
		// This binary's own build stamp (#249) — the composition root is the
		// only place that knows it; internal/metrics never imports
		// internal/version.
		Build: metrics.BuildInfo{
			Version:   version.Version,
			Commit:    version.Commit,
			BuildDate: version.BuildDate,
		},
		// The read-back label filter's live counters (#565), read straight
		// off the Store rather than duplicated here — see
		// Store.LabelsDeclined and metrics.GaugeSources.LabelsDeclined.
		LabelsDeclined: st.LabelsDeclined,
	})

	// The node-plane listener's own TLS server certificate (#403, ADR-0031 §5).
	// Issued here, and RE-issued in-process before it expires: a certificate
	// minted once and held static expires while the process is still running,
	// and from that instant every daemon's chain verification fails and the
	// whole fleet fail-closes off the Relay. The Relay is its own CA, so
	// re-issuance is a function call against a key already open in this address
	// space — no restart, no operator, no network. It is wired here rather than
	// beside the CA above only so the rotation observer can reach appMetrics.
	nodePlaneCert, err := relayCA.NewServerCertificate([]string{cfg.Hostname}, nil,
		ca.WithRotationObserver(serverCertObserver("node-plane", metrics.ListenerNodePlane, appMetrics)))
	if err != nil {
		return nil, nil, fmt.Errorf("issue node-plane server certificate: %w", err)
	}

	// Every handshake asks nodePlaneCert for the certificate to present, which
	// is what makes the guarantee unconditional: rotation is driven by
	// connections, not by a timer that a sleeping process could miss.
	creds := transport.ServerCredentials(nodePlaneCert.GetCertificate, clientCAs, denylist)

	// Rehydrate the denylist from the persisted authority before the listener
	// accepts any connection: the Denylist is a derived cache of
	// registry.RevokedNodeIDs(); the store is the source of truth (issue #133,
	// ADR-0006 "revocation is instant" must also hold across a restart).
	revokedIDs, err := reg.RevokedNodeIDs()
	if err != nil {
		return nil, nil, fmt.Errorf("load revoked node ids: %w", err)
	}
	for _, id := range revokedIDs {
		denylist.Add(id)
	}

	tokenSvc := enroll.NewService(st.Tokens())
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc, revocation.WithLogger(logger))
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter),
		enroll.WithEnrollmentObserver(appMetrics),
		enroll.WithAttemptObserver(eventsink.Enrollment(eventBus)),
		enroll.WithServerLogger(logger))

	// policyCache is the display-only effective-Policy cache (#117, invariant
	// 12 / ADR-0002): the tunnel handler records what a daemon reports in
	// DaemonMessage.policy, and describe_node (mounted below when
	// ControlEnabled) reads it. It always exists — independent of
	// ControlEnabled — so a daemon's PolicySnapshot is captured whether or not
	// the control-plane listener is on.
	policyCache := policyview.New()

	// vocabCache is policyCache's sibling for the per-Node Template Operation
	// vocabulary (#291, ADR-0021): the tunnel handler records what a daemon
	// reports in DaemonMessage.templates, and describe_node/list_operations
	// read it. Display-only, and likewise independent of ControlEnabled.
	vocabCache := nodevocab.New()

	ts := &tunnelServer{conns: conns, reg: reg, policy: policyCache, vocab: vocabCache}
	// ts.sink is set below, ONLY inside the cfg.ControlEnabled branch — this
	// is the "#154 flip": execution is on if and only if the control plane
	// (its only consumer surface, MCP + /api/v1) is on. Disabled: ts.sink
	// stays nil, exactly as before this issue. Integration tests, or
	// installDevHarness in a devharness-tagged build, may also inject a
	// taskSink directly.

	// The real adapter to the SQLite-backed audit trail (#102) is the Recorder
	// below, and the real persisted Relay-wide emergency stop (#101, ADR-0013 —
	// see watchFreezeSignals in freeze_signal.go for the local engage/release
	// lever) is the Control.
	// One audit sink, shared by the capability layer and the MCP read surface
	// (#288): read-access records land in the same trail as dispatches, via
	// the same writer.
	auditSink := auditsink.New(st.Audit(), auditsink.WithLogger(logger))

	// The read lane (#441): filtered, paginated queries over the audit trail
	// and over Jobs/Tasks, adapted onto capability.AuditQuery/JobQuery by
	// internal/auditquery — auditsink's twin, for the same import-boundary
	// reason (capability's allowlist bars internal/audit).
	queries := auditquery.New(st.AuditQueries(), st.JobQueries())

	// The approval gate (#269, ADR-0027). Loaded BEFORE the capability layer is
	// built, and a load failure aborts startup rather than degrading: an empty
	// Gate must only ever mean "no rules configured", never "the rules could
	// not be read". approval.Load draws that distinction — an empty path is the
	// former, everything else is an error.
	approvalGate, err := approval.Load(cfg.ApprovalGatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load approval gate config: %w", err)
	}
	if n := len(approvalGate.Rules()); n > 0 {
		slog.Info("approval gating enabled", "rules", n, "config", cfg.ApprovalGatePath)
	}

	// ONE RoleGate for the whole process. It answers both "who may dispatch
	// this Action" and "who may decide an approval for one" (#270), and those
	// two must be the same ladder read from the same object: an approver who
	// could release what they could not request would be a side door around
	// ADR-0001's admin-only Raw Exec.
	roleGate := authz.NewRoleGate()

	// The one TokenService in the process: the authenticator VERIFIES through
	// it and the Control API MINTS through it (via capability.NewAccountAdmin
	// below), but each is handed a narrow interface exposing only its half
	// (controlplane.TokenVerifier / capability.APITokenStore), so neither
	// surface holds the other's power. Constructed here, above the shared
	// capability objects, because NewAccountAdmin needs it (#653) and both
	// branches below share the AccountAdmin it builds.
	apiTokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)

	// The ONE Recorder: audit trail, metrics and log, shared by the Control,
	// the read lane and the Approvals, and so the whole capability layer
	// (capability.NewExecution refuses a read lane or an Approvals over a different one).
	rec := capability.NewRecorder(auditSink, appMetrics, logger)

	// The Freeze and its role floor (ADR-0013, #101) over the real RoleGate
	// (#653): both branches below carry a real Authorizer, not just the
	// ControlEnabled one, which is what makes NewAccountAdmin below
	// satisfiable — its fail-open guard requires a real Authorizer. Tightening
	// the disabled branch this way changes no caller's outcome there: nothing
	// is mounted on that path (see the ControlEnabled==false branch's comment
	// below).
	freezeControl := capability.NewControl(rec, roleGate, st.Freeze())

	// Account and API-Token administration (#653): the same Accounts store and
	// TokenService the authenticator and bootstrap-token use, so identity
	// administration inherits one floor (invariant 10) instead of the Control
	// API deciding role itself per handler. Built over the Control, so it
	// shares its Authorizer and trail.
	accountAdmin := capability.NewAccountAdmin(freezeControl, st.Accounts(), apiTokenSvc)

	// The read lane (#441): filtered, paginated queries over the audit trail
	// and over Jobs/Tasks — one seam, shared by every surface (invariant 10).
	// certExpiringWithin is state:cert-expiring's warning window (#414,
	// ADR-0034), computed once above and shared by every surface below. The
	// Policy-view and Template-vocabulary reads (#680, QRY-28) are the same
	// policyCache/vocabCache the Tunnel handler writes into below (ts),
	// Get-only from this side. Wiring them here is what lets
	// describe_node/list_operations disclose a Node's Policy and Template
	// vocabulary through the ONE capability layer, on every surface, instead
	// of each surface holding its own cache reference — and, for vocabCache,
	// what lets a Template Operation be dispatched at all: the capability
	// layer resolves its fan-out and class from it (ADR-0042). Without it
	// every Template dispatch is refused. A nil clock is the real one.
	readLane := capability.NewReadLane(rec, reg, queries, queries, policyCache, vocabCache, certExpiringWithin, nil)

	// The out-of-band notification envelope (#270, ADR-0027). Optional: with no
	// URL configured nothing is pushed and approvers poll the queue. Configured
	// but unusable is a startup error, on the gate config's precedent — a
	// notifier the operator asked for and did not get is a silent gap in how
	// they learn a fleet action is waiting.
	var notifier capability.ApprovalNotifier
	if cfg.ApprovalWebhookURL != "" {
		n, err := approvalnotify.New(approvalnotify.Config{
			URL:        cfg.ApprovalWebhookURL,
			SecretPath: cfg.ApprovalWebhookSecretPath,
			Timeout:    cfg.ApprovalWebhookTimeout,
		}, approvalnotify.WithLogger(logger))
		if err != nil {
			return nil, nil, fmt.Errorf("configure approval webhook: %w", err)
		}
		notifier = n
		slog.Info("approval webhook enabled",
			"url", cfg.ApprovalWebhookURL, "signed", cfg.ApprovalWebhookSecretPath != "")
	}

	// The approval callout (ADR-0027), over the one Recorder and the same
	// RoleGate as dispatch (#270). Batch/window grants (#378, ADR-0027 decision
	// 12) are wired unconditionally alongside the gate: a Grant can only ever be
	// created through an approval Request the gate itself required, so with no
	// rules configured nothing is gated, nothing can be granted, and the store
	// simply holds no rows. MCP task handles (#374, ADR-0028) are wired for the
	// same reason: a handle is only ever minted for a dispatch the gate parked,
	// so with no rules configured nothing parks and the table stays empty. A nil
	// clock is the real one.
	approvals := capability.NewApprovals(rec, approvalGate, st.Approvals(), roleGate, st.Grants(), st.MCPTasks(), notifier, nil)

	var execution *capability.Execution
	var controlSrv *controlplane.Server
	var dispatchRouter *dispatch.Router
	if cfg.ControlEnabled {
		// A dedicated server cert for the control-plane listener, independent
		// of the node-plane nodePlaneCert above: separate listeners get
		// separate certificates, even though both chain to the same Relay CA.
		// They also rotate independently — each holder owns its own leaf, its
		// own key, and its own jittered renewal instant, so neither listener
		// can be affected by the other's re-issuance (#403, ADR-0031 §5).
		controlCert, err := relayCA.NewServerCertificate([]string{cfg.Hostname}, nil,
			ca.WithRotationObserver(serverCertObserver("control-plane", metrics.ListenerControlPlane, appMetrics)))
		if err != nil {
			return nil, nil, fmt.Errorf("issue control-plane server certificate: %w", err)
		}

		// This is THE production execution flip (#154): the Relay becomes
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
		// dispatch and refusal is audited (#102). This flip adds no new
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
			capability.NewBlastCap(cfg.ReadBlastCap, cfg.MutateBlastCap),
			// Dispatch idempotency keys (#895): the MCP execution tools forward an
			// optional key so a call re-issued after a lost response re-attaches to
			// its Job. Without this a keyed call is refused, never run unkeyed.
			st.IdempotencyKeys(),
			st.Jobs(), st.Tasks(), router,
			cfg.DispatchConcurrency,
			nil, // newID: the production default
			// The event seam's Job-grained publisher (#416).
			eventsink.Jobs(eventBus))

		// Seed the founding admin Account (#295, ADR-0010). Idempotent and
		// deterministic: it creates the row on first start and returns the
		// existing one every time after, never repairing an operator's
		// deliberate disable or demotion. Fail closed — if the identity
		// substrate cannot be established, the control plane does not come up
		// with a hardcoded identity instead.
		foundingAdmin, err := st.Accounts().EnsureFoundingAdmin(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("seed founding admin account: %w", err)
		}
		slog.Info("founding admin account ready",
			"account_id", foundingAdmin.ID,
			"account", foundingAdmin.Name,
			"role", string(foundingAdmin.Role),
			"enabled", foundingAdmin.Enabled,
		)

		// apiTokenSvc is constructed above, before the shared capability
		// objects (#653: NewAccountAdmin needs it), and reused here.

		// OAuth 2.1 protected-resource support (#299, ADR-0024). Discovery
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

		// The Admin Console's human authentication lane (#418, ADR-0009).
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
			// that fail-closed property into a silent no-op — the same shape
			// as the #357 bug where a nil sink disabled every read record in
			// production and nothing said so.
			consoleAuthSvc = consoleauth.NewService(
				st.Accounts(), st.Passwords(), consoleSessions,
				consoleauth.NewThrottle(), auditSink,
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
					// (#459): a Console session authenticates the Console,
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

		authn := controlplane.NewAuthenticator(apiTokenSvc, authOpts...)
		controlSrv = controlplane.New(
			controlplane.Config{Addr: cfg.ControlAddr, GetCertificate: controlCert.GetCertificate},
			// Two credential kinds, routed by prefix: per-Account API Tokens
			// verified against the store, and OAuth sessions verified against
			// the IdP. No shared secret and no digest held in memory
			// (ADR-0023, ADR-0024).
			authn,
		)

		// sd bundles every collaborator a control surface's Mount may need,
		// assembled exactly once (invariant 10: execution above is a single
		// instance, delivered to every surface below — no surface constructs
		// its own capability.Execution or dispatcher). See control_surfaces.go
		// for the ControlSurface seam (#162) this replaces the two inline
		// mount stanzas with.
		sd := surfaceDeps{
			logger:    logger,
			ops:       opvocabLister{},
			execution: execution,
			// The leaf capability services (invariant 10): each surface is
			// handed the narrow one it uses, not the Execution — see
			// surfaceDeps. A field forgotten here is a nil pointer behind a
			// non-nil interface, so the Console's account routes and the
			// read-lane routes are exercised end to end by the e2e tests.
			freezeControl: freezeControl,
			readLane:      readLane,
			accountAdmin:  accountAdmin,
			approvals:     approvals,
			jobs:          st.Jobs(),
			tasks:         st.Tasks(),
			tokens:        tokenSvc,
			revocation:    revocationSvc,
			audit:         st.Audit(),
			// The read-access sink (#288, ADR-0025). This assignment was
			// MISSING until #357: surfaceDeps.auditSink stayed nil, so
			// readAuditor's defensive `sink == nil` skip silently disabled every
			// read-access record in production — the trail ADR-0025 exists to
			// keep was empty, and nothing failed to say so. Wiring it here
			// revives it for the MCP read tools and supplies the Control API's
			// Job-read route. TestSurfaceDeps_AuditSinkIsWired is the regression
			// guard, because a nil here fails silently by design.
			auditSink: auditSink,
			// The same RoleGate the capability layer authorizes with (#397):
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
			// above — see nodestate.Input's doc comment (#414).
			//
			// freeze is the read half of the Relay-wide emergency stop, for the
			// control-plane banner. The store's repository, not the capability
			// layer: the Console must be able to SEE the Freeze and must not be
			// able to touch it, and handing it an object with Engage on it
			// would make that a matter of discipline instead of type.
			freeze: st.Freeze(),

			consoleAuth: consoleAuthSvc,

			// The event seam (#416) — the Console's one live-read route
			// mounts over this, narrowed to a reader with no Publish
			// method on it (console/seams.go).
			events: eventBus,

			// The two fingerprints day one renders (#427). The CA's is
			// fixed for the life of the process; the server leaf's is read
			// live because it is re-issued about daily.
			//
			// controlCert, not nodePlaneCert: this is the certificate the
			// browser reading that screen is actually talking to. ADR-0031
			// decision 1 (one certificate for both listeners) is not
			// implemented yet, so "the server certificate" is still
			// listener-scoped and the screen says which one it means.
			trust: consoleTrustReader{
				caFingerprint: relayCA.Fingerprint(),
				serverCert:    controlCert,
			},
			// state:cert-expiring's warning window (#414, ADR-0034), the same
			// value every other surface below was handed.
			certExpiringWithin: certExpiringWithin,
			// Test-only (#721, serverHooks): empty on the production path,
			// since newServer always calls newServerWithHooks with an empty
			// serverHooks. See mcpSurface.Mount.
			testMCPOptions: hooks.testMCPOptions,
		}
		surfaces := defaultControlSurfaces()
		if cfg.ConsoleEnabled {
			// Appended only when enabled, so with the Console off there is no
			// /console/ route on the listener at all. Absent, not refusing —
			// the same posture ADR-0026 requires of console_execution, applied
			// one level up.
			surfaces = append(surfaces, consoleSurface{})
		}
		for _, s := range surfaces {
			s.Mount(controlSrv.Mux(), sd)
		}
	}
	// With ControlEnabled off no consumer surface is mounted (MCP and API
	// require it), so no Execution is built: before #899 a no-op-dispatcher
	// Service was built here and never called. The Control (a real RoleGate,
	// #653), AccountAdmin, read lane and Approvals above are still built, as
	// before, and SIGUSR1/2 drives freezeControl.

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, denylist)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, denylist)),
	)
	relayv1.RegisterTunnelServer(srv, ts)
	relayv1.RegisterEnrollmentServer(srv, enrollSrv)

	deps := &appDeps{
		ca:         relayCA,
		store:      st,
		registry:   reg,
		jobs:       st.Jobs(),
		tasks:      st.Tasks(),
		audit:      st.Audit(),
		tokens:     tokenSvc,
		denylist:   denylist,
		conns:      conns,
		revocation: revocationSvc,
		limiter:    limiter,
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
	// `relay bootstrap-token` is a standalone utility subcommand (see
	// bootstrap_token.go), checked before flag.Parse/parseConfig so it never
	// touches Relay startup config. It mints the founding admin's first API
	// Token against the local store and exits; it never starts a server.
	if len(os.Args) > 1 && os.Args[1] == "bootstrap-token" {
		os.Exit(runBootstrapTokenCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
	// `relay console-password` is the same shape of local, root-owned lever
	// for the Console's first human credential (#418): reaching the Console
	// requires a password, so the first one cannot be set through it.
	if len(os.Args) > 1 && os.Args[1] == "console-password" {
		os.Exit(runConsolePasswordCommand(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}

	// `relay --version` prints the build stamp and exits (#249). Checked here,
	// alongside bootstrap-token and before flag.Parse/parseConfig, because the
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

	cfg := parseConfig()
	srv, deps, err := newServer(cfg)
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
	// Freeze (#101, ADR-0013) — see freeze_signal.go for the asymmetric-
	// activation rationale. It must start before Serve so a signal sent
	// immediately after startup is never missed.
	go watchFreezeSignals(context.Background(), deps.freezeControl)
	lis, err := net.Listen("tcp", cfg.Addr) //nolint:noctx // process-lifetime listener opened at startup; there is no context to bound it
	if err != nil {
		slog.Error("listen failed", "addr", cfg.Addr, "err", err)
		os.Exit(1)
	}
	slog.Info("relay listening",
		"version", version.Version,
		"commit", version.Commit,
		"build_date", version.BuildDate,
		"addr", cfg.Addr,
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
		controlLis, err := net.Listen("tcp", cfg.ControlAddr) //nolint:noctx // process-lifetime listener opened at startup; there is no context to bound it
		if err != nil {
			slog.Error("control-plane listen failed", "addr", cfg.ControlAddr, "err", err)
			os.Exit(1)
		}
		slog.Info("control-plane listening",
			"addr", cfg.ControlAddr,
			"credential_configured", true,
		)
		go func() {
			if err := deps.control.Serve(controlLis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("control-plane serve failed", "err", err)
				os.Exit(1)
			}
		}()
	}

	// The approval expiry sweeper (#269, ADR-0027): retire parked Requests
	// whose TTL has passed, so the queue does not fill with zombies.
	//
	// The sweeper is HOUSEKEEPING, not the expiry guarantee. A lapsed Request
	// is already undecidable and unredeemable by the clock alone
	// (approval.Request.PastDeadline), so a sweeper that stalls cannot make a
	// stale approval usable — it only leaves the stored state looking live for
	// longer than it is. That is why a sweep error logs and continues rather
	// than taking the process down.
	if deps.store != nil {
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

		// The audit chain checkpoint (#896): a metadata-only log line an
		// operator keeps as an anchor for relay-audit-verify -expect.
		go auditsink.NewCheckpointer(deps.store.AuditChain(), auditsink.DefaultCheckpointInterval, deps.logger).
			Run(context.Background(), func(err error) {
				slog.Error("audit chain checkpoint failed", "err", err)
			})
	}

	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
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

// parsedEnvOr reads key from the environment and parses it with parse,
// falling back to fallback when the variable is unset, unparseable, or
// rejected by parse (ok == false), and warning on the last two.
func parsedEnvOr[T any](key string, fallback T, parse func(string) (v T, ok bool)) T {
	env := os.Getenv(key)
	if env == "" {
		return fallback
	}
	v, ok := parse(env)
	if !ok {
		slog.Warn("ignoring invalid "+key, "value", env)
		return fallback
	}
	return v
}

// intEnvOr reads an integer from the environment, falling back to fallback
// and warning on anything unparseable. It applies no bounds of its own:
// range checks on these values live where the value is consumed.
func intEnvOr(key string, fallback int) int {
	return parsedEnvOr(key, fallback, func(s string) (int, bool) {
		v, err := strconv.Atoi(s)
		return v, err == nil
	})
}

// boolEnvOr reads a boolean (as strconv.ParseBool accepts it) from the
// environment, falling back to fallback and warning on anything unparseable.
func boolEnvOr(key string, fallback bool) bool {
	return parsedEnvOr(key, fallback, func(s string) (bool, bool) {
		v, err := strconv.ParseBool(s)
		return v, err == nil
	})
}

// durationEnvOr reads a positive duration from the environment, falling back
// to fallback and warning on anything unparseable.
//
// A non-positive value is refused rather than accepted: every duration read
// this way bounds something (a session's life, a step-up window), and "0"
// silently meaning "unbounded" is how a control gets turned off by a typo.
func durationEnvOr(key string, fallback time.Duration) time.Duration {
	return parsedEnvOr(key, fallback, func(s string) (time.Duration, bool) {
		d, err := time.ParseDuration(s)
		return d, err == nil && d > 0
	})
}

// clampedStepUpWindow caps the operator's step-up window at
// consoleauth.MaxStepUpWindow, warning when it does: a window long enough to
// be convenient is long enough for someone else at the keyboard.
func clampedStepUpWindow(d time.Duration) time.Duration {
	clamped, did := consoleauth.ClampStepUpWindow(d)
	if did {
		slog.Warn("console step-up window exceeds the maximum; clamped",
			"requested", d, "effective", clamped)
	}
	return clamped
}

// certExpiringFractionFromEnv reads RELAY_CERT_EXPIRING_FRACTION, given the
// flag-derived fallback.
//
// Unlike every other RELAY_* env var in parseConfig, an unparsable value
// here does NOT fall back to fallback: ADR-0034 and relay.env.example both
// promise the Relay REFUSES TO START on a state:cert-expiring fraction
// outside (0, 1], and silently keeping the default would let a typo
// (`0.o5`) swap in a different alarm threshold than the operator wrote, with
// nothing but a log line to notice by. This returns 0 — itself out of
// range — so the value routes through newServer's existing (0, 1] check and
// fails startup there: one range check, one fail-startup error message, not
// two.
func certExpiringFractionFromEnv(env string, fallback float64) float64 {
	if env == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(env, 64)
	if err != nil {
		slog.Error("invalid RELAY_CERT_EXPIRING_FRACTION; refusing to start", "value", env, "err", err)
		return 0
	}
	return v
}
