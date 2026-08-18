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
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/metrics"
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

	// MinDaemonVersion is the minimum relay-daemon version (ADR-0014); empty
	// means the gate is off and no Node is ever Outdated. Same startup-only,
	// never-API-settable mechanism as ReadBlastCap/MutateBlastCap above
	// (invariant 11, ADR-0010). A malformed value refuses startup — see
	// newServer.
	MinDaemonVersion string

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
	// capability is the Relay's single capability layer (ADR-0009/0010). When
	// Config.ControlEnabled, newServer wires it with the real Job engine
	// (capability.WithExecution) over the real mTLS tunnel and the real
	// role-gated Authorizer (authz.NewRoleGate) — this is the "#154 flip": MCP/
	// Control API dispatch actually runs on the fleet. When disabled, capSvc
	// keeps the v0.0.5 default no-op dispatcher/allow-all-by-construction-
	// unreachable seams (no consumer surface is mounted either), exactly as
	// before this issue.
	capability *capability.Service
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
	// Config.ControlEnabled — the same Conduit capSvc's Job engine dispatches
	// through — exposed so integration tests (and a later real-fleet e2e
	// surface, #121) can block on a live Tunnel via Router.WaitForAny/
	// Connected before dispatching, rather than racing the offline
	// fail-fast (ADR-0004). Nil when the control plane is disabled.
	dispatch *dispatch.Router
	// metrics is the real capability.MetricsSink/enroll.EnrollmentObserver
	// (#182), exposed so tests can assert on its counters/gauges directly.
	metrics *metrics.Metrics
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

	controlEnabled := flag.Bool("control-enabled", false,
		"enable the control-plane listener (MCP + /api/v1); disabled by default")
	controlAddr := flag.String("control-addr", ":9443",
		"control-plane HTTPS listen address (distinct from -addr, the node-plane gRPC listener)")
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

	cfg.EnrollIPRate = *enrollIPRate
	if env := os.Getenv("RELAY_ENROLL_IP_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollIPRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_RATE", "value", env)
		}
	}
	cfg.EnrollIPBurst = *enrollIPBurst
	if env := os.Getenv("RELAY_ENROLL_IP_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollIPBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_BURST", "value", env)
		}
	}
	cfg.EnrollGlobalRate = *enrollGlobalRate
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollGlobalRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_RATE", "value", env)
		}
	}
	cfg.EnrollGlobalBurst = *enrollGlobalBurst
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollGlobalBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_BURST", "value", env)
		}
	}
	cfg.EnrollMaxTrackedIPs = *enrollMaxTrackedIPs
	if env := os.Getenv("RELAY_ENROLL_MAX_TRACKED_IPS"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollMaxTrackedIPs = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_MAX_TRACKED_IPS", "value", env)
		}
	}
	cfg.MaxNodes = *maxNodes
	if env := os.Getenv("RELAY_MAX_NODES"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.MaxNodes = v
		} else {
			slog.Warn("ignoring invalid RELAY_MAX_NODES", "value", env)
		}
	}
	cfg.ReadBlastCap = *readBlastCap
	if env := os.Getenv("RELAY_READ_BLAST_CAP"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.ReadBlastCap = v
		} else {
			slog.Warn("ignoring invalid RELAY_READ_BLAST_CAP", "value", env)
		}
	}
	cfg.MutateBlastCap = *mutateBlastCap
	if env := os.Getenv("RELAY_MUTATE_BLAST_CAP"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.MutateBlastCap = v
		} else {
			slog.Warn("ignoring invalid RELAY_MUTATE_BLAST_CAP", "value", env)
		}
	}

	cfg.MinDaemonVersion = envOr("RELAY_MIN_DAEMON_VERSION", *minDaemonVersion)
	cfg.ApprovalGatePath = envOr("RELAY_APPROVAL_GATE_CONFIG", *approvalGatePath)
	cfg.ApprovalWebhookURL = envOr("RELAY_APPROVAL_WEBHOOK_URL", *approvalWebhookURL)
	cfg.ApprovalWebhookSecretPath = envOr("RELAY_APPROVAL_WEBHOOK_SECRET_FILE", *approvalWebhookSecret)
	cfg.ApprovalWebhookTimeout = *approvalWebhookTimeout
	if env := os.Getenv("RELAY_APPROVAL_WEBHOOK_TIMEOUT"); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			cfg.ApprovalWebhookTimeout = d
		} else {
			slog.Warn("ignoring invalid RELAY_APPROVAL_WEBHOOK_TIMEOUT", "value", env)
		}
	}

	cfg.ControlEnabled = *controlEnabled
	if env := os.Getenv("RELAY_CONTROL_ENABLED"); env != "" {
		if v, err := strconv.ParseBool(env); err == nil {
			cfg.ControlEnabled = v
		} else {
			slog.Warn("ignoring invalid RELAY_CONTROL_ENABLED", "value", env)
		}
	}
	cfg.ControlAddr = envOr("RELAY_CONTROL_ADDR", *controlAddr)
	cfg.OAuthIssuer = envOr("RELAY_OAUTH_ISSUER", *oauthIssuer)
	cfg.OAuthAudience = envOr("RELAY_OAUTH_AUDIENCE", *oauthAudience)
	cfg.OAuthAccountClaim = envOr("RELAY_OAUTH_ACCOUNT_CLAIM", *oauthAccountClaim)
	cfg.OAuthRequiredScope = envOr("RELAY_OAUTH_REQUIRED_SCOPE", *oauthRequiredScope)
	cfg.OAuthPublicURL = envOr("RELAY_OAUTH_PUBLIC_URL", *oauthPublicURL)

	return cfg
}

// newServer constructs and wires the gRPC server and all its dependencies from
// cfg. It does not create a listener or call Serve — those belong to main so
// that tests can construct the server without binding a port.
func newServer(cfg Config) (*grpc.Server, *appDeps, error) {
	relayCA, err := ca.Open(cfg.CADir)
	if err != nil {
		return nil, nil, fmt.Errorf("open CA: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(relayCA.Bundle()) {
		return nil, nil, fmt.Errorf("parse CA bundle into cert pool")
	}

	serverCert, err := relayCA.IssueServerCertificate([]string{cfg.Hostname}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("issue server certificate: %w", err)
	}

	// A malformed min_daemon_version refuses startup rather than silently
	// leaving the outdated gate in an unpredictable state (ADR-0014). Empty
	// is valid — it means the gate is off.
	if cfg.MinDaemonVersion != "" && !registry.ValidVersion(cfg.MinDaemonVersion) {
		return nil, nil, fmt.Errorf("invalid min-daemon-version %q: not a valid semver version", cfg.MinDaemonVersion)
	}

	st, err := store.Open(cfg.StorePath, store.WithMaxNodes(cfg.MaxNodes), store.WithMinDaemonVersion(cfg.MinDaemonVersion))
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
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

	creds := transport.ServerCredentials(serverCert, clientCAs, denylist)

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
	reg := st.Registry()

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
	})

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
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc)
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter),
		enroll.WithEnrollmentObserver(appMetrics))

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

	// base is the capability.Option set common to both branches below: the
	// real BlastCap (ADR-0004/0012; see the ReadBlastCap/MutateBlastCap doc
	// comment on Config for the file-vs-flag deviation flagged for human
	// review), the real adapter to the SQLite-backed audit trail (#102), and
	// the real persisted Relay-wide emergency stop (#101, ADR-0013 — see
	// watchFreezeSignals in freeze_signal.go for the local engage/release
	// lever). A fresh slice is built per branch below (not appended to) so
	// neither branch aliases or mutates the other's backing array.
	// One audit sink, shared by the capability layer and the MCP read surface
	// (#288): read-access records land in the same trail as dispatches, via
	// the same writer.
	auditSink := auditsink.New(st.Audit())

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

	base := []capability.Option{
		capability.WithCapChecker(capability.NewBlastCap(cfg.ReadBlastCap, cfg.MutateBlastCap)),
		capability.WithAuditSink(auditSink),
		capability.WithFreeze(st.Freeze()),
		capability.WithMetrics(appMetrics),
		capability.WithApprovals(approvalGate, st.Approvals(), roleGate),
		// Batch/window grants (#378, ADR-0027 decision 12). Wired
		// unconditionally alongside the gate: a Grant can only ever be created
		// through an approval Request the gate itself required, so with no
		// rules configured nothing is gated, nothing can be granted, and the
		// store simply holds no rows.
		capability.WithApprovalGrants(st.Grants()),
		// MCP task handles (#374, ADR-0028). Wired alongside the gate for the
		// same reason grants are: a handle is only ever minted for a dispatch
		// the gate parked, so with no rules configured nothing parks and the
		// table stays empty.
		capability.WithMCPTasks(st.MCPTasks()),
	}

	// The out-of-band notification envelope (#270, ADR-0027). Optional: with no
	// URL configured nothing is pushed and approvers poll the queue. Configured
	// but unusable is a startup error, on the gate config's precedent — a
	// notifier the operator asked for and did not get is a silent gap in how
	// they learn a fleet action is waiting.
	if cfg.ApprovalWebhookURL != "" {
		notifier, err := approvalnotify.New(approvalnotify.Config{
			URL:        cfg.ApprovalWebhookURL,
			SecretPath: cfg.ApprovalWebhookSecretPath,
			Timeout:    cfg.ApprovalWebhookTimeout,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("configure approval webhook: %w", err)
		}
		base = append(base, capability.WithApprovalNotifier(notifier))
		slog.Info("approval webhook enabled",
			"url", cfg.ApprovalWebhookURL, "signed", cfg.ApprovalWebhookSecretPath != "")
	}

	var capSvc *capability.Service
	var controlSrv *controlplane.Server
	var dispatchRouter *dispatch.Router
	if cfg.ControlEnabled {
		// A dedicated server cert for the control-plane listener, independent
		// of the node-plane gRPC serverCert above: separate listeners get
		// separate certificates, even though both chain to the same Relay CA.
		controlCert, err := relayCA.IssueServerCertificate([]string{cfg.Hostname}, nil)
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
		router, reconciler, sink := newDispatchStack(st.Tasks())
		// reconciler is captured by router's onConnect closure
		// (dispatch_wiring.go) and fires on every Node (re)connect — this is
		// what makes crash-mid-Job restart reconciliation happen; it is not
		// called directly from here.
		_ = reconciler
		ts.sink = sink
		dispatchRouter = router

		// A FRESH slice, not append(base, ...): base's backing array must
		// never be aliased/mutated by this branch (there is only one
		// newServer call per Config today, but the two branches must stay
		// independently safe regardless).
		enabledOpts := append([]capability.Option{}, base...)
		enabledOpts = append(enabledOpts,
			capability.WithExecution(st.Jobs(), st.Tasks(), router),
			capability.WithAuthorizer(roleGate))
		capSvc = capability.New(reg, enabledOpts...)

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

		// The one TokenService in the process: the authenticator VERIFIES
		// through it and the Control API MINTS through it, but each is handed
		// a narrow interface exposing only its half (controlplane.TokenVerifier
		// / api.APITokenService), so neither surface holds the other's power.
		apiTokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)

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

		authn := controlplane.NewAuthenticator(apiTokenSvc, authOpts...)
		controlSrv = controlplane.New(
			controlplane.Config{Addr: cfg.ControlAddr, TLSCert: controlCert},
			// Two credential kinds, routed by prefix: per-Account API Tokens
			// verified against the store, and OAuth sessions verified against
			// the IdP. No shared secret and no digest held in memory
			// (ADR-0023, ADR-0024).
			authn,
		)

		// sd bundles every collaborator a control surface's Mount may need,
		// assembled exactly once (invariant 10: capSvc above is a single
		// instance, delivered to every surface below — no surface constructs
		// its own capability.Service or dispatcher). See control_surfaces.go
		// for the ControlSurface seam (#162) this replaces the two inline
		// mount stanzas with.
		sd := surfaceDeps{
			registry:     reg,
			policy:       policyCache,
			vocab:        vocabCache,
			ops:          opvocabLister{},
			capability:   capSvc,
			jobs:         st.Jobs(),
			tasks:        st.Tasks(),
			tokens:       tokenSvc,
			accountsRepo: st.Accounts(),
			apiTokens:    apiTokenSvc,
			revocation:   revocationSvc,
			audit:        st.Audit(),
			// The read-access sink (#288, ADR-0025). This assignment was
			// MISSING until #357: surfaceDeps.auditSink stayed nil, so
			// readAuditor's defensive `sink == nil` skip silently disabled every
			// read-access record in production — the trail ADR-0025 exists to
			// keep was empty, and nothing failed to say so. Wiring it here
			// revives it for the MCP read tools and supplies the Control API's
			// Job-read route. TestSurfaceDeps_AuditSinkIsWired is the regression
			// guard, because a nil here fails silently by design.
			auditSink: auditSink,
			now:       func() time.Time { return time.Now().UTC() },
			metrics:   appMetrics,
		}
		for _, s := range defaultControlSurfaces() {
			s.Mount(controlSrv.Mux(), sd)
		}
	} else {
		// No consumer surface is mounted (MCP/API require ControlEnabled),
		// so capSvc keeps the v0.0.5 default no-op dispatcher/allow-all authz
		// — identical to every build before this issue.
		capSvc = capability.New(reg, base...)
	}

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
		capability: capSvc,
		tunnel:     ts,
		control:    controlSrv,
		dispatch:   dispatchRouter,
		metrics:    appMetrics,
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
	go watchFreezeSignals(context.Background(), deps.capability)
	lis, err := net.Listen("tcp", cfg.Addr)
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
		"min_daemon_version", cfg.MinDaemonVersion,
	)

	// The control-plane listener (MCP + /api/v1, ADR-0009/0010) is separate
	// from the node-plane gRPC listener above: its own address, its own
	// goroutine, its own lifecycle. deps.control is nil unless
	// cfg.ControlEnabled, so this is a no-op on the default (disabled) path.
	if deps.control != nil {
		controlLis, err := net.Listen("tcp", cfg.ControlAddr)
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
