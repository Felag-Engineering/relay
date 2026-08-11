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
	"time"

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
	// Interim: ADR-0010/0012 call for a root-owned config FILE; the Relay has
	// no config-file loader yet, so blast caps use the existing startup
	// flags+env mechanism (same as MaxNodes/mTLS paths). The security
	// property — set only at startup, never settable via any API — holds. A
	// real config-file loader is a separate future change. Flagged for human
	// review. The control-plane credential hash (below) uses the same
	// interim mechanism: a root-owned FILE (path via flag/env), not a value
	// on this Config struct — the same deviation, now also covering secret
	// material.
	ReadBlastCap   int
	MutateBlastCap int

	// MinDaemonVersion is the minimum relay-daemon version (ADR-0014); empty
	// means the gate is off and no Node is ever Outdated. It follows the SAME
	// interim root-owned-file/flags+env mechanism as ReadBlastCap/
	// MutateBlastCap above: set only at startup, never settable via any API
	// (invariant #11, ADR-0010). A malformed value refuses startup — see
	// newServer.
	MinDaemonVersion string

	// ControlEnabled, ControlAddr, and ControlCredentialHashFile configure the
	// control-plane HTTP listener (MCP + /api/v1, ADR-0009/0010) — separate
	// from the node-plane gRPC listener (Addr above). Default disabled
	// (ControlEnabled=false) for backward compatibility; when enabled, a
	// missing or malformed ControlCredentialHashFile refuses startup rather
	// than serving an unauthenticated or misconfigured control plane.
	ControlEnabled            bool
	ControlAddr               string
	ControlCredentialHashFile string
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
	// staged Authorizer (authz.NewStaged) — this is the "#154 flip": MCP/
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
	minDaemonVersion := flag.String("min-daemon-version", "",
		"minimum relay-daemon semver version (ADR-0014); empty disables the outdated gate")

	controlEnabled := flag.Bool("control-enabled", false,
		"enable the control-plane listener (MCP + /api/v1); disabled by default")
	controlAddr := flag.String("control-addr", ":9443",
		"control-plane HTTPS listen address (distinct from -addr, the node-plane gRPC listener)")
	controlCredentialHashFile := flag.String("control-credential-hash-file", "",
		"path to a root-owned file containing the control-plane credential hash (sha256:<hex>); required if -control-enabled")

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

	cfg.ControlEnabled = *controlEnabled
	if env := os.Getenv("RELAY_CONTROL_ENABLED"); env != "" {
		if v, err := strconv.ParseBool(env); err == nil {
			cfg.ControlEnabled = v
		} else {
			slog.Warn("ignoring invalid RELAY_CONTROL_ENABLED", "value", env)
		}
	}
	cfg.ControlAddr = envOr("RELAY_CONTROL_ADDR", *controlAddr)
	cfg.ControlCredentialHashFile = envOr("RELAY_CONTROL_CREDENTIAL_HASH_FILE", *controlCredentialHashFile)

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
	base := []capability.Option{
		capability.WithCapChecker(capability.NewBlastCap(cfg.ReadBlastCap, cfg.MutateBlastCap)),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithFreeze(st.Freeze()),
		capability.WithMetrics(appMetrics),
	}

	var capSvc *capability.Service
	var controlSrv *controlplane.Server
	var dispatchRouter *dispatch.Router
	if cfg.ControlEnabled {
		digest, err := controlplane.LoadCredentialHashFile(cfg.ControlCredentialHashFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load control credential hash: %w", err)
		}

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
		// authz.NewStaged Authorizer (ADR-0010) both run before any
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
			capability.WithAuthorizer(authz.NewStaged()))
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

		controlSrv = controlplane.New(
			controlplane.Config{Addr: cfg.ControlAddr, TLSCert: controlCert},
			// The seeded credential now resolves to that stored Account on
			// every request, so audit attributes it by ID and current role,
			// and disabling the Account cuts the credential off immediately.
			controlplane.NewAuthenticator(digest, controlplane.WithAccounts(st.Accounts())),
		)

		// sd bundles every collaborator a control surface's Mount may need,
		// assembled exactly once (invariant 10: capSvc above is a single
		// instance, delivered to every surface below — no surface constructs
		// its own capability.Service or dispatcher). See control_surfaces.go
		// for the ControlSurface seam (#162) this replaces the two inline
		// mount stanzas with.
		sd := surfaceDeps{
			registry:   reg,
			policy:     policyCache,
			vocab:      vocabCache,
			ops:        opvocabLister{},
			capability: capSvc,
			jobs:       st.Jobs(),
			tasks:      st.Tasks(),
			tokens:     tokenSvc,
			revocation: revocationSvc,
			audit:      st.Audit(),
			now:        func() time.Time { return time.Now().UTC() },
			metrics:    appMetrics,
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
	// `relay hash-credential` is a standalone utility subcommand (see
	// hash_credential.go), checked before flag.Parse/parseConfig so it never
	// touches Relay startup config. It reads the plaintext credential from
	// STDIN only and exits; it never starts a server.
	if len(os.Args) > 1 && os.Args[1] == "hash-credential" {
		runHashCredentialCommand()
		return
	}

	// `relay --version` prints the build stamp and exits (#249). Checked here,
	// alongside hash-credential and before flag.Parse/parseConfig, because the
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

	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
