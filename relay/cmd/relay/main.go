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
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/api"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
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
	// capability is the Relay's single capability layer (ADR-0009/0010).
	// v0.0.5 [3/8] wires it here with its default (no-op/allow-all) seams
	// only — no surface is wired to it yet (no consumer until v0.0.6). The
	// composition root owns it so later issues (#99 engine, #100 caps,
	// #102 audit) can swap in real seams and tests can reach it.
	capability *capability.Service
	// tunnel is the registered tunnelServer. Exposed so integration tests and
	// installDevHarness can inject a taskSink (test/devharness-only; never set
	// in an untagged (production) build).
	tunnel *tunnelServer
	// control is the control-plane HTTP server (MCP + /api/v1, ADR-0009/0010),
	// nil when Config.ControlEnabled is false (default; backward-compatible).
	// It has its own listener and lifecycle, independent of the node-plane
	// gRPC server above.
	control *controlplane.Server
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

	st, err := store.Open(cfg.StorePath, store.WithMaxNodes(cfg.MaxNodes))
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}

	// denylist and conns implement immediate Node revocation (ADR-0006).
	// denylist.Add is now reachable at runtime via the post-enroll revocation
	// recheck: if a token is revoked mid-enrollment the handler calls
	// revocationSvc.RevokeNode, which calls denylist.Add. An admin-trigger RPC
	// to revoke nodes on demand still requires a proto change (future milestone).
	denylist := revocation.NewDenylist()
	conns := revocation.NewConnections()

	creds := transport.ServerCredentials(serverCert, clientCAs, denylist)

	// Enrollment_Enroll is the only certless RPC: daemons call it before they have
	// a client certificate. All other RPCs (including Tunnel and Enrollment_Renew)
	// remain mTLS-required. Renew is intentionally absent here: it is authenticated
	// by the caller's existing mTLS client cert, not a token.
	certless := map[string]struct{}{
		gleipnirv1.Enrollment_Enroll_FullMethodName: {},
	}

	limiter := ratelimit.New(ratelimit.Config{
		PerIPRatePerMin:  float64(cfg.EnrollIPRate),
		PerIPBurst:       float64(cfg.EnrollIPBurst),
		GlobalRatePerMin: float64(cfg.EnrollGlobalRate),
		GlobalBurst:      float64(cfg.EnrollGlobalBurst),
		MaxTrackedIPs:    cfg.EnrollMaxTrackedIPs,
	})
	reg := st.Registry()
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc)
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter))

	// policyCache is the display-only effective-Policy cache (#117, invariant
	// 12 / ADR-0002): the tunnel handler records what a daemon reports in
	// DaemonMessage.policy, and describe_node (mounted below when
	// ControlEnabled) reads it. It always exists — independent of
	// ControlEnabled — so a daemon's PolicySnapshot is captured whether or not
	// the control-plane listener is on.
	policyCache := policyview.New()

	ts := &tunnelServer{conns: conns, reg: reg, policy: policyCache}
	// ts.sink is intentionally left nil here — newServer never sets it under
	// any build tag. Only integration tests, or installDevHarness in a
	// devharness-tagged build with RELAY_DEVHARNESS_SOCKET set, inject a
	// taskSink after calling newServer.

	// capSvc is constructed with its default allow-all authz and no-op
	// dispatch — no execution surface is wired to it yet (see the
	// appDeps.capability doc comment); WithExecution is still not called, so
	// New's real-dispatcher fail-open guard is not tripped by the real
	// AuditSink/FreezeStore below. The CapChecker is the real BlastCap
	// (ADR-0004/0012); see the ReadBlastCap/MutateBlastCap doc comment on
	// Config for the file-vs-flag deviation flagged for human review. The
	// AuditSink is the real adapter to the SQLite-backed audit trail (#102);
	// the FreezeStore is the real persisted Relay-wide emergency stop
	// (#101, ADR-0013) — see watchFreezeSignals (freeze_signal.go) for the
	// local engage/release lever.
	capSvc := capability.New(reg,
		capability.WithCapChecker(capability.NewBlastCap(cfg.ReadBlastCap, cfg.MutateBlastCap)),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithFreeze(st.Freeze()))

	// controlSrv is the control-plane HTTP server (MCP + /api/v1,
	// ADR-0009/0010) — nil unless ControlEnabled. It has its own listener,
	// bound by main, independent of the node-plane gRPC server below.
	var controlSrv *controlplane.Server
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

		controlSrv = controlplane.New(
			controlplane.Config{Addr: cfg.ControlAddr, TLSCert: controlCert},
			controlplane.NewAuthenticator(digest),
		)

		// The real MCP server (#117's read tools, #118's execution tools)
		// mounts on Mux() at "/mcp", replacing the #115 placeholder — reached
		// only through the Authenticator.Middleware controlplane.New already
		// wraps the mux in (invariant 10: one control path).
		//
		// #118, owner DECISION 1: the execution tools (run_operation,
		// raw_exec, cancel_job, get_job) are wired here against the SAME
		// capSvc every other surface uses, but production dispatch stays
		// OFF — capSvc above has no WithExecution call, so its dispatcher is
		// still the v0.0.5 default noopDispatcher: every matched Node
		// reports OutcomeUnspecified, nothing is actually sent. Flipping
		// capSvc to the real Job engine (WithExecution) in this composition
		// root is deliberately isolated to #154, which also lands the
		// production Authorizer that flip requires. All #118 acceptance is
		// proven in-package against a test-wired execution capability
		// (mcp_test.go/mcp_exec_test.go).
		mcpHandler := mcp.New(reg, policyCache, opvocabLister{}, capSvc,
			jobResultReader{jobsRepo: st.Jobs(), tasksRepo: st.Tasks()})
		controlSrv.Mux().Handle("/mcp", mcpHandler)

		// api.Register mounts the /api/v1 Control API slice (#116) onto the
		// control-plane's existing Mux — no new listener, no new auth (invariant
		// 10). It reuses the already-constructed tokenSvc/revocationSvc/capSvc/
		// st.Audit() collaborators; it never touches cfg or a blast cap
		// (invariant 11).
		api.Register(controlSrv.Mux(), api.Deps{
			Tokens:       tokenSvc,
			TokenRevoker: revocationSvc,
			Nodes:        revocationSvc,
			Freeze:       capSvc,
			Audit:        st.Audit(),
			Now:          func() time.Time { return time.Now().UTC() },
		})
	}

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, denylist)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, denylist)),
	)
	gleipnirv1.RegisterTunnelServer(srv, ts)
	gleipnirv1.RegisterEnrollmentServer(srv, enrollSrv)

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
