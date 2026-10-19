package main

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
)

// reloadGate is a gate file with one rule, for a reload that changes the gate.
const reloadGate = `{
  "rules": [
    {
      "name": "all-mutates-need-a-human",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": false, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`

// reloadFixture is a composition root built by newServer over test Files, and a
// reloader over it whose load reads body and whose open builds test Files. The
// tests that use it swap slog's default and so are not parallel.
type reloadFixture struct {
	t       *testing.T
	dir     string
	body    string
	logBuf  *reloadLogBuffer
	logs    *swapHandler
	deps    *appDeps
	r       *reloader
	opened  int
	openErr error
}

// reloadLogBuffer is a bytes.Buffer safe for the concurrent writes a running server makes.
type reloadLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *reloadLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *reloadLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *reloadLogBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

func (f *reloadFixture) toml(extra string) string {
	return "[node_plane]\nlisten_address = \"127.0.0.1:17654\"\n" +
		"[ca]\ndir = " + strconv.Quote(filepath.Join(f.dir, "ca")) + "\n" +
		"[store]\npath = " + strconv.Quote(filepath.Join(f.dir, "relay.db")) + "\n" +
		"[tls]\nhostname = \"localhost\"\n" + extra
}

func newReloadFixture(t *testing.T) *reloadFixture {
	t.Helper()
	f := &reloadFixture{t: t, dir: t.TempDir(), logBuf: &reloadLogBuffer{}}
	f.body = f.toml("[reach]\nmutate_blast_cap = 5\n[log]\nformat = \"text\"\n")
	f.logs = newSwapHandler(newLogHandler(f.logBuf, mustParse(t, f.body).Log))
	prev := slog.Default()
	slog.SetDefault(slog.New(f.logs))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sc := mustParse(t, f.body)
	_, deps, err := newServer(sc.Config, testStartupFiles(t, sc.Config))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	f.deps = deps
	f.r = newReloader("relay.toml", sc, deps, f.logs, f.logBuf)
	f.r.load = func(string) (startupConfig, error) { return parseConfig([]byte(f.body), readSecretPlain) }
	f.r.open = func(gatePath, caDir, storePath string) (startup.Files, error) {
		f.opened++
		if f.openErr != nil {
			return startup.Files{}, f.openErr
		}
		return testStartupFiles(t, Config{ApprovalGatePath: gatePath, CADir: caDir, StorePath: storePath}), nil
	}
	f.logBuf.Reset()
	return f
}

func mustParse(t *testing.T, body string) startupConfig {
	t.Helper()
	sc, err := parseConfig([]byte(body), readSecretPlain)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	return sc
}

// records returns the trail's records of the given kind.
func (f *reloadFixture) records(kind string) []audit.Record {
	f.t.Helper()
	all, err := f.deps.audit.List(context.Background())
	if err != nil {
		f.t.Fatalf("List: %v", err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func TestReloader_SuccessSwapsSnapshotGateAndLog(t *testing.T) {
	f := newReloadFixture(t)
	gatePath := filepath.Join(f.dir, "gate.json")
	if err := os.WriteFile(gatePath, []byte(reloadGate), 0o600); err != nil {
		t.Fatal(err)
	}
	liveBefore := f.deps.live.cur.Load()
	f.body = f.toml("[reach]\nmutate_blast_cap = 7\n[log]\nformat = \"json\"\n[approval]\ngate_rules_path = " + strconv.Quote(gatePath) + "\n")

	changed, err := f.r.reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if want := "reach.mutate_blast_cap log.format approval.gate_rules_path"; strings.Join(sortedByWant(changed, want), " ") != want {
		t.Errorf("changed = %v, want %s", changed, want)
	}
	if got := f.deps.live.OperatorSettings().MutateBlastCap; got != 7 {
		t.Errorf("MutateBlastCap = %d, want 7", got)
	}
	if f.deps.live.cur.Load() == liveBefore {
		t.Error("the snapshot was not replaced")
	}
	if n := len(f.deps.gate.rules()); n != 1 {
		t.Errorf("the gate holds %d rules, want 1", n)
	}
	f.logBuf.Reset()
	slog.Info("after the reload")
	if out := f.logBuf.String(); !strings.HasPrefix(out, "{") {
		t.Errorf("log after reload = %q, want JSON", out)
	}
	recs := f.records(audit.KindConfigReload)
	if len(recs) != 1 || recs[0].Principal != audit.PrincipalLocalHost {
		t.Fatalf("config_reload records = %+v, want exactly one attributed to local-host", recs)
	}
	if len(f.records(audit.KindConfigReloadRefused)) != 0 {
		t.Error("an applied reload wrote a refusal record")
	}
}

// sortedByWant orders got by the position of each key in want, so the check does
// not depend on the order the reload lists a key it adds last.
func sortedByWant(got []string, want string) []string {
	var out []string
	for _, k := range strings.Fields(want) {
		for _, g := range got {
			if g == k {
				out = append(out, k)
			}
		}
	}
	return out
}

func TestReloader_RefusalLeavesEverythingUntouched(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *reloadFixture)
		stage auditsink.ReloadStage
		keys  []string
	}{
		{"load error", func(f *reloadFixture) { f.body = "this is not toml [" }, auditsink.ReloadRefusedFile, nil},
		{"bind-time change", func(f *reloadFixture) {
			f.body = strings.Replace(f.toml("[reach]\nmutate_blast_cap = 7\n"), "localhost", "other.example", 1)
		}, auditsink.ReloadRefusedRestart, []string{"tls.hostname"}},
		{"open error", func(f *reloadFixture) {
			f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")
			f.openErr = errors.New("the gate file is malformed")
		}, auditsink.ReloadRefusedNamedFiles, nil},
		{"CA mismatch", func(f *reloadFixture) {
			f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")
			f.r.open = func(gatePath, _, storePath string) (startup.Files, error) {
				return testStartupFiles(t, Config{ApprovalGatePath: gatePath, CADir: filepath.Join(f.dir, "replaced-ca"), StorePath: storePath}), nil
			}
		}, auditsink.ReloadRefusedCA, nil},
		{"secret file unreadable", func(f *reloadFixture) {
			f.body = f.toml("[approval]\nwebhook_url_file = \"/run/x/url\"\n")
			f.r.load = func(string) (startupConfig, error) {
				return parseConfig([]byte(f.body), func(string) ([]byte, error) { return nil, errors.New("read failed") })
			}
		}, auditsink.ReloadRefusedSecretFile, nil},
		{"setting refused", func(f *reloadFixture) {
			f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")
			f.r.load = func(string) (startupConfig, error) {
				sc := mustParse(t, f.body)
				sc.Config.DispatchConcurrency = 0
				return sc, nil
			}
		}, auditsink.ReloadRefusedSettings, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReloadFixture(t)
			liveBefore, gateBefore := f.deps.live.cur.Load(), f.deps.gate.cur.Load()
			tc.setup(f)

			if _, err := f.r.reload(context.Background()); err == nil {
				t.Fatal("reload succeeded, want a refusal")
			}
			if f.deps.live.cur.Load() != liveBefore || f.deps.gate.cur.Load() != gateBefore {
				t.Error("a refused reload replaced the snapshot or the gate")
			}
			f.logBuf.Reset()
			slog.Info("after the refusal")
			if out := f.logBuf.String(); strings.HasPrefix(out, "{") {
				t.Errorf("log after a refused reload = %q, want the original text format", out)
			}
			if len(f.records(audit.KindConfigReload)) != 0 {
				t.Error("a refused reload wrote a config_reload record")
			}
			recs := f.records(audit.KindConfigReloadRefused)
			if len(recs) != 1 {
				t.Fatalf("config_reload_refused records = %d, want 1", len(recs))
			}
			want, err := auditsink.HostConfigReloadRefusedRecord("x", recs[0].Timestamp, tc.stage, tc.keys)
			if err != nil {
				t.Fatal(err)
			}
			if recs[0].Reason != want.Reason {
				t.Errorf("Reason = %q, want %q", recs[0].Reason, want.Reason)
			}
		})
	}
}

func TestReloader_CAFingerprintMismatchRefuses(t *testing.T) {
	f := newReloadFixture(t)
	liveBefore, gateBefore := f.deps.live.cur.Load(), f.deps.gate.cur.Load()
	f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")
	f.r.open = func(gatePath, _, storePath string) (startup.Files, error) {
		// A CA directory key the process is not running on: a different CA.
		return testStartupFiles(t, Config{ApprovalGatePath: gatePath, CADir: filepath.Join(f.dir, "replaced-ca"), StorePath: storePath}), nil
	}

	if _, err := f.r.reload(context.Background()); err == nil {
		t.Fatal("reload with a different CA on disk succeeded")
	}
	if f.deps.live.cur.Load() != liveBefore || f.deps.gate.cur.Load() != gateBefore {
		t.Error("the snapshot or the gate was replaced")
	}
	if !strings.Contains(f.logBuf.String(), "restart required") {
		t.Errorf("log = %q, want restart required", f.logBuf.String())
	}
	f.logBuf.Reset()
	slog.Info("after the refusal")
	if out := f.logBuf.String(); strings.HasPrefix(out, "{") {
		t.Errorf("log after a refused reload = %q, want the original text format", out)
	}
	recs := f.records(audit.KindConfigReloadRefused)
	if len(recs) != 1 || !strings.Contains(recs[0].Reason, "the CA on disk is not the CA this Relay is running") {
		t.Errorf("refusal records = %+v", recs)
	}
}

func TestReloader_AuditFailureRefuses(t *testing.T) {
	f := newReloadFixture(t)
	liveBefore := f.deps.live.cur.Load()
	// A record with this id is already on the trail, so every append with it fails.
	if err := f.deps.audit.Append(context.Background(), audit.Record{
		ID: "collide", Timestamp: f.r.now(), Kind: audit.KindPasswordSet, Principal: audit.PrincipalLocalHost,
	}); err != nil {
		t.Fatal(err)
	}
	f.r.newID = func() (string, error) { return "collide", nil }
	f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")

	if _, err := f.r.reload(context.Background()); err == nil {
		t.Fatal("reload succeeded though its audit record could not be written")
	}
	if f.deps.live.cur.Load() != liveBefore {
		t.Error("the snapshot was replaced")
	}
	if !strings.Contains(f.logBuf.String(), "could not be audited") {
		t.Errorf("log = %q, want the refusal's audit failure logged", f.logBuf.String())
	}
	if len(f.records(audit.KindConfigReload)) != 0 {
		t.Error("a config_reload record was written")
	}
}

func TestReloader_BindTimeCheckedBeforeOpen(t *testing.T) {
	f := newReloadFixture(t)
	f.body = strings.Replace(f.body, filepath.Join(f.dir, "ca"), filepath.Join(f.dir, "elsewhere"), 1)

	if _, err := f.r.reload(context.Background()); err == nil {
		t.Fatal("reload with a changed ca.dir succeeded")
	}
	if f.opened != 0 {
		t.Errorf("open ran %d times before the bind-time refusal, want 0 (opening would create a CA)", f.opened)
	}
	if !strings.Contains(f.logBuf.String(), "ca.dir") {
		t.Errorf("log = %q, want it to name ca.dir", f.logBuf.String())
	}
}

func TestReloader_PanicDoesNotExit(t *testing.T) {
	f := newReloadFixture(t)
	good := f.r.open
	f.r.open = func(string, string, string) (startup.Files, error) { panic("boom") }
	f.body = f.toml("[reach]\nmutate_blast_cap = 7\n")

	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchReload(ctx, hup, f.r); close(done) }()

	hup <- os.Interrupt
	waitFor(t, func() bool { return len(f.records(audit.KindConfigReloadRefused)) == 1 })
	if r := f.records(audit.KindConfigReloadRefused)[0]; !strings.Contains(r.Reason, "the reload failed unexpectedly") {
		t.Errorf("Reason = %q, want the internal stage", r.Reason)
	}

	f.r.open = good
	hup <- os.Interrupt
	waitFor(t, func() bool { return len(f.records(audit.KindConfigReload)) == 1 })
	if got := f.deps.live.OperatorSettings().MutateBlastCap; got != 7 {
		t.Errorf("MutateBlastCap = %d after the reload that followed a panic, want 7", got)
	}
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestSwapHandler_DerivedLoggersFollowSwap(t *testing.T) {
	var buf bytes.Buffer
	text := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	sh := newSwapHandler(text)
	derived := slog.New(sh).With("component", "x").WithGroup("g").With("k", "v")

	derived.Info("before")
	if out := buf.String(); !strings.Contains(out, "component=x") || !strings.Contains(out, "g.k=v") || strings.HasPrefix(out, "{") {
		t.Fatalf("before the swap: %q", out)
	}
	derived.Debug("hidden")
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("a debug line passed an info-level handler")
	}

	buf.Reset()
	sh.swap(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	derived.Debug("after")
	out := buf.String()
	for _, want := range []string{`"msg":"after"`, `"component":"x"`, `"g":{"k":"v"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("after the swap: %q does not contain %s", out, want)
		}
	}
}

func TestNewServer_OperatorSettingsConsumersReadLiveSnapshot(t *testing.T) {
	f := newReloadFixture(t)
	deps := f.deps
	reg := deps.registry

	next := *deps.live.cur.Load()
	next.settings.MaxNodes = 1
	next.settings.MinDaemonVersion = "1.2.0"
	next.settings.EnrollIPRatePerMinute, next.settings.EnrollIPBurst = 1, 1
	next.settings.EnrollGlobalRatePerMinute, next.settings.EnrollGlobalBurst = 1, 100
	deps.live.swap(&next)

	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", DaemonVersion: "1.1.0"}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-b"}); !errors.Is(err, registry.ErrAtCapacity) {
		t.Errorf("second Upsert at the swapped-in cap 1 = %v, want ErrAtCapacity", err)
	}
	if n, _ := reg.Get("node-a"); !n.Outdated {
		t.Error("Outdated did not follow the swapped-in minimum version")
	}
	if !deps.limiter.Allow("10.0.0.1") {
		t.Fatal("first enrollment refused")
	}
	if deps.limiter.Allow("10.0.0.1") {
		t.Error("second enrollment allowed at the swapped-in per-IP burst of 1")
	}
}

func TestNewServer_ZeroFilesStillRefusedFirst(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.CertExpiringFraction = 7
	_, _, err := newServer(cfg, startup.Files{})
	if err == nil || !strings.Contains(err.Error(), "start-time file check") {
		t.Fatalf("newServer = %v, want the start-time file check refusal ahead of the settings checks", err)
	}
}

// TestSignals_OnlyFreezeAndReloadHandleSignals: os/signal is imported by the
// Freeze lever and the reload lever and nowhere else in the binary, so no third
// signal-driven path to a running Relay exists.
func TestSignals_OnlyFreezeAndReloadHandleSignals(t *testing.T) {
	allowed := map[string]bool{"freeze_signal.go": true, "reload_signal.go": true}
	entries, err := fs.ReadDir(os.DirFS("."), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/signal" && !allowed[name] {
				t.Errorf("%s imports os/signal; only the Freeze and reload levers may", name)
			}
		}
	}
}
