package main

// reload.go is the Relay's configuration reload (RC-21). It reruns the start
// steps that read the configuration file against the path given at start, and
// applies the result all-or-nothing: any failure refuses the whole reload and
// leaves the running configuration untouched. On success it swaps three
// things: the operator-settings snapshot, the approval gate (built from the
// file's [[approval.rules]]) and the log handler. Every reload, applied or
// refused, writes one audit record attributed to the host, naming setting keys
// and fixed phrases only (RC-18).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
)

// reloadAuditTimeout bounds one reload audit append.
const reloadAuditTimeout = 10 * time.Second

type reloader struct {
	path   string
	file   relayconfig.Config // the file the Relay is running on
	caFP   string             // fingerprint of the CA this process runs on
	live   *liveConfig
	gate   *liveGate
	logs   *swapHandler
	stderr io.Writer
	audit  audit.Repository
	logger *slog.Logger
	newID  func() (string, error)
	now    func() time.Time

	// The start steps a reload reruns. Production sets loadConfig and
	// startup.Open; only this package's tests substitute them.
	load func(path string) (startupConfig, error)
	open func(caDir, storePath string) (startup.Files, error)
}

// newReloader builds the reloader for the Relay main started from sc at path.
// newID is copied from hostAuditID here, so a test that swaps hostAuditID does
// so before calling it, or sets r.newID.
func newReloader(path string, sc startupConfig, deps *appDeps, logs *swapHandler, stderr io.Writer) *reloader {
	return &reloader{
		path:   path,
		file:   sc.File,
		caFP:   deps.ca.Fingerprint(),
		live:   deps.live,
		gate:   deps.gate,
		logs:   logs,
		stderr: stderr,
		audit:  deps.audit,
		logger: deps.logger,
		newID:  hostAuditID,
		now:    func() time.Time { return time.Now().UTC() },
		load:   loadConfig,
		open:   startup.Open,
	}
}

// reload reruns start steps 2 to 6 and applies the result, returning the keys
// of the settings that changed. The order is load-bearing: the file check
// (RC-15) comes first, inside load; the bind-time diff comes before the named
// files are opened, because opening creates a missing CA or store directory;
// and nothing is swapped until the audit record is written.
func (r *reloader) reload(ctx context.Context) ([]string, error) {
	sc, err := r.load(r.path)
	if errors.Is(err, errSecretFileUnread) {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedSecretFile, nil, err)
	}
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedFile, nil, err)
	}
	for _, w := range sc.Warnings {
		slog.Warn(w.String(), "reload", true)
	}

	changes := relayconfig.Diff(r.file, sc.File)
	var restart []string
	for _, c := range changes {
		if c.RestartRequired {
			restart = append(restart, c.Key)
			slog.Error("configuration reload refused: restart required", "setting", c.Key)
		}
	}
	if len(restart) > 0 {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedRestart, restart,
			fmt.Errorf("restart required: %d setting(s) are applied only at start", len(restart)))
	}

	cfg := sc.Config
	files, err := r.open(cfg.CADir, cfg.StorePath)
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedNamedFiles, nil, err)
	}
	// ca.dir is unchanged, so a different CA here means the files on disk were
	// replaced or removed. The running process keeps its CA either way; refusing
	// makes the divergence loud before a restart silently trusts a new root.
	if files.CA().Fingerprint() != r.caFP {
		slog.Error("configuration reload refused: restart required",
			"reason", "the CA on disk is not the CA this Relay is running")
		return nil, r.refuse(ctx, auditsink.ReloadRefusedCA, nil,
			errors.New("the CA on disk is not the CA this Relay is running"))
	}

	next, err := newRunning(cfg, r.logger)
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedSettings, nil, err)
	}

	keys := make([]string, 0, len(changes))
	for _, c := range changes {
		keys = append(keys, c.Key)
	}
	// The gate is built before anything is written or swapped: a rule that
	// cannot be loaded refuses the whole reload, naming a rule's position and
	// never its name or a value.
	gate, err := approval.NewGate(cfg.ApprovalRules)
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedSettings, nil, err)
	}

	id, err := r.newID()
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedAudit, nil, fmt.Errorf("generate audit record id: %w", err))
	}
	rec, err := auditsink.HostConfigReloadRecord(id, r.now(), keys)
	if err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedAudit, nil, err)
	}
	if err := r.appendRecord(ctx, rec); err != nil {
		return nil, r.refuse(ctx, auditsink.ReloadRefusedAudit, nil, err)
	}

	// The handler is built before the first swap, so the swaps below are bare
	// atomic stores and a reload is never half-applied.
	handler := newLogHandler(r.stderr, sc.Log)
	r.gate.swap(gate)
	r.live.swap(next)
	r.logs.swap(handler)
	r.file = sc.File

	slog.Info("configuration reloaded", "changed", keys)
	if n := len(cfg.ApprovalRules); n > 0 {
		slog.Info("approval gating enabled", "rules", n)
	}
	return keys, nil
}

// refuse logs the refusal, audits it best-effort, and returns err. Nothing is
// swapped and the process never exits. Every error reaching here names only a
// key, a line, a rule's position or a path; the audit record carries a fixed
// phrase, never the error's text.
func (r *reloader) refuse(ctx context.Context, stage auditsink.ReloadStage, restartKeys []string, err error) error {
	slog.Error("configuration reload refused; the running configuration is unchanged", "err", err)
	r.auditRefusal(ctx, stage, restartKeys)
	return err
}

// auditRefusal records a refused reload. A failure here, including the refusal
// for an unwritable trail, is logged and never changes the outcome.
func (r *reloader) auditRefusal(ctx context.Context, stage auditsink.ReloadStage, restartKeys []string) {
	id, err := r.newID()
	if err == nil {
		var rec audit.Record
		if rec, err = auditsink.HostConfigReloadRefusedRecord(id, r.now(), stage, restartKeys); err == nil {
			err = r.appendRecord(ctx, rec)
		}
	}
	if err != nil {
		slog.Error("configuration reload refusal could not be audited", "err", err)
	}
}

func (r *reloader) appendRecord(ctx context.Context, rec audit.Record) error {
	ctx, cancel := context.WithTimeout(ctx, reloadAuditTimeout)
	defer cancel()
	return r.audit.Append(ctx, rec)
}
