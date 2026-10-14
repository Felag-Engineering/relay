package auditsink

import (
	"context"
	"log/slog"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// DefaultCheckpointInterval is how often the Checkpointer looks at the audit
// chain's head. A constant, not configuration: it adds no operator-settable
// surface (invariant 11).
const DefaultCheckpointInterval = 5 * time.Minute

// Checkpointer periodically logs the audit chain's head. The line is
// the ADR-0025 metadata stream's anchor: it carries the chain format, a seq and
// a hash and nothing about any record's content. An operator who keeps these
// lines in their log pipeline can later pass any of them to
// relay-audit-verify -expect SEQ:HASH, which detects tail truncation and
// re-chaining that the chain alone cannot. External anchoring is #284's
// follow-up.
//
// It is a log line and not an audit row on purpose: a checkpoint inside the
// chain it anchors cannot anchor that chain.
type Checkpointer struct {
	reader   audit.ChainHeadReader
	interval time.Duration
	logger   *slog.Logger
	last     uint64
}

// NewCheckpointer builds a Checkpointer. A nil logger uses slog.Default(); a
// non-positive interval uses DefaultCheckpointInterval.
func NewCheckpointer(r audit.ChainHeadReader, interval time.Duration, logger *slog.Logger) *Checkpointer {
	if interval <= 0 {
		interval = DefaultCheckpointInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Checkpointer{reader: r, interval: interval, logger: logger}
}

// Checkpoint logs the head if it has advanced since the last line, and reports
// whether it logged. An empty trail (seq 0) is never logged: it would be a
// useless anchor.
func (c *Checkpointer) Checkpoint(ctx context.Context) (bool, error) {
	h, err := c.reader.ChainHead(ctx)
	if err != nil {
		return false, err
	}
	if h.Seq == 0 || h.Seq == c.last {
		return false, nil
	}
	c.logger.Info("audit chain checkpoint",
		"format", audit.ChainFormat,
		"seq", h.Seq,
		"hash", h.Hash.Hex(),
	)
	c.last = h.Seq
	return true, nil
}

// Run checkpoints immediately, then on every tick, until ctx is done. A failed
// checkpoint is reported to onError and the loop continues.
func (c *Checkpointer) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		if _, err := c.Checkpoint(ctx); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
