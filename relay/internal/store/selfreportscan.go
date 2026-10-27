package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// This file is the boot answer to "which Nodes carry a stored self-reported
// field this Relay will no longer serve". getNode declines such a field on
// every read through registry.DeclineMalformedSelfReport, silently, for the
// reason labelscan.go gives for Labels: a per-read log line would re-log every
// listing forever. This scan logs each (Node, field) once per process.
//
// It is exact for the same reason the Label scan is: Hello and Enroll are the
// only writers of these columns, and both apply the same bound before they
// write, so every row it finds was stored before that bound existed. It heals
// on the Node's next Hello, which rewrites every column.
//
// It reads only, from the raw nodes table, and never repairs a row. It runs at
// boot and nowhere else, for the single-connection reason ScanDeclinedLabels
// documents; it is O(Nodes), bounded by the Node cap.

// DeclinedSelfReport is one reported finding: a stored self-reported field the
// read-back declines to serve. The value is deliberately absent, as it is from
// DeclinedLabel: it is the Node's own bytes, and the ones a bound refused.
type DeclinedSelfReport struct {
	NodeID string
	Field  string // one of the registry.Field* names
}

// DeclinedSelfReportSet is the scan's result. Fields and Nodes are exact and
// never capped; Reported holds at most maxDeclinedReported findings, in
// (node_id, field order) order; Truncated says whether more existed.
type DeclinedSelfReportSet struct {
	Fields    int64
	Nodes     int64
	Reported  []DeclinedSelfReport
	Truncated bool
}

// ScanDeclinedSelfReports runs the one-shot startup scan over the stored
// self-reported fields, logs one WARN per (Node, field) it finds plus one
// summary, or one INFO line when nothing is declined, and returns the result.
// Boot-only, with a bounded context, exactly as ScanDeclinedLabels.
func (s *Store) ScanDeclinedSelfReports(ctx context.Context) (DeclinedSelfReportSet, error) {
	set, err := scanDeclinedSelfReports(ctx, s.db)
	if err != nil {
		return DeclinedSelfReportSet{}, fmt.Errorf("scan nodes: %w", err)
	}
	if set.Fields == 0 {
		s.logger.Info("startup scan: no stored self-reported fields declined on read-back")
		return set, nil
	}
	for _, d := range set.Reported {
		s.logger.Warn("stored self-reported field declined on read-back",
			slog.String("node_id", d.NodeID),
			slog.String("field", d.Field),
		)
	}
	s.logger.Warn("startup scan: stored self-reported fields declined on read-back",
		slog.Int64("fields_declined_at_scan", set.Fields),
		slog.Int64("nodes_affected_at_scan", set.Nodes),
		slog.Int("reported", len(set.Reported)),
		slog.Bool("truncated", set.Truncated),
	)
	return set, nil
}

// scanDeclinedSelfReports classifies every nodes row with the read-back's own
// rule, registry.DeclineMalformedSelfReport, so the two cannot disagree. An
// ip_addresses column that does not decode is not counted: getNode reports
// that Node as unreadable, which is a different signal.
func scanDeclinedSelfReports(ctx context.Context, q queryer) (DeclinedSelfReportSet, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT node_id, hostname, os, kernel, arch, ip_addresses,
			policy_fingerprint, template_set_fingerprint, daemon_version
		FROM nodes ORDER BY node_id`)
	if err != nil {
		return DeclinedSelfReportSet{}, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	var set DeclinedSelfReportSet
	for rows.Next() {
		var (
			nodeID string
			raw    registry.SelfReport
			ipJSON sql.NullString
		)
		if err := rows.Scan(&nodeID, &raw.Facts.Hostname, &raw.Facts.OS, &raw.Facts.Kernel,
			&raw.Facts.Arch, &ipJSON, &raw.PolicyFingerprint, &raw.TemplateSetFingerprint,
			&raw.DaemonVersion); err != nil {
			return DeclinedSelfReportSet{}, fmt.Errorf("scan nodes row: %w", err)
		}
		if ips, err := decodeIPAddresses(ipJSON); err == nil {
			raw.Facts.IPAddresses = ips
		}
		_, fields := registry.DeclineMalformedSelfReport(raw)
		if len(fields) == 0 {
			continue
		}
		set.Nodes++
		for _, f := range fields {
			set.Fields++
			if len(set.Reported) >= maxDeclinedReported {
				set.Truncated = true
				continue
			}
			set.Reported = append(set.Reported, DeclinedSelfReport{NodeID: nodeID, Field: f})
		}
	}
	return set, rows.Err()
}
