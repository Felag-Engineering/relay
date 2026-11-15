// Package main: audit_helpers_test.go holds the audit-trail reads that
// composition-root tests assert on. Each fails the test on a read error, so an
// unreadable trail never passes as an empty one.
package main

import (
	"context"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// auditList returns every Record in repo, in the trail's order.
func auditList(t testing.TB, repo audit.Repository) []audit.Record {
	t.Helper()
	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	return records
}

// auditByNode returns the Records repo holds for nodeID.
func auditByNode(t testing.TB, repo audit.Repository, nodeID string) []audit.Record {
	t.Helper()
	records, err := repo.ByNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("audit ByNode(%s): %v", nodeID, err)
	}
	return records
}

// auditByJob returns the Records repo holds for jobID.
func auditByJob(t testing.TB, repo audit.Repository, jobID string) []audit.Record {
	t.Helper()
	records, err := repo.ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("audit ByJob(%s): %v", jobID, err)
	}
	return records
}

// auditByApproval returns the Records repo holds for the approval Request requestID.
func auditByApproval(t testing.TB, repo audit.Repository, requestID string) []audit.Record {
	t.Helper()
	records, err := repo.ByApproval(context.Background(), requestID)
	if err != nil {
		t.Fatalf("audit ByApproval(%s): %v", requestID, err)
	}
	return records
}

// recordsOfKind returns the Records in records whose Kind is kind, order kept.
func recordsOfKind(records []audit.Record, kind string) []audit.Record {
	var out []audit.Record
	for _, r := range records {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}
