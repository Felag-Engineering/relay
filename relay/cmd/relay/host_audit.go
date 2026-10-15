package main

import "github.com/Felag-Engineering/relay/relay/internal/audit"

// hostAuditID mints the audit record ID for a host-side credential lever.
// It is a var so a test can make the record unwritable (a colliding
// audit_id) without database/sql, which only internal/store may import. A test
// that swaps it mutates package state, so it must not run in parallel.
var hostAuditID = audit.NewID
