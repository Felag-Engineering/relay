package revocation

import "sync"

// recordedSet tracks the Node ids for which THIS PROCESS has already
// written a node_revoke record through a RevocationRecorder that returned
// nil — set only by revokeChunk, after its record call succeeds, and read
// only by RevokeNodeRecorded.
//
// WHY NOT THE DENYLIST. Denylist membership does NOT mean "a record
// exists" for a Node. Three production paths put a Node on the denylist
// with no node_revoke record anywhere: enroll.Service's post-Upsert
// revocation recheck self-denylists a just-minted identity
// (enroll/handler.go:540, through NodeDenylister.RevokeNode, which also
// persists SetRevoked, so it survives a restart); a cascade chunk whose
// record call failed or blew cascadeAuditBudget is revoked anyway and
// deliberately left unrecorded (see revokeChunk); and at startup the
// denylist is rehydrated wholesale from registry.RevokedNodeIDs()
// (relay/cmd/relay/main.go:638). In all three, an admin's explicit
// POST /api/v1/nodes/{id}/revoke with a reason is exactly what supplies the
// missing attribution. Suppressing a record on "is it denylisted" would
// answer that request 204 with no record at all, leaving the Node
// permanently revoked with zero attribution, on the security surface. This set exists so that cannot happen: the
// suppression it drives is keyed on a record this process actually wrote,
// never on denylist membership.
//
// WHAT IT IS NOT. This is in-process only, empty after every restart,
// deliberately: it is a race-window dedup for the single Relay process that
// is running right now, not a durable "has this Node ever been recorded"
// oracle. The trail is the only thing that can answer that question, and
// this package cannot read it (imports_test.go forbids importing
// internal/audit).
//
// MEMORY. It grows monotonically for the lifetime of the process, bounded
// by the number of distinct Node ids this process has cascade-revoked — the
// same order of growth as the Denylist beside it, which also never shrinks.
type recordedSet struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

// newRecordedSet creates an empty recordedSet.
func newRecordedSet() *recordedSet {
	return &recordedSet{ids: make(map[string]struct{})}
}

// markAll records every id in ids as having a record this process wrote.
// Callers must only call this after a RevocationRecorder call covering ids
// has returned nil.
func (r *recordedSet) markAll(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		r.ids[id] = struct{}{}
	}
}

// has reports whether id was previously marked.
//
// Every caller of markAll and has holds that Node's keyed lock (nodeLocks)
// for the whole of the read-or-write, so per Node id this set is already
// serialised by that lock; the mutex here is only for safety across
// different Node ids sharing the same map.
func (r *recordedSet) has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ids[id]
	return ok
}
