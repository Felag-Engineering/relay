package revocation

import (
	"context"
	"sort"
	"sync"
)

// keyedLock is one entry in a keyedMutex: ch is the lock itself (capacity 1,
// a send acquires it, a receive releases it), and refs counts everyone who
// currently holds OR is waiting for it.
type keyedLock struct {
	ch   chan struct{}
	refs int
}

// keyedMutex is a set of mutexes keyed by an arbitrary string, created on
// first use and deleted once nobody holds or is waiting for them.
//
// Deleting idle entries matters because both callers in this package key it
// on caller-supplied input straight off the wire — a token id off
// r.PathValue, a Node id off the registry — so a keyedMutex that never shrank
// would grow without bound for the lifetime of the process.
//
// INVARIANT (a): refs counts HOLDERS PLUS WAITERS, both incremented under
// k.mu before the entry's channel is ever touched. So refs == 0, observed
// under k.mu, means nobody holds the lock and nobody is about to — which is
// what makes it safe to delete the map entry at that point. unlock's delete
// additionally checks that k.keys[key] is still THIS *keyedLock by pointer
// identity, so the reasoning above stays safe to rely on even if a future
// code path breaks it: a stale unlock can never delete a newer entry for the
// same key.
//
// INVARIANT (b): ctx is honoured ONLY WHILE WAITING for the lock. Once lock
// returns a nil error, the caller holds the lock unconditionally until it
// calls unlock — cancelling ctx after that does nothing. The holder may be
// partway through irreversible work (a token cascade, a Node's
// record-then-revoke) and must not be interrupted because a client hung up.
type keyedMutex struct {
	mu   sync.Mutex
	keys map[string]*keyedLock
}

// newKeyedMutex creates an empty keyedMutex.
func newKeyedMutex() *keyedMutex {
	return &keyedMutex{keys: make(map[string]*keyedLock)}
}

// lock acquires the mutex for key, blocking until it is free or ctx is done.
// A nil error means the caller now holds the lock and must call the returned
// unlock exactly once to release it; a non-nil error (ctx.Err()) means the
// caller acquired nothing and nothing it guards has happened yet.
func (k *keyedMutex) lock(ctx context.Context, key string) (unlock func(), err error) {
	// Checked BEFORE the select below: Go picks uniformly at random when two
	// select cases are both ready, so without this explicit pre-check an
	// already-cancelled caller would still acquire an uncontended lock about
	// half the time, and "a cancelled call does nothing" would hold only
	// intermittently.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	k.mu.Lock()
	l, ok := k.keys[key]
	if !ok {
		l = &keyedLock{ch: make(chan struct{}, 1)}
		k.keys[key] = l
	}
	l.refs++
	k.mu.Unlock()

	release := func() {
		k.mu.Lock()
		l.refs--
		if l.refs == 0 && k.keys[key] == l {
			delete(k.keys, key)
		}
		k.mu.Unlock()
	}

	select {
	case l.ch <- struct{}{}:
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			<-l.ch
			release()
		})
	}, nil
}

// lockAll acquires every key in keys, in ascending order, deduplicating any
// key that appears more than once (locking the same key twice would
// self-deadlock). It uses context.Background(): once a caller holds any of
// these locks it must run to completion, the same reasoning as lock's
// invariant (b) above.
//
// DEADLOCK FREEDOM: Service keeps token locks and Node locks in two separate
// keyedMutexes and acquires them in one global order, never the reverse:
//
//   - RevokeToken holds its one token lock and then, while still holding it,
//     takes that token's Node locks through lockAll, in ascending key order;
//   - RevokeNodeRecorded holds a single Node lock and acquires nothing else;
//   - nothing ever takes a token lock while holding a Node lock, and nothing
//     holds two token locks at once.
//
// Within the Node class every multi-key acquisition goes through lockAll, so
// two goroutines with overlapping but differently-ordered key sets converge on
// the same ascending order and cannot deadlock each other.
func (k *keyedMutex) lockAll(keys []string) (unlock func()) {
	sorted := make([]string, len(keys))
	copy(sorted, keys)
	sort.Strings(sorted)

	unique := sorted[:0]
	for _, key := range sorted {
		if len(unique) == 0 || key != unique[len(unique)-1] {
			unique = append(unique, key)
		}
	}

	unlocks := make([]func(), 0, len(unique))
	for _, key := range unique {
		// context.Background(): lockAll never waits on a caller's context, see
		// the doc above.
		u, err := k.lock(context.Background(), key)
		if err != nil {
			// Unreachable: context.Background() never errors.
			panic("revocation: keyedMutex.lock with context.Background() returned an error: " + err.Error())
		}
		unlocks = append(unlocks, u)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(unlocks) - 1; i >= 0; i-- {
				unlocks[i]()
			}
		})
	}
}
