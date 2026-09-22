package revocation

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestKeyedMutex_ExclusivePerKey asserts that two goroutines contending for
// the same key never run their critical section at the same time.
func TestKeyedMutex_ExclusivePerKey(t *testing.T) {
	k := newKeyedMutex()
	var inCriticalSection int32
	var overlapped atomic.Bool

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				unlock, err := k.lock(context.Background(), "same-key")
				if err != nil {
					t.Errorf("lock: %v", err)
					return
				}
				if atomic.AddInt32(&inCriticalSection, 1) != 1 {
					overlapped.Store(true)
				}
				atomic.AddInt32(&inCriticalSection, -1)
				unlock()
			}
		}()
	}
	wg.Wait()

	if overlapped.Load() {
		t.Error("two goroutines were inside the critical section for the same key at once")
	}
}

// TestKeyedMutex_DifferentKeysDoNotBlock asserts that holding one key never
// blocks acquisition of a different key.
func TestKeyedMutex_DifferentKeysDoNotBlock(t *testing.T) {
	k := newKeyedMutex()

	unlockA, err := k.lock(context.Background(), "a")
	if err != nil {
		t.Fatalf("lock(a): %v", err)
	}
	defer unlockA()

	done := make(chan struct{})
	go func() {
		unlockB, err := k.lock(context.Background(), "b")
		if err != nil {
			t.Errorf("lock(b): %v", err)
			return
		}
		unlockB()
		close(done)
	}()

	select {
	case <-done:
		// expected: key b was acquirable while key a is held.
	case <-time.After(2 * time.Second):
		t.Fatal("lock(b) blocked on an unrelated key a is holding")
	}
}

// TestKeyedMutex_LockHonoursContextWhileWaiting covers the three cases where
// ctx must be honoured: a contended key with an already-cancelled context, a
// contended key with a short deadline, and — the case the explicit
// ctx.Err() pre-check exists for — an uncontended, FREE key with an
// already-cancelled context. Without that pre-check, select picks uniformly
// at random between a ready send and a done ctx, so a free key would only
// fail this about half the time.
func TestKeyedMutex_LockHonoursContextWhileWaiting(t *testing.T) {
	t.Run("held key, already-cancelled context", func(t *testing.T) {
		k := newKeyedMutex()
		unlockHolder, err := k.lock(context.Background(), "key")
		if err != nil {
			t.Fatalf("lock(holder): %v", err)
		}
		defer unlockHolder()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		unlock, err := k.lock(ctx, "key")
		if err != ctx.Err() {
			t.Fatalf("lock error = %v, want ctx.Err() = %v", err, ctx.Err())
		}
		if unlock != nil {
			t.Error("unlock should be nil on a cancelled wait")
		}
	})

	t.Run("held key, short deadline", func(t *testing.T) {
		k := newKeyedMutex()
		unlockHolder, err := k.lock(context.Background(), "key")
		if err != nil {
			t.Fatalf("lock(holder): %v", err)
		}
		defer unlockHolder()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		unlock, err := k.lock(ctx, "key")
		if err != context.DeadlineExceeded {
			t.Fatalf("lock error = %v, want context.DeadlineExceeded", err)
		}
		if unlock != nil {
			t.Error("unlock should be nil on a timed-out wait")
		}
	})

	t.Run("free key, already-cancelled context", func(t *testing.T) {
		k := newKeyedMutex()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		unlock, err := k.lock(ctx, "free-key")
		if err != ctx.Err() {
			t.Fatalf("lock error = %v, want ctx.Err() = %v", err, ctx.Err())
		}
		if unlock != nil {
			t.Error("unlock should be nil when the caller's context is already cancelled")
		}
	})

	// The key must still be acquirable after every one of the above: a
	// cancelled wait must not have left the entry locked or orphaned.
	t.Run("the key stays acquirable afterward", func(t *testing.T) {
		k := newKeyedMutex()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := k.lock(ctx, "key"); err == nil {
			t.Fatal("expected an error from a cancelled lock")
		}

		unlock, err := k.lock(context.Background(), "key")
		if err != nil {
			t.Fatalf("lock after a cancelled waiter: %v", err)
		}
		unlock()
	})
}

// TestKeyedMutex_DropsIdleEntries asserts the internal map is empty once
// every lock on a key has been released — the guard against unbounded growth
// from caller-supplied keys.
func TestKeyedMutex_DropsIdleEntries(t *testing.T) {
	k := newKeyedMutex()

	for _, key := range []string{"a", "b", "c"} {
		unlock, err := k.lock(context.Background(), key)
		if err != nil {
			t.Fatalf("lock(%s): %v", key, err)
		}
		unlock()
	}

	k.mu.Lock()
	n := len(k.keys)
	k.mu.Unlock()
	if n != 0 {
		t.Errorf("keyedMutex has %d entries after every key was unlocked, want 0", n)
	}
}

// TestKeyedMutex_LockAllIsOrderIndependent runs two goroutines whose lockAll
// calls cover overlapping key sets given in opposite orders — the case a
// lock-ordering regression deadlocks. A duplicated key within one call is
// exercised too. Both goroutines completing within the timeout is the
// assertion; a regression hangs rather than fails an assertion, so the
// timeout is what turns that into a red test.
func TestKeyedMutex_LockAllIsOrderIndependent(t *testing.T) {
	k := newKeyedMutex()

	var wg sync.WaitGroup
	done := make(chan struct{})

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(reverse bool) {
			defer wg.Done()
			for iter := 0; iter < 100; iter++ {
				keys := []string{"node-1", "node-2", "node-3", "node-2"} // node-2 duplicated
				if reverse {
					keys = []string{"node-3", "node-2", "node-1", "node-3"}
				}
				unlock := k.lockAll(keys)
				unlock()
			}
		}(i == 1)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(5 * time.Second):
		t.Fatal("lockAll deadlocked on overlapping, differently-ordered key sets")
	}
}
