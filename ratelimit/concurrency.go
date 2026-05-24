package ratelimit

import (
	"sync"
	"sync/atomic"
)

// Concurrency tracks the number of in-flight requests per key. The zero
// value is ready to use.
//
// # Semantics
//
// Begin increments the per-key counter and returns the new value plus a
// release closure. Callers compare the returned `current` against their
// cap and reject if it exceeds; in both accept and reject cases they
// MUST call End so the counter goes back down. The typical pattern:
//
//	cur, end := lim.Begin(key)
//	defer end()
//	if cur > max {
//	    // reject ...
//	    return
//	}
//
// This API intentionally separates "tracking" from "policy" so callers
// can use the same counter for per-token caps + monitoring + heuristics
// without forcing every consumer to agree on the limit.
type Concurrency struct {
	counters sync.Map // map[string]*int32
}

// Begin increments the per-key inflight counter and returns the new
// value (always >= 1) plus a closure that decrements when called.
// Calling the closure more than once is harmless.
func (c *Concurrency) Begin(key string) (current int32, end func()) {
	v, _ := c.counters.LoadOrStore(key, new(int32))
	ctr := v.(*int32)
	cur := atomic.AddInt32(ctr, 1)
	var done int32
	return cur, func() {
		if atomic.CompareAndSwapInt32(&done, 0, 1) {
			atomic.AddInt32(ctr, -1)
		}
	}
}

// Snapshot returns the current inflight count for key (zero if unseen).
// Useful for telemetry / admin panels.
func (c *Concurrency) Snapshot(key string) int32 {
	v, ok := c.counters.Load(key)
	if !ok {
		return 0
	}
	return atomic.LoadInt32(v.(*int32))
}
