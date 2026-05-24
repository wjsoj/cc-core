// Package ratelimit provides keyed RPM (requests-per-minute) and concurrency
// gates. Both are framework-agnostic — no HTTP types, no logger — so they
// drop into any Go service.
//
// # Keying convention
//
// Callers compose the key from whatever dimensions need their own bucket.
// CPA-Claude uses `<provider> + "|" + <clientToken>` so Claude and Codex
// traffic from the same client share a token but get independent counters.
//
// # No GC
//
// Both gates keep per-key state for the life of the process. This is
// intentional: the number of distinct keys is bounded by the number of
// (provider, client-token) pairs ever observed, which is small for a
// reverse-proxy deployment. If your workload has unbounded key space, wrap
// with an LRU.
package ratelimit

import (
	"sync"
	"time"
)

// Window is the sliding window for RPM counting. Exported so callers can
// document the cap unit ("requests per <Window>") in their UI.
const Window = time.Minute

// RPM enforces a sliding Window requests-per-minute cap per key. The zero
// value is ready to use.
type RPM struct {
	buckets sync.Map // map[string]*rpmBucket
}

type rpmBucket struct {
	mu     sync.Mutex
	stamps []time.Time // oldest first
}

// Allow records an attempt for key against limit. Returns (true, 0) when the
// request fits in the last-Window window; (false, retryAfterSec) when it
// would exceed the cap. limit <= 0 disables the check (always allows).
//
// retryAfterSec is the whole seconds until the oldest in-window stamp ages
// out (minimum 1).
func (l *RPM) Allow(key string, limit int) (allowed bool, retryAfterSec int) {
	if limit <= 0 {
		return true, 0
	}
	v, _ := l.buckets.LoadOrStore(key, &rpmBucket{})
	b := v.(*rpmBucket)

	now := time.Now()
	cutoff := now.Add(-Window)

	b.mu.Lock()
	defer b.mu.Unlock()

	drop := 0
	for drop < len(b.stamps) && b.stamps[drop].Before(cutoff) {
		drop++
	}
	if drop > 0 {
		b.stamps = b.stamps[drop:]
	}

	if len(b.stamps) >= limit {
		wait := b.stamps[0].Add(Window).Sub(now)
		sec := int(wait / time.Second)
		if wait%time.Second > 0 {
			sec++
		}
		if sec < 1 {
			sec = 1
		}
		return false, sec
	}
	b.stamps = append(b.stamps, now)
	return true, 0
}
