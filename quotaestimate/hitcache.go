package quotaestimate

import (
	"sync"
	"time"

	"github.com/wjsoj/cc-core/auth"
)

// settleAfter is how long after a rejection the ledger is trusted to hold
// every row of the measured span. Rows are written when a request ends, and
// a request that was in flight when the 429 landed finishes — and logs —
// afterwards, timestamped before the hit. Until it settles, the hit-based
// estimate is recomputed on every read; after, it is immutable and cached.
const settleAfter = 10 * time.Minute

// HitCache serves the offline, rejection-anchored estimate for credential
// list rows, where one ledger query per credential per poll would be the
// wrong price for a number that stops changing ten minutes after the hit.
// Keyed by (credential, hit time): a new rejection is a new key, and the old
// entry is dropped. The zero value is ready to use.
type HitCache struct {
	mu      sync.Mutex
	entries map[string]hitEntry
}

type hitEntry struct {
	hitAt time.Time
	est   Estimate
}

// Weekly returns the seven-day estimate reconstructed from the credential's
// last rejection, or nil when the last rejection was not a weekly one or
// there is none. spend is only called on a cache miss.
func (c *HitCache) Weekly(authID string, hit auth.QuotaHit, spend SpendFunc, now time.Time) *Estimate {
	w, ok := FromHit(hit)
	if !ok || w.Key != WindowSevenDay {
		return nil
	}
	c.mu.Lock()
	if e, found := c.entries[authID]; found && e.hitAt.Equal(hit.At) {
		c.mu.Unlock()
		est := e.est
		return &est
	}
	c.mu.Unlock()

	est := Project(w, hit, spend, now)
	if est.SpendError == "" && now.Sub(hit.At) >= settleAfter {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = make(map[string]hitEntry)
		}
		c.entries[authID] = hitEntry{hitAt: hit.At, est: est}
		c.mu.Unlock()
	}
	return &est
}

// Forget drops a credential's cached entry (on credential removal).
func (c *HitCache) Forget(authID string) {
	c.mu.Lock()
	delete(c.entries, authID)
	c.mu.Unlock()
}
