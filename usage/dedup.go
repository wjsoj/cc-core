package usage

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// Request-level billing idempotency.
//
// A single downstream request can reach the billing path more than once. The
// two paths that actually happen in production:
//
//   - retryRoundTripper replays a request on the SAME credential after a
//     transient wire error (auth/retry.go). If the first attempt already
//     reached the upstream and produced usage, both attempts can report.
//   - credential failover replays it on a DIFFERENT credential. The upstream
//     may have billed the first attempt before it failed, so the user's
//     request is charged twice.
//
// Neither is hypothetical: sub2api documents the same failure mode in its
// config ("A timed-out request may already have incurred upstream usage;
// account failover can therefore duplicate upstream billing"), and solves it
// with a dedup table keyed on (request_id, api_key_id) plus a content
// fingerprint. Deduper is that mechanism without the SQL.
//
// Scope matters. The key is (requestID, scope), not requestID alone, because
// one request legitimately writes to several independent ledgers — the
// per-credential ledger and the per-client-token ledger both record it. Give
// each ledger its own scope and they stop colliding, exactly as sub2api's
// api_key_id component does.
//
// Deliberately in-memory and bounded, not persisted: the duplicates this
// guards against arrive within seconds of each other, while persisting every
// request id would grow the state file without bound. A restart drops the
// window, which is correct — requests in flight across a restart were never
// completed, so there is nothing to double-bill.

// ErrRequestConflict is returned when a request id is reused with a different
// content fingerprint. That is not a retry — it means the caller minted a
// colliding id (or reused one across unrelated requests), so billing either
// entry would be wrong. The FIRST entry stands; the caller should log loudly
// and skip.
var ErrRequestConflict = errors.New("usage: request id reused with different content")

const (
	// DefaultDedupTTL is how long a request id stays claimed. Retries and
	// failovers land far inside this window; anything later is a new request.
	DefaultDedupTTL = 10 * time.Minute

	// DefaultDedupMaxEntries caps memory. At ~64 bytes per entry this is a
	// couple of MB — far above the in-flight count of any real deployment,
	// so eviction is a backstop, not a routine event.
	DefaultDedupMaxEntries = 32768
)

type dedupEntry struct {
	key         string
	fingerprint uint64
	expiresAt   time.Time
}

// Deduper admits a (requestID, scope) pair exactly once within a TTL window.
// The zero value is not usable; call NewDeduper. Safe for concurrent use.
type Deduper struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]*dedupEntry
	// order is a FIFO of live keys, so expiry and overflow eviction are both
	// amortised O(1) instead of a full scan.
	order []*dedupEntry
	now   func() time.Time
}

// NewDeduper returns a Deduper. Non-positive ttl or max fall back to the
// package defaults.
func NewDeduper(ttl time.Duration, max int) *Deduper {
	if ttl <= 0 {
		ttl = DefaultDedupTTL
	}
	if max <= 0 {
		max = DefaultDedupMaxEntries
	}
	return &Deduper{
		ttl:     ttl,
		max:     max,
		entries: make(map[string]*dedupEntry),
		now:     time.Now,
	}
}

// Admit reports whether this (requestID, scope) pair should be billed.
//
//	(true,  nil)               first sighting — bill it
//	(false, nil)               exact duplicate — already billed, skip silently
//	(false, ErrRequestConflict) id reused with different content — skip and alert
//
// An empty requestID is always admitted: with no id there is nothing to
// deduplicate, and refusing to bill would silently lose revenue. Callers that
// can supply an id should — this is fail-open by design.
func (d *Deduper) Admit(requestID, scope string, fingerprint uint64) (bool, error) {
	if requestID == "" {
		return true, nil
	}
	key := requestID + "\x00" + scope

	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	// Sweep first so an id whose TTL lapsed is treated as a new request rather
	// than a duplicate.
	d.evictLocked(now)

	if prev, ok := d.entries[key]; ok {
		if prev.fingerprint != fingerprint {
			return false, fmt.Errorf("%w: request %q scope %q", ErrRequestConflict, requestID, scope)
		}
		return false, nil
	}

	e := &dedupEntry{key: key, fingerprint: fingerprint, expiresAt: now.Add(d.ttl)}
	d.entries[key] = e
	d.order = append(d.order, e)
	// Trim again AFTER inserting: sweeping only on entry would leave the map
	// permanently one over max, since every call adds one entry after its own
	// eviction pass.
	d.evictLocked(now)
	return true, nil
}

// evictLocked drops expired entries from the front of the FIFO, then trims
// oldest-first if the map is still over capacity.
func (d *Deduper) evictLocked(now time.Time) {
	i := 0
	for ; i < len(d.order); i++ {
		e := d.order[i]
		if cur, ok := d.entries[e.key]; ok && cur == e && now.Before(e.expiresAt) {
			break
		}
		if cur, ok := d.entries[e.key]; ok && cur == e {
			delete(d.entries, e.key)
		}
	}
	// Still over capacity → drop oldest live entries until we fit.
	for len(d.entries) > d.max && i < len(d.order) {
		e := d.order[i]
		if cur, ok := d.entries[e.key]; ok && cur == e {
			delete(d.entries, e.key)
		}
		i++
	}
	if i > 0 {
		d.order = append(d.order[:0], d.order[i:]...)
	}
}

// Len reports how many request ids are currently claimed. Test/metrics helper.
func (d *Deduper) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Fingerprint derives the content hash Admit compares. It covers the billable
// quantities, so a genuine retry of the same request hashes identically while
// a different request that happens to reuse the id does not.
//
// extra lets a caller bind additional identity — model, credential id,
// provider — anything whose change means "this is not the same request".
// sub2api hashes the same shape (user/account/apikey/model/tokens/costs).
func Fingerprint(c Counts, costUSD float64, extra ...string) uint64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%d|%d|%d|%d|%d|%.10f",
		c.InputTokens, c.OutputTokens, c.CacheCreateTokens, c.CacheReadTokens,
		c.Requests, costUSD)
	for _, s := range extra {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(s))
	}
	return h.Sum64()
}

// ── Store integration ────────────────────────────────────────────────────

// Dedup scopes used by the Store's own ledgers. They keep the per-credential
// and per-client writes of one request from cancelling each other out.
const (
	dedupScopeAuth   = "auth"
	dedupScopeClient = "client"
)

// EnableDedup installs a Deduper so RecordOnce / RecordClientOnce can enforce
// idempotency. Passing nil disables it — RecordOnce then behaves exactly like
// Record. Call once during setup, before the store is shared across goroutines.
func (s *Store) EnableDedup(d *Deduper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dedup = d
}

// RecordOnce is Record guarded by request-level idempotency: a replayed
// requestID (retry or credential failover) is counted once. It reports whether
// the counts were applied, and returns ErrRequestConflict if the id was reused
// with different content — in which case nothing is recorded.
//
// With no Deduper installed, or an empty requestID, it degrades to Record and
// reports true. Billing must never be lost just because dedup is unavailable.
func (s *Store) RecordOnce(requestID, authID, label string, c Counts) (bool, error) {
	s.mu.Lock()
	d := s.dedup
	s.mu.Unlock()
	if d == nil {
		s.Record(authID, label, c)
		return true, nil
	}
	ok, err := d.Admit(requestID, dedupScopeAuth, Fingerprint(c, 0, authID))
	if err != nil || !ok {
		return false, err
	}
	s.Record(authID, label, c)
	return true, nil
}

// RecordClientOnce is RecordClient with the same idempotency guarantee. It
// uses a separate dedup scope from RecordOnce, so one request may legitimately
// write both ledgers under the same requestID.
func (s *Store) RecordClientOnce(requestID, token, label string, counts Counts, costUSD float64) (bool, error) {
	s.mu.Lock()
	d := s.dedup
	s.mu.Unlock()
	if d == nil {
		s.RecordClient(token, label, counts, costUSD)
		return true, nil
	}
	ok, err := d.Admit(requestID, dedupScopeClient, Fingerprint(counts, costUSD, token))
	if err != nil || !ok {
		return false, err
	}
	s.RecordClient(token, label, counts, costUSD)
	return true, nil
}
