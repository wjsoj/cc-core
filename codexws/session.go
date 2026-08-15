package codexws

import (
	"sync"
	"time"

	"github.com/wjsoj/cc-core/mimicry"
)

// SessionRegistry mints and remembers the upstream session id for a logical
// downstream conversation.
//
// # Why this is stateful
//
// The session id is not decoration. It is the handshake's `session-id`, the
// `thread-id`, the `x-codex-window-id` prefix, and — the expensive part —
// the frame's `prompt_cache_key`. In the captured turn, a stable cache key
// bought 22272 of 22735 input tokens from the upstream prompt cache. Mint a
// fresh id per WebSocket connection and every reconnect pays list price for a
// conversation the upstream already has cached.
//
// mimicry.CodexSessionUUIDFor is deterministic given (anchor, startedAt), so
// the only thing needed for stickiness is a stable startedAt. Two stateless
// ways to get one were considered and rejected:
//
//   - Deriving the timestamp from the anchor. A UUIDv7's leading 48 bits are a
//     real Unix millisecond value; a hash-derived one lands in an arbitrary
//     year, which no genuine client would ever produce.
//   - Truncating time.Now() to a coarse bucket. This is worse than it looks:
//     every session the proxy serves would rotate its id at the same instant,
//     across all accounts at once. That synchronised rotation is itself a
//     cross-account correlation signal — the opposite of what we want.
//
// So the registry records when each conversation was actually first seen,
// which is what a genuine client's session start is.
//
// # Anchoring
//
// The anchor must identify one logical conversation and must NOT be a value a
// downstream client can choose freely across tenants — the id it produces is
// the upstream prompt-cache namespace, so a caller able to steer the anchor
// could aim at another tenant's cached prefix. Compose it from the credential
// and the downstream caller, e.g. accountKey + "|" + clientToken + "|" + slot.
type SessionRegistry struct {
	ttl time.Duration
	// now is injected for tests; nil means time.Now.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*sessionEntry
	// nextSweep bounds how often an insert walks the map.
	nextSweep time.Time
}

type sessionEntry struct {
	id        string
	startedAt time.Time
	lastSeen  time.Time
}

// DefaultSessionTTL is how long an idle conversation keeps its session id.
//
// Comfortably longer than a working session's quiet gaps and shorter than the
// 24h prompt_cache_retention the captures report, so an entry never outlives
// the cache it exists to hit.
const DefaultSessionTTL = 6 * time.Hour

// sweepInterval bounds the cost of expiry. Entries are small and a proxy has
// few concurrent conversations, so a periodic full walk is cheaper than
// per-entry timers.
const sweepInterval = 10 * time.Minute

// NewSessionRegistry returns a registry with the given idle TTL; ttl <= 0 uses
// DefaultSessionTTL.
func NewSessionRegistry(ttl time.Duration) *SessionRegistry {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &SessionRegistry{ttl: ttl, entries: map[string]*sessionEntry{}}
}

func (r *SessionRegistry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// SessionID returns the stable upstream session id for anchor, minting one on
// first sight and refreshing its idle timer on every call.
//
// A nil registry mints a fresh id each call rather than panicking: losing
// stickiness costs cache hits, which is a far better failure than dropping the
// turn.
func (r *SessionRegistry) SessionID(anchor string) string {
	if r == nil {
		return mimicry.NewCodexSessionUUID()
	}
	now := r.clock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[anchor]; ok && now.Sub(e.lastSeen) <= r.ttl {
		e.lastSeen = now
		return e.id
	}
	// Either brand new, or idle past the TTL — in which case it is a new
	// conversation as far as upstream is concerned, and re-deriving from the
	// same anchor with a fresh start time is exactly right.
	e := &sessionEntry{
		id:        mimicry.CodexSessionUUIDFor(anchor, now),
		startedAt: now,
		lastSeen:  now,
	}
	r.entries[anchor] = e
	r.sweepLocked(now)
	return e.id
}

// Identity is SessionID plus the rest of the per-connection identity, so a
// caller cannot accidentally hand the handshake and the frame rewriter
// different values — the mismatch they would produce is the exact tell both
// exist to remove.
func (r *SessionRegistry) Identity(accountKey, anchor string) mimicry.CodexFrameIdentity {
	return mimicry.CodexFrameIdentity{
		AccountKey: accountKey,
		SessionID:  r.SessionID(anchor),
	}
}

// Forget drops an anchor, so the next call mints a new session.
func (r *SessionRegistry) Forget(anchor string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.entries, anchor)
	r.mu.Unlock()
}

// Len reports how many conversations are currently tracked.
func (r *SessionRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func (r *SessionRegistry) sweepLocked(now time.Time) {
	if now.Before(r.nextSweep) {
		return
	}
	r.nextSweep = now.Add(sweepInterval)
	for k, e := range r.entries {
		if now.Sub(e.lastSeen) > r.ttl {
			delete(r.entries, k)
		}
	}
}
