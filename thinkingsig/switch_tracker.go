// Package thinkingsig handles mid-conversation upstream credential
// rotation safely.
//
// Anthropic's `thinking` content blocks ship with a cryptographic
// `signature` field that is bound to the issuing account. When a
// multi-turn conversation rotates from credential A to credential B,
// any past assistant turns echoed in `messages[]` still carry A's
// signatures; B's verifier rejects with `400 signature in thinking`.
//
// SwitchTracker observes which credential last handled each
// `(clientToken, conversation)` pair, and SanitizeForSwitch removes
// the signed blocks before the request crosses the boundary.
package thinkingsig

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// SwitchTracker remembers which upstream credential last handled each
// (clientToken, conversation) pair so we can detect mid-conversation
// account rotation. The signal feeds SanitizeForSwitch: when account
// A's signed thinking blocks are about to be sent to account B,
// B's verifier returns 400.
//
// Conversation identity is the sha256 of the first user message —
// the same anchor any caller-side `SessionIDFor` uses to keep
// multi-turn requests on a stable session id. New topics rotate this
// hash, which correctly forces a "switch" decision on a fresh
// credential too (no prior thinking blocks to worry about there,
// but the bookkeeping stays consistent).
//
// Why per (clientToken, convKey) and not per clientToken alone —
// one downstream client token may run several concurrent
// conversations; a switch on one shouldn't be silently inherited by
// another that's still stuck to the old account.
type SwitchTracker struct {
	mu      sync.Mutex
	entries map[string]switchEntry
	// Test hook — leave nil in production.
	now func() time.Time
}

type switchEntry struct {
	authID   string
	lastSeen time.Time
}

// SwitchTrackerIdleTTL drops conversations untouched longer than this.
// 2 hours covers normal idle gaps in a session without leaking
// memory for one-shot clients that never come back.
const SwitchTrackerIdleTTL = 2 * time.Hour

// NewSwitchTracker spins up a tracker with a background GC goroutine.
func NewSwitchTracker() *SwitchTracker {
	t := &SwitchTracker{entries: make(map[string]switchEntry)}
	go t.gcLoop()
	return t
}

// Check records that this conversation is now on currentAuthID and
// returns whether the prior observation (if any) used a different
// auth. First-touch returns false (no prior thinking blocks
// possible).
//
// Empty inputs are treated as "no signal" — return false, do nothing.
func (t *SwitchTracker) Check(clientToken string, body []byte, currentAuthID string) bool {
	if clientToken == "" || currentAuthID == "" {
		return false
	}
	convKey := conversationKey(body)
	if convKey == "" {
		return false
	}
	key := clientToken + "|" + convKey

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.timeNow()
	prev, exists := t.entries[key]
	t.entries[key] = switchEntry{authID: currentAuthID, lastSeen: now}
	return exists && prev.authID != currentAuthID
}

func (t *SwitchTracker) timeNow() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *SwitchTracker) gcLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-SwitchTrackerIdleTTL)
		t.mu.Lock()
		for k, v := range t.entries {
			if v.lastSeen.Before(cutoff) {
				delete(t.entries, k)
			}
		}
		t.mu.Unlock()
	}
}

// conversationKey hashes the first user message so multi-turn
// requests of the same conversation share one key.
func conversationKey(body []byte) string {
	first := firstUserText(body)
	if first == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(first))
	return hex.EncodeToString(sum[:])[:16]
}
