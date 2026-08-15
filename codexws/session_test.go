package codexws

import (
	"sync"
	"testing"
	"time"
)

func TestSessionRegistryReusesIDForSameAnchor(t *testing.T) {
	r := NewSessionRegistry(time.Hour)
	a := r.SessionID("acct|tok|slot")
	b := r.SessionID("acct|tok|slot")
	if a != b {
		t.Errorf("same anchor must reuse its session: %q vs %q", a, b)
	}
	if c := r.SessionID("acct|tok|other"); c == a {
		t.Error("different anchors must get different sessions")
	}
	// The id is what goes on the wire as session-id; it has to be a v7.
	if len(a) != 36 || a[14] != '7' {
		t.Errorf("session id %q is not a UUIDv7", a)
	}
}

// Reuse is what buys the upstream prompt cache; a reconnect inside the TTL must
// not mint a new id.
func TestSessionRegistryKeepsIDAcrossIdleGapWithinTTL(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	r := NewSessionRegistry(time.Hour)
	r.now = func() time.Time { return now }

	first := r.SessionID("anchor")
	now = now.Add(59 * time.Minute)
	if got := r.SessionID("anchor"); got != first {
		t.Errorf("id rotated inside the TTL: %q → %q", first, got)
	}
	// Each touch refreshes the idle timer, so a busy conversation never rotates.
	now = now.Add(59 * time.Minute)
	if got := r.SessionID("anchor"); got != first {
		t.Errorf("id rotated despite continuous use: %q → %q", first, got)
	}
}

func TestSessionRegistryRotatesAfterIdleTTL(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	r := NewSessionRegistry(time.Hour)
	r.now = func() time.Time { return now }

	first := r.SessionID("anchor")
	now = now.Add(time.Hour + time.Second)
	second := r.SessionID("anchor")
	if second == first {
		t.Error("an anchor idle past the TTL is a new conversation and must get a new id")
	}
	// The new id's embedded timestamp must be the new start, not the old one.
	if second[14] != '7' {
		t.Errorf("rotated id %q is not a v7", second)
	}
}

// The timestamp must track real time: a v7 whose leading bits land in an
// arbitrary year is something no genuine client produces.
func TestSessionRegistryEmbedsRealStartTime(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	r := NewSessionRegistry(time.Hour)
	r.now = func() time.Time { return now }
	id := r.SessionID("anchor")

	var ms int64
	for _, c := range id[0:8] + id[9:13] {
		var v int64
		switch {
		case c >= '0' && c <= '9':
			v = int64(c - '0')
		case c >= 'a' && c <= 'f':
			v = int64(c-'a') + 10
		default:
			t.Fatalf("non-hex in timestamp prefix of %q", id)
		}
		ms = ms<<4 | v
	}
	if ms != now.UnixMilli() {
		t.Errorf("embedded start = %d, want %d", ms, now.UnixMilli())
	}
}

// Two anchors minted in the same millisecond must not collide, and must not
// rotate together — synchronised rotation across accounts would itself be a
// correlation signal.
func TestSessionRegistryDistinctAnchorsDoNotSyncRotate(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	r := NewSessionRegistry(time.Hour)
	r.now = func() time.Time { return now }

	a := r.SessionID("acct-a")
	b := r.SessionID("acct-b")
	if a == b {
		t.Fatal("distinct anchors collided")
	}
	// Keep a alive, let b go idle: only b rotates.
	now = now.Add(30 * time.Minute)
	r.SessionID("acct-a")
	now = now.Add(40 * time.Minute)
	if got := r.SessionID("acct-a"); got != a {
		t.Error("the live anchor must keep its id")
	}
	if got := r.SessionID("acct-b"); got == b {
		t.Error("the idle anchor should have rotated")
	}
}

func TestSessionRegistryForgetAndSweep(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	r := NewSessionRegistry(time.Minute)
	r.now = func() time.Time { return now }

	r.SessionID("a")
	r.SessionID("b")
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}
	r.Forget("a")
	if r.Len() != 1 {
		t.Errorf("Forget did not drop the entry: Len = %d", r.Len())
	}
	// Expired entries must not accumulate.
	now = now.Add(time.Hour)
	r.SessionID("c")
	if r.Len() != 1 {
		t.Errorf("sweep left %d entries, want only the fresh one", r.Len())
	}
}

// A nil registry must degrade to fresh ids, never panic: losing cache hits is a
// far better failure than dropping the turn.
func TestSessionRegistryNilIsUsable(t *testing.T) {
	var r *SessionRegistry
	if id := r.SessionID("anchor"); len(id) != 36 {
		t.Errorf("nil registry returned %q", id)
	}
	if r.Len() != 0 {
		t.Error("nil registry Len should be 0")
	}
	r.Forget("anchor")
}

// Identity is the whole point: the handshake and the frame rewriter must be
// unable to disagree.
func TestSessionRegistryIdentityMatchesSessionID(t *testing.T) {
	r := NewSessionRegistry(time.Hour)
	id := r.Identity("acct-key", "anchor")
	if id.AccountKey != "acct-key" {
		t.Errorf("AccountKey = %q", id.AccountKey)
	}
	if id.SessionID != r.SessionID("anchor") {
		t.Error("Identity and SessionID disagree for one anchor")
	}
	norm, err := id.Normalized()
	if err != nil {
		t.Fatalf("Identity must produce a valid identity: %v", err)
	}
	if norm.ThreadID != norm.SessionID {
		t.Error("a fresh thread collapses thread onto session")
	}
	// And it must survive the handshake builder unchanged.
	h := BuildUpstreamHeadersWithOptions(UpstreamHeaderOptions{
		AccessToken: "tok", AccountID: "acct-uuid", Identity: &id,
	})
	if got := hdr(h, "session-id"); got != norm.SessionID {
		t.Errorf("handshake session-id = %q, want %q", got, norm.SessionID)
	}
	if got := hdr(h, "x-codex-window-id"); got != norm.WindowID() {
		t.Errorf("handshake window-id = %q, want %q", got, norm.WindowID())
	}
}

func TestSessionRegistryConcurrent(t *testing.T) {
	r := NewSessionRegistry(time.Hour)
	var wg sync.WaitGroup
	ids := make([]string, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i] = r.SessionID("shared-anchor")
		}(i)
	}
	wg.Wait()
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("goroutine %d got a different id: %q vs %q", i, id, ids[0])
		}
	}
}
