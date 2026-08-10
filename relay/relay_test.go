package relay

import (
	"net/http"
	"strings"
	"testing"
)

func TestApplyAndRead(t *testing.T) {
	h := http.Header{}
	Apply(h, "cpa-claude/0.19.85", "sk-downstream-abc", "sess-123")

	id, ok := Read(h)
	if !ok {
		t.Fatal("Read reported no identity after Apply")
	}
	if id.Peer != "cpa-claude/0.19.85" || id.Session != "sess-123" {
		t.Fatalf("round trip lost fields: %+v", id)
	}
	// The token must never appear on the wire.
	if strings.Contains(id.Client, "sk-downstream") {
		t.Fatalf("client id leaks the token: %q", id.Client)
	}
	if id.Client != ClientID("sk-downstream-abc") {
		t.Fatalf("client id = %q, want the hash of the token", id.Client)
	}
}

// The whole point is that two downstream users land on different scheduler
// slots, and that one user's separate CLI windows do too.
func TestSlotIDSeparatesUsersAndSessions(t *testing.T) {
	a1 := Identity{Client: ClientID("user-a"), Session: "s1"}
	a2 := Identity{Client: ClientID("user-a"), Session: "s2"}
	b1 := Identity{Client: ClientID("user-b"), Session: "s1"}

	if a1.SlotID() == a2.SlotID() {
		t.Error("one user's two sessions share a slot — they would pin to one credential")
	}
	if a1.SlotID() == b1.SlotID() {
		t.Error("two users with the same session id share a slot")
	}
	// A sessionless caller still gets its own slot, not a shared blank one.
	c := Identity{Client: ClientID("user-c")}
	d := Identity{Client: ClientID("user-d")}
	if c.SlotID() == d.SlotID() || c.SlotID() == "" {
		t.Errorf("sessionless callers collapsed: %q vs %q", c.SlotID(), d.SlotID())
	}
}

// Apply must overwrite anything the sender's own ingress carried: a direct
// caller that stamps these headers itself must not have them survive a hop.
func TestApplyOverwritesInboundValues(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderClient, "attacker-supplied")
	h.Set(HeaderSession, "attacker-session")
	h.Set(HeaderPeer, "totally-legit/9")

	Apply(h, "cpa-claude/0.19.85", "sk-real", "real-session")

	id, _ := Read(h)
	if id.Client == "attacker-supplied" || id.Session == "attacker-session" {
		t.Fatalf("inbound values survived Apply: %+v", id)
	}
}

// With no downstream token there is nothing to identify, and a blank identity
// shared by every anonymous caller would be worse than none — they would all
// pin to one credential together.
func TestApplyWithoutTokenStampsNothing(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderClient, "stale")
	Apply(h, "cpa-claude/0.19.85", "   ", "sess")
	if _, ok := Read(h); ok {
		t.Fatalf("stamped an identity for an unidentified caller: %v", h)
	}
}

func TestStrip(t *testing.T) {
	h := http.Header{}
	Apply(h, "peer/1", "tok", "sess")
	Strip(h)
	if _, ok := Read(h); ok {
		t.Fatal("Read still found an identity after Strip")
	}
	for _, k := range []string{HeaderPeer, HeaderClient, HeaderSession} {
		if h.Get(k) != "" {
			t.Errorf("%s survived Strip", k)
		}
	}
}

// A recovered value becomes a map key in the receiver's scheduler, so junk must
// be dropped whole rather than partially accepted.
func TestReadRejectsUnusableValues(t *testing.T) {
	for _, bad := range []string{
		"has space",
		"emoji-🙂",
		"new\nline",
		strings.Repeat("x", maxValue+1),
	} {
		h := http.Header{}
		h.Set(HeaderClient, bad)
		if _, ok := Read(h); ok {
			t.Errorf("Read accepted %q as a client id", bad)
		}
	}

	// A bad session on a good client degrades to "no session", not to a
	// rejected identity: the user is still worth telling apart.
	h := http.Header{}
	h.Set(HeaderClient, ClientID("tok"))
	h.Set(HeaderSession, "bad value")
	id, ok := Read(h)
	if !ok || id.Session != "" {
		t.Fatalf("bad session should degrade to empty, got %+v (ok=%t)", id, ok)
	}
}

func TestClientIDIsStableAndDistinct(t *testing.T) {
	// Stability across calls is what makes the id usable as a sticky key.
	first, second := ClientID("tok-a"), ClientID("tok-"+"a")
	if first != second {
		t.Errorf("ClientID is not stable: %q vs %q", first, second)
	}
	if ClientID("tok-a") == ClientID("tok-b") {
		t.Error("ClientID collides across tokens")
	}
	if ClientID("") != "" {
		t.Error("ClientID of an empty token should be empty")
	}
}
