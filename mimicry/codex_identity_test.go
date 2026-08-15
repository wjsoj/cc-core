package mimicry

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Both captures show every Codex session/thread/window id as a UUIDv7. The
// version nibble sits at string index 14 and is plainly visible on the wire, so
// minting a v4 there is a tell that no amount of header work hides.
func TestNewCodexSessionUUIDIsV7(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id := NewCodexSessionUUID()
		if len(id) != 36 {
			t.Fatalf("uuid %q has length %d, want 36", id, len(id))
		}
		if id[14] != '7' {
			t.Errorf("uuid %q: version nibble = %c, want 7", id, id[14])
		}
		// RFC 4122 variant: the first hex digit of the 4th group is 8, 9, a or b.
		switch id[19] {
		case '8', '9', 'a', 'b':
		default:
			t.Errorf("uuid %q: variant nibble = %c, want one of 8/9/a/b", id, id[19])
		}
		if seen[id] {
			t.Errorf("uuid %q repeated across calls", id)
		}
		seen[id] = true
	}
}

// A v7's leading 48 bits are a Unix-millisecond timestamp. If ours did not
// track real time, the ids would sort into an implausible era.
func TestCodexSessionUUIDEncodesTimestamp(t *testing.T) {
	at := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	id := CodexSessionUUIDFor("anchor", at)
	raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", "")[:12])
	if err != nil {
		t.Fatalf("decode timestamp prefix: %v", err)
	}
	var ms int64
	for _, b := range raw {
		ms = ms<<8 | int64(b)
	}
	if ms != at.UnixMilli() {
		t.Errorf("embedded timestamp = %d, want %d", ms, at.UnixMilli())
	}
}

// Session stickiness: same anchor + same start instant must reproduce the id,
// or a multi-turn conversation would present as N different sessions upstream.
func TestCodexSessionUUIDForIsStable(t *testing.T) {
	at := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	a := CodexSessionUUIDFor("account|conversation", at)
	b := CodexSessionUUIDFor("account|conversation", at)
	if a != b {
		t.Errorf("same anchor+time must yield the same id: %q vs %q", a, b)
	}
	if c := CodexSessionUUIDFor("account|other", at); c == a {
		t.Error("different anchors must yield different ids")
	}
	if a[14] != '7' {
		t.Errorf("derived id %q is not a v7", a)
	}
}

// One upstream account is one installation. Deriving per client token would
// present a single ChatGPT account as many machines.
func TestCodexInstallationIDForIsStablePerAccount(t *testing.T) {
	a := CodexInstallationIDFor("acct-1")
	if a != CodexInstallationIDFor("acct-1") {
		t.Error("installation id must be stable for an account")
	}
	if a == CodexInstallationIDFor("acct-2") {
		t.Error("different accounts must get different installation ids")
	}
	if len(a) != 36 || a[14] != '4' {
		t.Errorf("installation id %q should be a v4-shaped UUID like the genuine client's", a)
	}
}

// Key ORDER in x-codex-turn-metadata is part of the captured byte shape; a map
// round-trip would sort the keys and silently change it.
func TestCodexTurnMetadataEncodeOrder(t *testing.T) {
	md := NewCodexHandshakeMetadata("inst", "sess", "")
	got := md.Encode()

	want := `{"installation_id":"inst","session_id":"sess","thread_id":"sess",` +
		`"turn_id":"","window_id":"sess:0","request_kind":"prewarm",` +
		`"thread_source":"user","sandbox":"seccomp"}`
	if got != want {
		t.Errorf("Encode() =\n  %s\nwant\n  %s", got, want)
	}
}

// The genuine handshake sends "turn_id":"" — an empty value, not an absent key.
func TestCodexTurnMetadataKeepsEmptyTurnID(t *testing.T) {
	if !strings.Contains(NewCodexHandshakeMetadata("i", "s", "").Encode(), `"turn_id":""`) {
		t.Error(`handshake metadata must carry "turn_id":"" explicitly`)
	}
}

// A hostile session id must not be able to break out of the JSON string.
func TestCodexTurnMetadataEscapes(t *testing.T) {
	md := NewCodexHandshakeMetadata("inst", `evil","sandbox":"none`, "")
	got := md.Encode()
	if strings.Count(got, `"sandbox"`) != 1 {
		t.Errorf("injection through session id changed the object: %s", got)
	}
	if !strings.Contains(got, `"sandbox":"seccomp"`) {
		t.Errorf("sandbox must stay seccomp, got %s", got)
	}
}

func TestCodexWindowID(t *testing.T) {
	if got := CodexWindowID("sess"); got != "sess:0" {
		t.Errorf("CodexWindowID = %q, want sess:0", got)
	}
	if got := CodexWindowID(""); got != "" {
		t.Errorf("empty session must yield an empty window id, got %q", got)
	}
}

// The Desktop profile is the shipped default; flipping it changes what both
// forks advertise upstream, so it gets an explicit assertion.
func TestDefaultCodexProfileIsDesktop(t *testing.T) {
	if DefaultCodexProfile().Originator != CodexDesktopOriginator {
		t.Errorf("default profile originator = %q, want %q",
			DefaultCodexProfile().Originator, CodexDesktopOriginator)
	}
}
