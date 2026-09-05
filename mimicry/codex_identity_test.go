package mimicry

import (
	"encoding/hex"
	"strconv"
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
		`"agent_name":"` + CodexDefaultAgentName + `","turn_id":"","window_id":"sess:0",` +
		`"window_number":0,"context_window_id":"","request_kind":"prewarm",` +
		`"thread_source":"user","sandbox":"seccomp","sandbox_mode":"workspace-write",` +
		`"auto_review_enabled":true,"node_repl_auto_review_required":false,` +
		`"node_repl_disabled":false}`
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
		t.Errorf("empty thread must yield an empty window id, got %q", got)
	}
}

// The window id follows the THREAD, not the session. They are equal on a fresh
// thread — which is why the session-anchored derivation looked correct for two
// captures — and crack/codexv0.153.4/rows/12 is the row that separates them.
func TestCodexHandshakeMetadataAnchorsWindowOnThread(t *testing.T) {
	md := NewCodexHandshakeMetadata("inst", "sess-id", "thread-id")
	if md.WindowID != "thread-id:0" {
		t.Errorf("window id = %q, want thread-id:0 (anchored on the thread)", md.WindowID)
	}
}

// context_window_id is not an independent UUID: every capture shows it sharing
// thread_id's first four groups and differing only in the trailing 12 hex
// digits. An unrelated UUID here is a one-comparison structural mismatch.
func TestCodexContextWindowIDSharesThreadPrefix(t *testing.T) {
	thread := "01a06fa9-a7f8-7811-8a75-3dccb3ea9a71"
	got := CodexContextWindowIDFor(thread)
	if len(got) != len(thread) {
		t.Fatalf("context window id %q is not UUID-shaped", got)
	}
	if got[:24] != thread[:24] {
		t.Errorf("context window id %q does not share the thread's first four groups (%q)", got, thread[:24])
	}
	if got == thread {
		t.Error("context window id must differ from the thread id in its last group")
	}
	if again := CodexContextWindowIDFor(thread); again != got {
		t.Errorf("derivation is not stable: %q then %q", got, again)
	}
	// A non-UUID input has no prefix to share; better empty than malformed.
	if got := CodexContextWindowIDFor("not-a-uuid"); got != "" {
		t.Errorf("non-UUID thread must yield an empty context window id, got %q", got)
	}
}

// The default profile is what both forks advertise upstream without opting in,
// so flipping it gets an explicit assertion. It was Desktop until 2026-09-05;
// gpt-6-astra's minimal_client_version of 0.153.0 put Desktop's 0.147.0 below
// the floor for the current flagship, and no Desktop capture at or above that
// version exists to bump it from. See DefaultCodexProfile's comment.
func TestDefaultCodexProfileIsCLI(t *testing.T) {
	if DefaultCodexProfile().Originator != CodexOriginator {
		t.Errorf("default profile originator = %q, want %q",
			DefaultCodexProfile().Originator, CodexOriginator)
	}
	if DefaultCodexProfile().Version != CodexCLIVersion {
		t.Errorf("default profile version = %q, want %q",
			DefaultCodexProfile().Version, CodexCLIVersion)
	}
}

// The whole point of the profile flip: whatever cc-core presents by default
// must clear the version floor the catalog puts on the current flagship.
func TestDefaultCodexProfileClearsAstraVersionFloor(t *testing.T) {
	const astraFloor = "0.153.0" // minimal_client_version, crack/codexv0.153.4/rows/01
	got := DefaultCodexProfile().Version
	if compareDottedVersions(got, astraFloor) < 0 {
		t.Errorf("default profile version %q is below gpt-6-astra's floor %q; "+
			"the backend will not route astra to it", got, astraFloor)
	}
}

// compareDottedVersions compares two dotted numeric versions, ignoring any
// pre-release suffix on the first segment triple.
func compareDottedVersions(a, b string) int {
	split := func(v string) []int {
		if i := strings.IndexAny(v, "-+"); i >= 0 {
			v = v[:i]
		}
		parts := strings.Split(v, ".")
		out := make([]int, len(parts))
		for i, p := range parts {
			n, _ := strconv.Atoi(p)
			out[i] = n
		}
		return out
	}
	x, y := split(a), split(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var xi, yi int
		if i < len(x) {
			xi = x[i]
		}
		if i < len(y) {
			yi = y[i]
		}
		if xi != yi {
			if xi < yi {
				return -1
			}
			return 1
		}
	}
	return 0
}
