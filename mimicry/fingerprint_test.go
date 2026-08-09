package mimicry

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Everything that names a version has to name the same one. A UA claiming
// 2.1.224 over a body whose billing block says 2.1.220 is the exact drift the
// package doc warns triggers Anthropic's third-party detection, and nothing
// else in the tree catches it — the Codex side has TestCodexVersionConsistency,
// the Claude side had none.
func TestClaudeVersionConsistency(t *testing.T) {
	if !strings.Contains(ClaudeCLIUserAgent, CLICurrentVersion) {
		t.Errorf("ClaudeCLIUserAgent %q does not carry CLICurrentVersion %q", ClaudeCLIUserAgent, CLICurrentVersion)
	}
	if want := "claude-cli/" + CLICurrentVersion + " (external, cli)"; ClaudeCLIUserAgent != want {
		t.Errorf("ClaudeCLIUserAgent = %q, want %q", ClaudeCLIUserAgent, want)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(CLICurrentVersion) {
		t.Errorf("CLICurrentVersion %q is not an x.y.z version", CLICurrentVersion)
	}

	// The billing block embeds the same version, followed by the 3-hex
	// per-request fingerprint suffix.
	billing := buildExternalBillingBlock([]byte(`{"messages":[{"role":"user","content":"hi"}]}`), CLICurrentVersion)
	var block struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(billing, &block); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block.Text, "cc_version="+CLICurrentVersion+".") {
		t.Errorf("billing block %q does not pin cc_version to %q", block.Text, CLICurrentVersion)
	}
}

// ClaudeStainlessOS deliberately does not track the capture: the proxy runs on
// Linux and the OS it advertises has to agree with auth.HostProfile and the
// sidecar telemetry. fingerprint.go says "do not fix this to match crack/" —
// this is the test that makes that instruction enforceable.
func TestStainlessOSStaysLinux(t *testing.T) {
	if ClaudeStainlessOS != "Linux" {
		t.Errorf("ClaudeStainlessOS = %q; it must stay Linux to agree with the host profile and sidecar telemetry", ClaudeStainlessOS)
	}
}

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewRequestUUIDShapeAndFreshness(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		got := NewRequestUUID()
		if !uuidV4Pattern.MatchString(got) {
			t.Fatalf("NewRequestUUID() = %q, not a v4 UUID", got)
		}
		if seen[got] {
			t.Fatalf("NewRequestUUID() repeated %q; a constant request id is louder than none", got)
		}
		seen[got] = true
	}
}

// Real CC sends x-client-request-id on every first-party request and the
// captured custom-base-url session sends it on none (crack/thirdparty/SPEC.md
// §1). Both halves matter: generating it is what closes the gap, and gating it
// on the first-party base is what keeps strict gateways from 4xx-ing us.
func TestClientRequestIDGeneratedOnlyForAnthropicBase(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}

	first := newReq(t, "https://api.anthropic.com/v1/messages")
	ApplyClaudeCodeHeaders(first, "sk-test", KindOAuth, true, true, id, nil)
	got := first.Header.Get("x-client-request-id")
	if !uuidV4Pattern.MatchString(got) {
		t.Errorf("first-party request id = %q, want a v4 UUID", got)
	}

	second := newReq(t, "https://api.anthropic.com/v1/messages")
	ApplyClaudeCodeHeaders(second, "sk-test", KindOAuth, true, true, id, nil)
	if other := second.Header.Get("x-client-request-id"); other == got {
		t.Errorf("request id %q reused across requests; real CC mints a fresh one each time", got)
	}

	third := newReq(t, "https://gateway.example.com/v1/messages")
	ApplyClaudeCodeHeaders(third, "sk-test", KindAPIKey, true, false, id, nil)
	if leaked := third.Header.Get("x-client-request-id"); leaked != "" {
		t.Errorf("third-party upstream got x-client-request-id %q", leaked)
	}
}

// A caller that already supplied one keeps it: the prepared generic path
// overrides deliberately (request_policy.go), the plain header layer does not.
func TestClientRequestIDNotClobberedWhenSupplied(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}
	req := newReq(t, "https://api.anthropic.com/v1/messages")
	req.Header.Set("x-client-request-id", "caller-supplied")
	ApplyClaudeCodeHeaders(req, "sk-test", KindOAuth, true, true, id, nil)
	if got := req.Header.Get("x-client-request-id"); got != "caller-supplied" {
		t.Errorf("caller value replaced with %q", got)
	}
}

// count_tokens carries no X-Stainless-Timeout on any path. The pinned-profile
// pass runs after the header layer and used to re-add it unconditionally,
// undoing the omission it had just made.
func TestForcePinnedProfileRespectsCountTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{"main keeps the pinned timeout", "https://api.anthropic.com/v1/messages", ClaudeStainlessTimeout},
		{"count_tokens has none", "https://api.anthropic.com/v1/messages/count_tokens", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq(t, tc.url)
			req.Header.Set("X-Stainless-Timeout", "3000")
			forcePinnedClaudeCodeProfile(req)
			if got := req.Header.Get("X-Stainless-Timeout"); got != tc.want {
				t.Errorf("X-Stainless-Timeout = %q, want %q", got, tc.want)
			}
			if got := req.Header.Get("User-Agent"); got != ClaudeCLIUserAgent {
				t.Errorf("User-Agent = %q, want the pinned UA", got)
			}
		})
	}
}

// A downstream client on a newer Claude Code must not keep its own UA while the
// body is rewritten to our pinned cc_version — that pairing is the drift the
// package doc calls out. The pinned-profile pass is what prevents it.
func TestNewerClientUserAgentIsPinnedBack(t *testing.T) {
	req := newReq(t, "https://api.anthropic.com/v1/messages")
	req.Header.Set("User-Agent", "claude-cli/2.1.226 (external, cli)")
	forcePinnedClaudeCodeProfile(req)
	if got := req.Header.Get("User-Agent"); got != ClaudeCLIUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, ClaudeCLIUserAgent)
	}
}

func TestAddMessageCacheBreakpoints(t *testing.T) {
	lastContent := func(t *testing.T, body []byte) []map[string]json.RawMessage {
		t.Helper()
		var obj struct {
			Messages []struct {
				Content []map[string]json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &obj); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(obj.Messages) == 0 {
			t.Fatal("no messages")
		}
		return obj.Messages[len(obj.Messages)-1].Content
	}

	t.Run("string content becomes a cached text block", func(t *testing.T) {
		out := addMessageCacheBreakpoints([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
		blocks := lastContent(t, out)
		if len(blocks) != 1 {
			t.Fatalf("got %d blocks, want 1", len(blocks))
		}
		if got := string(blocks[0]["cache_control"]); got != `{"type":"ephemeral","ttl":"1h"}` {
			t.Errorf("cache_control = %s", got)
		}
	})

	t.Run("breakpoint lands on the last block only", func(t *testing.T) {
		out := addMessageCacheBreakpoints([]byte(
			`{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`))
		blocks := lastContent(t, out)
		if _, ok := blocks[0]["cache_control"]; ok {
			t.Error("first block gained a breakpoint")
		}
		if got := string(blocks[1]["cache_control"]); got != `{"type":"ephemeral","ttl":"1h"}` {
			t.Errorf("last block cache_control = %s", got)
		}
	})

	t.Run("only the last message is touched", func(t *testing.T) {
		out := addMessageCacheBreakpoints([]byte(
			`{"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"}]}`))
		var obj struct {
			Messages []struct {
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatal(err)
		}
		if string(obj.Messages[0].Content) != `"a"` {
			t.Errorf("earlier message was rewritten: %s", obj.Messages[0].Content)
		}
	})

	t.Run("an existing client ttl is respected", func(t *testing.T) {
		out := addMessageCacheBreakpoints([]byte(
			`{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral","ttl":"5m"}}]}]}`))
		if got := string(lastContent(t, out)[0]["cache_control"]); got != `{"type":"ephemeral","ttl":"5m"}` {
			t.Errorf("client ttl overwritten: %s", got)
		}
	})

	t.Run("a bare client cache_control is upgraded in place", func(t *testing.T) {
		out := addMessageCacheBreakpoints([]byte(
			`{"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}]}]}`))
		if got := string(lastContent(t, out)[0]["cache_control"]); got != `{"type":"ephemeral","ttl":"1h"}` {
			t.Errorf("cache_control = %s", got)
		}
	})

	t.Run("malformed input is returned unchanged", func(t *testing.T) {
		for _, in := range []string{`not json`, `{}`, `{"messages":[]}`, `{"messages":"nope"}`, `{"messages":[{"role":"user"}]}`} {
			if got := string(addMessageCacheBreakpoints([]byte(in))); got != in {
				t.Errorf("addMessageCacheBreakpoints(%s) = %s, want it unchanged", in, got)
			}
		}
	})
}
