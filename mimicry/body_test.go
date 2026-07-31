package mimicry

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func testID() SimIdentity {
	return SimIdentity{
		AccountKey:  "test-account@example.com",
		AccountUUID: "00000000-0000-0000-0000-000000000000",
		ClientToken: "test-client-token",
	}
}

// TestMimicrySmoke exercises the body rewriter on the shapes /v1/messages
// requests actually take. It doesn't assert byte-equality against a golden
// payload (the cch hash and session UUID change with body content) — it
// asserts the structural invariants real Claude Code 2.1.183 requests carry.
func TestMimicrySmoke(t *testing.T) {
	cases := []struct {
		name              string
		in                string
		expectSystemCount int // 2 = no original system, 3 = single-block original, etc.
	}{
		{
			name:              "string-system",
			in:                `{"model":"claude-sonnet-4-5","system":"You are a helpful assistant.","messages":[{"role":"user","content":"hello"}]}`,
			expectSystemCount: 3,
		},
		{
			name:              "array-system",
			in:                `{"model":"claude-sonnet-4-5","system":[{"type":"text","text":"You are a helpful assistant."}],"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`,
			expectSystemCount: 3,
		},
		{
			name:              "no-system",
			in:                `{"model":"claude-opus-4-5","messages":[{"role":"user","content":"hi"}]}`,
			expectSystemCount: 2,
		},
		{
			name:              "multi-turn",
			in:                `{"model":"claude-sonnet-4-5","system":"sys","messages":[{"role":"user","content":"q1"},{"role":"assistant","content":"a1"},{"role":"user","content":"q2"},{"role":"assistant","content":"a2"},{"role":"user","content":"q3"}]}`,
			expectSystemCount: 3,
		},
		{
			name:              "two-block-system",
			in:                `{"model":"claude-sonnet-4-5","system":[{"type":"text","text":"part one"},{"type":"text","text":"part two"}],"messages":[{"role":"user","content":"hi"}]}`,
			expectSystemCount: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := ApplyClaudeCodeBodyMimicry([]byte(tc.in), "claude-sonnet-4-5", testID())

			// 1. Output must still be valid JSON.
			var parsed map[string]json.RawMessage
			if err := json.Unmarshal(out, &parsed); err != nil {
				t.Fatalf("output not valid JSON: %v\n%s", err, out)
			}

			// 2. system must be the right number of blocks for CC 2.1.183:
			//    [billing, "You are Claude Code...", ...originalBlocks].
			var sys []map[string]any
			if err := json.Unmarshal(parsed["system"], &sys); err != nil {
				t.Fatalf("system not array: %v", err)
			}
			if len(sys) != tc.expectSystemCount {
				t.Fatalf("expected %d system blocks, got %d", tc.expectSystemCount, len(sys))
			}
			billing, _ := sys[0]["text"].(string)
			if !strings.HasPrefix(billing, "x-anthropic-billing-header:") {
				t.Errorf("system[0] missing billing prefix: %q", billing)
			}
			if !strings.Contains(billing, "cc_version="+CLICurrentVersion+".") {
				t.Errorf("system[0] missing cc_version=%s: %q", CLICurrentVersion, billing)
			}
			if strings.Contains(billing, "cch=00000") {
				t.Errorf("system[0] cch placeholder still present: %q", billing)
			}
			if _, hasCC := sys[0]["cache_control"]; hasCC {
				t.Errorf("system[0] (billing) must NOT carry cache_control")
			}

			ccPrompt, _ := sys[1]["text"].(string)
			if !strings.HasPrefix(ccPrompt, "You are Claude Code") {
				t.Errorf("system[1] missing CC prompt: %q", ccPrompt)
			}
			if _, hasCC := sys[1]["cache_control"]; hasCC {
				t.Errorf("system[1] (CC intro) must NOT carry cache_control — real 2.1.183 leaves it bare")
			}

			// 3. When original system was supplied, real CC 2.1.183 puts a
			//    PLAIN ephemeral 1h breakpoint on the LAST system block and
			//    scope:global on the SECOND-TO-LAST (when >=2 original blocks).
			//    Verified across all 18 /v1/messages in crack/cc2156.
			if tc.expectSystemCount > 2 {
				last := sys[len(sys)-1]
				cc, ok := last["cache_control"].(map[string]any)
				if !ok {
					t.Fatalf("last system block missing cache_control")
				}
				if cc["ttl"] != "1h" {
					t.Errorf("last system cache_control ttl: want 1h got %v", cc["ttl"])
				}
				if _, hasScope := cc["scope"]; hasScope {
					t.Errorf("last system block must be plain ephemeral (no scope), got %v", cc)
				}
			}
			if tc.expectSystemCount >= 4 {
				secondLast := sys[len(sys)-2]
				cc, ok := secondLast["cache_control"].(map[string]any)
				if !ok {
					t.Fatalf("second-to-last system block missing cache_control")
				}
				if cc["ttl"] != "1h" {
					t.Errorf("second-to-last system cache_control ttl: want 1h got %v", cc["ttl"])
				}
				if cc["scope"] != "global" {
					t.Errorf("second-to-last system cache_control scope: want global got %v", cc["scope"])
				}
			}

			// 4. metadata.user_id must be present and JSON-shaped, with the
			//    real account_uuid we passed in.
			var md map[string]json.RawMessage
			if err := json.Unmarshal(parsed["metadata"], &md); err != nil {
				t.Fatalf("metadata not object: %v", err)
			}
			var uidStr string
			if err := json.Unmarshal(md["user_id"], &uidStr); err != nil {
				t.Fatalf("metadata.user_id not string: %v", err)
			}
			var uidObj map[string]string
			if err := json.Unmarshal([]byte(uidStr), &uidObj); err != nil {
				t.Fatalf("metadata.user_id not JSON-encoded: %v (%q)", err, uidStr)
			}
			if len(uidObj["device_id"]) != 64 {
				t.Errorf("device_id wrong length: %d", len(uidObj["device_id"]))
			}
			if uidObj["session_id"] == "" {
				t.Errorf("session_id empty")
			}
			if uidObj["account_uuid"] != "00000000-0000-0000-0000-000000000000" {
				t.Errorf("account_uuid not propagated: %q", uidObj["account_uuid"])
			}

			// 5. Last message has cache_control on its last content block.
			var msgs []map[string]json.RawMessage
			if err := json.Unmarshal(parsed["messages"], &msgs); err != nil {
				t.Fatalf("messages not array: %v", err)
			}
			if len(msgs) == 0 {
				t.Fatalf("messages empty after rewrite")
			}
			last := msgs[len(msgs)-1]
			var lastBlocks []map[string]any
			if err := json.Unmarshal(last["content"], &lastBlocks); err != nil {
				t.Fatalf("last message content not array: %v", err)
			}
			if len(lastBlocks) == 0 {
				t.Fatalf("last message has no content blocks")
			}
			if _, ok := lastBlocks[len(lastBlocks)-1]["cache_control"]; !ok {
				t.Errorf("last content block missing cache_control")
			}
		})
	}
}

// TestPerAccountStability asserts the core security-experiment invariant:
// device_id depends ONLY on the account anchor, not on the downstream
// client token. Two different downstream users hitting the same account
// must present identical device_ids (same device, multiple windows) and
// distinct session_ids (separate concurrent sessions).
func TestPerAccountStability(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hello"}]}`)
	user1 := SimIdentity{AccountKey: "alice@example.com", AccountUUID: "u-alice", ClientToken: "client-A"}
	user2 := SimIdentity{AccountKey: "alice@example.com", AccountUUID: "u-alice", ClientToken: "client-B"}

	d1 := DeviceIDFor(user1.AccountKey)
	d2 := DeviceIDFor(user2.AccountKey)
	if d1 != d2 {
		t.Errorf("same account must yield same device_id: %s vs %s", d1, d2)
	}

	s1 := SessionIDFor(user1, body)
	s2 := SessionIDFor(user2, body)
	if s1 == s2 {
		t.Errorf("different downstream clients must yield different session_ids")
	}

	// Different account → different device.
	user3 := SimIdentity{AccountKey: "bob@example.com", AccountUUID: "u-bob", ClientToken: "client-A"}
	if DeviceIDFor(user3.AccountKey) == d1 {
		t.Errorf("different accounts must yield different device_ids")
	}
}

// TestSessionStableAcrossTurns asserts that the session_id stays stable as
// a multi-turn conversation grows (matching a real `claude` invocation),
// because it's keyed on the first user message rather than the full body.
func TestSessionStableAcrossTurns(t *testing.T) {
	id := SimIdentity{AccountKey: "alice@example.com", AccountUUID: "u-alice", ClientToken: "client-A"}
	turn1 := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"first question"}]}`)
	turn2 := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"first question"},{"role":"assistant","content":"answer"},{"role":"user","content":"follow up"}]}`)
	turn3New := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"completely different first question"}]}`)

	s1 := SessionIDFor(id, turn1)
	s2 := SessionIDFor(id, turn2)
	if s1 != s2 {
		t.Errorf("session_id must stay stable across turns of one conversation: %s vs %s", s1, s2)
	}
	s3 := SessionIDFor(id, turn3New)
	if s1 == s3 {
		t.Errorf("starting a new conversation must rotate session_id")
	}
}

// TestHaikuSkip confirms Haiku models bypass body rewriting entirely
// (Anthropic doesn't third-party-check Haiku).
func TestHaikuSkip(t *testing.T) {
	in := `{"model":"claude-haiku-4-5","system":"sys","messages":[{"role":"user","content":"hi"}]}`
	out := ApplyClaudeCodeBodyMimicry([]byte(in), "claude-haiku-4-5-20251001", testID())
	if string(out) != in {
		t.Errorf("haiku body was modified — should be passthrough\nin=%s\nout=%s", in, out)
	}
}

// TestAlreadyClaudeCode confirms we don't double-rewrite a request whose
// system already starts with the Claude Code prompt.
func TestAlreadyClaudeCode(t *testing.T) {
	in := `{"model":"claude-sonnet-4-5","system":[{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude. Stuff."}],"messages":[{"role":"user","content":"hi"}]}`
	out := ApplyClaudeCodeBodyMimicry([]byte(in), "claude-sonnet-4-5", testID())

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	var sys []map[string]any
	if err := json.Unmarshal(parsed["system"], &sys); err != nil {
		t.Fatalf("system not array: %v", err)
	}
	if len(sys) != 1 {
		t.Errorf("already-CC system should not be rewritten, got %d blocks", len(sys))
	}
}

// TestBillingBlockSkipsRewrite covers proxied / prompt-drifted real Claude
// Code traffic: a request whose system carries the billing attribution block
// but whose prompt does NOT match any hard-coded ClaudeCodePromptPrefixes
// (e.g. an upstream gateway relayed it, or CC shipped a revised prompt, or it
// is a subagent prompt). This must be recognized as genuine CC and left
// untouched — rewriting it would strip the client's cache_control and destroy
// Anthropic's prompt-cache prefix. Guards the sub2api oauth-mimicry-cache
// -prefix-break fix.
func TestBillingBlockSkipsRewrite(t *testing.T) {
	in := `{"model":"claude-sonnet-4-5","system":[` +
		`{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=deadbeef;"},` +
		`{"type":"text","text":"You are a bespoke internal coding agent.","cache_control":{"type":"ephemeral","ttl":"1h"}}` +
		`],"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`
	out := ApplyClaudeCodeBodyMimicry([]byte(in), "claude-sonnet-4-5", testID())

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	var sys []map[string]any
	if err := json.Unmarshal(parsed["system"], &sys); err != nil {
		t.Fatalf("system not array: %v", err)
	}
	// Must NOT have injected the intro block — system stays at its 2 blocks.
	if len(sys) != 2 {
		t.Fatalf("billing-block request must not be rewritten, got %d system blocks", len(sys))
	}
	if txt, _ := sys[1]["text"].(string); !strings.HasPrefix(txt, "You are a bespoke") {
		t.Errorf("client system prompt was altered: %q", txt)
	}
	// The client's own message-level cache_control must survive verbatim
	// (addMessageCacheBreakpoints must not have run).
	if !strings.Contains(string(out), `"content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]`) {
		t.Errorf("client message cache_control was rewritten; prompt-cache prefix broken:\n%s", out)
	}
}

// TestNoBetaGatedFieldInjection confirms we do NOT synthesize beta-gated
// body fields (thinking / output_config / context_management) when the
// downstream client didn't send them. Real CC carries these but each is
// gated by a beta header that only some clients negotiate; injecting
// blindly would 400 the request whenever the client's anthropic-beta
// list lacks the matching marker, which is both worse for the user AND
// a stronger fingerprint than omitting them.
func TestNoBetaGatedFieldInjection(t *testing.T) {
	in := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`
	out := ApplyClaudeCodeBodyMimicry([]byte(in), "claude-sonnet-4-5", testID())
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	for _, key := range []string{"thinking", "output_config", "context_management"} {
		if _, ok := parsed[key]; ok {
			t.Errorf("%s was synthesized but client didn't send it — this should be omitted to avoid breaking non-CC clients on beta-gated fields", key)
		}
	}
}

// TestClientBetaGatedFieldsPassThrough confirms client-supplied values for
// beta-gated fields are preserved verbatim — we don't strip them either.
func TestClientBetaGatedFieldsPassThrough(t *testing.T) {
	in := `{"model":"claude-sonnet-4-5","thinking":{"type":"enabled","budget_tokens":16000},"messages":[{"role":"user","content":"hi"}]}`
	out := ApplyClaudeCodeBodyMimicry([]byte(in), "claude-sonnet-4-5", testID())
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	if string(parsed["thinking"]) != `{"type":"enabled","budget_tokens":16000}` {
		t.Errorf("thinking was modified: %s", parsed["thinking"])
	}
}

// TestCCHSigning asserts the cch field is replaced with a 5-hex digest
// derived from body content (different bodies → different cch).
func TestCCHSigning(t *testing.T) {
	a := ApplyClaudeCodeBodyMimicry(
		[]byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"alpha"}]}`),
		"claude-sonnet-4-5", testID(),
	)
	b := ApplyClaudeCodeBodyMimicry(
		[]byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"beta"}]}`),
		"claude-sonnet-4-5", testID(),
	)
	if string(a) == string(b) {
		t.Fatalf("two distinct bodies produced identical output — cch not signing body content")
	}
}

// TestClaudeCodeFingerprintUTF16Vectors locks the JavaScript string-indexing
// semantics extracted from the real 2.1.220 bundle. In particular, emoji use
// two UTF-16 code units; byte or rune indexing produces different suffixes.
func TestClaudeCodeFingerprintUTF16Vectors(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "ascii", text: "abcdefghijklmnopqrstuvwxyz", want: "ac9"},
		{name: "emoji-at-index-4", text: "abcd😀efghijklmnopqrstuvwxyz", want: "e25"},
		{name: "bmp-non-ascii", text: "中文字符测试abcdefghijklmnop", want: "3f7"},
		{name: "multiple-emoji", text: "abc😀def😀ghijklmnop😀qrstuvwxyz", want: "a94"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"messages": []any{map[string]any{"role": "user", "content": tt.text}},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if got := computeClaudeCodeFingerprint(body, "2.1.220"); got != tt.want {
				t.Fatalf("fingerprint: got %s want %s", got, tt.want)
			}
		})
	}
}

// The 2.1.220 bundle literally contains `cch=00000` and no code that replaces
// it (crack/cc2220/SPEC.md, "`cch` — exhaustive static analysis"). That is a
// standing temptation to "align" cc-core by shipping the placeholder — but no
// genuine request ever carries it: 43/43 captured values are non-zero and
// unique. This test fails loudly if the signer is ever removed or neutered.
func TestCCHIsNeverPlaceholder(t *testing.T) {
	const billing = `{"system":[{"type":"text","text":` +
		`"x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=00000;"}]}`

	got := signBillingHeaderCCH([]byte(billing))
	if bytes.Contains(got, []byte("cch=00000")) {
		t.Fatalf("placeholder survived signing — real clients never send it:\n%s", got)
	}

	m := regexp.MustCompile(`cch=([0-9a-f]{5});`).FindSubmatch(got)
	if m == nil {
		t.Fatalf("signed body has no 5-hex cch: %s", got)
	}

	// Deterministic for a fixed body — a silent seed/algorithm change is a
	// behavioural change to every proxied request and must be explicit.
	if again := signBillingHeaderCCH([]byte(billing)); !bytes.Equal(got, again) {
		t.Error("cch signing is not deterministic for a fixed body")
	}
}
