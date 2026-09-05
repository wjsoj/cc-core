package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

// capturedFrameShape mirrors crack/codexapp0.147.0/rows/18: a continuation
// frame with the exact top-level key order and the exact client_metadata key
// set the captures show. The ids are the client's; every one of them must be
// gone from the output.
//
// Three properties of the real frame are load-bearing here and are reproduced
// verbatim: session_id == thread_id, x-codex-window-id == "<session>:0", and
// prompt_cache_key == session_id.
const capturedFrameShape = `{"type":"response.create","model":"gpt-5.6-sol",` +
	`"previous_response_id":"resp_CLIENT",` +
	`"input":[{"type":"custom_tool_call_output","id":"ctco_1","call_id":"call_1",` +
	`"output":[{"type":"input_text","text":"ok"}],` +
	`"internal_chat_message_metadata_passthrough":{"turn_id":"01a0034e-0000-7000-8000-000000000003"}}],` +
	`"tool_choice":"auto","parallel_tool_calls":false,` +
	`"reasoning":{"effort":"medium","summary":"detailed","context":"all_turns"},` +
	`"store":false,"stream":true,` +
	`"stream_options":{"reasoning_summary_delivery":"sequential_cutoff"},` +
	`"include":["reasoning.encrypted_content"],` +
	`"prompt_cache_key":"01a0034b-0000-7000-8000-000000000001",` +
	`"text":{"verbosity":"low"},` +
	`"client_metadata":{` +
	`"session_id":"01a0034b-0000-7000-8000-000000000001",` +
	`"thread_id":"01a0034b-0000-7000-8000-000000000001",` +
	`"turn_id":"01a0034e-0000-7000-8000-000000000003",` +
	`"x-codex-installation-id":"556e7a6a-0000-4000-8000-000000000002",` +
	`"x-codex-window-id":"01a0034b-0000-7000-8000-000000000001:0",` +
	`"x-codex-ws-stream-request-start-ms":"1786761700000",` +
	`"ws_request_header_x_openai_internal_codex_responses_lite":"true",` +
	`"x-codex-turn-metadata":"{\"installation_id\":\"556e7a6a-0000-4000-8000-000000000002\",\"session_id\":\"01a0034b-0000-7000-8000-000000000001\",\"thread_id\":\"01a0034b-0000-7000-8000-000000000001\",\"turn_id\":\"01a0034e-0000-7000-8000-000000000003\",\"window_id\":\"01a0034b-0000-7000-8000-000000000001:0\",\"request_kind\":\"turn\",\"thread_source\":\"user\",\"sandbox\":\"seccomp\"}"` +
	`}}`

const (
	clientSessionID = "01a0034b-0000-7000-8000-000000000001"
	clientInstallID = "556e7a6a-0000-4000-8000-000000000002"
	clientTurnID    = "01a0034e-0000-7000-8000-000000000003"
	ourSessionID    = "01a00500-0000-7000-8000-0000000000aa"
)

func testIdentity() CodexFrameIdentity {
	return CodexFrameIdentity{AccountKey: "acct-1", SessionID: ourSessionID}
}

func TestRewriteCodexClientFrameRebindsEveryClientID(t *testing.T) {
	out, err := RewriteCodexClientFrame([]byte(capturedFrameShape), testIdentity())
	if err != nil {
		t.Fatalf("RewriteCodexClientFrame: %v", err)
	}
	got := string(out)

	// Nothing of the downstream client's identity may survive.
	for _, leaked := range []string{clientSessionID, clientInstallID, clientTurnID} {
		if strings.Contains(got, leaked) {
			t.Errorf("client id %q survived the rewrite:\n%s", leaked, got)
		}
	}

	var f struct {
		Type           string `json:"type"`
		PromptCacheKey string `json:"prompt_cache_key"`
		Input          []struct {
			Passthrough struct {
				TurnID string `json:"turn_id"`
			} `json:"internal_chat_message_metadata_passthrough"`
		} `json:"input"`
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("rewritten frame is not valid JSON: %v\n%s", err, got)
	}
	if f.Type != "response.create" {
		t.Errorf("type = %q", f.Type)
	}
	if f.ClientMetadata["session_id"] != ourSessionID {
		t.Errorf("session_id = %q, want %q", f.ClientMetadata["session_id"], ourSessionID)
	}
	// The captures always collapse these two; so must we.
	if f.ClientMetadata["thread_id"] != ourSessionID {
		t.Errorf("thread_id = %q, want it collapsed onto session %q",
			f.ClientMetadata["thread_id"], ourSessionID)
	}
	if want := CodexInstallationIDFor("acct-1"); f.ClientMetadata["x-codex-installation-id"] != want {
		t.Errorf("installation id = %q, want %q", f.ClientMetadata["x-codex-installation-id"], want)
	}
	if want := ourSessionID + ":0"; f.ClientMetadata["x-codex-window-id"] != want {
		t.Errorf("window id = %q, want %q", f.ClientMetadata["x-codex-window-id"], want)
	}
	// prompt_cache_key tracks session_id in every captured frame; rebinding the
	// session must carry it along or we lose the upstream prompt cache.
	if f.PromptCacheKey != ourSessionID {
		t.Errorf("prompt_cache_key = %q, want %q", f.PromptCacheKey, ourSessionID)
	}

	// The turn id is mapped, not passed through — and the copy buried inside
	// input[] must agree with the one in client_metadata, or the frame
	// contradicts itself.
	wantTurn := CodexTurnIDFor("acct-1", clientTurnID)
	if f.ClientMetadata["turn_id"] != wantTurn {
		t.Errorf("turn_id = %q, want %q", f.ClientMetadata["turn_id"], wantTurn)
	}
	if len(f.Input) != 1 || f.Input[0].Passthrough.TurnID != wantTurn {
		t.Errorf("input passthrough turn_id not rebound: %+v", f.Input)
	}

	// The embedded turn-metadata string must have been rewritten too.
	var embedded map[string]any
	if err := json.Unmarshal([]byte(f.ClientMetadata["x-codex-turn-metadata"]), &embedded); err != nil {
		t.Fatalf("embedded turn metadata is not valid JSON: %v", err)
	}
	for key, want := range map[string]string{
		"installation_id": CodexInstallationIDFor("acct-1"),
		"session_id":      ourSessionID,
		"thread_id":       ourSessionID,
		"turn_id":         wantTurn,
		"window_id":       ourSessionID + ":0",
	} {
		if embedded[key] != want {
			t.Errorf("embedded %s = %q, want %q", key, embedded[key], want)
		}
	}
	// Untouched fields stay untouched.
	if embedded["request_kind"] != "turn" || embedded["sandbox"] != "seccomp" {
		t.Errorf("non-identity metadata was altered: %v", embedded)
	}
}

// Top-level key order is part of the captured shape. A map round-trip would
// silently sort it.
func TestRewriteCodexClientFramePreservesTopLevelKeyOrder(t *testing.T) {
	out, err := RewriteCodexClientFrame([]byte(capturedFrameShape), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"type", "model", "previous_response_id", "input", "tool_choice",
		"parallel_tool_calls", "reasoning", "store", "stream", "stream_options",
		"include", "prompt_cache_key", "text", "client_metadata",
	}
	got := topLevelKeyOrder(t, string(out))
	if len(got) != len(want) {
		t.Fatalf("key order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// A genuine client sends session_id == thread_id, so one UUID maps from two
// slots. A map-based substitution would pick a winner at random; this asserts
// the output is byte-identical across many runs.
func TestRewriteCodexClientFrameIsDeterministic(t *testing.T) {
	first, err := RewriteCodexClientFrame([]byte(capturedFrameShape), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		out, err := RewriteCodexClientFrame([]byte(capturedFrameShape), testIdentity())
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(first) {
			t.Fatalf("run %d differs — substitution is order-dependent", i)
		}
	}
}

// Chaining guard: if one pair's replacement is another pair's source, a
// per-pair ReplaceAll would apply both in sequence. A single pass must not.
func TestSubstituteTokensDoesNotChain(t *testing.T) {
	in := []byte(`{"a":"AAA","b":"BBB"}`)
	got := string(substituteTokens(in, []tokenSub{{from: "AAA", to: "BBB"}, {from: "BBB", to: "CCC"}}))
	want := `{"a":"BBB","b":"CCC"}`
	if got != want {
		t.Errorf("substituteTokens chained: got %s, want %s", got, want)
	}
}

func TestSubstituteTokensNoMatchSharesInput(t *testing.T) {
	in := []byte(`{"a":"zzz"}`)
	out := substituteTokens(in, []tokenSub{{from: "AAA", to: "BBB"}})
	if &out[0] != &in[0] {
		t.Error("a no-op substitution should return the input slice, not a copy")
	}
}

// A third-party client that knows nothing about client_metadata still has to
// look like Codex upstream.
func TestRewriteCodexClientFrameSynthesizesMissingMetadata(t *testing.T) {
	bare := `{"type":"response.create","model":"gpt-5.6-sol","input":[],"stream":true}`
	out, err := RewriteCodexClientFrame([]byte(bare), testIdentity())
	if err != nil {
		t.Fatalf("RewriteCodexClientFrame: %v", err)
	}
	got := string(out)

	keys := topLevelKeyOrder(t, got)
	if keys[len(keys)-1] != "client_metadata" {
		t.Errorf("client_metadata must be appended LAST (captures put it there), got order %v", keys)
	}

	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("synthesized frame is not valid JSON: %v\n%s", err, got)
	}
	if f.ClientMetadata["session_id"] != ourSessionID {
		t.Errorf("session_id = %q", f.ClientMetadata["session_id"])
	}
	if f.ClientMetadata["x-codex-window-id"] != ourSessionID+":0" {
		t.Errorf("window id = %q", f.ClientMetadata["x-codex-window-id"])
	}
	// The lite switch travels in the body because a WebSocket cannot set
	// per-message headers; a synthesized metadata that omits it is not a Codex
	// frame.
	if f.ClientMetadata["ws_request_header_x_openai_internal_codex_responses_lite"] != "true" {
		t.Error("synthesized metadata must carry the responses-lite switch")
	}
	if _, err := json.Marshal(f.ClientMetadata["x-codex-turn-metadata"]); err != nil {
		t.Errorf("embedded turn metadata unusable: %v", err)
	}
}

// Anything that is not a response.create must pass through untouched — this
// function must never be what breaks a turn.
func TestRewriteCodexClientFrameLeavesOtherFramesAlone(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.cancel"}`,
		`{"type":"session.update","session":{}}`,
		`not json at all`,
		``,
		`[]`,
	} {
		out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
		if err != nil {
			t.Errorf("frame %q returned error %v", frame, err)
		}
		if string(out) != frame {
			t.Errorf("frame %q was rewritten to %q", frame, out)
		}
	}
}

// A missing identity is a caller bug, and the frame must be returned unchanged
// rather than half-rewritten.
func TestRewriteCodexClientFrameRequiresIdentity(t *testing.T) {
	for _, id := range []CodexFrameIdentity{
		{SessionID: ourSessionID},
		{AccountKey: "acct-1"},
		{},
	} {
		out, err := RewriteCodexClientFrame([]byte(capturedFrameShape), id)
		if err == nil {
			t.Errorf("identity %+v should be rejected", id)
		}
		if string(out) != capturedFrameShape {
			t.Errorf("frame must be returned unchanged on error")
		}
	}
}

// A client that used a non-zero window index must still be pinned to the index
// the handshake advertised.
func TestRewriteCodexClientFrameRebindsWindowIndex(t *testing.T) {
	frame := strings.Replace(capturedFrameShape,
		`"x-codex-window-id":"`+clientSessionID+`:0"`,
		`"x-codex-window-id":"`+clientSessionID+`:7"`, 1)
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ":7") {
		t.Errorf("client window index survived:\n%s", out)
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if f.ClientMetadata["x-codex-window-id"] != ourSessionID+":0" {
		t.Errorf("window id = %q", f.ClientMetadata["x-codex-window-id"])
	}
}

// The turn id mapping has to be stable across the frames of one turn, and
// account-scoped so two downstream users cannot collide.
func TestCodexTurnIDFor(t *testing.T) {
	a := CodexTurnIDFor("acct-1", clientTurnID)
	if a != CodexTurnIDFor("acct-1", clientTurnID) {
		t.Error("mapping must be stable")
	}
	if a == CodexTurnIDFor("acct-2", clientTurnID) {
		t.Error("different accounts must not share a mapped turn id")
	}
	if a == clientTurnID {
		t.Error("mapped turn id must differ from the client's")
	}
	if len(a) != 36 || a[14] != '7' {
		t.Errorf("mapped turn id %q should be a UUIDv7 like the genuine client's", a)
	}
	// A v7 source keeps its timestamp, so ordering survives the mapping.
	ts, ok := uuidV7Timestamp(a)
	if !ok {
		t.Fatal("mapped id is not a parseable v7")
	}
	srcTS, _ := uuidV7Timestamp(clientTurnID)
	if !ts.Equal(srcTS) {
		t.Errorf("timestamp = %v, want it carried over from %v", ts, srcTS)
	}
	// A non-v7 source still yields a usable id.
	if got := CodexTurnIDFor("acct-1", "not-a-uuid"); len(got) != 36 {
		t.Errorf("non-v7 source produced %q", got)
	}
}

// topLevelKeyOrder returns the object's keys in the order they appear in the
// encoded bytes, which encoding/json's map decoding throws away.
func topLevelKeyOrder(t *testing.T, s string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		t.Fatalf("not an object: %v", tok)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("decode key: %v", err)
		}
		keys = append(keys, k.(string))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("decode value: %v", err)
		}
	}
	return keys
}

// --- regressions from the adversarial review -------------------------------

// A downstream client is free to put anything in client_metadata. A one-
// character "session id" used to be substituted as a literal token, rewriting
// every occurrence of that character in the frame — JSON syntax and user prose
// included — and producing a frame the backend would reject outright.
func TestRewriteCodexClientFrameIgnoresNonUUIDClientIDs(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol",` +
		`"input":[{"type":"message","role":"user","content":[{"type":"input_text",` +
		`"text":"a quick brown fox jumps over the lazy dog"}]}],` +
		`"client_metadata":{"session_id":"a","thread_id":"a","turn_id":"e",` +
		`"x-codex-installation-id":"o"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatalf("RewriteCodexClientFrame: %v", err)
	}
	var f struct {
		Model string `json:"model"`
		Input []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("frame was corrupted into invalid JSON: %v\n%s", err, out)
	}
	if f.Model != "gpt-5.6-sol" {
		t.Errorf("model was mangled: %q", f.Model)
	}
	if got := f.Input[0].Content[0].Text; got != "a quick brown fox jumps over the lazy dog" {
		t.Errorf("user prose was rewritten: %q", got)
	}
}

// One token being a prefix of another must not split it.
func TestSubstituteTokensPrefersLongestMatch(t *testing.T) {
	got := string(substituteTokens([]byte("abcdef"), []tokenSub{
		{from: "abc", to: "X"},
		{from: "abcdef", to: "Y"},
	}))
	if got != "Y" {
		t.Errorf("longest match not preferred: got %q, want %q", got, "Y")
	}
}

// The frame type must come from a real parse. A client discussing the Codex
// protocol would otherwise get its cancel frame rewritten.
func TestRewriteCodexClientFrameIgnoresTypeNameInProse(t *testing.T) {
	frame := `{"type":"response.cancel","reason":"user mentioned \"response.create\" in chat"}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != frame {
		t.Errorf("a non-create frame was rewritten:\n got %s\nwant %s", out, frame)
	}
}

// The synthesized metadata must carry the full captured key set — a
// client_metadata missing keys is its own fingerprint — and must declare the
// only request_kind that pairs with an empty turn_id.
func TestSynthesizedClientMetadataMatchesCapturedShape(t *testing.T) {
	bare := `{"type":"response.create","model":"gpt-5.6-sol","input":[]}`
	out, err := RewriteCodexClientFrame([]byte(bare), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"session_id", "thread_id", "turn_id",
		"x-codex-installation-id", "x-codex-window-id", "x-codex-turn-metadata",
		"x-codex-ws-stream-request-start-ms",
		"ws_request_header_x_openai_internal_codex_responses_lite",
	}
	if len(f.ClientMetadata) != len(want) {
		t.Errorf("client_metadata has %d keys, want the captured %d: %v",
			len(f.ClientMetadata), len(want), f.ClientMetadata)
	}
	for _, k := range want {
		if _, ok := f.ClientMetadata[k]; !ok {
			t.Errorf("synthesized client_metadata is missing %q", k)
		}
	}
	var md map[string]any
	if err := json.Unmarshal([]byte(f.ClientMetadata["x-codex-turn-metadata"]), &md); err != nil {
		t.Fatalf("embedded metadata invalid: %v", err)
	}
	// turn_id == "" only ever appears alongside request_kind "prewarm"; the turn
	// variant additionally carries fields a proxy cannot synthesize.
	if md["turn_id"] != "" || md["request_kind"] != CodexRequestKindPrewarm {
		t.Errorf("synthesized metadata claims %q with turn_id %q — no genuine client sends that",
			md["request_kind"], md["turn_id"])
	}
}

// The no-client_metadata branch is the third-party client this whole function
// exists for, and it used to return early — skipping the prompt_cache_key
// rebind, so the one case the doc promised to cover was the one that leaked.
func TestRewriteCodexClientFrameRebindsCacheKeyWhenSynthesizingMetadata(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol",` +
		`"prompt_cache_key":"attacker-chosen-key","input":[]}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "attacker-chosen-key") {
		t.Errorf("client-chosen prompt_cache_key survived:\n%s", out)
	}
	var f struct {
		PromptCacheKey string            `json:"prompt_cache_key"`
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if f.PromptCacheKey != ourSessionID {
		t.Errorf("prompt_cache_key = %q, want %q", f.PromptCacheKey, ourSessionID)
	}
	// And it must agree with the metadata we just synthesized.
	if f.ClientMetadata["session_id"] != f.PromptCacheKey {
		t.Errorf("prompt_cache_key %q disagrees with session_id %q",
			f.PromptCacheKey, f.ClientMetadata["session_id"])
	}
}

// A third-party client that sends its own cache key must not have it forwarded:
// it would leak the client's identifier upstream and disagree with the session
// we advertised on the handshake.
func TestRewriteCodexClientFrameRebindsForeignPromptCacheKey(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol",` +
		`"prompt_cache_key":"some-client-chosen-key","input":[],` +
		`"client_metadata":{"session_id":"` + clientSessionID + `"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "some-client-chosen-key") {
		t.Errorf("foreign prompt_cache_key survived:\n%s", out)
	}
	var f struct {
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if f.PromptCacheKey != ourSessionID {
		t.Errorf("prompt_cache_key = %q, want %q", f.PromptCacheKey, ourSessionID)
	}
}

// Window rebinding is scoped to client_metadata; a window id quoted in a user's
// prompt is none of our business.
func TestRewriteCodexClientFrameLeavesWindowIDInProseAlone(t *testing.T) {
	prose := `my app sends "x-codex-window-id":"deadbeef:9" and it breaks`
	frame := `{"type":"response.create","model":"gpt-5.6-sol",` +
		`"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":` +
		mustJSON(t, prose) + `}]}],` +
		`"client_metadata":{"session_id":"` + clientSessionID + `",` +
		`"x-codex-window-id":"` + clientSessionID + `:3"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Input []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got := f.Input[0].Content[0].Text; got != prose {
		t.Errorf("user prose was rewritten:\n got %q\nwant %q", got, prose)
	}
	if f.ClientMetadata["x-codex-window-id"] != ourSessionID+":0" {
		t.Errorf("window id = %q", f.ClientMetadata["x-codex-window-id"])
	}
}

// A session id the caller did not derive properly must be refused rather than
// silently shipped — it becomes our upstream session-id and prompt_cache_key.
func TestRewriteCodexClientFrameRejectsNonUUIDSessionID(t *testing.T) {
	_, err := RewriteCodexClientFrame([]byte(capturedFrameShape),
		CodexFrameIdentity{AccountKey: "acct-1", SessionID: "not-a-uuid"})
	if err == nil {
		t.Error("a non-UUID SessionID must be rejected")
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- previous_response_id stripping ----------------------------------------

// Both forks stripped this key with unmarshal → delete → marshal, which makes
// Go re-emit the top-level keys in sorted order. Codex's own order is stable
// across every captured frame and is part of the shape, so the round-trip
// undid the byte fidelity everything else here protects.
func TestRemoveCodexPreviousResponseIDPreservesKeyOrder(t *testing.T) {
	out := RemoveCodexPreviousResponseID([]byte(capturedFrameShape))
	if strings.Contains(string(out), "previous_response_id") {
		t.Fatalf("key survived:\n%s", out)
	}
	want := []string{
		"type", "model", "input", "tool_choice", "parallel_tool_calls",
		"reasoning", "store", "stream", "stream_options", "include",
		"prompt_cache_key", "text", "client_metadata",
	}
	got := topLevelKeyOrder(t, string(out))
	if len(got) != len(want) {
		t.Fatalf("key order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRemoveCodexPreviousResponseIDPositions(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"middle", `{"a":1,"previous_response_id":"resp_x","b":2}`, `{"a":1,"b":2}`},
		{"first", `{"previous_response_id":"resp_x","b":2}`, `{"b":2}`},
		{"last", `{"a":1,"previous_response_id":"resp_x"}`, `{"a":1}`},
		{"only", `{"previous_response_id":"resp_x"}`, `{}`},
		{"absent", `{"a":1}`, `{"a":1}`},
		{"spaced", `{"a":1, "previous_response_id" : "resp_x" , "b":2}`, `{"a":1, "b":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(RemoveCodexPreviousResponseID([]byte(tc.in)))
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
			var probe map[string]any
			if err := json.Unmarshal([]byte(got), &probe); err != nil {
				t.Errorf("result is not valid JSON: %v", err)
			}
		})
	}
}

// The key name must not be matched inside user prose.
func TestRemoveCodexPreviousResponseIDIgnoresProse(t *testing.T) {
	in := `{"type":"response.create","input":[{"type":"message","content":` +
		`[{"type":"input_text","text":"set \"previous_response_id\":\"resp_1\" to chain"}]}]}`
	if got := string(RemoveCodexPreviousResponseID([]byte(in))); got != in {
		t.Errorf("prose was edited:\n got %s\nwant %s", got, in)
	}
}

func TestCodexPreviousResponseID(t *testing.T) {
	if got := CodexPreviousResponseID([]byte(capturedFrameShape)); got != "resp_CLIENT" {
		t.Errorf("got %q, want resp_CLIENT", got)
	}
	if got := CodexPreviousResponseID([]byte(`{"a":1}`)); got != "" {
		t.Errorf("absent key should yield empty, got %q", got)
	}
	// Must not read it out of prose either.
	in := `{"type":"response.create","input":[{"text":"\"previous_response_id\":\"resp_evil\""}]}`
	if got := CodexPreviousResponseID([]byte(in)); got != "" {
		t.Errorf("read %q out of user prose", got)
	}
}

// Strip-then-rewrite is the order the forks will use; the result must still be
// a well-formed frame with our identity bound.
func TestRemoveThenRewriteComposes(t *testing.T) {
	stripped := RemoveCodexPreviousResponseID([]byte(capturedFrameShape))
	out, err := RewriteCodexClientFrame(stripped, testIdentity())
	if err != nil {
		t.Fatalf("rewrite after strip: %v", err)
	}
	if strings.Contains(string(out), "previous_response_id") {
		t.Error("stripped key came back")
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if f.ClientMetadata["session_id"] != ourSessionID {
		t.Errorf("identity not bound after strip: %q", f.ClientMetadata["session_id"])
	}
}

// --- regressions from the third review pass --------------------------------

// A client that sends non-UUID identifiers got NO rebinding at all: addSub
// requires a canonical UUID (it must, or a one-character id would rewrite the
// whole frame), and the synthesize branch only fires when client_metadata is
// missing entirely. So its ids went upstream and contradicted the handshake —
// the exact tell this file removes.
func TestRewriteCodexClientFrameOverwritesNonUUIDMetadata(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
		`"client_metadata":{"session_id":"sess-abc","thread_id":"sess-abc",` +
		`"turn_id":"turn-xyz","x-codex-installation-id":"install-1",` +
		`"x-codex-window-id":"sess-abc:3"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"sess-abc", "turn-xyz", "install-1"} {
		if strings.Contains(string(out), leaked) {
			t.Errorf("non-UUID client id %q survived:\n%s", leaked, out)
		}
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if f.ClientMetadata["session_id"] != ourSessionID {
		t.Errorf("session_id = %q, want %q", f.ClientMetadata["session_id"], ourSessionID)
	}
	if f.ClientMetadata["x-codex-window-id"] != ourSessionID+":0" {
		t.Errorf("window id = %q", f.ClientMetadata["x-codex-window-id"])
	}
	if f.ClientMetadata["turn_id"] == "turn-xyz" || f.ClientMetadata["turn_id"] == "" {
		t.Errorf("turn_id = %q, want it mapped into our domain", f.ClientMetadata["turn_id"])
	}
}

// A partial client_metadata is neither "absent" nor fully substitutable; it
// must still come out complete and ours.
func TestRewriteCodexClientFrameCompletesPartialMetadata(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
		`"client_metadata":{"session_id":"` + clientSessionID + `"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	for _, k := range []string{
		"session_id", "thread_id", "turn_id", "x-codex-installation-id",
		"x-codex-window-id", "x-codex-turn-metadata",
		"ws_request_header_x_openai_internal_codex_responses_lite",
		"x-codex-ws-stream-request-start-ms",
	} {
		if _, ok := f.ClientMetadata[k]; !ok {
			t.Errorf("completed metadata is missing %q: %v", k, f.ClientMetadata)
		}
	}
	if f.ClientMetadata["session_id"] != ourSessionID {
		t.Errorf("session_id = %q", f.ClientMetadata["session_id"])
	}
	// An empty turn_id may only pair with prewarm.
	var md map[string]any
	if err := json.Unmarshal([]byte(f.ClientMetadata["x-codex-turn-metadata"]), &md); err != nil {
		t.Fatal(err)
	}
	if md["turn_id"] == "" && md["request_kind"] != CodexRequestKindPrewarm {
		t.Errorf("empty turn_id paired with %q; no captured frame does that", md["request_kind"])
	}
}

// The client's own non-identity metadata describes ITS turn and is not ours to
// invent or discard.
func TestRewriteCodexClientFramePreservesForeignMetadataKeys(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
		`"client_metadata":{"session_id":"` + clientSessionID + `",` +
		`"turn_id":"` + clientTurnID + `",` +
		`"x-codex-turn-metadata":"{\"session_id\":\"` + clientSessionID + `\",\"turn_id\":\"` + clientTurnID +
		`\",\"request_kind\":\"turn\",\"thread_source\":\"ambient_suggestions\",\"sandbox\":\"danger-full-access\"}",` +
		`"some-client-key":"keep-me"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ClientMetadata map[string]string `json:"client_metadata"`
	}
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if f.ClientMetadata["some-client-key"] != "keep-me" {
		t.Error("an unrecognized client key was dropped")
	}
	var md map[string]any
	if err := json.Unmarshal([]byte(f.ClientMetadata["x-codex-turn-metadata"]), &md); err != nil {
		t.Fatal(err)
	}
	// thread_source is genuinely variable (user / system / ambient_suggestions
	// all appear in the captures) and sandbox describes the client's own
	// environment — neither is an identity field.
	if md["thread_source"] != "ambient_suggestions" || md["sandbox"] != "danger-full-access" {
		t.Errorf("non-identity turn metadata was overwritten: %v", md)
	}
	if md["session_id"] != ourSessionID {
		t.Errorf("embedded session_id = %q, want ours", md["session_id"])
	}
}

// Rebinding an absent prompt_cache_key used to be a no-op, so a third-party
// client reached upstream with no cache key — the stable session id bought
// nothing and every request paid list price.
func TestRewriteCodexClientFrameInsertsMissingPromptCacheKey(t *testing.T) {
	for name, frame := range map[string]string{
		"before text": `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
			`"include":["reasoning.encrypted_content"],"text":{"verbosity":"low"},` +
			`"client_metadata":{"session_id":"` + clientSessionID + `"}}`,
		"no text": `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
			`"client_metadata":{"session_id":"` + clientSessionID + `"}}`,
		"nothing but type": `{"type":"response.create"}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				PromptCacheKey string `json:"prompt_cache_key"`
			}
			if err := json.Unmarshal(out, &f); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, out)
			}
			if f.PromptCacheKey != ourSessionID {
				t.Errorf("prompt_cache_key = %q, want %q\n%s", f.PromptCacheKey, ourSessionID, out)
			}
		})
	}
}

// Inserting must not disturb the captured top-level order.
func TestPromptCacheKeyInsertKeepsCapturedOrder(t *testing.T) {
	frame := `{"type":"response.create","model":"gpt-5.6-sol","input":[],` +
		`"include":["reasoning.encrypted_content"],"text":{"verbosity":"low"},` +
		`"client_metadata":{"session_id":"` + clientSessionID + `"}}`
	out, err := RewriteCodexClientFrame([]byte(frame), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"type", "model", "input", "include", "prompt_cache_key", "text", "client_metadata"}
	got := topLevelKeyOrder(t, string(out))
	if len(got) != len(want) {
		t.Fatalf("key order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
