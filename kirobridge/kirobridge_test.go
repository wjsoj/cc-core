package kirobridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/kiroapi"
	"github.com/wjsoj/cc-core/kirotransport"
	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

// ---- model map ----

func TestMapModel(t *testing.T) {
	cases := map[string]string{
		// Sonnet family
		"claude-sonnet-4-5-20250929":     ModelClaudeSonnet45,
		"claude-sonnet-4-6":              ModelClaudeSonnet46,
		"claude-sonnet-4-6-thinking":     ModelClaudeSonnet46,
		"claude-sonnet-4-20250514":       ModelClaudeSonnet4,
		"claude-3-5-sonnet-latest":       ModelClaudeSonnet45, // default sonnet → newest
		// Opus family (verified against capture)
		"claude-opus-4-5":                ModelClaudeOpus45,
		"claude-opus-4-6":                ModelClaudeOpus46,
		"claude-opus-4-7":                ModelClaudeOpus47,
		"claude-opus-4-7-thinking":       ModelClaudeOpus47,
		// Haiku
		"claude-haiku-4-5-20251001":      ModelClaudeHaiku45,
		"claude-3-5-haiku-20241022":      ModelClaudeHaiku45,
		// Non-Anthropic catalog
		"deepseek-3.2":                   ModelDeepseek32,
		"minimax-m2.5":                   ModelMinimaxM25,
		"minimax-m2.1":                   ModelMinimaxM21,
		"glm-5":                          ModelGLM5,
		"qwen3-coder-next":               ModelQwen3CoderNext,
		// Unknown
		"unknown-model-xyz":              "",
	}
	for in, want := range cases {
		if got := MapModel(in); got != want {
			t.Errorf("MapModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContextWindow(t *testing.T) {
	if got := ContextWindow(ModelClaudeOpus47); got != 1_000_000 {
		t.Errorf("opus 4.7 should be 1M, got %d", got)
	}
	if got := ContextWindow(ModelClaudeOpus46); got != 1_000_000 {
		t.Errorf("opus 4.6 should be 1M, got %d", got)
	}
	if got := ContextWindow(ModelClaudeSonnet46); got != 1_000_000 {
		t.Errorf("sonnet 4.6 should be 1M, got %d", got)
	}
	if got := ContextWindow(ModelClaudeOpus45); got != 200_000 {
		t.Errorf("opus 4.5 should be 200K, got %d", got)
	}
	if got := ContextWindow(ModelClaudeSonnet45); got != 200_000 {
		t.Errorf("sonnet 4.5 should be 200K, got %d", got)
	}
}

func TestSupportedInputTypes(t *testing.T) {
	got := SupportedInputTypes(ModelGLM5)
	if len(got) != 1 || got[0] != "TEXT" {
		t.Errorf("glm-5 should be TEXT-only, got %v", got)
	}
	got = SupportedInputTypes(ModelMinimaxM25)
	if len(got) != 1 || got[0] != "TEXT" {
		t.Errorf("minimax-m2.5 should be TEXT-only, got %v", got)
	}
	got = SupportedInputTypes(ModelClaudeOpus47)
	if len(got) != 2 {
		t.Errorf("opus 4.7 should include IMAGE, got %v", got)
	}
}

// ---- system + content parsing ----

func TestParseSystemStringAndArray(t *testing.T) {
	if got := parseSystem(json.RawMessage(`"hello"`)); got != "hello" {
		t.Fatalf("plain string: %q", got)
	}
	got := parseSystem(json.RawMessage(`[{"type":"text","text":"A"},{"type":"text","text":"B"}]`))
	if got != "A\n\nB" {
		t.Fatalf("array form: %q", got)
	}
}

// ---- core convert ----

func TestConvertBasicTextRequest(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 1024,
		System:    json.RawMessage(`"You are helpful."`),
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
	}
	out, err := Convert(req, ConvertOptions{ProfileARN: "arn:test"})
	if err != nil {
		t.Fatal(err)
	}
	kr := out.Request
	if kr.ProfileARN != "arn:test" {
		t.Errorf("profileArn: %q", kr.ProfileARN)
	}
	cs := kr.ConversationState
	if cs.AgentTaskType != "vibe" || cs.ChatTriggerType != "MANUAL" {
		t.Errorf("defaults: task=%q trigger=%q", cs.AgentTaskType, cs.ChatTriggerType)
	}
	content := cs.CurrentMessage.UserInputMessage.Content
	if !strings.Contains(content, "--- CONTEXT ENTRY BEGIN ---") || !strings.Contains(content, "You are helpful.") || !strings.Contains(content, "Hello") {
		t.Fatalf("merged content wrong: %q", content)
	}
	if cs.CurrentMessage.UserInputMessage.ModelID != ModelClaudeSonnet46 {
		t.Errorf("modelId mapping: %q", cs.CurrentMessage.UserInputMessage.ModelID)
	}
}

func TestConvertOpus47(t *testing.T) {
	req := &AnthropicRequest{
		Model:    "claude-opus-4-7",
		Messages: []AnthropicMessage{{Role: "user", Content: json.RawMessage(`"x"`)}},
	}
	out, _ := Convert(req, ConvertOptions{})
	if got := out.Request.ConversationState.CurrentMessage.UserInputMessage.ModelID; got != ModelClaudeOpus47 {
		t.Fatalf("opus 4.7 mapping: %q", got)
	}
}

// ---- prefill stripping ----

func TestConvertStripsTrailingAssistant(t *testing.T) {
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"first"`)},
			{Role: "assistant", Content: json.RawMessage(`"prefill draft"`)},
		},
	}
	out, err := Convert(req, ConvertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// After prefill strip, only "first" remains and becomes the current
	// message (no history).
	cs := out.Request.ConversationState
	if len(cs.History) != 0 {
		t.Fatalf("history should be empty after prefill strip: %+v", cs.History)
	}
	if !strings.Contains(cs.CurrentMessage.UserInputMessage.Content, "first") {
		t.Fatalf("current content: %q", cs.CurrentMessage.UserInputMessage.Content)
	}
}

// ---- history + tool round-trip ----

func TestConvertHistoryWithTools(t *testing.T) {
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"What's the weather?"`)},
			{Role: "assistant", Content: json.RawMessage(`[
				{"type":"text","text":"Let me check."},
				{"type":"tool_use","id":"tu_1","name":"weather","input":{"city":"SF"}}
			]`)},
			{Role: "user", Content: json.RawMessage(`[
				{"type":"tool_result","tool_use_id":"tu_1","content":"sunny, 72F"}
			]`)},
		},
		Tools: []AnthropicTool{
			{
				Name:        "weather",
				Description: "Get current weather",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}}}`),
			},
		},
	}
	out, err := Convert(req, ConvertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cs := out.Request.ConversationState
	if len(cs.History) != 2 {
		t.Fatalf("history len: %d", len(cs.History))
	}
	if uses := cs.History[1].AssistantResponseMessage.ToolUses; len(uses) != 1 || uses[0].Name != "weather" {
		t.Fatalf("toolUses: %+v", uses)
	}
	tr := cs.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults
	if len(tr) != 1 || tr[0].ToolUseID != "tu_1" || tr[0].Status != "success" {
		t.Fatalf("toolResults: %+v", tr)
	}
}

// ---- orphan tool removal ----

func TestConvertDropsOrphanToolUse(t *testing.T) {
	// tool_use without matching tool_result → must be stripped from history.
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"go"`)},
			{Role: "assistant", Content: json.RawMessage(`[
				{"type":"tool_use","id":"tu_orphan","name":"x","input":{}},
				{"type":"tool_use","id":"tu_paired","name":"y","input":{}}
			]`)},
			{Role: "user", Content: json.RawMessage(`[
				{"type":"tool_result","tool_use_id":"tu_paired","content":"ok"}
			]`)},
		},
	}
	out, _ := Convert(req, ConvertOptions{})
	uses := out.Request.ConversationState.History[1].AssistantResponseMessage.ToolUses
	if len(uses) != 1 || uses[0].ToolUseID != "tu_paired" {
		t.Fatalf("orphan tu_orphan should be scrubbed: %+v", uses)
	}
}

func TestConvertDropsOrphanToolResult(t *testing.T) {
	// tool_result without matching tool_use → silently dropped.
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`[
				{"type":"tool_result","tool_use_id":"never_called","content":"strange"}
			]`)},
		},
	}
	out, _ := Convert(req, ConvertOptions{})
	if got := out.Request.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults; len(got) != 0 {
		t.Fatalf("orphan tool_result should be dropped: %+v", got)
	}
}

// ---- placeholder tools for history ----

func TestConvertSynthesizesPlaceholderTool(t *testing.T) {
	// Tool 'weather' used in history but missing from current tools[].
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"go"`)},
			{Role: "assistant", Content: json.RawMessage(`[{"type":"tool_use","id":"tu_1","name":"weather","input":{}}]`)},
			{Role: "user", Content: json.RawMessage(`[{"type":"tool_result","tool_use_id":"tu_1","content":"ok"}]`)},
		},
		Tools: []AnthropicTool{}, // intentionally empty
	}
	out, _ := Convert(req, ConvertOptions{})
	tools := out.Request.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools
	if len(tools) != 1 || tools[0].ToolSpecification.Name != "weather" {
		t.Fatalf("placeholder not synthesized: %+v", tools)
	}
	if !strings.Contains(string(tools[0].ToolSpecification.InputSchema.JSON), "additionalProperties") {
		t.Fatalf("placeholder schema malformed: %s", tools[0].ToolSpecification.InputSchema.JSON)
	}
}

// ---- image content ----

func TestConvertImageBase64(t *testing.T) {
	req := &AnthropicRequest{
		Model: "claude-opus-4-7",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`[
				{"type":"text","text":"What is this?"},
				{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}
			]`)},
		},
	}
	out, _ := Convert(req, ConvertOptions{AllowImages: true})
	imgs := out.Request.ConversationState.CurrentMessage.UserInputMessage.Images
	if len(imgs) != 1 || imgs[0].Format != "png" || imgs[0].Source.Bytes != "iVBORw0KGgo=" {
		t.Fatalf("image not converted: %+v", imgs)
	}
}

func TestConvertImageSkippedWhenDisabled(t *testing.T) {
	req := &AnthropicRequest{
		Model: "glm-5",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"x"}}]`)},
		},
	}
	out, _ := Convert(req, ConvertOptions{AllowImages: false})
	if got := out.Request.ConversationState.CurrentMessage.UserInputMessage.Images; len(got) != 0 {
		t.Fatalf("image should be skipped: %+v", got)
	}
}

// ---- schema normalization ----

func TestNormalizeJSONSchema(t *testing.T) {
	// Missing fields → defaults applied
	got := NormalizeJSONSchema(json.RawMessage(`{}`))
	var v map[string]any
	_ = json.Unmarshal(got, &v)
	if v["type"] != "object" {
		t.Errorf("type default: %v", v["type"])
	}
	if _, ok := v["properties"].(map[string]any); !ok {
		t.Errorf("properties default not object: %v", v["properties"])
	}
	if arr, ok := v["required"].([]any); !ok || len(arr) != 0 {
		t.Errorf("required default not empty array: %v", v["required"])
	}
	if v["additionalProperties"] != true {
		t.Errorf("additionalProperties default: %v", v["additionalProperties"])
	}

	// null fields → coerced
	got = NormalizeJSONSchema(json.RawMessage(`{"type":null,"properties":null,"required":null}`))
	_ = json.Unmarshal(got, &v)
	if v["type"] != "object" {
		t.Errorf("null type not coerced: %v", v["type"])
	}

	// Junk input → canonical
	got = NormalizeJSONSchema(json.RawMessage(`"not an object"`))
	_ = json.Unmarshal(got, &v)
	if v["type"] != "object" {
		t.Errorf("junk input not coerced: %v", v)
	}

	// Mixed required entries → filtered to strings
	got = NormalizeJSONSchema(json.RawMessage(`{"type":"object","required":["a",1,null,"b"]}`))
	_ = json.Unmarshal(got, &v)
	req := v["required"].([]any)
	if len(req) != 2 || req[0] != "a" || req[1] != "b" {
		t.Errorf("non-string required entries not filtered: %v", req)
	}
}

// ---- tool name shortening ----

func TestShortenToolName(t *testing.T) {
	if got := ShortenToolName("foo"); got != "foo" {
		t.Errorf("short name passed through: %q", got)
	}
	long := strings.Repeat("a", 100)
	got := ShortenToolName(long)
	if len(got) != 63 || !strings.HasPrefix(got, strings.Repeat("a", 54)) || got[54] != '_' {
		t.Errorf("shortened format wrong: %q (len=%d)", got, len(got))
	}
	// Deterministic
	if ShortenToolName(long) != got {
		t.Errorf("shortening not deterministic")
	}
}

// ---- session_id extraction ----

func TestExtractSessionID(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	// JSON form
	if got := ExtractSessionID(`{"session_id":"` + uuid + `"}`); got != uuid {
		t.Errorf("json form: %q", got)
	}
	// String-tag form
	if got := ExtractSessionID("user_abc_account__session_" + uuid); got != uuid {
		t.Errorf("string-tag form: %q", got)
	}
	// Junk
	if got := ExtractSessionID("nope"); got != "" {
		t.Errorf("junk should return empty: %q", got)
	}
	if got := ExtractSessionID(""); got != "" {
		t.Errorf("empty: %q", got)
	}
}

func TestConvertUsesMetadataSessionID(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	req := &AnthropicRequest{
		Model:    "claude-sonnet-4-6",
		Messages: []AnthropicMessage{{Role: "user", Content: json.RawMessage(`"x"`)}},
		Metadata: &AnthropicMetadata{UserID: `{"session_id":"` + uuid + `"}`},
	}
	out, _ := Convert(req, ConvertOptions{})
	if got := out.Request.ConversationState.ConversationID; got != uuid {
		t.Fatalf("metadata session_id not used: %q", got)
	}
}

func TestConvertRejectsAssistantOnly(t *testing.T) {
	req := &AnthropicRequest{
		Model:    "claude-sonnet-4-6",
		Messages: []AnthropicMessage{{Role: "assistant", Content: json.RawMessage(`"hi"`)}},
	}
	_, err := Convert(req, ConvertOptions{})
	if err == nil {
		t.Fatal("expected error when only assistant message present")
	}
}

func TestConvertToolResultErrorStatus(t *testing.T) {
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"go"`)},
			{Role: "assistant", Content: json.RawMessage(`[{"type":"tool_use","id":"tu","name":"x","input":{}}]`)},
			{Role: "user", Content: json.RawMessage(`[{"type":"tool_result","tool_use_id":"tu","content":"oops","is_error":true}]`)},
		},
	}
	out, _ := Convert(req, ConvertOptions{})
	tr := out.Request.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults[0]
	if tr.Status != "error" || !tr.IsError {
		t.Fatalf("error tool result: %+v", tr)
	}
}

func TestDeriveConversationIDStable(t *testing.T) {
	a := deriveConversationID([]AnthropicMessage{{Role: "user", Content: json.RawMessage(`"x"`)}})
	b := deriveConversationID([]AnthropicMessage{{Role: "user", Content: json.RawMessage(`"x"`)}})
	if a != b {
		t.Fatalf("not stable: %q vs %q", a, b)
	}
	c := deriveConversationID([]AnthropicMessage{{Role: "user", Content: json.RawMessage(`"y"`)}})
	if a == c {
		t.Fatal("different inputs should differ")
	}
}

// ---- stream translator ----

func TestStreamTranslatorTextOnly(t *testing.T) {
	body := buildKiroStream([]frameSpec{
		{event: "assistantResponseEvent", payload: `{"content":"Hello"}`},
		{event: "assistantResponseEvent", payload: `{"content":", world!"}`},
	})
	stream := openTestStream(t, body)
	defer stream.Close()

	tr := NewStreamTranslator(stream, "claude-sonnet-4-6", "msg_test")
	events := drainEvents(tr)
	if err := tr.Err(); err != nil {
		t.Fatal(err)
	}

	want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if got := names(events); !equalSeq(got, want) {
		t.Fatalf("event sequence:\n  got:  %v\n  want: %v", got, want)
	}
	var combined string
	for _, e := range events {
		if e.Name != "content_block_delta" {
			continue
		}
		var parsed map[string]any
		_ = json.Unmarshal(e.Data, &parsed)
		delta := parsed["delta"].(map[string]any)
		if delta["type"] == "text_delta" {
			combined += delta["text"].(string)
		}
	}
	if combined != "Hello, world!" {
		t.Fatalf("combined text: %q", combined)
	}
}

func TestStreamTranslatorToolUse(t *testing.T) {
	body := buildKiroStream([]frameSpec{
		{event: "assistantResponseEvent", payload: `{"content":"I'll check."}`},
		{event: "toolUseEvent", payload: `{"toolUseId":"tu_1","name":"weather","input":"{\"city\":\""}`},
		{event: "toolUseEvent", payload: `{"toolUseId":"tu_1","name":"weather","input":"SF\"}","stop":true}`},
	})
	stream := openTestStream(t, body)
	defer stream.Close()

	tr := NewStreamTranslator(stream, "claude-sonnet-4-6", "msg_test")
	events := drainEvents(tr)
	if err := tr.Err(); err != nil {
		t.Fatal(err)
	}
	names := names(events)
	if names[0] != "message_start" || names[len(names)-1] != "message_stop" {
		t.Fatalf("framing wrong: %v", names)
	}
	for _, e := range events {
		if e.Name == "message_delta" {
			var v map[string]any
			_ = json.Unmarshal(e.Data, &v)
			delta := v["delta"].(map[string]any)
			if delta["stop_reason"] != "tool_use" {
				t.Errorf("stop_reason: %v", delta["stop_reason"])
			}
		}
	}
}

// TestStreamTranslatorToolUsePartialJSONUnquoted verifies that Kiro's
// JSON-encoded `input` string is unescaped exactly once on the way through
// the translator. If we leave the extra layer of quoting in, Claude Code
// concatenates the fragments into a JSON string literal instead of the
// expected input object → "Invalid tool parameters".
func TestStreamTranslatorToolUsePartialJSONUnquoted(t *testing.T) {
	body := buildKiroStream([]frameSpec{
		// Wire format: input is itself a JSON-encoded string value.
		// Fragments below concatenate to {"file_path":"/etc/hosts"}.
		{event: "toolUseEvent", payload: `{"toolUseId":"tu_1","name":"Read","input":"{\"file_path\":\""}`},
		{event: "toolUseEvent", payload: `{"toolUseId":"tu_1","name":"Read","input":"/etc/hosts\"}","stop":true}`},
	})
	stream := openTestStream(t, body)
	defer stream.Close()

	tr := NewStreamTranslator(stream, "claude-haiku-4-5", "msg_test")
	events := drainEvents(tr)
	if err := tr.Err(); err != nil {
		t.Fatal(err)
	}

	var assembled strings.Builder
	for _, ev := range events {
		if ev.Name != "content_block_delta" {
			continue
		}
		var v struct {
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(ev.Data, &v); err != nil {
			t.Fatal(err)
		}
		if v.Delta.Type == "input_json_delta" {
			assembled.WriteString(v.Delta.PartialJSON)
		}
	}
	got := assembled.String()
	want := `{"file_path":"/etc/hosts"}`
	if got != want {
		t.Fatalf("partial_json reassembly:\n  got:  %s\n  want: %s", got, want)
	}
	// Final assembled fragment must parse as a JSON object.
	var obj map[string]any
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("assembled input not valid JSON object: %v", err)
	}
}

// TestStreamTranslatorToolUseNameRestored verifies that long tool names
// shortened at Convert time are restored to their original on the way out
// when the caller passes the name map.
func TestStreamTranslatorToolUseNameRestored(t *testing.T) {
	body := buildKiroStream([]frameSpec{
		{event: "toolUseEvent", payload: `{"toolUseId":"tu_2","name":"shortened_abc","input":"{}","stop":true}`},
	})
	stream := openTestStream(t, body)
	defer stream.Close()

	nm := ToolNameMap{}
	long := strings.Repeat("a_very_long_tool_name", 4) // > 63 chars; doesn't matter for the test
	nm.Apply("shortened_abc", long)

	tr := NewStreamTranslatorWithMap(stream, "claude-haiku-4-5", "msg_test", nm)
	events := drainEvents(tr)
	if err := tr.Err(); err != nil {
		t.Fatal(err)
	}
	var sawName string
	for _, ev := range events {
		if ev.Name != "content_block_start" {
			continue
		}
		var v struct {
			ContentBlock struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"content_block"`
		}
		if json.Unmarshal(ev.Data, &v) == nil && v.ContentBlock.Type == "tool_use" {
			sawName = v.ContentBlock.Name
		}
	}
	if sawName != long {
		t.Fatalf("tool name not restored: got %q, want %q", sawName, long)
	}
}

func TestSSEEventMarshal(t *testing.T) {
	e := SSEEvent{Name: "ping", Data: []byte(`{"a":1}`)}
	want := "event: ping\ndata: {\"a\":1}\n\n"
	if got := string(e.Marshal()); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// --- helpers ---

type frameSpec struct {
	event   string
	payload string
}

func buildKiroStream(specs []frameSpec) []byte {
	var out []byte
	for _, s := range specs {
		h := eventstream.NewHeaders()
		h.SetString(":message-type", "event")
		h.SetString(":event-type", s.event)
		out = append(out, eventstream.EncodeFrame(h, []byte(s.payload))...)
	}
	return out
}

func openTestStream(t *testing.T, body []byte) *kiroapi.Stream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", kirotransport.EventStreamContentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := &kiroapi.Client{
		HTTP:  &hostRewriter{base: srv.URL, next: srv.Client()},
		Token: "t",
	}
	stream, err := c.GenerateAssistantResponse(context.Background(), &kiroapi.GenerateAssistantResponseRequest{
		ConversationState: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func drainEvents(tr *StreamTranslator) []SSEEvent {
	var out []SSEEvent
	for tr.Next() {
		ev := tr.Event()
		data := make([]byte, len(ev.Data))
		copy(data, ev.Data)
		out = append(out, SSEEvent{Name: ev.Name, Data: data})
	}
	return out
}

func names(events []SSEEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Name
	}
	return out
}

func equalSeq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type hostRewriter struct {
	base string
	next *http.Client
}

func (r *hostRewriter) Do(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.base)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return r.next.Do(req)
}
