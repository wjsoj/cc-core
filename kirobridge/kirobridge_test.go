package kirobridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/kiroapi"
	"github.com/wjsoj/cc-core/kirotransport"
	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

func TestMapModel(t *testing.T) {
	cases := map[string]string{
		"claude-sonnet-4-5-20250929":     "CLAUDE_SONNET_4_5_V1_0",
		"claude-sonnet-4-6":              "CLAUDE_SONNET_4_5_V1_0",
		"claude-opus-4-7":                "CLAUDE_OPUS_4_1_20250805_V1_0",
		"claude-3-5-haiku-20241022":      "CLAUDE_3_5_HAIKU_20241022_V1_0",
		"claude-haiku-4-5-20251001":      "CLAUDE_HAIKU_4_5_V1_0",
		"unknown-model-xyz":              "auto",
	}
	for in, want := range cases {
		if got := MapModel(in); got != want {
			t.Errorf("MapModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSystemStringAndArray(t *testing.T) {
	if got := parseSystem(json.RawMessage(`"hello"`)); got != "hello" {
		t.Fatalf("plain string: %q", got)
	}
	got := parseSystem(json.RawMessage(`[{"type":"text","text":"A"},{"type":"text","text":"B"}]`))
	if got != "A\n\nB" {
		t.Fatalf("array form: %q", got)
	}
	if parseSystem(nil) != "" {
		t.Fatal("nil should yield empty")
	}
}

func TestConvertBasicTextRequest(t *testing.T) {
	req := &AnthropicRequest{
		Model:     "claude-sonnet-4-5-20250929",
		MaxTokens: 1024,
		System:    json.RawMessage(`"You are helpful."`),
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
	}
	kr, err := Convert(req, ConvertOptions{ProfileARN: "arn:test"})
	if err != nil {
		t.Fatal(err)
	}
	if kr.ProfileARN != "arn:test" {
		t.Errorf("profileArn: %q", kr.ProfileARN)
	}
	cs := kr.ConversationState
	if cs.AgentTaskType != "vibe" || cs.ChatTriggerType != "MANUAL" {
		t.Errorf("defaults: task=%q trigger=%q", cs.AgentTaskType, cs.ChatTriggerType)
	}
	if cs.ConversationID == "" {
		t.Error("conversation_id should auto-derive")
	}
	got := cs.CurrentMessage.UserInputMessage.Content
	if !strings.Contains(got, "--- CONTEXT ENTRY BEGIN ---") || !strings.Contains(got, "You are helpful.") || !strings.Contains(got, "Hello") {
		t.Fatalf("merged content wrong: %q", got)
	}
	if cs.CurrentMessage.UserInputMessage.ModelID != "CLAUDE_SONNET_4_5_V1_0" {
		t.Errorf("modelId mapping: %q", cs.CurrentMessage.UserInputMessage.ModelID)
	}
}

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
	kr, err := Convert(req, ConvertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cs := kr.ConversationState
	if len(cs.History) != 2 {
		t.Fatalf("history len: %d", len(cs.History))
	}
	if cs.History[0].UserInputMessage == nil || cs.History[1].AssistantResponseMessage == nil {
		t.Fatalf("history shape wrong: %+v", cs.History)
	}
	if uses := cs.History[1].AssistantResponseMessage.ToolUses; len(uses) != 1 || uses[0].Name != "weather" {
		t.Fatalf("toolUses: %+v", uses)
	}
	tr := cs.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults
	if len(tr) != 1 || tr[0].ToolUseID != "tu_1" || tr[0].Status != "success" {
		t.Fatalf("toolResults: %+v", tr)
	}
	if len(tr[0].Content) != 1 || tr[0].Content[0]["text"] != "sunny, 72F" {
		t.Fatalf("toolResult content: %+v", tr[0].Content)
	}
	tools := cs.CurrentMessage.UserInputMessage.UserInputMessageContext.Tools
	if len(tools) != 1 || tools[0].ToolSpecification.Name != "weather" {
		t.Fatalf("tools: %+v", tools)
	}
}

func TestConvertRejectsAssistantLast(t *testing.T) {
	req := &AnthropicRequest{
		Model: "claude-sonnet-4-6",
		Messages: []AnthropicMessage{
			{Role: "assistant", Content: json.RawMessage(`"hi"`)},
		},
	}
	_, err := Convert(req, ConvertOptions{})
	if err == nil {
		t.Fatal("expected error when last message is assistant")
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
	kr, _ := Convert(req, ConvertOptions{})
	tr := kr.ConversationState.CurrentMessage.UserInputMessage.UserInputMessageContext.ToolResults[0]
	if tr.Status != "error" || !tr.IsError {
		t.Fatalf("error tool result: %+v", tr)
	}
}

func TestDeriveConversationIDStable(t *testing.T) {
	a := deriveConversationID([]AnthropicMessage{
		{Role: "user", Content: json.RawMessage(`"x"`)},
	})
	b := deriveConversationID([]AnthropicMessage{
		{Role: "user", Content: json.RawMessage(`"x"`)},
	})
	if a != b {
		t.Fatalf("not stable: %q vs %q", a, b)
	}
	c := deriveConversationID([]AnthropicMessage{
		{Role: "user", Content: json.RawMessage(`"y"`)},
	})
	if a == c {
		t.Fatal("different inputs should differ")
	}
}

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

	names := names(events)
	want := []string{"message_start", "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	if !equalSeq(names, want) {
		t.Fatalf("event sequence:\n  got:  %v\n  want: %v", names, want)
	}
	// Verify text accumulates correctly.
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
	// Should see: message_start, cb_start(text), cb_delta(text), cb_stop(text),
	// cb_start(tool_use), cb_delta(input_json), cb_delta(input_json), cb_stop(tool_use),
	// message_delta (stop_reason=tool_use), message_stop
	names := names(events)
	if names[0] != "message_start" || names[len(names)-1] != "message_stop" {
		t.Fatalf("framing wrong: %v", names)
	}
	// Find the message_delta and check stop_reason.
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
		// Defensive copy because Data may share buffer with the next call.
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

// Keep `bytes` and `io` imports used in case of future tests.
var _ = bytes.NewReader
var _ = io.EOF
