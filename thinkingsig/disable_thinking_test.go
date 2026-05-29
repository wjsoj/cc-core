package thinkingsig

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIsThinkingError(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"signature", `{"error":{"message":"messages.5.content.0: Invalid ` + "`signature`" + ` in ` + "`thinking`" + ` block"}}`, true},
		{"cannot be modified", `{"error":{"type":"invalid_request_error","message":"messages.3.content.8: ` + "`thinking`" + ` or ` + "`redacted_thinking`" + ` blocks in the latest assistant message cannot be modified. These blocks must remain as they were in the original response."}}`, true},
		{"unrelated 500", `{"error":{"message":"internal server error"}}`, false},
		{"unrelated model", `{"error":{"message":"No available channel for model claude-haiku-4-5-20251001"}}`, false},
	}
	for _, c := range cases {
		if got := IsThinkingError([]byte(c.body)); got != c.want {
			t.Errorf("%s: IsThinkingError=%v want %v", c.name, got, c.want)
		}
	}
}

func TestDisableThinking(t *testing.T) {
	in := []byte(`{
		"model":"claude-opus-4-8",
		"thinking":{"type":"enabled","budget_tokens":10000},
		"messages":[
			{"role":"user","content":"do a thing"},
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"reasoning","signature":"sig_A"},
				{"type":"tool_use","id":"tu_1","name":"bash","input":{},"signature":"bad"}
			]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"ok"}]}
		]
	}`)
	out := DisableThinking(in)
	if bytes.Equal(out, in) {
		t.Fatal("DisableThinking made no change")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if _, has := obj["thinking"]; has {
		t.Error("top-level thinking field not removed")
	}
	var msgs []struct {
		Role    string            `json:"role"`
		Content []json.RawMessage `json:"content"`
	}
	_ = json.Unmarshal(obj["messages"], &msgs)
	asst := msgs[1]
	if asst.Role != "assistant" {
		t.Fatalf("expected assistant at index 1, got %s", asst.Role)
	}
	// thinking block dropped, tool_use kept but its signature stripped.
	if len(asst.Content) != 1 {
		t.Fatalf("expected 1 block (tool_use) after disable, got %d", len(asst.Content))
	}
	var blk map[string]json.RawMessage
	_ = json.Unmarshal(asst.Content[0], &blk)
	var typ string
	_ = json.Unmarshal(blk["type"], &typ)
	if typ != "tool_use" {
		t.Fatalf("remaining block should be tool_use, got %s", typ)
	}
	if _, has := blk["signature"]; has {
		t.Error("tool_use signature not stripped")
	}
	// tool_result in the following user turn must be preserved (loop continuity).
	if msgs[2].Role != "user" || len(msgs[2].Content) != 1 {
		t.Error("tool_result user turn altered")
	}
}

func TestDisableThinkingNoopWhenNothingToStrip(t *testing.T) {
	in := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`)
	if out := DisableThinking(in); !bytes.Equal(out, in) {
		t.Errorf("expected no change, got %s", out)
	}
}
