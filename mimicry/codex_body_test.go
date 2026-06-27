package mimicry

import (
	"encoding/json"
	"testing"
)

func TestStripThinkingSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"with-suffix", "gpt-5.3-codex(high)", "gpt-5.3-codex"},
		{"no-suffix", "gpt-5.3-codex", "gpt-5.3-codex"},
		{"empty", "", ""},
		{"empty-group", "foo()", "foo"},
		{"open-at-start", "(x)", "(x)"},
		{"not-closed", "foo(high", "foo(high"},
		{"trailing-paren-no-open", "foo)", "foo)"},
		{"nested-take-last-open", "a(b)(c)", "a(b)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripThinkingSuffix(tc.in); got != tc.want {
				t.Fatalf("StripThinkingSuffix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCodexOAuthPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/v1/responses/compact", "/responses/compact"},
		{"/v1/responses", "/responses"},
		{"/v1/chat/completions", "/responses"},
		{"", "/responses"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := CodexOAuthPath(tc.in); got != tc.want {
				t.Fatalf("CodexOAuthPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// decode is a small helper to unmarshal sanitized output back into a map.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal sanitized body: %v\nbody: %s", err, b)
	}
	return m
}

func TestSanitizeCodexRequestBody_Regular(t *testing.T) {
	in := `{
		"model": "gpt-5.3-codex(high)",
		"input": "hello there",
		"temperature": 0.7,
		"top_p": 0.9,
		"user": "alice",
		"max_output_tokens": 100,
		"context_management": {"foo": "bar"},
		"previous_response_id": "resp_123",
		"stream": false
	}`
	out, baseModel, err := SanitizeCodexRequestBody([]byte(in), "/v1/responses")
	if err != nil {
		t.Fatalf("SanitizeCodexRequestBody error: %v", err)
	}
	if baseModel != "gpt-5.3-codex" {
		t.Fatalf("baseModel = %q, want %q", baseModel, "gpt-5.3-codex")
	}
	m := decode(t, out)

	// Forced fields.
	if m["model"] != "gpt-5.3-codex" {
		t.Errorf("model = %v, want gpt-5.3-codex", m["model"])
	}
	if m["stream"] != true {
		t.Errorf("stream = %v, want true", m["stream"])
	}
	if m["store"] != false {
		t.Errorf("store = %v, want false", m["store"])
	}
	if m["parallel_tool_calls"] != true {
		t.Errorf("parallel_tool_calls = %v, want true", m["parallel_tool_calls"])
	}
	include, ok := m["include"].([]any)
	if !ok || len(include) != 1 || include[0] != "reasoning.encrypted_content" {
		t.Errorf("include = %v, want [reasoning.encrypted_content]", m["include"])
	}

	// Deleted fields.
	for _, k := range []string{"temperature", "top_p", "user", "max_output_tokens", "context_management"} {
		if _, present := m[k]; present {
			t.Errorf("field %q should have been deleted", k)
		}
	}

	// Preserved field.
	if m["previous_response_id"] != "resp_123" {
		t.Errorf("previous_response_id = %v, want resp_123 (must be preserved)", m["previous_response_id"])
	}

	// String input promoted to message array.
	items, ok := m["input"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("input = %v, want single-element message array", m["input"])
	}
	msg, _ := items[0].(map[string]any)
	if msg["type"] != "message" || msg["role"] != "user" {
		t.Errorf("promoted input item = %v, want type=message role=user", msg)
	}
	content, _ := msg["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("input content = %v, want single text block", msg["content"])
	}
	tb, _ := content[0].(map[string]any)
	if tb["type"] != "input_text" || tb["text"] != "hello there" {
		t.Errorf("input text block = %v, want input_text 'hello there'", tb)
	}
}

func TestSanitizeCodexRequestBody_SystemToDeveloper(t *testing.T) {
	in := `{
		"model": "gpt-5.3-codex",
		"input": [
			{"type": "message", "role": "system", "content": [{"type": "input_text", "text": "be terse"}]},
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]}
		]
	}`
	out, _, err := SanitizeCodexRequestBody([]byte(in), "/v1/responses")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	m := decode(t, out)
	items, _ := m["input"].([]any)
	if len(items) != 2 {
		t.Fatalf("input items = %d, want 2", len(items))
	}
	first, _ := items[0].(map[string]any)
	if first["role"] != "developer" {
		t.Errorf("first item role = %v, want developer", first["role"])
	}
	second, _ := items[1].(map[string]any)
	if second["role"] != "user" {
		t.Errorf("second item role = %v, want user (unchanged)", second["role"])
	}
}

func TestSanitizeCodexRequestBody_Compact(t *testing.T) {
	in := `{
		"model": "gpt-5.3-codex(high)",
		"input": [{"type": "message", "role": "user", "content": []}],
		"instructions": "compact this",
		"previous_response_id": "resp_999",
		"tools": [{"type": "image_generation"}],
		"stream": true,
		"include": ["reasoning.encrypted_content"],
		"store": false,
		"temperature": 0.5
	}`
	out, baseModel, err := SanitizeCodexRequestBody([]byte(in), "/v1/responses/compact")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if baseModel != "gpt-5.3-codex" {
		t.Fatalf("baseModel = %q, want gpt-5.3-codex", baseModel)
	}
	m := decode(t, out)

	// Only whitelisted fields retained, model stripped.
	want := map[string]any{
		"model":                "gpt-5.3-codex",
		"instructions":         "compact this",
		"previous_response_id": "resp_999",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("compact[%q] = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["input"]; !ok {
		t.Errorf("compact must retain input")
	}
	// Everything else dropped.
	for _, k := range []string{"tools", "stream", "include", "store", "temperature", "parallel_tool_calls"} {
		if _, present := m[k]; present {
			t.Errorf("compact field %q should have been dropped", k)
		}
	}
}

func TestEnsureImageGenerationTool(t *testing.T) {
	imageType := func(v any) bool {
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, t := range arr {
			m, _ := t.(map[string]any)
			if m != nil && m["type"] == "image_generation" {
				return true
			}
		}
		return false
	}

	t.Run("spark-no-inject-nil", func(t *testing.T) {
		got := ensureImageGenerationTool(nil, "gpt-image-spark")
		arr, ok := got.([]any)
		if !ok || len(arr) != 0 {
			t.Fatalf("spark with nil tools = %v, want empty array", got)
		}
	})

	t.Run("spark-passthrough", func(t *testing.T) {
		existing := []any{map[string]any{"type": "web_search"}}
		got := ensureImageGenerationTool(existing, "gpt-image-spark")
		if imageType(got) {
			t.Fatalf("spark should not inject image_generation, got %v", got)
		}
		if arr, _ := got.([]any); len(arr) != 1 {
			t.Fatalf("spark should pass tools through unchanged, got %v", got)
		}
	})

	t.Run("inject-on-nil", func(t *testing.T) {
		got := ensureImageGenerationTool(nil, "gpt-5.3-codex")
		arr, _ := got.([]any)
		if len(arr) != 1 || !imageType(got) {
			t.Fatalf("normal model nil tools = %v, want [{image_generation}]", got)
		}
		tm, _ := arr[0].(map[string]any)
		if tm["output_format"] != "png" {
			t.Errorf("output_format = %v, want png", tm["output_format"])
		}
	})

	t.Run("append-when-absent", func(t *testing.T) {
		existing := []any{map[string]any{"type": "web_search"}}
		got := ensureImageGenerationTool(existing, "gpt-5.3-codex")
		arr, _ := got.([]any)
		if len(arr) != 2 || !imageType(got) {
			t.Fatalf("expected web_search + image_generation, got %v", got)
		}
	})

	t.Run("no-duplicate", func(t *testing.T) {
		existing := []any{map[string]any{"type": "image_generation", "output_format": "jpeg"}}
		got := ensureImageGenerationTool(existing, "gpt-5.3-codex")
		arr, _ := got.([]any)
		if len(arr) != 1 {
			t.Fatalf("should not duplicate image_generation, got %v", got)
		}
		// Existing entry preserved verbatim (not replaced).
		tm, _ := arr[0].(map[string]any)
		if tm["output_format"] != "jpeg" {
			t.Errorf("existing tool should be preserved, output_format = %v", tm["output_format"])
		}
	})
}

func TestJoinCodexAPIKeyUpstreamURL(t *testing.T) {
	cases := []struct {
		name, baseURL, path, want string
	}{
		// Bare-origin relay (new-api / one-api) — the bug report: must keep /v1.
		{"bare origin responses", "https://zz1cc.cc.cd", "/v1/responses", "https://zz1cc.cc.cd/v1/responses"},
		{"bare origin chat", "https://relay.example", "/v1/chat/completions", "https://relay.example/v1/chat/completions"},
		{"bare origin models", "https://relay.example", "/v1/models", "https://relay.example/v1/models"},
		{"bare origin trailing slash", "https://relay.example/", "/v1/responses", "https://relay.example/v1/responses"},
		{"bare origin with port", "https://relay.example:8080", "/v1/responses", "https://relay.example:8080/v1/responses"},
		// BaseURL already carries /v1 — strip inbound /v1, no doubling.
		{"openai v1", "https://api.openai.com/v1", "/v1/responses", "https://api.openai.com/v1/responses"},
		{"openai v1 models", "https://api.openai.com/v1", "/v1/models", "https://api.openai.com/v1/models"},
		// Custom gateway path — authoritative, strip /v1.
		{"gateway codex", "https://gateway.io/codex", "/v1/responses", "https://gateway.io/codex/responses"},
		{"gateway codex compact", "https://gateway.io/codex", "/v1/responses/compact", "https://gateway.io/codex/responses/compact"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := JoinCodexAPIKeyUpstreamURL(c.baseURL, c.path); got != c.want {
				t.Fatalf("JoinCodexAPIKeyUpstreamURL(%q, %q) = %q, want %q", c.baseURL, c.path, got, c.want)
			}
		})
	}
}
