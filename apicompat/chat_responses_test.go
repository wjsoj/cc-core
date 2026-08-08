package apicompat

import (
	"encoding/json"
	"testing"
)

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, b)
	}
	return m
}

func convert(t *testing.T, body string) map[string]any {
	t.Helper()
	out, err := ChatCompletionsToResponses([]byte(body))
	if err != nil {
		t.Fatalf("ChatCompletionsToResponses: %v", err)
	}
	return decodeJSON(t, out)
}

func TestChatToResponsesBasic(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-5.6-sol",
		"messages": [
			{"role": "system", "content": "be terse"},
			{"role": "system", "content": "and polite"},
			{"role": "user", "content": "hi"}
		],
		"reasoning_effort": "high"
	}`)

	if got["model"] != "gpt-5.6-sol" {
		t.Errorf("model = %v", got["model"])
	}
	// System messages stay as input items in order. `instructions` is left
	// alone so a client prompt cannot displace the field the Codex backend
	// expects to hold the CLI's own prompt.
	if _, ok := got["instructions"]; ok {
		t.Errorf("instructions synthesized from system messages: %v", got["instructions"])
	}
	reasoning, _ := got["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" || reasoning["summary"] != "auto" {
		t.Errorf("reasoning = %v", got["reasoning"])
	}

	input, _ := got["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("input len = %d, want system+system+user", len(input))
	}
	for i, want := range []string{"be terse", "and polite"} {
		sys, _ := input[i].(map[string]any)
		if sys["role"] != "system" {
			t.Errorf("input[%d].role = %v, want system", i, sys["role"])
		}
		parts, _ := sys["content"].([]any)
		part, _ := parts[0].(map[string]any)
		if part["text"] != want {
			t.Errorf("input[%d] text = %v, want %q", i, part["text"], want)
		}
	}
	item, _ := input[2].(map[string]any)
	if item["type"] != "message" || item["role"] != "user" {
		t.Fatalf("input[2] = %v", item)
	}
	parts, _ := item["content"].([]any)
	part, _ := parts[0].(map[string]any)
	if part["type"] != "input_text" || part["text"] != "hi" {
		t.Errorf("user content part = %v", part)
	}
}

func TestChatToResponsesSamplingParamsOnlyForNonReasoningModels(t *testing.T) {
	// gpt-5.x rejects temperature/top_p on Responses.
	got := convert(t, `{"model":"gpt-5.6-sol","temperature":0.7,"top_p":0.9,
		"messages":[{"role":"user","content":"hi"}]}`)
	if _, ok := got["temperature"]; ok {
		t.Errorf("temperature forwarded to a reasoning model: %v", got)
	}
	if _, ok := got["top_p"]; ok {
		t.Errorf("top_p forwarded to a reasoning model: %v", got)
	}

	got = convert(t, `{"model":"gpt-4o","temperature":0.7,
		"messages":[{"role":"user","content":"hi"}]}`)
	if got["temperature"] != 0.7 {
		t.Errorf("temperature dropped for a non-reasoning model: %v", got)
	}
}

func TestChatToResponsesMaxTokens(t *testing.T) {
	// max_completion_tokens is the current field and wins over max_tokens.
	got := convert(t, `{"model":"gpt-5.6-sol","max_tokens":4000,"max_completion_tokens":2000,
		"messages":[{"role":"user","content":"hi"}]}`)
	if got["max_output_tokens"].(float64) != 2000 {
		t.Errorf("max_output_tokens = %v, want 2000", got["max_output_tokens"])
	}

	// A tiny cap is raised to the floor: reasoning models spend the whole
	// budget on hidden reasoning and return an empty message otherwise.
	got = convert(t, `{"model":"gpt-5.6-sol","max_tokens":16,
		"messages":[{"role":"user","content":"hi"}]}`)
	if got["max_output_tokens"].(float64) != minMaxOutputTokens {
		t.Errorf("max_output_tokens = %v, want floor %d", got["max_output_tokens"], minMaxOutputTokens)
	}

	got = convert(t, `{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"hi"}]}`)
	if _, ok := got["max_output_tokens"]; ok {
		t.Errorf("max_output_tokens invented without a client cap: %v", got)
	}
}

func TestChatToResponsesToolRoundTrip(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-5.6-sol",
		"messages": [
			{"role": "user", "content": "weather?"},
			{"role": "assistant", "content": "checking",
			 "tool_calls": [{"id": "call_1", "type": "function",
			                 "function": {"name": "get_weather", "arguments": "{\"city\":\"HK\"}"}}]},
			{"role": "tool", "tool_call_id": "call_1", "content": "22C"}
		],
		"tools": [{"type": "function", "function": {
			"name": "get_weather", "description": "look up",
			"parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}],
		"tool_choice": {"type": "function", "function": {"name": "get_weather"}}
	}`)

	input, _ := got["input"].([]any)
	wantTypes := []string{"message", "message", "function_call", "function_call_output"}
	if len(input) != len(wantTypes) {
		t.Fatalf("input len = %d, want %d", len(input), len(wantTypes))
	}
	for i, want := range wantTypes {
		m, _ := input[i].(map[string]any)
		if m["type"] != want {
			t.Fatalf("input[%d].type = %v, want %v", i, m["type"], want)
		}
	}

	// Assistant text must use output_text; the backend rejects input_text
	// for that role.
	assistant, _ := input[1].(map[string]any)
	aparts, _ := assistant["content"].([]any)
	apart, _ := aparts[0].(map[string]any)
	if apart["type"] != "output_text" {
		t.Errorf("assistant part type = %v, want output_text", apart["type"])
	}

	call, _ := input[2].(map[string]any)
	if call["call_id"] != "call_1" || call["name"] != "get_weather" || call["arguments"] != `{"city":"HK"}` {
		t.Errorf("function_call = %v", call)
	}
	result, _ := input[3].(map[string]any)
	if result["call_id"] != "call_1" || result["output"] != "22C" {
		t.Errorf("function_call_output = %v", result)
	}

	tools, _ := got["tools"].([]any)
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "get_weather" || tool["description"] != "look up" {
		t.Errorf("tool = %v", tool)
	}
	// An absent strict is pinned to false rather than left to the backend.
	if tool["strict"] != false {
		t.Errorf("tool.strict = %v, want false", tool["strict"])
	}
	if _, nested := tool["function"]; nested {
		t.Errorf("tool kept chat's function nesting: %v", tool)
	}
	tc, _ := got["tool_choice"].(map[string]any)
	if tc["type"] != "function" || tc["name"] != "get_weather" {
		t.Errorf("tool_choice = %v", tc)
	}
}

func TestChatToResponsesLegacyFunctions(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hi"}],
		"functions": [{"name": "f", "description": "d"}],
		"function_call": {"name": "f"}
	}`)
	tools, _ := got["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("legacy functions[] not converted: %v", got["tools"])
	}
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "f" {
		t.Errorf("tool = %v", tool)
	}
	// A function with no schema still needs a valid empty object schema.
	params, _ := tool["parameters"].(map[string]any)
	if params["type"] != "object" || params["properties"] == nil {
		t.Errorf("parameters = %v, want an empty object schema", params)
	}
	tc, _ := got["tool_choice"].(map[string]any)
	if tc["type"] != "function" || tc["name"] != "f" {
		t.Errorf("tool_choice from legacy function_call = %v", got["tool_choice"])
	}
}

func TestChatToResponsesToolParametersGetProperties(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}]
	}`)
	tools, _ := got["tools"].([]any)
	tool, _ := tools[0].(map[string]any)
	params, _ := tool["parameters"].(map[string]any)
	if params["properties"] == nil {
		t.Errorf("object schema missing required properties: %v", params)
	}
}

func TestChatToResponsesMultimodal(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-5.6-sol",
		"messages": [{"role": "user", "content": [
			{"type": "text", "text": "what is this"},
			{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
			{"type": "image_url", "image_url": {"url": "data:image/png;base64,"}}
		]}]
	}`)
	input, _ := got["input"].([]any)
	item, _ := input[0].(map[string]any)
	parts, _ := item["content"].([]any)
	// The empty data URI is dropped — forwarding it makes the upstream reject
	// the whole request.
	if len(parts) != 2 {
		t.Fatalf("parts = %v, want text + one image", parts)
	}
	img, _ := parts[1].(map[string]any)
	if img["type"] != "input_image" || img["image_url"] != "data:image/png;base64,AAAA" {
		t.Errorf("image part = %v", img)
	}
}

func TestChatToResponsesAssistantReasoningPreserved(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-5.6-sol",
		"messages": [
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": "answer", "reasoning_content": "thought"},
			{"role": "user", "content": "again"}
		]
	}`)
	input, _ := got["input"].([]any)
	assistant, _ := input[1].(map[string]any)
	parts, _ := assistant["content"].([]any)
	part, _ := parts[0].(map[string]any)
	if part["text"] != "<thinking>thought</thinking>\nanswer" {
		t.Errorf("assistant text = %q", part["text"])
	}
}

func TestChatToResponsesResponseFormat(t *testing.T) {
	got := convert(t, `{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "hi"}],
		"response_format": {"type":"json_schema","json_schema":{"name":"x","schema":{"type":"object"}}}
	}`)
	text, _ := got["text"].(map[string]any)
	format, _ := text["format"].(map[string]any)
	// Responses inlines the schema fields and keeps the type tag.
	if format["type"] != "json_schema" || format["name"] != "x" || format["schema"] == nil {
		t.Errorf("text.format = %v", format)
	}
}

func TestChatToResponsesRejectsUnusableBodies(t *testing.T) {
	for _, body := range []string{
		`not json`,
		`{"model":"m"}`,
		// Nothing that maps to an input item at all.
		`{"model":"m","messages":[{"role":"user","content":""}]}`,
	} {
		if _, err := ChatCompletionsToResponses([]byte(body)); err == nil {
			t.Errorf("expected error for %s", body)
		}
	}
}
