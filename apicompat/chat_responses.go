// Package apicompat translates between the two OpenAI request/response
// protocols this proxy has to bridge: Chat Completions
// (POST /v1/chat/completions) and Responses (POST /v1/responses).
//
// It exists because the ChatGPT Codex backend — the upstream behind every
// ChatGPT subscription OAuth credential — hosts only /codex/responses. Without
// a bridge, every OpenAI-compatible client (Cherry Studio, OpenWebUI,
// LangChain, a bare `openai` SDK) is structurally unroutable to a subscription
// credential and can only be served by a paid relay API key, no matter how idle
// the subscription accounts are. That is a protocol gap, not a scheduling one,
// so it cannot be fixed in the credential pool.
//
// The package is pure data translation: no HTTP, no gin, no credential
// awareness. Callers own transport, keepalive and billing; they feed bytes in
// and get bytes out. Streaming is a small state machine (StreamState) that maps
// each Responses SSE event onto zero or more chat.completion.chunk frames.
//
// Field mappings and edge cases (legacy functions[]/function_call, the 128
// max_output_tokens floor, reasoning models rejecting sampling parameters,
// json_schema response_format, incomplete_details → finish_reason) follow the
// behaviour of the LGPL project github.com/Wei-Shaw/sub2api, whose gateway
// covers the same protocol pair in production. The mappings are facts about
// the two APIs; this is an independent MIT implementation of them, not a port
// of that code.
package apicompat

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
)

// minMaxOutputTokens is the floor applied when a Chat Completions max_tokens is
// carried over to Responses. Very small caps make reasoning models spend the
// whole budget on hidden reasoning and return an empty message, which surfaces
// to the user as a silent blank reply.
const minMaxOutputTokens = 128

// ---------------------------------------------------------------------------
// Request: Chat Completions → Responses
// ---------------------------------------------------------------------------

// ChatCompletionsToResponses rewrites a Chat Completions request body into a
// Responses request body.
//
// The result is a generic Responses request. Callers targeting the Codex
// backend should still run it through mimicry.SanitizeCodexRequestBody, which
// owns that backend's narrower whitelist (it drops temperature/top_p/
// max_output_tokens, forces stream/store/include, and so on). Duplicating that
// whitelist here would let the two drift.
//
// An error means the body cannot be represented as a Responses request at all
// (malformed JSON, no messages, nothing that maps to an input item). Callers
// should treat it as "this credential can't serve the request" rather than as
// a client error: an API-key credential forwards chat/completions verbatim and
// may well accept the same body.
func ChatCompletionsToResponses(body []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode chat/completions body: %w", err)
	}
	msgs, _ := raw["messages"].([]any)
	if len(msgs) == 0 {
		return nil, fmt.Errorf("chat/completions body has no messages")
	}

	out := map[string]any{}
	model, _ := raw["model"].(string)
	if model != "" {
		out["model"] = model
	}
	for _, k := range []string{"parallel_tool_calls", "previous_response_id", "metadata", "service_tier"} {
		if v, ok := raw[k]; ok {
			out[k] = v
		}
	}
	// Reasoning models reject sampling parameters on Responses
	// ("Unsupported parameter: temperature"), so they are carried over only
	// for non-reasoning models.
	if !isReasoningModel(model) {
		for _, k := range []string{"temperature", "top_p"} {
			if v, ok := raw[k]; ok {
				out[k] = v
			}
		}
	}
	// max_completion_tokens is the current field and wins over the legacy
	// max_tokens when a client sends both.
	if n, ok := maxOutputTokens(raw); ok {
		out["max_output_tokens"] = n
	}
	// Chat's flat reasoning_effort is Responses' nested reasoning object. An
	// explicit `reasoning` wins — some clients send both.
	if v, ok := raw["reasoning"]; ok {
		out["reasoning"] = v
	} else if eff, ok := raw["reasoning_effort"].(string); ok && eff != "" {
		out["reasoning"] = map[string]any{"effort": eff, "summary": "auto"}
	}
	if format := responseFormatToTextFormat(raw["response_format"]); format != nil {
		out["text"] = map[string]any{"format": format}
	}

	instructions, input, err := chatMessagesToResponsesInput(msgs)
	if err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("chat/completions body produced no input items")
	}
	out["input"] = input
	if instructions != "" {
		out["instructions"] = instructions
	}
	if tools := chatToolsToResponses(raw["tools"], raw["functions"]); len(tools) > 0 {
		out["tools"] = tools
	}
	// tool_choice is already schema-compatible apart from the forced-function
	// object; the legacy function_call field needs mapping.
	if tc, ok := chatToolChoiceToResponses(raw["tool_choice"]); ok {
		out["tool_choice"] = tc
	} else if fc, ok := legacyFunctionCallToToolChoice(raw["function_call"]); ok {
		out["tool_choice"] = fc
	}
	return json.Marshal(out)
}

// isReasoningModel reports whether the model rejects sampling parameters on the
// Responses API. The whole gpt-5 line is reasoning-only.
func isReasoningModel(model string) bool {
	return strings.HasPrefix(model, "gpt-5")
}

// maxOutputTokens resolves the Chat Completions output cap onto Responses'
// max_output_tokens, applying the floor. Returns ok=false when the client set
// no cap.
func maxOutputTokens(raw map[string]any) (int, bool) {
	n := 0
	if v, ok := raw["max_tokens"].(float64); ok && v > 0 {
		n = int(v)
	}
	if v, ok := raw["max_completion_tokens"].(float64); ok && v > 0 {
		n = int(v)
	}
	if n <= 0 {
		return 0, false
	}
	if n < minMaxOutputTokens {
		n = minMaxOutputTokens
	}
	return n, true
}

// chatMessagesToResponsesInput splits a Chat Completions messages array into
// the out-of-band instructions string and the Responses input items.
func chatMessagesToResponsesInput(msgs []any) (instructions string, input []any, err error) {
	var systems []string
	input = make([]any, 0, len(msgs))
	for _, mv := range msgs {
		m, _ := mv.(map[string]any)
		if m == nil {
			continue
		}
		switch role, _ := m["role"].(string); role {
		case "system", "developer":
			// Responses carries the system prompt out-of-band. Concatenating
			// keeps multi-system-message clients working; emitting developer
			// input items instead reorders badly once tool results interleave.
			if t := flattenContentText(m["content"]); t != "" {
				systems = append(systems, t)
			}
		case "tool", "function":
			callID, _ := m["tool_call_id"].(string)
			if callID == "" {
				callID, _ = m["name"].(string)
			}
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": callID,
				"output":  flattenContentText(m["content"]),
			})
		case "assistant":
			input = append(input, assistantToResponsesItems(m)...)
		default: // user, and anything unrecognised — treat as user input.
			parts := contentParts(m["content"], "input_text")
			if len(parts) == 0 {
				continue
			}
			input = append(input, map[string]any{
				"type": "message", "role": "user", "content": parts,
			})
		}
	}
	return strings.Join(systems, "\n\n"), input, nil
}

// assistantToResponsesItems renders one assistant turn as Responses items: at
// most one message item, then one function_call item per tool call.
func assistantToResponsesItems(m map[string]any) []any {
	var items []any
	var text strings.Builder

	// Prior reasoning is preserved as tagged text rather than dropped: without
	// it a multi-turn conversation loses the assistant's own chain of thought,
	// and Responses has no assistant-side reasoning input item we can replay.
	if rc, _ := m["reasoning_content"].(string); rc != "" {
		text.WriteString("<thinking>" + rc + "</thinking>")
	}
	if s := flattenContentText(m["content"]); s != "" {
		if text.Len() > 0 {
			text.WriteString("\n")
		}
		text.WriteString(s)
	}
	if text.Len() > 0 {
		items = append(items, map[string]any{
			"type": "message", "role": "assistant",
			// Assistant text must be output_text; the backend rejects
			// input_text for this role.
			"content": []any{map[string]any{"type": "output_text", "text": text.String()}},
		})
	}

	calls, _ := m["tool_calls"].([]any)
	for _, cv := range calls {
		cm, _ := cv.(map[string]any)
		if cm == nil {
			continue
		}
		fn, _ := cm["function"].(map[string]any)
		name, _ := fn["name"].(string)
		args, _ := fn["arguments"].(string)
		callID, _ := cm["id"].(string)
		if args == "" {
			args = "{}"
		}
		items = append(items, map[string]any{
			"type": "function_call", "call_id": callID,
			"name": name, "arguments": args,
		})
	}
	return items
}

// flattenContentText reduces a Chat message `content` (string, or array of
// content parts) to plain text, for the places Responses wants a bare string.
func flattenContentText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, pv := range v {
			p, _ := pv.(map[string]any)
			if p == nil {
				continue
			}
			if t, _ := p["text"].(string); t != "" {
				b.WriteString(t)
			}
		}
		return b.String()
	}
	return ""
}

// contentParts converts a Chat message `content` into Responses content parts.
// textType selects the per-role text part name ("input_text" for user,
// "output_text" for assistant) — the wrong one for the role is rejected.
func contentParts(content any, textType string) []any {
	switch v := content.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []any{map[string]any{"type": textType, "text": v}}
	case []any:
		parts := make([]any, 0, len(v))
		for _, pv := range v {
			p, _ := pv.(map[string]any)
			if p == nil {
				continue
			}
			switch t, _ := p["type"].(string); t {
			case "text", "input_text", "output_text":
				if s, _ := p["text"].(string); s != "" {
					parts = append(parts, map[string]any{"type": textType, "text": s})
				}
			case "image_url", "input_image":
				if url := imagePartURL(p); url != "" {
					parts = append(parts, map[string]any{"type": "input_image", "image_url": url})
				}
			}
		}
		return parts
	}
	return nil
}

// imagePartURL extracts the URL from either content-part spelling: Chat nests
// it under image_url.url, Responses keeps it flat. An empty base64 data URI —
// what several clients emit for an image that failed to load — is dropped,
// since forwarding it makes the upstream reject the whole request.
func imagePartURL(p map[string]any) string {
	url := ""
	switch iu := p["image_url"].(type) {
	case map[string]any:
		url, _ = iu["url"].(string)
	case string:
		url = iu
	}
	if url == "" {
		url, _ = p["url"].(string)
	}
	if isEmptyDataURI(url) {
		return ""
	}
	return url
}

func isEmptyDataURI(url string) bool {
	if !strings.HasPrefix(url, "data:") {
		return false
	}
	idx := strings.Index(url, ",")
	return idx >= 0 && strings.TrimSpace(url[idx+1:]) == ""
}

// chatToolsToResponses flattens Chat's {type:"function",function:{…}} wrapper
// into the Responses shape, which hoists name/description/parameters to the top
// level, and folds in the legacy top-level functions[] array. Already-flat
// entries (a client speaking Responses tools on the chat route) pass through.
func chatToolsToResponses(toolsV, functionsV any) []any {
	var out []any
	tools, _ := toolsV.([]any)
	for _, tv := range tools {
		t, _ := tv.(map[string]any)
		if t == nil {
			continue
		}
		fn, ok := t["function"].(map[string]any)
		if !ok {
			// Flat entry: still normalize its schema.
			if _, has := t["parameters"]; has {
				t["parameters"] = normalizeToolParameters(t["parameters"])
			}
			out = append(out, t)
			continue
		}
		out = append(out, flattenFunctionTool(fn))
	}
	// Legacy functions[]: same payload, one nesting level less.
	functions, _ := functionsV.([]any)
	for _, fv := range functions {
		fn, _ := fv.(map[string]any)
		if fn == nil {
			continue
		}
		out = append(out, flattenFunctionTool(fn))
	}
	return out
}

func flattenFunctionTool(fn map[string]any) map[string]any {
	flat := map[string]any{"type": "function"}
	for _, k := range []string{"name", "description", "strict"} {
		if v, ok := fn[k]; ok {
			flat[k] = v
		}
	}
	flat["parameters"] = normalizeToolParameters(fn["parameters"])
	return flat
}

// normalizeToolParameters fills in the parts of a JSON Schema that Responses
// requires but Chat tolerates omitting: an object schema must carry
// `properties`, and a missing schema must still be a valid empty object.
func normalizeToolParameters(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok || len(m) == 0 {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	if t, _ := m["type"].(string); t == "object" {
		if _, has := m["properties"]; !has {
			m["properties"] = map[string]any{}
		}
	}
	return m
}

// chatToolChoiceToResponses maps Chat's tool_choice onto the Responses form.
// String modes are identical; the forced-function object loses its nesting.
func chatToolChoiceToResponses(v any) (any, bool) {
	switch tc := v.(type) {
	case string:
		return tc, tc != ""
	case map[string]any:
		if fn, ok := tc["function"].(map[string]any); ok {
			name, _ := fn["name"].(string)
			return map[string]any{"type": "function", "name": name}, name != ""
		}
		return tc, true
	}
	return nil, false
}

// legacyFunctionCallToToolChoice maps the pre-tools `function_call` field onto
// tool_choice. "none"/"auto" carry over verbatim; {"name":…} becomes a forced
// function choice.
func legacyFunctionCallToToolChoice(v any) (any, bool) {
	switch fc := v.(type) {
	case string:
		return fc, fc != ""
	case map[string]any:
		name, _ := fc["name"].(string)
		if name == "" {
			return nil, false
		}
		return map[string]any{"type": "function", "name": name}, true
	}
	return nil, false
}

// responseFormatToTextFormat maps Chat's response_format onto Responses'
// text.format. The json_schema variant differs: Chat wraps the schema in a
// `json_schema` object, Responses inlines its fields and keeps the type tag.
func responseFormatToTextFormat(v any) any {
	rf, ok := v.(map[string]any)
	if !ok || len(rf) == 0 {
		return nil
	}
	if t, _ := rf["type"].(string); t != "json_schema" {
		return rf
	}
	inner, ok := rf["json_schema"].(map[string]any)
	if !ok {
		return rf
	}
	out := make(map[string]any, len(inner)+1)
	maps.Copy(out, inner)
	out["type"] = "json_schema"
	return out
}
