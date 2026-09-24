package mimicry

import (
	"encoding/json"
	"testing"
)

func TestGPT6OAuthUsesResponsesLite(t *testing.T) {
	for _, model := range []string{"gpt-6-sol", "gpt-6-luna", "gpt-6-sol(ultra)", "gpt-6-luna(max)"} {
		for _, path := range []string{"/v1/responses", "/v1/responses/compact"} {
			body, _ := json.Marshal(map[string]any{"model": model, "input": "hello", "parallel_tool_calls": true})
			out, _, err := SanitizeCodexRequestBody(body, path)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			if path == "/v1/responses" && got["parallel_tool_calls"] != false {
				t.Errorf("%s: parallel tools enabled: %s", model, out)
			}
			if tools, ok := got["tools"].([]any); ok && len(tools) != 0 {
				t.Errorf("%s: injected unsupported tool: %s", model, out)
			}
		}
	}
}
