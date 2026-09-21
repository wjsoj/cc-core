package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodexAgentCacheHintsAndLiteDefaults(t *testing.T) {
	body := []byte(`{"model":"gpt-6-astra(high)","reasoning":{"effort":"low","summary":"auto"},"parallel_tool_calls":true,"generate":true,"prompt_cache_options":{},"input":[{"role":"user","prompt_cache_breakpoint":true,"content":[{"type":"input_text","text":"hi","prompt_cache_breakpoint":true}]},{"type":"function_call_output","call_id":"c","output":[{"type":"input_text","text":"result","prompt_cache_breakpoint":true}]}],"tools":[{"type":"function","name":"f","parameters":{"type":"object","properties":{"prompt_cache_breakpoint":{"const":9007199254740993}}}}]}`)
	out, _, err := SanitizeCodexRequestBody(body, "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["parallel_tool_calls"]) != "false" || strings.Contains(string(raw["input"]), "prompt_cache_breakpoint") {
		t.Fatalf("unsupported shape: %s", out)
	}
	if !strings.Contains(string(raw["tools"]), `9007199254740993`) || !strings.Contains(string(raw["tools"]), "prompt_cache_breakpoint") {
		t.Fatalf("schema corrupted: %s", out)
	}
	if strings.Contains(string(out), `"generate"`) || strings.Contains(string(out), "prompt_cache_options") || !strings.Contains(string(out), `"effort":"high"`) {
		t.Fatalf("normalization failed: %s", out)
	}
}

func TestCodexAgentMalformedBodyRejected(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/v1/responses/compact"} {
		for _, body := range []string{"null", "[]", "{} {}", ""} {
			if _, _, err := SanitizeCodexRequestBody([]byte(body), path); err == nil {
				t.Errorf("accepted %q on %s", body, path)
			}
		}
	}
}

func TestCodexAgentImageFunctionNotDuplicated(t *testing.T) {
	for _, tool := range []string{`{"type":"function","name":"image_gen.imagegen"}`, `{"type":"namespace","name":"image_gen","tools":[{"type":"function","name":"imagegen"}]}`} {
		out, _, err := SanitizeCodexRequestBody([]byte(`{"model":"gpt-5.5","input":"draw","tools":[`+tool+`]}`), "/v1/responses")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), `"type":"image_generation"`) {
			t.Fatalf("injected duplicate image tool: %s", out)
		}
	}
}
