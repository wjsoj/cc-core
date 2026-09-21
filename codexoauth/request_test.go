package codexoauth

import (
	"strings"
	"testing"
)

func TestPrepareCodexAgentRoundTripInput(t *testing.T) {
	request, err := PrepareCodexRequest([]byte(`{"model":"gpt-5.6-sol(high)","messages":[{"role":"user","content":"run"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"run","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"}],"tools":[{"type":"function","function":{"name":"run","parameters":{"type":"object","properties":{"n":{"const":9007199254740993}}}}}]}`), "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if !request.Chat || request.Path != "/v1/responses" || request.Model != "gpt-5.6-sol" {
		t.Fatalf("wrong routing: %+v", request)
	}
	body := string(request.Body)
	for _, want := range []string{`"type":"function_call_output"`, `"call_id":"call_1"`, `"effort":"high"`, `"parallel_tool_calls":false`, `9007199254740993`, `"stream":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s: %s", want, body)
		}
	}
}
