package apicompat

import (
	"strings"
	"testing"
)

func TestResponsesToChatCompletion(t *testing.T) {
	out, err := ResponsesToChatCompletion([]byte(`{
		"id": "resp_abc",
		"model": "gpt-5.6-sol",
		"status": "completed",
		"output": [
			{"type": "reasoning", "summary": [{"text": "hmm"}]},
			{"type": "message", "content": [{"type": "output_text", "text": "hello"}]},
			{"type": "function_call", "call_id": "call_9", "name": "f", "arguments": "{}"}
		],
		"usage": {"input_tokens": 100, "output_tokens": 7, "total_tokens": 107,
		          "input_tokens_details": {"cached_tokens": 40}}
	}`), "gpt-5.6-sol-alias", 1700000000)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got := decodeJSON(t, out)

	if got["object"] != "chat.completion" {
		t.Errorf("object = %v", got["object"])
	}
	// The client's requested model is echoed back, not the upstream's.
	if got["model"] != "gpt-5.6-sol-alias" {
		t.Errorf("model = %v", got["model"])
	}
	if got["id"] != "chatcmpl-abc" {
		t.Errorf("id = %v", got["id"])
	}

	choices, _ := got["choices"].([]any)
	choice, _ := choices[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
	msg, _ := choice["message"].(map[string]any)
	// Reasoning must not leak into the answer text.
	if msg["content"] != "hello" {
		t.Errorf("content = %q", msg["content"])
	}
	if msg["reasoning_content"] != "hmm" {
		t.Errorf("reasoning_content = %v", msg["reasoning_content"])
	}
	calls, _ := msg["tool_calls"].([]any)
	call, _ := calls[0].(map[string]any)
	if call["id"] != "call_9" {
		t.Errorf("tool_call = %v", call)
	}

	u, _ := got["usage"].(map[string]any)
	if u["prompt_tokens"].(float64) != 100 || u["completion_tokens"].(float64) != 7 || u["total_tokens"].(float64) != 107 {
		t.Errorf("usage = %v", u)
	}
	details, _ := u["prompt_tokens_details"].(map[string]any)
	if details["cached_tokens"].(float64) != 40 {
		t.Errorf("prompt_tokens_details = %v", details)
	}
}

func TestResponsesToChatCompletionIncompleteReasons(t *testing.T) {
	cases := map[string]string{
		"max_output_tokens": "length",
		"content_filter":    "content_filter",
		"something_else":    "stop",
	}
	for reason, want := range cases {
		out, err := ResponsesToChatCompletion([]byte(`{
			"id":"resp_1","status":"incomplete",
			"incomplete_details":{"reason":"`+reason+`"},
			"output":[{"type":"message","content":[{"type":"output_text","text":"x"}]}]
		}`), "m", 0)
		if err != nil {
			t.Fatalf("convert: %v", err)
		}
		choices, _ := decodeJSON(t, out)["choices"].([]any)
		choice, _ := choices[0].(map[string]any)
		if choice["finish_reason"] != want {
			t.Errorf("incomplete_details.reason=%s → finish_reason=%v, want %s", reason, choice["finish_reason"], want)
		}
	}
}

// collectFrames runs backend SSE payloads through the stream converter and
// returns the decoded chat frames plus whether the stream terminated.
func collectFrames(t *testing.T, st *StreamState, payloads ...string) ([]map[string]any, bool) {
	t.Helper()
	var chunks []map[string]any
	terminal := false
	for _, p := range payloads {
		frames, term := st.Translate([]byte(p))
		if term {
			terminal = true
		}
		for _, f := range frames {
			if IsDoneFrame(f) {
				chunks = append(chunks, map[string]any{"__done": true})
				continue
			}
			body := strings.TrimSuffix(strings.TrimPrefix(string(f), "data: "), "\n\n")
			chunks = append(chunks, decodeJSON(t, []byte(body)))
		}
	}
	return chunks, terminal
}

func deltaOf(t *testing.T, chunk map[string]any) map[string]any {
	t.Helper()
	choices, _ := chunk["choices"].([]any)
	if len(choices) == 0 {
		return nil
	}
	c, _ := choices[0].(map[string]any)
	d, _ := c["delta"].(map[string]any)
	return d
}

func finishOf(chunk map[string]any) string {
	choices, _ := chunk["choices"].([]any)
	if len(choices) == 0 {
		return ""
	}
	c, _ := choices[0].(map[string]any)
	fr, _ := c["finish_reason"].(string)
	return fr
}

func TestStreamTextDeltas(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 1700000000)
	chunks, terminal := collectFrames(t, st,
		`{"type":"response.created","response":{"id":"resp_z"}}`,
		`{"type":"response.in_progress"}`,
		`{"type":"response.output_text.delta","delta":"he"}`,
		`{"type":"response.output_text.delta","delta":"llo"}`,
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":5,"output_tokens":2}}}`,
	)
	if !terminal {
		t.Fatal("stream did not report terminal")
	}
	// role + 2 text + finish + [DONE]. Lifecycle chatter emits nothing.
	if len(chunks) != 5 {
		t.Fatalf("chunks = %d: %v", len(chunks), chunks)
	}
	if deltaOf(t, chunks[0])["role"] != "assistant" {
		t.Errorf("first frame must announce the role: %v", chunks[0])
	}
	if chunks[0]["id"] != "chatcmpl-z" {
		t.Errorf("id not taken from response.created: %v", chunks[0]["id"])
	}
	text := ""
	for _, ch := range chunks[1:3] {
		text += deltaOf(t, ch)["content"].(string)
	}
	if text != "hello" {
		t.Errorf("text = %q", text)
	}
	if finishOf(chunks[3]) != "stop" {
		t.Errorf("finish_reason = %q", finishOf(chunks[3]))
	}
	if chunks[4]["__done"] != true {
		t.Errorf("missing [DONE] terminator: %v", chunks[4])
	}
}

func TestStreamToolCalls(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", true, 1700000000)
	chunks, terminal := collectFrames(t, st,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"item_1","type":"function_call","call_id":"call_1","name":"get_weather"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"item_1","output_index":0,"delta":"{\"city\":"}`,
		`{"type":"response.function_call_arguments.delta","item_id":"item_1","output_index":0,"delta":"\"HK\"}"}`,
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":9,"output_tokens":3,"total_tokens":12}}}`,
	)
	if !terminal {
		t.Fatal("stream did not report terminal")
	}

	args, finish, sawHeader := "", "", false
	var usage map[string]any
	for _, ch := range chunks {
		if ch["__done"] == true {
			continue
		}
		if u, ok := ch["usage"].(map[string]any); ok {
			usage = u
			continue
		}
		if fr := finishOf(ch); fr != "" {
			finish = fr
		}
		calls, _ := deltaOf(t, ch)["tool_calls"].([]any)
		for _, cv := range calls {
			call, _ := cv.(map[string]any)
			if call["id"] == "call_1" {
				sawHeader = true
			}
			if call["index"].(float64) != 0 {
				t.Errorf("tool_call index = %v, want 0", call["index"])
			}
			fn, _ := call["function"].(map[string]any)
			if a, ok := fn["arguments"].(string); ok {
				args += a
			}
		}
	}
	if !sawHeader {
		t.Error("no tool_call header frame carrying the call id")
	}
	if args != `{"city":"HK"}` {
		t.Errorf("assembled arguments = %q", args)
	}
	if finish != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", finish)
	}
	if usage == nil || usage["prompt_tokens"].(float64) != 9 {
		t.Errorf("usage frame = %v", usage)
	}
}

func TestStreamParallelToolCallsKeepDistinctIndexes(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 0)
	chunks, _ := collectFrames(t, st,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"function_call","call_id":"call_a","name":"f"}}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"b","type":"function_call","call_id":"call_b","name":"g"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"b","output_index":1,"delta":"{}"}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	)
	indexByID := map[string]float64{}
	argIndex := -1.0
	for _, ch := range chunks {
		if ch["__done"] == true {
			continue
		}
		calls, _ := deltaOf(t, ch)["tool_calls"].([]any)
		for _, cv := range calls {
			call, _ := cv.(map[string]any)
			if id, ok := call["id"].(string); ok && id != "" {
				indexByID[id] = call["index"].(float64)
				continue
			}
			argIndex = call["index"].(float64)
		}
	}
	if indexByID["call_a"] != 0 || indexByID["call_b"] != 1 {
		t.Errorf("tool indexes = %v, want call_a=0 call_b=1", indexByID)
	}
	// Argument deltas must land on the call they belong to, not the first one.
	if argIndex != 1 {
		t.Errorf("argument delta index = %v, want 1", argIndex)
	}
}

func TestStreamReasoningDeltas(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 0)
	chunks, _ := collectFrames(t, st,
		`{"type":"response.reasoning_summary_text.delta","delta":"thinking"}`,
		`{"type":"response.output_text.delta","delta":"answer"}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	)
	sawReasoning := false
	for _, ch := range chunks {
		if ch["__done"] == true {
			continue
		}
		if rc, ok := deltaOf(t, ch)["reasoning_content"].(string); ok && rc == "thinking" {
			sawReasoning = true
		}
		// Reasoning must never be emitted as answer content.
		if content, ok := deltaOf(t, ch)["content"].(string); ok && content == "thinking" {
			t.Error("reasoning leaked into content")
		}
	}
	if !sawReasoning {
		t.Error("reasoning delta dropped instead of surfacing as reasoning_content")
	}
}

func TestStreamOmitsUsageUnlessRequested(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 0)
	chunks, _ := collectFrames(t, st,
		`{"type":"response.output_text.delta","delta":"x"}`,
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":5,"output_tokens":2}}}`,
	)
	for _, ch := range chunks {
		if _, ok := ch["usage"]; ok {
			t.Fatalf("usage frame emitted without stream_options.include_usage: %v", ch)
		}
	}
}

func TestStreamIncompleteMapsToLength(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 0)
	chunks, terminal := collectFrames(t, st,
		`{"type":"response.output_text.delta","delta":"x"}`,
		`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`,
	)
	if !terminal {
		t.Fatal("response.incomplete is a terminal event")
	}
	found := ""
	for _, ch := range chunks {
		if ch["__done"] != true {
			if fr := finishOf(ch); fr != "" {
				found = fr
			}
		}
	}
	if found != "length" {
		t.Errorf("finish_reason = %q, want length", found)
	}
}

func TestStreamFinalizeClosesTruncatedStream(t *testing.T) {
	st := NewStreamState("gpt-5.6-sol", false, 0)
	if _, terminal := collectFrames(t, st, `{"type":"response.output_text.delta","delta":"x"}`); terminal {
		t.Fatal("stream terminated early")
	}
	// A truncated upstream still owes the client a finish frame and [DONE],
	// otherwise the client reports a disconnect instead of a short answer.
	frames := st.Finalize()
	if len(frames) < 2 || !IsDoneFrame(frames[len(frames)-1]) {
		t.Fatalf("Finalize did not close the stream: %q", frames)
	}
	// Finalize is idempotent — a late terminal event must not double-close.
	if extra := st.Finalize(); extra != nil {
		t.Errorf("second Finalize emitted %q", extra)
	}
}
