package apicompat

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCodexAgentToolArgumentsWithoutDeltas(t *testing.T) {
	for _, event := range []string{"response.output_item.added", "response.output_item.done", "response.completed"} {
		t.Run(event, func(t *testing.T) {
			st := NewStreamState("m", false, 0)
			item := `{"id":"fc_1","type":"function_call","call_id":"call_1","name":"run","arguments":"{\"n\":1}"}`
			payload := `{"type":"` + event + `","output_index":0,"item":` + item + `}`
			if event == "response.completed" {
				payload = `{"type":"response.completed","response":{"status":"completed","output":[` + item + `]}}`
			}
			frames, _ := st.Translate([]byte(payload))
			joined := string(bytes.Join(frames, nil))
			if !strings.Contains(joined, `"name":"run"`) || !strings.Contains(joined, `"arguments":"{\"n\":1}"`) {
				t.Fatalf("lost executable tool call: %s", joined)
			}
		})
	}
}

func TestCodexAgentToolArgumentsDeduplicated(t *testing.T) {
	st := NewStreamState("m", false, 0)
	var all [][]byte
	for _, p := range []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"run"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"n\":"}`,
		`{"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"n\":1}"}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"run","arguments":"{\"n\":1}"}}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	} {
		frames, _ := st.Translate([]byte(p))
		all = append(all, frames...)
	}
	var args string
	headers := 0
	for _, f := range all {
		if IsDoneFrame(f) {
			continue
		}
		var v struct {
			Choices []struct {
				Delta struct {
					Tools []struct {
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(bytes.TrimPrefix(f, []byte("data:"))), &v); err != nil {
			t.Fatal(err)
		}
		for _, c := range v.Choices {
			for _, tool := range c.Delta.Tools {
				args += tool.Function.Arguments
				if tool.Function.Name != "" {
					headers++
				}
			}
		}
	}
	if args != `{"n":1}` || headers != 1 {
		t.Fatalf("tool reconstructed as %q with %d headers", args, headers)
	}
	if frames, _ := st.Translate([]byte(`{"type":"response.completed"}`)); len(frames) != 0 {
		t.Fatal("duplicate terminal emitted")
	}
}

func TestCodexAgentFailureIsNotSuccessfulCompletion(t *testing.T) {
	for _, p := range []string{
		`{"type":"error","status":400,"error":{"code":"invalid_request_error","message":"bad request"}}`,

		`{"type":"error","code":"invalid_request_error","message":"bad request"}`,
		`{"type":"response.failed","response":{"status":"failed","error":{"code":"bad_tool","message":"bad tool"}}}`,
		`{"type":"response.cancelled","response":{"status":"cancelled"}}`,
	} {
		st := NewStreamState("m", false, 0)
		frames, terminal := st.Translate([]byte(p))
		out := string(bytes.Join(frames, nil))
		if !terminal || !strings.Contains(out, `"error":`) || strings.Contains(out, `"finish_reason"`) {
			t.Fatalf("false success: %s", out)
		}
	}
	if _, err := ResponsesToChatCompletion([]byte(`{"status":"failed","error":{"message":"failed"}}`), "m", 0); err == nil {
		t.Fatal("failed JSON became completion")
	}
	st := NewStreamState("m", false, 0)
	if out := string(bytes.Join(st.Finalize(), nil)); !strings.Contains(out, `"incomplete_stream"`) || strings.Contains(out, `"finish_reason"`) {
		t.Fatalf("truncation became success: %s", out)
	}
}
