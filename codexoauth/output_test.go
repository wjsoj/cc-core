package codexoauth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTerminalOutputRestoredAndDeduplicated(t *testing.T) {
	var a OutputAccumulator
	a.Observe([]byte(`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"c","name":"f","arguments":"{}"}}`))
	a.Observe([]byte(`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"c","name":"f","arguments":"{\"x\":1}"}}`))
	a.Observe([]byte(`{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","content":[]}}`))
	out := a.Observe([]byte(`{"type":"response.incomplete","response":{"status":"incomplete","output":[],"usage":{"output_tokens":3}}}`))
	var result struct {
		Response struct {
			Output []struct {
				ID string `json:"id"`
			}
			Usage struct {
				Output int `json:"output_tokens"`
			}
		}
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Response.Output) != 2 || result.Response.Output[0].ID != "msg_1" || result.Response.Usage.Output != 3 {
		t.Fatalf("bad reconstruction: %s", out)
	}
}

func TestTerminalOutputHydratesOnlyMissingIDs(t *testing.T) {
	var a OutputAccumulator
	i := int64(0)
	a.Add(&i, json.RawMessage(`{"id":"fc_1","type":"function_call"}`))
	out, err := a.Patch([]byte(`{"output":[{"type":"function_call","arguments":"{}"}]}`))
	if err != nil || !strings.Contains(string(out), `"id":"fc_1"`) {
		t.Fatalf("missing id: %s %v", out, err)
	}
	original := []byte(`{"output":[{"type":"function_call","id":"existing"}]}`)
	out, err = a.Patch(original)
	if err != nil || string(out) != string(original) {
		t.Fatalf("overwrote terminal id: %s", out)
	}
}
