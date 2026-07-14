package usage

import (
	"encoding/json"
	"testing"
)

func TestEnsureOpenAIStreamUsageAddsFlag(t *testing.T) {
	body := []byte(`{"model":"gpt-5","stream":true,"messages":[]}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	opts, _ := raw["stream_options"].(map[string]any)
	if opts == nil || opts["include_usage"] != true {
		t.Fatalf("include_usage not set: %s", got)
	}
}

func TestEnsureOpenAIStreamUsageForcesUsageAndPreservesOtherOptions(t *testing.T) {
	body := []byte(`{"messages":[],"stream_options":{"include_usage":false,"foo":"bar"}}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	var raw struct {
		StreamOptions map[string]any `json:"stream_options"`
	}
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	if raw.StreamOptions["include_usage"] != true {
		t.Fatalf("include_usage should be forced true: %s", got)
	}
	if raw.StreamOptions["foo"] != "bar" {
		t.Fatalf("existing stream option lost: %s", got)
	}
}

// A Responses API request (has `input`, no `messages`) must NOT get
// stream_options injected — /v1/responses rejects the unknown parameter with a
// 400 on strict upstreams (observed in prod: "Unknown parameter:
// 'stream_options.include_usage'"). Its usage is already carried by the
// response.completed event, so the body must pass through byte-for-byte.
func TestEnsureOpenAIStreamUsageSkipsResponsesAPI(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","stream":true,"input":"hi"}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("Responses API body must pass through unchanged; got %s", got)
	}
	var raw map[string]any
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, injected := raw["stream_options"]; injected {
		t.Fatalf("stream_options must NOT be injected into a Responses request: %s", got)
	}
}

func TestMissingUsageFallbackCounts(t *testing.T) {
	got := MissingUsageFallbackCounts([]byte(`{"input":"hi"}`))
	if got.Requests != 1 {
		t.Fatalf("Requests=%d want 1", got.Requests)
	}
	if got.InputTokens < MissingUsageFallbackMinInputTokens {
		t.Fatalf("InputTokens=%d below floor", got.InputTokens)
	}
	if got.OutputTokens != MissingUsageFallbackMinOutputTokens {
		t.Fatalf("OutputTokens=%d want %d", got.OutputTokens, MissingUsageFallbackMinOutputTokens)
	}
}
