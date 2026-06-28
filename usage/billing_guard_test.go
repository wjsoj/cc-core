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
	body := []byte(`{"stream_options":{"include_usage":false,"foo":"bar"}}`)
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
