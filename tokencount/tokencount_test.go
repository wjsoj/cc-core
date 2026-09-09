package tokencount

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tiktoken-go/tokenizer"
)

func TestAnthropicBodyCountsEveryPart(t *testing.T) {
	body := []byte(`{
	  "model":"claude-sonnet-5",
	  "system":"You are a coding agent working in a terminal.",
	  "messages":[
	    {"role":"user","content":[{"type":"text","text":"refactor the parser"}]},
	    {"role":"assistant","content":[{"type":"text","text":"which file"}]}
	  ],
	  "tools":[{"name":"bash","description":"run a shell command","input_schema":{"type":"object","properties":{"command":{"type":"string"}}}}]
	}`)
	got, err := EstimateAnthropicInputTokens(body)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	// The parts alone are ~45 tokens of prose and schema; anything far below
	// that means a section was skipped, which is the failure that matters — a
	// caller sizing a context window against a too-small number overruns it.
	if got < 40 {
		t.Errorf("estimate = %d, too low to have counted system + messages + tools", got)
	}
	if got > 400 {
		t.Errorf("estimate = %d, far above the body's actual content — the walk is charging for JSON punctuation", got)
	}
}

// Dropping a section is the dangerous failure, so each one has to move the
// answer on its own.
func TestEveryAnthropicSectionMovesTheCount(t *testing.T) {
	base := `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}`
	baseline, err := EstimateAnthropicInputTokens([]byte(base))
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	long := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 20)
	for name, body := range map[string]string{
		"system":   fmt.Sprintf(`{"model":"claude-sonnet-5","system":%q,"messages":[{"role":"user","content":"hi"}]}`, long),
		"messages": fmt.Sprintf(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":%q}]}`, long),
		"tools":    fmt.Sprintf(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"t","description":%q}]}`, long),
	} {
		got, err := EstimateAnthropicInputTokens([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got <= baseline+100 {
			t.Errorf("%s: %d vs baseline %d — 900 characters were added and barely counted, so this section is being dropped", name, got, baseline)
		}
	}
}

func TestResponsesBodyCountsEveryPart(t *testing.T) {
	base := `{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	baseline, err := EstimateResponsesInputTokens([]byte(base))
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	long := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 20)
	for name, body := range map[string]string{
		"instructions": fmt.Sprintf(`{"model":"gpt-5.6-sol","instructions":%q,"input":[]}`, long),
		"input":        fmt.Sprintf(`{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":%q}]}]}`, long),
		"tools":        fmt.Sprintf(`{"model":"gpt-5.6-sol","input":[],"tools":[{"type":"function","name":"t","description":%q}]}`, long),
	} {
		got, err := EstimateResponsesInputTokens([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got <= baseline+100 {
			t.Errorf("%s: %d vs baseline %d — the section is being dropped", name, got, baseline)
		}
	}
}

// A conversation is mostly JSON scaffolding by byte count. Tokenizing the raw
// bytes instead of walking the values inflates a long one badly, which would
// make the endpoint worse than useless — a caller would compact far too early.
func TestLongConversationIsNotInflatedByJSONPunctuation(t *testing.T) {
	sentence := "the quick brown fox jumps over the lazy dog. "
	var msgs []map[string]any
	for i := 0; i < 60; i++ {
		msgs = append(msgs, map[string]any{
			"role":    "user",
			"content": []map[string]any{{"type": "text", "text": sentence}},
		})
	}
	body, _ := json.Marshal(map[string]any{"model": "claude-sonnet-5", "messages": msgs})

	got, err := EstimateAnthropicInputTokens(body)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	// 60 copies of a ~10-token sentence plus framing: the honest answer is
	// around 900. The raw-bytes mistake lands near len(body)/4, well over 1500.
	if got > int(len(body)/6) {
		t.Errorf("estimate = %d for a %d-byte body — that is punctuation being charged for, not content", got, len(body))
	}
	if got < 600 {
		t.Errorf("estimate = %d, too low for 60 messages of prose", got)
	}
}

func TestModelIsRequiredAndBadJSONIsAnError(t *testing.T) {
	for _, body := range []string{`{"messages":[]}`, `{"model":"  ","messages":[]}`, `not json`} {
		if _, err := EstimateAnthropicInputTokens([]byte(body)); err == nil {
			t.Errorf("%s was accepted; the vendor endpoints reject it too", body)
		}
	}
}

// Never zero: a caller that asked how big its request is cannot act on zero,
// and both vendors return at least one token for a non-empty body.
func TestEmptyBodyStillCountsOne(t *testing.T) {
	got, err := EstimateAnthropicInputTokens([]byte(`{"model":"claude-sonnet-5","messages":[]}`))
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if got < 1 {
		t.Errorf("estimate = %d, want at least 1", got)
	}
}

func TestCodecSelection(t *testing.T) {
	for model, want := range map[string]tokenizer.Encoding{
		"gpt-4":         tokenizer.Cl100kBase,
		"gpt-4-turbo":   tokenizer.Cl100kBase,
		"gpt-3.5-turbo": tokenizer.Cl100kBase,
		"gpt-4o":        tokenizer.O200kBase,
		"gpt-4.1":       tokenizer.O200kBase,
		"gpt-5.6-sol":   tokenizer.O200kBase,
		"gpt-6-astra":   tokenizer.O200kBase,
		"claude-opus-5": tokenizer.O200kBase,
	} {
		if got := EncodingFor(model); got != want {
			t.Errorf("EncodingFor(%q) = %v, want %v", model, got, want)
		}
	}
}
