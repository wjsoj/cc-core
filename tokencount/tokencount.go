// Package tokencount answers a token-count request locally, for the case where
// the credential serving a request cannot answer it upstream.
//
// Both vendors publish a counting endpoint — Anthropic's
// POST /v1/messages/count_tokens and OpenAI's POST /v1/responses/input_tokens —
// and both are worth forwarding when the credential actually reaches the vendor,
// because the vendor counts things a local tokenizer cannot see: role and
// message-boundary framing, tool schemas, images, and files.
//
// Resale relays are the problem. None of the ones in production implement
// either route, so a proxy that only forwards answers 404 forever: this
// deployment logged 1634 count_tokens requests across 17 customer tokens in
// fourteen days and served exactly zero of them. Claude Code calls the endpoint
// constantly to decide when to compact a conversation, and a 404 pushes it back
// onto its own cruder guess.
//
// So: forward where the vendor is reachable, estimate here where it is not.
// The estimate is approximate by construction — Anthropic does not publish its
// tokenizer, so an Anthropic body is counted with OpenAI's — and being within a
// short distance of the truth is worth much more to a context-window decision
// than an error is. sub2api reached the same conclusion for the same reason and
// ships the same tiktoken fallback for providers whose Anthropic-compatible
// layer has no count_tokens.
package tokencount

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tiktoken-go/tokenizer"
)

// framingTokensPerMessage approximates what the vendor counts and a tokenizer
// cannot see: the role, the message boundary, and the turn scaffolding around
// each message. OpenAI documents ~3-4 tokens per message for the chat framing
// and the same order applies to Anthropic's; undercounting here is the one
// direction that actually hurts, because a caller sizing a context window
// against a too-small number overruns it.
const framingTokensPerMessage = 4

// EstimateAnthropicInputTokens counts an Anthropic /v1/messages body: system,
// every message's text, and the tool schemas.
func EstimateAnthropicInputTokens(body []byte) (int, error) {
	var req struct {
		Model    string          `json:"model"`
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("parse count_tokens request: %w", err)
	}
	if strings.TrimSpace(req.Model) == "" {
		return 0, fmt.Errorf("parse count_tokens request: model is required")
	}
	codec, err := codecFor(req.Model)
	if err != nil {
		return 0, err
	}

	total := countText(codec, req.System)
	for _, m := range req.Messages {
		// Framing once per message — the role and the turn boundary — not once
		// per content block. A block is part of the message, not another turn.
		total += framingTokensPerMessage
		total += countText(codec, m.Content)
	}
	total += countSchema(codec, req.Tools)
	return atLeastOne(total), nil
}

// EstimateResponsesInputTokens counts an OpenAI Responses body: instructions,
// input, and tool schemas. The shape is the one
// POST /v1/responses/input_tokens takes.
func EstimateResponsesInputTokens(body []byte) (int, error) {
	var req struct {
		Model        string          `json:"model"`
		Instructions string          `json:"instructions"`
		Input        json.RawMessage `json:"input"`
		Tools        json.RawMessage `json:"tools"`
		ToolChoice   json.RawMessage `json:"tool_choice"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("parse input_tokens request: %w", err)
	}
	if strings.TrimSpace(req.Model) == "" {
		return 0, fmt.Errorf("parse input_tokens request: model is required")
	}
	codec, err := codecFor(req.Model)
	if err != nil {
		return 0, err
	}

	total := countTokens(codec, req.Instructions)
	total += countText(codec, req.Input)
	total += framingTokensPerMessage * countInputItems(req.Input)
	total += countSchema(codec, req.Tools)
	total += countSchema(codec, req.ToolChoice)
	return atLeastOne(total), nil
}

// countText walks a value and counts only the strings a model actually reads.
//
// Deliberately NOT a tokenization of the raw JSON. A conversation is mostly
// punctuation and wire-protocol key names by byte count, and charging for those
// inflated a 60-message body to 1380 tokens against a true ~700 — which is
// worse than no endpoint at all, because a caller sizing its context window
// against it compacts twice as early as it needs to.
//
// Keys are skipped for the same reason. The exception is a tool schema, which
// the model does see in full; countSchema handles that separately.
func countText(codec tokenizer.Codec, raw json.RawMessage) int {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return countTokens(codec, string(raw))
	}
	return walkText(codec, v)
}

func walkText(codec tokenizer.Codec, v any) int {
	switch t := v.(type) {
	case string:
		return countTokens(codec, t)
	case []any:
		total := 0
		for _, item := range t {
			total += walkText(codec, item)
		}
		return total
	case map[string]any:
		total := 0
		for _, item := range t {
			total += walkText(codec, item)
		}
		return total
	default:
		return 0
	}
}

// countSchema counts a tool definition as serialized JSON, keys included.
//
// This is the one place the raw form is right: a tool's name, description and
// parameter schema are rendered into the prompt more or less verbatim, so the
// property names are tokens the model is charged for.
func countSchema(codec tokenizer.Codec, raw json.RawMessage) int {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return countTokens(codec, string(raw))
	}
	return countTokens(codec, compact.String())
}

func countTokens(codec tokenizer.Codec, text string) int {
	if strings.TrimSpace(text) == "" {
		return 0
	}
	ids, _, err := codec.Encode(text)
	if err != nil {
		// Fall back to a byte-ratio estimate rather than failing the request:
		// a rough number still lets the caller size a context window, and this
		// endpoint has no other answer to give.
		return len(text)/4 + 1
	}
	return len(ids)
}

// countInputItems reports how many turns a Responses `input` carries, so the
// per-message framing is charged once each rather than once per content part.
func countInputItems(raw json.RawMessage) int {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return 1 // a bare string input is one turn
	}
	return len(items)
}

// EncodingFor reports which tiktoken encoding a model uses. Exported so the
// choice can be asserted directly rather than inferred from two codecs
// disagreeing on some sample string — they agree on most of them.
func EncodingFor(model string) tokenizer.Encoding {
	m := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(m, "gpt-3.5") ||
		(strings.HasPrefix(m, "gpt-4") && !strings.HasPrefix(m, "gpt-4o") && !strings.HasPrefix(m, "gpt-4.1")) {
		return tokenizer.Cl100kBase
	}
	return tokenizer.O200kBase
}

// codecFor picks the encoding. o200k_base covers every current model; the
// cl100k_base arm is for the older GPT-4/3.5 names a relay may still expose.
func codecFor(model string) (tokenizer.Codec, error) {
	return tokenizer.Get(EncodingFor(model))
}

// atLeastOne keeps the answer a positive integer. A caller that asked how big
// its request is never wants to be told zero, and both vendors' endpoints
// return at least one token for a non-empty body.
func atLeastOne(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
