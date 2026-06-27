package mimicry

// codex_body.go is the authoritative copy of the Codex backend request-shaping
// logic that was previously duplicated byte-for-byte in the downstream apps
// (CPA-Claude and hypitoken). It transforms a client's OpenAI /v1/responses
// body into the narrow subset the ChatGPT Codex backend
// (chatgpt.com/backend-api/codex) accepts.
//
// This is the request-body counterpart to mimicry/codex.go's header mimicry:
// codex.go pins the upstream request headers (Originator / User-Agent /
// Version / OpenAI-Beta / Chatgpt-Account-Id) to codex-tui/0.135.0, while this
// file normalizes the request body shape. The two are complementary halves of
// the same Codex-CLI emulation. Behavior is modeled on CLIProxyAPI's codex
// translator/executor and sub2api's compact-request normalizer — see the
// per-function notes below.

import (
	"encoding/json"
	"net/url"
	"strings"
)

// JoinCodexAPIKeyUpstreamURL joins an API-key credential's BaseURL with an
// inbound OpenAI-style path ("/v1/responses", "/v1/chat/completions",
// "/v1/models") for the passthrough (non-OAuth) Codex forwarder.
//
// The rule resolves a long-standing footgun where the two forks disagreed and
// each only handled one BaseURL shape:
//
//   - BaseURL carries its own path segment (".../v1", ".../codex", …): it is
//     authoritative. The inbound "/v1" prefix is stripped and the bare
//     endpoint appended.
//     api.openai.com/v1 + /v1/responses → https://api.openai.com/v1/responses
//     gateway.io/codex  + /v1/responses → https://gateway.io/codex/responses
//   - BaseURL is a bare origin (no path, e.g. "https://relay.example"): the
//     FULL inbound path including "/v1" is appended, because virtually every
//     OpenAI-compatible relay (new-api / one-api / official) serves its API
//     under "/v1". Stripping it sent the request to the gateway's HTML
//     homepage, which the SSE reader surfaced as
//     "stream disconnected before completion".
//     relay.example + /v1/responses → https://relay.example/v1/responses
//
// This is backward-compatible for both forks: any BaseURL that already carries
// a path is unchanged, and a bare-origin BaseURL — which previously 404'd on
// the strip-/v1 fork and only worked on the keep-/v1 fork — now works on both.
func JoinCodexAPIKeyUpstreamURL(baseURL, clientPath string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURLHasPath(baseURL) {
		return baseURL + strings.TrimPrefix(clientPath, "/v1")
	}
	return baseURL + clientPath
}

// baseURLHasPath reports whether baseURL carries a path segment after the host
// (e.g. "/v1", "/codex"). A parse failure is treated as "has path" so we fall
// back to the conservative strip-/v1 behavior rather than risk doubling it.
func baseURLHasPath(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return true
	}
	return strings.Trim(u.Path, "/") != ""
}

// CodexOAuthPath maps a client-facing path under /v1 to the corresponding
// suffix on the ChatGPT Codex backend (mounted under /codex). The backend
// hosts:
//   - /responses           — streaming inference (non-streaming clients are
//     satisfied via aggregateCodexResponseStream).
//   - /responses/compact   — Codex CLI's conversation-compaction endpoint;
//     body shape is the same /v1/responses payload,
//     so the same sanitize/transport path applies.
func CodexOAuthPath(clientPath string) string {
	switch clientPath {
	case "/v1/responses/compact":
		return "/responses/compact"
	default:
		return "/responses"
	}
}

// SanitizeCodexRequestBody shapes the client's /v1/responses body into what
// the ChatGPT Codex backend expects. Behavior is modeled directly on
// CLIProxyAPI (translator/codex/openai/responses/codex_openai-responses_request.go
// + runtime/executor/codex_executor.go:Execute): the backend accepts a
// narrow subset of the OpenAI /v1/responses schema, so we force the
// required fields, delete the ones that get rejected, and normalize the
// payload shape. Upstream is always streamed — the `stream` bool on the
// client request does not change the body we send.
//
// clientPath selects the schema variant: /v1/responses/compact is a much
// stricter endpoint that only accepts {model, input, instructions,
// previous_response_id} — anything else (notably `include`,
// `context_management`, `tools`, `store`, `stream`) gets rejected with
// `Unknown parameter`. We mirror sub2api's normalizeOpenAICompactRequestBody
// for that path.
func SanitizeCodexRequestBody(body []byte, clientPath string) ([]byte, string, error) {
	if clientPath == "/v1/responses/compact" {
		return sanitizeCodexCompactRequestBody(body)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, "", err
	}
	// Strip thinking suffix from model. CLIProxyAPI uses "model-name(value)"
	// convention (e.g. gpt-5.3-codex(high)); the backend wants just the
	// base model name. Plain model names are passed through untouched.
	baseModel := ""
	if m, ok := raw["model"].(string); ok {
		baseModel = StripThinkingSuffix(m)
		raw["model"] = baseModel
	}

	// Always stream upstream — the backend only emits completed responses
	// via SSE. Non-streaming clients get aggregation on our side.
	raw["stream"] = true

	// Required fields for the Codex backend.
	raw["store"] = false
	raw["parallel_tool_calls"] = true
	raw["include"] = []any{"reasoning.encrypted_content"}

	// Fields the backend rejects or that leak through from openai.com-
	// compatible SDKs but don't belong on the Codex backend. Note:
	// `previous_response_id` is intentionally NOT stripped — Codex CLI
	// chains multi-turn conversations on this field, and sub2api preserves
	// it for the same reason. Stripping it makes every turn a cold start
	// and may correlate with CF rate-limit bursts.
	for _, k := range []string{
		"prompt_cache_retention",
		"safety_identifier",
		"stream_options",
		"max_output_tokens",
		"max_completion_tokens",
		"temperature",
		"top_p",
		"truncation",
		"user",
		"context_management",
	} {
		delete(raw, k)
	}

	// service_tier: backend only honors "priority"; anything else 400s.
	if st, ok := raw["service_tier"].(string); ok && st != "priority" {
		delete(raw, "service_tier")
	}

	// Input may be a plain string on SDKs that use the convenience shape.
	// Promote to the canonical [{"type":"message","role":"user",...}] form.
	if s, ok := raw["input"].(string); ok {
		raw["input"] = []any{map[string]any{
			"type": "message",
			"role": "user",
			"content": []any{map[string]any{
				"type": "input_text",
				"text": s,
			}},
		}}
	}
	// Convert role "system" → "developer" in input items (Codex rejects
	// "system" there).
	if items, ok := raw["input"].([]any); ok {
		for _, it := range items {
			if m, _ := it.(map[string]any); m != nil {
				if role, _ := m["role"].(string); role == "system" {
					m["role"] = "developer"
				}
			}
		}
	}

	// Normalize legacy/preview built-in tool type aliases.
	normalizeBuiltinToolsInPlace(raw)

	// Backfill empty instructions (backend requires the key to exist).
	if v, ok := raw["instructions"]; !ok || v == nil {
		raw["instructions"] = ""
	}

	// Ensure image_generation tool is present (matches vendor CLI; skipped
	// on *-spark models where the backend rejects it).
	raw["tools"] = ensureImageGenerationTool(raw["tools"], baseModel)

	out, err := json.Marshal(raw)
	return out, baseModel, err
}

// sanitizeCodexCompactRequestBody is the strict whitelist for the
// /codex/responses/compact endpoint. Mirrors sub2api's
// normalizeOpenAICompactRequestBody: the backend rejects everything except
// these four fields, so we drop the rest entirely (in particular
// `include`, `context_management`, `tools`, `store`, `stream`,
// `parallel_tool_calls` — all of which SanitizeCodexRequestBody force-
// injects for the regular /responses path and which would 400 here).
//
// The model field still has its CLIProxyAPI thinking-suffix stripped so
// `gpt-5.3-codex(high)` → `gpt-5.3-codex` for billing/upstream consistency.
func sanitizeCodexCompactRequestBody(body []byte) ([]byte, string, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, "", err
	}
	baseModel := ""
	if m, ok := raw["model"].(string); ok {
		baseModel = StripThinkingSuffix(m)
	}
	out := map[string]any{}
	for _, k := range []string{"model", "input", "instructions", "previous_response_id"} {
		v, ok := raw[k]
		if !ok {
			continue
		}
		if k == "model" && baseModel != "" {
			out[k] = baseModel
			continue
		}
		out[k] = v
	}
	encoded, err := json.Marshal(out)
	return encoded, baseModel, err
}

// normalizeBuiltinToolsInPlace rewrites the legacy Codex built-in tool
// aliases to the stable names the backend accepts today. Mirrors
// CLIProxyAPI's normalizeCodexBuiltinTools.
func normalizeBuiltinToolsInPlace(raw map[string]any) {
	rewrite := func(m map[string]any) {
		if t, _ := m["type"].(string); t != "" {
			if n := normalizeBuiltinToolType(t); n != "" {
				m["type"] = n
			}
		}
	}
	if tools, ok := raw["tools"].([]any); ok {
		for _, t := range tools {
			if m, _ := t.(map[string]any); m != nil {
				rewrite(m)
			}
		}
	}
	if tc, ok := raw["tool_choice"].(map[string]any); ok {
		rewrite(tc)
		if inner, ok := tc["tools"].([]any); ok {
			for _, t := range inner {
				if m, _ := t.(map[string]any); m != nil {
					rewrite(m)
				}
			}
		}
	}
}

func normalizeBuiltinToolType(t string) string {
	switch t {
	case "web_search_preview", "web_search_preview_2025_03_11":
		return "web_search"
	}
	return ""
}

// StripThinkingSuffix mirrors thinking.ParseSuffix from CLIProxyAPI: a
// trailing "(value)" group (e.g. "gpt-5.3-codex(high)") is removed and the
// bare model name returned. Names without the suffix form are untouched.
func StripThinkingSuffix(model string) string {
	if !strings.HasSuffix(model, ")") {
		return model
	}
	i := strings.LastIndex(model, "(")
	if i <= 0 {
		return model
	}
	return model[:i]
}

// ensureImageGenerationTool guarantees the tools array has an entry of
// type=image_generation. The ChatGPT backend injects this server-side on
// the vendor CLI's requests; if we strip it (or the client omits it)
// responses with image-generation prompts fail. Skipped for "*-spark"
// models the backend rejects the tool on (matches CLIProxyAPI).
func ensureImageGenerationTool(current any, baseModel string) any {
	if strings.HasSuffix(baseModel, "spark") {
		if current == nil {
			return []any{}
		}
		return current
	}
	imageTool := map[string]any{"type": "image_generation", "output_format": "png"}
	arr, ok := current.([]any)
	if !ok || arr == nil {
		return []any{imageTool}
	}
	for _, t := range arr {
		if tm, _ := t.(map[string]any); tm != nil {
			if typ, _ := tm["type"].(string); typ == "image_generation" {
				return arr
			}
		}
	}
	return append(arr, imageTool)
}
