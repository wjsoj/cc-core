package mimicry

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Codex CLI fingerprint, pinned to codex-tui/0.147.0. The identity template
// (Originator / UA shape / Version header) was verified against a live ChatGPT
// Pro `codex` (Rust TUI) session capture at 0.135.0 — see crack/codex/SPEC.md
// (whistle dump 2026-05-30). The line still exposes the gpt-5.6-{sol,terra,luna}
// models.
//
// 0.147.0 (released 2026-08-07) was verified against the UPSTREAM SOURCE rather
// than a new capture — codex-rs is open source, and for header construction the
// source is stronger evidence than a dump, since it is the thing that generates
// the dump. Two findings from codex-rs/login/src/auth/default_client.rs and
// codex-rs/core/src/client.rs at that tag drive the constants below.
//
// The UA template is unchanged: get_codex_user_agent() builds
// "{originator}/{version} ({os_type} {os_version}; {arch}) {terminal_ua}{suffix}",
// which is exactly the 0.135.0 shape, so only the version segments move. The
// OS/terminal segment stays our synthetic Arch/Konsole identity.
//
// `codex-tui` remains a live originator at 0.147.0 (it is still in the known-
// originator set in codex-rs/otel/src/metrics/tags.rs alongside the library
// default `codex_cli_rs`), and it is what our own capture shows the TUI send,
// so it is deliberately NOT changed to the library default.
//
// Transport note: real codex-tui streams a turn over a WebSocket
// (OpenAI-Beta: responses_websockets=2026-02-06, wss://chatgpt.com/backend-api/
// codex/responses). We forward over the HTTP POST /backend-api/codex/responses
// path, which the backend still accepts and which an HTTP-API proxy needs. We
// mimic the 0.147.0 *identity* (Originator / User-Agent / Version) over it.
//
// We deliberately do NOT replicate the WS/TUI-only headers the capture shows
// (x-codex-turn-metadata carrying workspace+git state, x-codex-window-id,
// x-codex-beta-features, thread-id): a proxy has no real workspace/window, and
// fabricating those is a worse fingerprint than omitting them.
//
// Bumping the version target requires re-verifying against real Codex traffic
// or the codex-rs source at that tag; CodexCLIVersion must match the version
// baked into CodexCLIUserAgent.
const (
	CodexCLIVersion   = "0.147.0"
	CodexCLIUserAgent = "codex-tui/0.147.0 (Arch Linux Rolling Release; x86_64) Konsole/260401 (codex-tui; 0.147.0)"
	CodexOriginator   = "codex-tui"

	// CodexRoutingHintHeader carries the model (and optionally the effective
	// service tier) the ChatGPT backend should route to. Real Codex sends it on
	// every ChatGPT-OAuth request — both the HTTP and the WS path — as
	// X_CODEX_ROUTING_HINT_HEADER in codex-rs/core/src/client.rs, gated on
	// `auth.uses_codex_backend()`, i.e. exactly the subscription-backed traffic
	// we forward. Omitting it is not neutral: the backend resolves some models
	// per-originator/per-hint, which is how third-party clients end up with
	// "Model not found gpt-5.6-luna-…" while the official CLI succeeds on the
	// same account (openai/codex#31967).
	CodexRoutingHintHeader = "x-codex-routing-hint"
)

// CodexServiceTier* are the only tier values that belong in a routing hint.
//
// Upstream formats the hint as "model={model};tier={tier}" whenever its own
// resolved service_tier is Some. Its service_tier comes from Codex's own
// validated config; ours comes off an arbitrary client request body, so we
// restrict the hint to the two tiers Codex actually selects rather than
// forwarding whatever a caller typed into a header. "default" is excluded on
// purpose — Codex treats it as a standard-routing sentinel, not a tier to send.
const (
	CodexServiceTierPriority = "priority"
	CodexServiceTierFlex     = "flex"
)

// CodexRoutingHint renders the x-codex-routing-hint value for a request, or ""
// when there is nothing safe to advertise (no model). serviceTier may be empty.
//
// The model is emitted as-is because the backend keys on the exact upstream
// slug; a caller must therefore pass the model it actually puts in the request
// body, after any model-map rewrite, or the hint and the body will disagree.
func CodexRoutingHint(model, serviceTier string) string {
	model = strings.TrimSpace(model)
	// A header value must be printable ASCII with no CR/LF. Model names are
	// slugs, so anything else is either a caller bug or an injection attempt;
	// drop the hint rather than emit a malformed header.
	if model == "" || !validHeaderValue(model) {
		return ""
	}
	hint := "model=" + model
	switch strings.ToLower(strings.TrimSpace(serviceTier)) {
	case CodexServiceTierPriority:
		hint += ";tier=" + CodexServiceTierPriority
	case CodexServiceTierFlex:
		hint += ";tier=" + CodexServiceTierFlex
	}
	return hint
}

// CodexModelAndTier reads the model and service_tier out of a Codex request
// body. Callers pass it the body they are ABOUT TO SEND — after sanitization
// and any model-map rewrite — so the routing hint and the body can never
// disagree about which model this request is for. Missing fields come back
// empty, which CodexRoutingHint handles by omitting the hint or the tier.
func CodexModelAndTier(body []byte) (model, serviceTier string) {
	var b struct {
		Model       string `json:"model"`
		ServiceTier string `json:"service_tier"`
	}
	if json.Unmarshal(body, &b) != nil {
		return "", ""
	}
	return b.Model, b.ServiceTier
}

// validHeaderValue reports whether s is safe to use as an HTTP header value:
// printable ASCII (plus horizontal tab), no control characters, no CR/LF.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// ApplyCodexCLIHeaders rewrites req to look like the Codex CLI talking to the
// ChatGPT subscription backend over the HTTP POST /codex/responses{,/compact}
// path. The caller supplies the OAuth access token and the chatgpt_account_id
// claim (from the id_token). isCompact selects the /responses/compact variant
// (plain JSON) vs the streaming /responses variant (SSE).
//
// Always overwrites Authorization and User-Agent: forwarding a client's UA
// (e.g. "curl/8.x") makes Cloudflare's edge 403 the request before it reaches
// the OpenAI backend, and the credential token must win over anything the
// downstream client sent.
//
// Accept-Encoding is forced to "identity" so SSE streams and 4xx error bodies
// stay readable end-to-end (a transport necessity, not part of the captured
// fingerprint).
//
// model is the model name going into the request body (post model-map rewrite)
// and serviceTier the request's service_tier, if any; together they produce the
// x-codex-routing-hint real Codex sends. Passing an empty model simply omits the
// hint — the header is never emitted with a stale or guessed value.
//
// NOTE: no OpenAI-Beta header is set here, and that is deliberate. Real Codex
// sets OpenAI-Beta *only* on the WebSocket handshake
// (responses_websockets=…, see codexws.BuildUpstreamHeaders); at 0.147.0 the
// string "responses=experimental" does not appear anywhere in codex-rs, so the
// legacy HTTP beta we used to send was a value no genuine client emits — a pure
// third-party tell. Any OpenAI-Beta the downstream client sent is left alone.
func ApplyCodexCLIHeaders(req *http.Request, accessToken, accountID string, isCompact bool, model, serviceTier string) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	if isCompact {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "text/event-stream")
	}
	// Delete before conditionally setting so a retried/rebuilt request can
	// never carry a routing hint for the previous attempt's model.
	req.Header.Del(CodexRoutingHintHeader)
	if hint := CodexRoutingHint(model, serviceTier); hint != "" {
		req.Header.Set(CodexRoutingHintHeader, hint)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Session_id", NewRequestUUID())
	req.Header.Set("Version", CodexCLIVersion)
	req.Header.Set("Originator", CodexOriginator)
	req.Header.Set("User-Agent", CodexCLIUserAgent)
	if accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
}

// CodexUsageUserAgent is the User-Agent the Codex CLI sends on its
// GET /backend-api/wham/usage probe — the same codex-tui UA as the request
// path, NOT the web portal's Chrome UA. The CLI's usage call carries only
// Authorization + Chatgpt-Account-Id + this UA (no oai-client-* headers).
const CodexUsageUserAgent = CodexCLIUserAgent
