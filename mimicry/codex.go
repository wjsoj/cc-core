package mimicry

import "net/http"

// Codex CLI fingerprint, pinned to codex-tui/0.144.1. The identity template
// (Originator / UA shape / Version header) was verified against a live ChatGPT
// Pro `codex` (Rust TUI) session capture at 0.135.0 — see crack/codex/SPEC.md
// (whistle dump 2026-05-30). Bumped to 0.144.1 (latest stable Codex CLI release
// per github.com/openai/codex — 0.145 is alpha-only — the line that exposes the
// gpt-5.6-{sol,terra,luna} models). The UA/Version format is unchanged from
// 0.135.0 (real 0.144.x UAs are byte-identical modulo the version and the
// OS/terminal segment, which is our synthetic Arch/Konsole identity anyway).
//
// Transport note: real codex-tui streams a turn over a WebSocket
// (OpenAI-Beta: responses_websockets=2026-02-06, wss://chatgpt.com/backend-api/
// codex/responses). We forward over the legacy HTTP POST /backend-api/codex/
// responses path (OpenAI-Beta: responses=experimental) — still accepted by the
// backend and what an HTTP-API proxy needs. We mimic the 0.144.1 *identity*
// (Originator / User-Agent / Version) over that path.
//
// We deliberately do NOT replicate the WS/TUI-only headers the capture shows
// (x-codex-turn-metadata carrying workspace+git state, x-codex-window-id,
// x-codex-beta-features, thread-id): a proxy has no real workspace/window, and
// fabricating those is a worse fingerprint than omitting them. The headers that
// authorize and route the request — Authorization, Chatgpt-Account-Id,
// Originator, OpenAI-Beta — are what the backend keys on.
//
// Bumping the version target requires re-capturing real Codex traffic (see
// crack/codex/) and updating these constants together; CodexCLIVersion must
// match the version baked into CodexCLIUserAgent.
const (
	CodexCLIVersion   = "0.144.1"
	CodexCLIUserAgent = "codex-tui/0.144.1 (Arch Linux Rolling Release; x86_64) Konsole/260401 (codex-tui; 0.144.1)"
	CodexOriginator   = "codex-tui"
	// CodexOpenAIBeta is the HTTP-POST beta marker. The WS handshake uses
	// responses_websockets=2026-02-06; the HTTP /responses endpoint reads
	// responses=experimental, which is the path we forward over.
	CodexOpenAIBeta = "responses=experimental"
)

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
func ApplyCodexCLIHeaders(req *http.Request, accessToken, accountID string, isCompact bool) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	if isCompact {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set("OpenAI-Beta", CodexOpenAIBeta)
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
