package codexws

import (
	"net/http"

	"github.com/wjsoj/cc-core/mimicry"
)

// CodexOpenAIBetaWS / CodexOpenAIBetaWSV1 are the OpenAI-Beta markers real
// codex-tui sends on the WebSocket handshake to
// wss://chatgpt.com/backend-api/codex/responses. They diverge from
// mimicry.CodexOpenAIBeta ("responses=experimental"), which is the HTTP-POST
// marker. Bump alongside mimicry.CodexCLIVersion when the Codex target moves.
const (
	CodexOpenAIBetaWS   = "responses_websockets=2026-02-06" // v2 (default)
	CodexOpenAIBetaWSV1 = "responses_websockets=2026-02-04" // v1
)

// BuildUpstreamHeaders returns the WebSocket-handshake headers for the ChatGPT
// Codex backend, reusing the pinned codex-tui identity from cc-core/mimicry so
// the WS and HTTP paths advertise the same client. The gorilla dialer owns the
// Upgrade / Connection / Sec-WebSocket-* headers, so those must NOT be set here.
//
// betaValue selects the responses_websockets version (default CodexOpenAIBetaWS).
// An empty sessionID mints a fresh request UUID. We deliberately omit the
// TUI-only x-codex-turn-metadata / x-codex-window-id / x-codex-beta-features /
// thread-id headers: a proxy has no real workspace/window, and fabricating them
// is a worse fingerprint than omitting them (same rationale as
// mimicry.ApplyCodexCLIHeaders).
func BuildUpstreamHeaders(accessToken, accountID, sessionID, betaValue string) http.Header {
	if betaValue == "" {
		betaValue = CodexOpenAIBetaWS
	}
	if sessionID == "" {
		sessionID = mimicry.NewRequestUUID()
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+accessToken)
	h.Set("OpenAI-Beta", betaValue)
	h.Set("Originator", mimicry.CodexOriginator)
	h.Set("User-Agent", mimicry.CodexCLIUserAgent)
	h.Set("Version", mimicry.CodexCLIVersion)
	h.Set("Session_id", sessionID)
	if accountID != "" {
		h.Set("Chatgpt-Account-Id", accountID)
	}
	return h
}
