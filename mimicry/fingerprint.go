// Package mimicry rewrites HTTP request headers and JSON bodies so they
// look like a real Claude Code CLI client. Two-layer fingerprint:
//
//  1. Headers: User-Agent / X-Stainless-* / Anthropic-Beta / X-App /
//     X-Claude-Code-Session-Id / x-client-request-id — matched against
//     the official client. ApplyClaudeCodeHeaders does this.
//
//  2. Body: system[0]=billing-header block + system[1]=Claude Code prompt
//     + cache_control breakpoints on the last message + metadata.user_id
//     in the JSON shape CC >= 2.1.78 emits.
//     ApplyClaudeCodeBodyMimicry does this.
//
// Missing any of these downgrades the request to "third-party app" billing
// on OAuth credentials. Constants live in this file and are pinned to the
// CC version we're impersonating; bumping the version target requires
// re-capturing real CC traffic (see crack/) and updating these values
// together. Drift between CLICurrentVersion and claudeCLIUserAgent will
// cause Anthropic's edge to flag the request.
package mimicry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Header values pinned to Claude Code 2.1.220 / @anthropic-ai/sdk 0.94.0.
// Values verified against a live CC 2.1.220 OAuth capture with 10 independent
// first turns plus one 10-turn conversation (2026-07-30 — see
// crack/cc2220/SPEC.md). The version, build_time, title-request class, UTF-16
// billing suffix semantics, and multi-turn cc_prev_req chain were verified.
// Stainless 0.94.0 / v26.3.0 remain unchanged. The capture used ordinary
// Sonnet 5, so context-1m behavior is intentionally NOT changed by this bump.
// CLICurrentVersion MUST match the version baked into ClaudeCLIUserAgent;
// any drift will cause the cc_version=X.Y.Z.{fp} billing block to disagree
// with the User-Agent and trigger Anthropic's third-party detection.
const (
	CLICurrentVersion      = "2.1.220"
	ClaudeCLIUserAgent     = "claude-cli/2.1.220 (external, cli)"
	ClaudeStainlessLang    = "js"
	ClaudeStainlessRuntime = "node"
	// 2.1.191 jumped the bundled Node runtime v24.3.0 → v26.3.0. This single
	// constant feeds BOTH the X-Stainless-Runtime-Version request header and the
	// telemetry env.node_version (sidecar), which the live capture confirms move
	// together. UNCHANGED through 2.1.220 (still v26.3.0). (crack/cc2220/SPEC.md.)
	ClaudeStainlessRuntimeV = "v26.3.0"
	ClaudeStainlessPackageV = "0.94.0"
	// ClaudeStainlessOS deliberately does NOT track the capture. The cc2220
	// dumps were taken on macOS, but the proxy runs on Linux and the OS it
	// advertises has to agree with everything else it claims to be: the
	// per-account synthetic host in auth.HostProfile and the platform fields
	// the sidecar telemetry sends. A "MacOS" header over Linux host telemetry
	// is a louder tell than either alone. Do not "fix" this to match crack/.
	ClaudeStainlessOS   = "Linux"
	ClaudeStainlessArch = "x64"
	ClaudeStainlessTimeout  = "600"
	ClaudeStainlessRetryCnt = "0"
	ClaudeAnthropicVersion  = "2023-06-01"
	// ClaudeAnthropicBetaFull is the Anthropic-Beta REQUEST HEADER real CC
	// 2.1.220 sends on an ordinary (NON-1M) main /v1/messages request — exact
	// value, exact order (13 items). Any beta we drop that real CLI sends will
	// downgrade us to "extra usage" billing; any extra beta we add that real CLI
	// doesn't send is also a fingerprint signal.
	//
	// The 2.1.220 request list is CONTEXT-MODE DEPENDENT — established by the
	// 2026-07-31 Linux capture (crack/cc2220/SPEC.md §1a), which caught both
	// modes in one session:
	//
	//	non-1M (claude-opus-4-8)   → this 13-item list        (5 requests)
	//	1M active (claude-opus-5)  → ClaudeAnthropicBeta1M    (1 request)
	//
	// The independent 2.1.220 macOS capture (ordinary Sonnet 5, 20 controlled
	// main requests) carried this same 13-item list, so the non-1M shape has
	// 25+ requests across two hosts behind it and is the right default.
	//
	// This REPLACES the old 14-item constant (13 + context-1m, no
	// fallback-credit) inherited from the 2.1.211 capture, which matched
	// NEITHER 2.1.220 variant: real CC only sends context-1m when the 1M window
	// is actually active, and when it does it also sends fallback-credit.
	//
	// NOTE: only injected on OAuth requests that arrive WITHOUT their own beta
	// list (headers.go) — real CC passthrough keeps the client's own list, so a
	// downstream client that wants 1M declares context-1m itself, exactly as
	// the real CLI does.
	ClaudeAnthropicBetaFull = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	// ClaudeAnthropicBeta1M is the same header when the 1M context window IS
	// active (15 items): context-1m-2025-08-07 at position 3 and
	// fallback-credit-2026-06-01 between effort and extended-cache-ttl. Captured
	// verbatim from the one `claude-opus-5` request in the 2026-07-31 session
	// whose telemetry reported the model as `claude-opus-5[1m]`
	// (crack/cc2220/SPEC.md §1a).
	//
	// NOT injected automatically: a request body carries no 1M marker (the
	// `[1m]` suffix exists only in telemetry), so cc-core cannot infer the mode.
	// Exported so a fork offering an explicit "1M mode" sends the real list
	// instead of hand-assembling one. Single-sample — re-verify on the next
	// capture before treating it as settled.
	ClaudeAnthropicBeta1M = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	// ClaudeAnthropicBetaCountTokens is the beta list real CC 2.1.220 sends on
	// POST /v1/messages/count_tokens — a request class of its own, NOT the main
	// list (5 items, 4 samples, crack/cc2220/SPEC.md §1b). count_tokens also
	// omits X-Stainless-Timeout, which every main request carries; headers.go
	// reproduces both differences.
	ClaudeAnthropicBetaCountTokens = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,token-counting-2024-11-01"
	// ClaudeReportedBetas is the SHORTER beta list real CC 2.1.191 reports in
	// its telemetry bodies (event_logging `betas`, datadog `betas`/ddtags) — 9
	// items, stopping at mid-conversation-system. In the 2.1.191 telemetry this
	// 9-item list pairs with the
	// `[1m]` model variant (1M-context active → context-1m beta reported);
	// plain-model events carry an 8-item variant without context-1m. Our sidecar
	// heartbeat emits the `[1m]` + 9-item pair, so this stays the 9-item list.
	// Verified unchanged 2.1.156→2.1.214. The 2.1.214 capture session ran WITH 1M
	// context, so its telemetry directly RE-CONFIRMS this exact 9-item list paired
	// with the `claude-opus-4-8[1m]` model (crack/cc2214/SPEC.md §3). Our sidecar
	// keeps emitting the `[1m]` + 9-item pair. The ordinary Sonnet 5 capture at
	// 2.1.220 independently observed the expected 8-item non-1M variant, but is
	// not evidence for changing this 1M sidecar constant. Keep it semantically
	// separate from ClaudeAnthropicBetaFull: request betas and reported telemetry
	// betas vary on different axes even when this 1M list happens to be a prefix.
	ClaudeReportedBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07"

	// ClaudeAnthropicBetaApikey is the Anthropic-Beta REQUEST HEADER real CC
	// sends on the API-KEY path (real CC pointed at a 3rd-party gateway with
	// x-api-key), captured from crack/apikey/rows/*-POST-…v1_messages. Strict
	// gateways (fucheers, etc.) reject any unknown beta token — notably they
	// reject advanced-tool-use-* and cache-diagnosis-*, which real CC does NOT
	// send on the apikey path. It also drops oauth-2025-04-20 (no OAuth here).
	// Keep this list verbatim from capture; no 2.1.183 api-key capture exists,
	// left verbatim from the 2.1.146 set.
	ClaudeAnthropicBetaApikey = "claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,context-1m-2025-08-07,effort-2025-11-24"
)

// Default cache_control TTL for cache breakpoints injected by the body
// layer. Real CC 2.1.191 uses "1h" with scope=global on the second-to-last
// system block (the last block is plain ephemeral) — match it so prefix
// caching works the same way and the request shape is byte-identical.
const (
	ClaudeDefaultCacheTTL   = "1h"
	ClaudeDefaultCacheScope = "global"
)

// ClaudeCodeSystemPrompt is the first non-billing system block on every
// real CLI request.
const ClaudeCodeSystemPrompt = "You are Claude Code, Anthropic's official CLI for Claude."

// ClaudeCodePromptPrefixes detects requests whose system field already
// looks like a Claude Code request — leave those alone (don't double-inject).
var ClaudeCodePromptPrefixes = []string{
	"You are Claude Code, Anthropic's official CLI for Claude",
	"You are a Claude agent, built on Anthropic's Claude Agent SDK",
	"You are a file search specialist for Claude Code",
	"You are a helpful AI assistant tasked with summarizing conversations",
}

// NewRequestUUID returns a fresh RFC 4122 v4 UUID — used for the
// x-client-request-id header that real CC sets on every request.
func NewRequestUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is essentially impossible; fall back to a
		// deterministic string so the request still ships.
		return "00000000-0000-4000-8000-000000000000"
	}
	return uuidFromBytes(b[:])
}

// UUIDFromBytes formats the first 16 bytes of b as a v4-shaped UUID
// (version + variant nibbles forced). Used to derive deterministic
// session ids from hashes — same input → same UUID forever.
func UUIDFromBytes(b []byte) string { return uuidFromBytes(b) }

func uuidFromBytes(b []byte) string {
	out := make([]byte, 16)
	copy(out, b)
	out[6] = (out[6] & 0x0f) | 0x40 // version 4
	out[8] = (out[8] & 0x3f) | 0x80 // variant RFC 4122
	hexs := hex.EncodeToString(out)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexs[0:8], hexs[8:12], hexs[12:16], hexs[16:20], hexs[20:32])
}

// ensureHeader sets name=value only if the header isn't already set.
// Client-supplied values win over our defaults so callers that have
// already copied through forwardable headers don't get clobbered.
func ensureHeader(h http.Header, name, value string) {
	if strings.TrimSpace(h.Get(name)) == "" {
		h.Set(name, value)
	}
}
