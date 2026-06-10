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

// Header values pinned to Claude Code 2.1.170 / @anthropic-ai/sdk 0.94.0.
// Values verified against a live CC 2.1.170 session capture
// (whistle dump 2026-06-10 — see hypitoken crack/cc2170/SPEC.md).
// CLICurrentVersion MUST match the version baked into ClaudeCLIUserAgent;
// any drift will cause the cc_version=X.Y.Z.{fp} billing block to disagree
// with the User-Agent and trigger Anthropic's third-party detection.
const (
	CLICurrentVersion       = "2.1.170"
	ClaudeCLIUserAgent      = "claude-cli/2.1.170 (external, cli)"
	ClaudeStainlessLang     = "js"
	ClaudeStainlessRuntime  = "node"
	ClaudeStainlessRuntimeV = "v24.3.0"
	ClaudeStainlessPackageV = "0.94.0"
	ClaudeStainlessOS       = "Linux"
	ClaudeStainlessArch     = "x64"
	ClaudeStainlessTimeout  = "600"
	ClaudeStainlessRetryCnt = "0"
	ClaudeAnthropicVersion  = "2023-06-01"
	// ClaudeAnthropicBetaFull is the Anthropic-Beta REQUEST HEADER captured
	// from real CC 2.1.170 — exact value, exact order (15 items). Any beta we
	// drop that real CLI sends will downgrade us to "extra usage" billing; any
	// extra beta we add that real CLI doesn't send is also a fingerprint signal.
	// 2.1.167→2.1.170 diff: DROPPED context-1m-2025-08-07 from the request
	// header (still present in ClaudeReportedBetas below — the two lists have
	// DIVERGED), and ADDED server-side-fallback-2026-06-01 + fallback-credit-
	// 2026-06-01 after effort-2025-11-24. (hypitoken crack/cc2170/SPEC.md §1.)
	ClaudeAnthropicBetaFull = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,server-side-fallback-2026-06-01,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	// ClaudeReportedBetas is the SHORTER beta list real CC 2.1.170 reports in
	// its telemetry bodies (event_logging `betas`, datadog `betas`/ddtags) — 9
	// items, stopping at mid-conversation-system. As of 2.1.170 this is NO
	// LONGER the first-9-of-BetaFull: it still reports context-1m-2025-08-07
	// (which BetaFull dropped) and omits the two new fallback betas. Verified
	// unchanged 2.1.156→2.1.170 (crack/cc2170/SPEC.md §4). Do NOT regenerate
	// this from ClaudeAnthropicBetaFull — they have diverged.
	ClaudeReportedBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07"
)

// Default cache_control TTL for cache breakpoints injected by the body
// layer. Real CC 2.1.170 uses "1h" with scope=global on the second-to-last
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
