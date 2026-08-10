package mimicry

import (
	"net/http"
	"strings"
)

// Credential kinds. Plain strings rather than typed enums so the caller can
// pass through whatever convention their auth package uses, as long as
// "oauth" identifies bearer-token OAuth credentials.
const (
	KindOAuth  = "oauth"
	KindAPIKey = "apikey"
)

// isCountTokensRequest reports whether req targets POST
// /v1/messages/count_tokens, which real CC treats as a request class of its own:
// its own (much shorter) beta list and no X-Stainless-Timeout at all
// (crack/cc2220/SPEC.md §1b). Both the plain header layer and the prepared
// pipeline have to agree on this, so it lives in one place.
func isCountTokensRequest(req *http.Request) bool {
	return req != nil && req.URL != nil &&
		strings.HasSuffix(strings.TrimSuffix(req.URL.Path, "/"), "/v1/messages/count_tokens")
}

// ApplyClaudeCodeHeaders rewrites req to look like a real Claude Code CLI
// client. Two layers of fingerprint matter to Anthropic's edge:
//
//  1. TLS — outside this package's concern (use auth.ClientFor with uTLS).
//  2. HTTP headers — handled here. The full set is User-Agent /
//     X-Stainless-* / X-App / Anthropic-Beta / X-Claude-Code-Session-Id /
//     x-client-request-id, plus Authorization / x-api-key from the
//     supplied credential.
//
// Client-supplied values (typically already populated by your forwardable-
// header copy step) win over our defaults, except for Authorization /
// x-api-key which we always overwrite with the pool-supplied credential.
//
// Known intentional deviation: Accept-Encoding is set to "gzip, br" on
// every request (matches real CC 2.1.201), not "identity". Wrap the
// response with cc-core/stream.Decompress so internal handlers see plain
// bytes.
//
// isAnthropicBase reports whether the upstream URL targets first-party
// Anthropic (api.anthropic.com); the dangerous-direct-browser-access and
// x-client-request-id headers are only set when true so third-party
// gateways (which often reject unknown headers) don't 4xx the request.
func ApplyClaudeCodeHeaders(req *http.Request, token, kind string, stream, isAnthropicBase bool, id SimIdentity, body []byte) {
	// Auth header — always overwrite whatever the client sent.
	if kind == KindAPIKey {
		req.Header.Del("Authorization")
		req.Header.Set("x-api-key", token)
	} else {
		req.Header.Del("x-api-key")
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	countTokens := isCountTokensRequest(req)

	// Anthropic protocol headers.
	ensureHeader(req.Header, "Anthropic-Version", ClaudeAnthropicVersion)
	if existing := strings.TrimSpace(req.Header.Get("Anthropic-Beta")); existing != "" {
		// Client supplied its own beta list. Keep it — it carries the request
		// class (main / title / count_tokens) that no single constant can — but
		// on the first-party OAuth path add back the betas a client on a custom
		// base URL structurally cannot declare. See beta.go and
		// crack/thirdparty/SPEC.md §1a; the transform is additive and idempotent.
		switch {
		case kind == KindOAuth && isAnthropicBase && countTokens:
			// count_tokens carries a different, much shorter OAuth vector, so
			// its repair is a different (smaller) set — see beta.go.
			req.Header.Set("Anthropic-Beta", UpgradeClaudeCountTokensBetaForOAuth(existing))
		case kind == KindOAuth && isAnthropicBase:
			req.Header.Set("Anthropic-Beta", UpgradeClaudeBetaVectorForOAuth(existing))
		case kind == KindOAuth && !strings.Contains(existing, "oauth"):
			// Non-Anthropic upstream: only the oauth marker, as before. Strict
			// gateways reject beta tokens they don't know, which is the same
			// reason ClaudeAnthropicBetaApikey is a shorter list.
			req.Header.Set("Anthropic-Beta", existing+",oauth-2025-04-20")
		}
	} else if kind == KindAPIKey {
		// Pick the right captured beta list per credential kind. The OAuth list
		// contains tokens (oauth-2025-04-20, advanced-tool-use-2025-11-20,
		// cache-diagnosis-2026-04-07) that strict 3rd-party apikey gateways will
		// reject — real CC's apikey path doesn't send them either.
		req.Header.Set("Anthropic-Beta", ClaudeAnthropicBetaApikey)
	} else if countTokens {
		// count_tokens is its own request class on the OAuth path with a much
		// shorter list — sending the main 13-item list here is a tell.
		req.Header.Set("Anthropic-Beta", ClaudeAnthropicBetaCountTokens)
	} else {
		req.Header.Set("Anthropic-Beta", ClaudeAnthropicBetaFull)
	}
	if isAnthropicBase {
		ensureHeader(req.Header, "Anthropic-Dangerous-Direct-Browser-Access", "true")
	}

	// Stainless SDK / device profile fingerprint headers.
	ensureHeader(req.Header, "X-App", "cli")
	ensureHeader(req.Header, "X-Stainless-Retry-Count", ClaudeStainlessRetryCnt)
	ensureHeader(req.Header, "X-Stainless-Lang", ClaudeStainlessLang)
	ensureHeader(req.Header, "X-Stainless-Runtime", ClaudeStainlessRuntime)
	ensureHeader(req.Header, "X-Stainless-Runtime-Version", ClaudeStainlessRuntimeV)
	ensureHeader(req.Header, "X-Stainless-Package-Version", ClaudeStainlessPackageV)
	ensureHeader(req.Header, "X-Stainless-Os", ClaudeStainlessOS)
	ensureHeader(req.Header, "X-Stainless-Arch", ClaudeStainlessArch)
	if !countTokens {
		// Real CC omits this one on count_tokens (it keeps Retry-Count).
		ensureHeader(req.Header, "X-Stainless-Timeout", ClaudeStainlessTimeout)
	}

	// Stable per-credential session ID; new UUID per request for the
	// client-request-id (only on first-party endpoint).
	ensureHeader(req.Header, "X-Claude-Code-Session-Id", SessionIDFor(id, body))
	if isAnthropicBase {
		ensureHeader(req.Header, "x-client-request-id", NewRequestUUID())
	}

	// User-Agent: keep the client value if it's already a Claude Code UA,
	// otherwise overwrite with our pinned default.
	curUA := strings.TrimSpace(req.Header.Get("User-Agent"))
	if !strings.HasPrefix(curUA, "claude-cli/") {
		req.Header.Set("User-Agent", ClaudeCLIUserAgent)
	}

	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept-Encoding", "gzip, br")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		ensureHeader(req.Header, "Accept", "application/json")
	}
}
