package mimicry

import "strings"

// Anthropic-Beta repair for genuine Claude Code requests that reached us over a
// custom base URL.
//
// A reverse proxy receives the shape in crack/thirdparty/SPEC.md §1a and must
// forward the shape in crack/cc2224/rows/13-v1_messages.json. Those two differ
// by a fixed set of betas that a client talking to a third-party gateway cannot
// declare, because it has no Anthropic account to declare them against. The
// surviving items keep their relative order, so the repair is a deterministic
// insertion rather than a guess — which is what makes it safe to do at all.
//
// Deliberately NOT a wholesale replacement with one constant. The inbound vector
// still carries the request class: a session-title request declares
// structured-outputs-2025-12-15 and a count_tokens request declares a much
// shorter list. Overwriting them all with ClaudeAnthropicBetaFull would erase
// that distinction and send every request a feature vector it did not ask for —
// itself a fingerprint, and a functional regression for structured outputs.

// claudeOAuthOnlyBetas are the betas real Claude Code sends on the first-party
// OAuth path and omits on a custom base URL. Derived by subtracting the captured
// custom-base-url main vector (crack/thirdparty/rows/01-v1_messages.json) from
// ClaudeAnthropicBetaFull; TestOAuthOnlyBetasMatchCapturedDelta re-derives it
// from both constants and fails the build if they drift apart.
//
// Every member is either the OAuth marker itself or an entitlement a gateway
// account cannot hold, which is why the set is safe to add back unconditionally
// once an OAuth credential has been selected.
var claudeOAuthOnlyBetas = []string{
	oauthBetaMarker,
	"advisor-tool-2026-03-01",
	"advanced-tool-use-2025-11-20",
	"extended-cache-ttl-2025-04-11",
	"cache-diagnosis-2026-04-07",
}

// claudeBeta1MPair is the context-mode pair. Both captures that observed
// context-1m-2025-08-07 (crack/cc2220/SPEC.md §1a, crack/cc2224/rows/13) also
// carried fallback-credit-2026-06-01, and neither was ever seen alone, so a
// client that declares the first gets the second.
//
// Neither is in claudeOAuthOnlyBetas: they track the context window, not the
// credential, and the custom-base-url capture was not in 1M mode, so it cannot
// tell "gated by OAuth" from "gated by context mode". Claiming a 1M window the
// downstream never asked for is worse than not claiming it.
const (
	// oauthBetaMarker is the beta that says "this request is on a first-party
	// OAuth credential" — present on every captured OAuth request and on no
	// captured custom-base-url one, which is what makes it a reliable
	// already-repaired sentinel.
	oauthBetaMarker = "oauth-2025-04-20"

	claudeBeta1MMarker   = "context-1m-2025-08-07"
	claudeBetaFallbackCr = "fallback-credit-2026-06-01"
)

// claudeBetaCanonicalOrder is the wire order real Claude Code uses, taken
// verbatim from ClaudeAnthropicBeta1M (the widest observed vector — every other
// captured list is a subsequence of it). Repaired vectors are emitted in this
// order so an inserted beta lands where the real client would have put it.
var claudeBetaCanonicalOrder = splitBetaList(ClaudeAnthropicBeta1M)

func splitBetaList(list string) []string {
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// UpgradeClaudeBetaVectorForOAuth returns the vector a real Claude Code client
// would have sent for this same request had it been talking to api.anthropic.com
// on an OAuth credential.
//
// It only ever adds. Items the caller declared are all retained, including ones
// cc-core has never captured (a newer Claude Code may declare a beta this
// version has no constant for) — those are kept, in their original relative
// order, after the canonical ones.
//
// A vector that already carries the OAuth marker is returned unchanged: it is
// either a first-party client whose own list is authoritative, or an already
// repaired one, and in both cases second-guessing it would be wrong.
//
// The empty string maps to the empty string. Callers requiring a vector must
// reject that case themselves — genuine rewrite does, because a request class we
// cannot identify is not one we can safely synthesize a list for.
func UpgradeClaudeBetaVectorForOAuth(existing string) string {
	declared := splitBetaList(existing)
	if len(declared) == 0 {
		return ""
	}

	present := make(map[string]bool, len(declared)+len(claudeOAuthOnlyBetas)+1)
	for _, beta := range declared {
		present[beta] = true
	}
	if present[oauthBetaMarker] {
		return existing
	}

	wanted := make(map[string]bool, len(present)+len(claudeOAuthOnlyBetas)+1)
	for beta := range present {
		wanted[beta] = true
	}
	for _, beta := range claudeOAuthOnlyBetas {
		wanted[beta] = true
	}
	if wanted[claudeBeta1MMarker] {
		wanted[claudeBetaFallbackCr] = true
	}

	out := make([]string, 0, len(wanted))
	emitted := make(map[string]bool, len(wanted))
	for _, beta := range claudeBetaCanonicalOrder {
		if wanted[beta] && !emitted[beta] {
			out = append(out, beta)
			emitted[beta] = true
		}
	}
	// Betas with no canonical position keep the caller's relative order and
	// trail the known ones, which is where every newer beta has appeared in
	// capture (structured-outputs-2025-12-15 in crack/thirdparty/rows/02).
	for _, beta := range declared {
		if !emitted[beta] {
			out = append(out, beta)
			emitted[beta] = true
		}
	}
	return strings.Join(out, ",")
}
