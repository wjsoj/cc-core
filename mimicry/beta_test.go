package mimicry

import (
	"sort"
	"strings"
	"testing"
)

// Captured verbatim from crack/claudev2.1.226-inbound/rows/ — the Anthropic-Beta headers a
// real Claude Code 2.1.226 sent through a custom base URL on 2026-08-09. These
// are the left-hand side of every repair in beta.go; edit only with a new
// capture, exactly like the OAuth-side constants in fingerprint.go.
const (
	capturedThirdPartyMainBeta  = "claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,effort-2025-11-24"
	capturedThirdPartyTitleBeta = "claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,effort-2025-11-24,structured-outputs-2025-12-15"
)

// The OAuth-only set is not a hand-maintained list: it is exactly what the
// captured custom-base-url vector is missing relative to the captured OAuth
// vector. Re-derive it here so that changing either constant without changing
// the other fails the build rather than silently shipping a wrong repair.
func TestOAuthOnlyBetasMatchCapturedDelta(t *testing.T) {
	inbound := make(map[string]bool)
	for _, beta := range splitBetaList(capturedThirdPartyMainBeta) {
		inbound[beta] = true
	}
	var delta []string
	for _, beta := range splitBetaList(ClaudeAnthropicBetaFull) {
		if !inbound[beta] {
			delta = append(delta, beta)
		}
	}

	got := append([]string(nil), claudeOAuthOnlyBetas...)
	sort.Strings(got)
	sort.Strings(delta)
	if strings.Join(got, ",") != strings.Join(delta, ",") {
		t.Fatalf("claudeOAuthOnlyBetas = %v, but Full minus the captured inbound vector = %v", got, delta)
	}

	// The inbound vector must also be a pure subset — anything the third party
	// declares that OAuth does not would mean the repair has to subtract too,
	// and additive-only would no longer be sound.
	full := make(map[string]bool)
	for _, beta := range splitBetaList(ClaudeAnthropicBetaFull) {
		full[beta] = true
	}
	for _, beta := range splitBetaList(capturedThirdPartyMainBeta) {
		if !full[beta] {
			t.Errorf("inbound beta %q is not in ClaudeAnthropicBetaFull; repair can no longer be additive-only", beta)
		}
	}
}

// The 1M pair and the OAuth-only set are different axes and must not overlap,
// or a non-1M request would start claiming a 1M window.
func TestOAuthOnlyBetasExcludeContextModePair(t *testing.T) {
	for _, beta := range claudeOAuthOnlyBetas {
		if beta == claudeBeta1MMarker || beta == claudeBetaFallbackCr {
			t.Errorf("context-mode beta %q must not be in the OAuth-only set", beta)
		}
	}
	if !strings.Contains(ClaudeAnthropicBeta1M, claudeBeta1MMarker) ||
		!strings.Contains(ClaudeAnthropicBeta1M, claudeBetaFallbackCr) {
		t.Error("ClaudeAnthropicBeta1M no longer carries the pair beta.go keys off")
	}
	if strings.Contains(ClaudeAnthropicBetaFull, claudeBeta1MMarker) {
		t.Error("ClaudeAnthropicBetaFull must stay the non-1M vector")
	}
}

func TestUpgradeClaudeBetaVectorForOAuth(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			// The headline case: captured inbound → captured outbound.
			"captured main vector becomes the captured OAuth main vector",
			capturedThirdPartyMainBeta,
			ClaudeAnthropicBetaFull,
		},
		{
			// structured-outputs has no canonical position, so it keeps its
			// place at the tail — where every newer beta has appeared so far.
			"title vector keeps its request-class bit",
			capturedThirdPartyTitleBeta,
			ClaudeAnthropicBetaFull + ",structured-outputs-2025-12-15",
		},
		{
			"already-OAuth vectors are returned untouched",
			ClaudeAnthropicBetaFull,
			ClaudeAnthropicBetaFull,
		},
		{
			"1M vectors are returned untouched",
			ClaudeAnthropicBeta1M,
			ClaudeAnthropicBeta1M,
		},
		{
			// Only what was declared, plus the OAuth-only set, plus the 1M
			// partner — the repair adds entitlements, it does not fill the
			// vector out to some canonical maximum.
			"a declared 1M marker drags in its captured partner",
			"claude-code-20250219,context-1m-2025-08-07,effort-2025-11-24",
			"claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07," +
				"advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24," +
				"fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07",
		},
		{
			"unknown betas survive, in the caller's order",
			"claude-code-20250219,zzz-future-2027-01-01,aaa-future-2027-02-02",
			"claude-code-20250219,oauth-2025-04-20,advisor-tool-2026-03-01," +
				"advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07," +
				"zzz-future-2027-01-01,aaa-future-2027-02-02",
		},
		{"empty stays empty", "", ""},
		{"whitespace-only stays empty", "  ,  ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UpgradeClaudeBetaVectorForOAuth(tc.in); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// Repairing an already repaired vector must be a no-op, because both the plain
// header layer and the prepared pipeline can run over the same request.
func TestUpgradeClaudeBetaVectorIsIdempotent(t *testing.T) {
	for _, in := range []string{capturedThirdPartyMainBeta, capturedThirdPartyTitleBeta, ClaudeAnthropicBetaCountTokens} {
		once := UpgradeClaudeBetaVectorForOAuth(in)
		if twice := UpgradeClaudeBetaVectorForOAuth(once); twice != once {
			t.Errorf("not idempotent for %q:\n once  %q\n twice %q", in, once, twice)
		}
	}
}

// The repair must never drop something the caller declared. Losing a beta is a
// functional regression (structured outputs stop parsing, 1M silently shrinks),
// which is worse than the fingerprint gap it was meant to close.
func TestUpgradeClaudeBetaVectorNeverDrops(t *testing.T) {
	for _, in := range []string{
		capturedThirdPartyMainBeta,
		capturedThirdPartyTitleBeta,
		ClaudeAnthropicBetaCountTokens,
		ClaudeAnthropicBetaApikey,
		"solo-2026-01-01",
	} {
		got := make(map[string]bool)
		for _, beta := range splitBetaList(UpgradeClaudeBetaVectorForOAuth(in)) {
			got[beta] = true
		}
		for _, beta := range splitBetaList(in) {
			if !got[beta] {
				t.Errorf("input %q lost declared beta %q", in, beta)
			}
		}
	}
}

// Canonical order is the wire order, so a repaired vector must never emit two
// items in an order the real client would not.
func TestRepairedVectorFollowsCanonicalOrder(t *testing.T) {
	index := make(map[string]int, len(claudeBetaCanonicalOrder))
	for i, beta := range claudeBetaCanonicalOrder {
		index[beta] = i
	}
	got := splitBetaList(UpgradeClaudeBetaVectorForOAuth(capturedThirdPartyTitleBeta))
	previous := -1
	for _, beta := range got {
		position, known := index[beta]
		if !known {
			continue
		}
		if position < previous {
			t.Fatalf("beta %q is out of canonical order in %v", beta, got)
		}
		previous = position
	}
}

// The count_tokens repair is a different, smaller set — and this is the check
// that it stays correct rather than merely asserted in a comment. Of the
// OAuth-only betas, only the marker appears in the captured count_tokens
// vector, so only the marker may be added there.
func TestCountTokensOAuthOnlyDeltaIsJustTheMarker(t *testing.T) {
	inCountTokens := make(map[string]bool)
	for _, beta := range splitBetaList(ClaudeAnthropicBetaCountTokens) {
		inCountTokens[beta] = true
	}
	for _, beta := range claudeOAuthOnlyBetas {
		if beta == oauthBetaMarker {
			if !inCountTokens[beta] {
				t.Errorf("captured count_tokens vector lost the oauth marker")
			}
			continue
		}
		if inCountTokens[beta] {
			t.Errorf("OAuth-only beta %q now appears in the count_tokens vector; "+
				"UpgradeClaudeCountTokensBetaForOAuth must add it too", beta)
		}
	}
}

// Repairing a custom-base-url count_tokens vector must reproduce the captured
// OAuth count_tokens vector exactly — not the main one.
func TestUpgradeCountTokensVector(t *testing.T) {
	// The captured OAuth vector minus the marker is what a client on a custom
	// base URL would send.
	var inbound []string
	for _, beta := range splitBetaList(ClaudeAnthropicBetaCountTokens) {
		if beta != oauthBetaMarker {
			inbound = append(inbound, beta)
		}
	}
	got := UpgradeClaudeCountTokensBetaForOAuth(strings.Join(inbound, ","))
	if got != ClaudeAnthropicBetaCountTokens {
		t.Errorf("got  %q\nwant %q", got, ClaudeAnthropicBetaCountTokens)
	}

	// And it must not drag in the main-request entitlements.
	for _, beta := range []string{"advisor-tool-2026-03-01", "advanced-tool-use-2025-11-20",
		"extended-cache-ttl-2025-04-11", "cache-diagnosis-2026-04-07"} {
		if strings.Contains(got, beta) {
			t.Errorf("count_tokens repair added %q, which real CC never sends there", beta)
		}
	}
}
