package mimicry

import (
	"net/http"
	"strings"
	"testing"
)

// The three OAuth-path beta lists are captured constants — a silent edit to
// any of them changes what Anthropic's edge sees on every request that arrives
// without its own list. Assert the exact wire values from crack/cc2220/SPEC.md
// (§1a non-1M / 1M, §1b count_tokens) so a typo or reorder fails loudly.
func TestClaudeBetaListsMatchCapture(t *testing.T) {
	cases := []struct {
		name  string
		got   string
		want  []string
		count int
	}{
		{
			name:  "non-1M main (default)",
			got:   ClaudeAnthropicBetaFull,
			count: 13,
			want: []string{
				"claude-code-20250219", "oauth-2025-04-20",
				"interleaved-thinking-2025-05-14", "redact-thinking-2026-02-12",
				"thinking-token-count-2026-05-13", "context-management-2025-06-27",
				"prompt-caching-scope-2026-01-05", "mid-conversation-system-2026-04-07",
				"advisor-tool-2026-03-01", "advanced-tool-use-2025-11-20",
				"effort-2025-11-24", "extended-cache-ttl-2025-04-11",
				"cache-diagnosis-2026-04-07",
			},
		},
		{
			name:  "1M active",
			got:   ClaudeAnthropicBeta1M,
			count: 15,
			want: []string{
				"claude-code-20250219", "oauth-2025-04-20",
				"context-1m-2025-08-07",
				"interleaved-thinking-2025-05-14", "redact-thinking-2026-02-12",
				"thinking-token-count-2026-05-13", "context-management-2025-06-27",
				"prompt-caching-scope-2026-01-05", "mid-conversation-system-2026-04-07",
				"advisor-tool-2026-03-01", "advanced-tool-use-2025-11-20",
				"effort-2025-11-24", "fallback-credit-2026-06-01",
				"extended-cache-ttl-2025-04-11", "cache-diagnosis-2026-04-07",
			},
		},
		{
			name:  "count_tokens",
			got:   ClaudeAnthropicBetaCountTokens,
			count: 5,
			want: []string{
				"claude-code-20250219", "oauth-2025-04-20",
				"interleaved-thinking-2025-05-14", "context-management-2025-06-27",
				"token-counting-2024-11-01",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := strings.Split(tc.got, ",")
			if len(parts) != tc.count {
				t.Fatalf("item count = %d, want %d: %q", len(parts), tc.count, tc.got)
			}
			if strings.Join(tc.want, ",") != tc.got {
				t.Errorf("beta list mismatch\n got: %q\nwant: %q",
					tc.got, strings.Join(tc.want, ","))
			}
		})
	}
}

// Real CC 2.1.220 only sends context-1m (and its companion fallback-credit)
// when the 1M window is actually active. Injecting them by default would be an
// extra-beta fingerprint signal on the ordinary path.
func TestDefaultBetaListOmits1MOnlyBetas(t *testing.T) {
	for _, beta := range []string{"context-1m-2025-08-07", "fallback-credit-2026-06-01"} {
		if strings.Contains(ClaudeAnthropicBetaFull, beta) {
			t.Errorf("default beta list must not carry 1M-only %q", beta)
		}
		if !strings.Contains(ClaudeAnthropicBeta1M, beta) {
			t.Errorf("1M beta list must carry %q", beta)
		}
	}
}

func newReq(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// count_tokens is a distinct request class: shorter beta list and — unlike
// every main request — no X-Stainless-Timeout.
func TestCountTokensHeaderClass(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}

	req := newReq(t, "https://api.anthropic.com/v1/messages/count_tokens?beta=true")
	ApplyClaudeCodeHeaders(req, "sk-test", KindOAuth, false, true, id, nil)

	if got := req.Header.Get("Anthropic-Beta"); got != ClaudeAnthropicBetaCountTokens {
		t.Errorf("count_tokens beta = %q, want %q", got, ClaudeAnthropicBetaCountTokens)
	}
	if got := req.Header.Get("X-Stainless-Timeout"); got != "" {
		t.Errorf("count_tokens must not carry X-Stainless-Timeout, got %q", got)
	}
	// Retry-Count IS still sent on count_tokens.
	if got := req.Header.Get("X-Stainless-Retry-Count"); got != ClaudeStainlessRetryCnt {
		t.Errorf("count_tokens retry-count = %q, want %q", got, ClaudeStainlessRetryCnt)
	}
}

func TestMainMessagesKeepsTimeoutAndFullBetas(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}

	req := newReq(t, "https://api.anthropic.com/v1/messages?beta=true")
	ApplyClaudeCodeHeaders(req, "sk-test", KindOAuth, true, true, id, nil)

	if got := req.Header.Get("Anthropic-Beta"); got != ClaudeAnthropicBetaFull {
		t.Errorf("main beta = %q, want the full non-1M list", got)
	}
	if got := req.Header.Get("X-Stainless-Timeout"); got != ClaudeStainlessTimeout {
		t.Errorf("main timeout = %q, want %q", got, ClaudeStainlessTimeout)
	}
}

// A client that declares its own betas keeps them verbatim (we only ensure the
// oauth marker) — this is how a downstream client opts into 1M, exactly as the
// real CLI does. count_tokens detection must not override that.
func TestClientSuppliedBetasWinOnCountTokens(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}

	req := newReq(t, "https://api.anthropic.com/v1/messages/count_tokens")
	req.Header.Set("Anthropic-Beta", "context-1m-2025-08-07")
	ApplyClaudeCodeHeaders(req, "sk-test", KindOAuth, false, true, id, nil)

	got := req.Header.Get("Anthropic-Beta")
	if !strings.HasPrefix(got, "context-1m-2025-08-07") {
		t.Errorf("client beta list was clobbered: %q", got)
	}
	if !strings.Contains(got, "oauth-2025-04-20") {
		t.Errorf("oauth marker not appended to client list: %q", got)
	}
}

// The apikey path has its own captured list and must not pick up the
// count_tokens branch (no apikey count_tokens capture exists).
func TestAPIKeyPathUnaffectedByCountTokens(t *testing.T) {
	id := SimIdentity{AccountKey: "acct", AccountUUID: "uuid", ClientToken: "tok"}

	req := newReq(t, "https://gateway.example.com/v1/messages/count_tokens")
	ApplyClaudeCodeHeaders(req, "sk-test", KindAPIKey, false, false, id, nil)

	if got := req.Header.Get("Anthropic-Beta"); got != ClaudeAnthropicBetaApikey {
		t.Errorf("apikey beta = %q, want the apikey list", got)
	}
}
