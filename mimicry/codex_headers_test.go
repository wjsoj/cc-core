package mimicry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real Codex sets OpenAI-Beta only on the WebSocket handshake. At 0.147.0 the
// string "responses=experimental" does not exist anywhere in codex-rs, so
// emitting it on the HTTP path is a value no genuine client sends.
func TestApplyCodexCLIHeadersSendsNoLegacyBeta(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.6-sol", "")

	if got := req.Header.Get("OpenAI-Beta"); got != "" {
		t.Errorf("OpenAI-Beta = %q; the HTTP path must send none", got)
	}
	if got := req.Header.Get("User-Agent"); got != CodexCLIUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, CodexCLIUserAgent)
	}
	if got := req.Header.Get("Version"); got != CodexCLIVersion {
		t.Errorf("Version = %q, want %q", got, CodexCLIVersion)
	}
	if got := req.Header.Get("Originator"); got != CodexOriginator {
		t.Errorf("Originator = %q, want %q", got, CodexOriginator)
	}
}

// A client-supplied OpenAI-Beta is the client's business — we stopped setting
// our own, which must not turn into stripping theirs.
func TestApplyCodexCLIHeadersLeavesClientBetaAlone(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("OpenAI-Beta", "something-the-client-wants")
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.6-sol", "")

	if got := req.Header.Get("OpenAI-Beta"); got != "something-the-client-wants" {
		t.Errorf("OpenAI-Beta = %q, want the client's value preserved", got)
	}
}

func TestApplyCodexCLIHeadersRoutingHint(t *testing.T) {
	for _, tc := range []struct {
		name, model, tier, want string
	}{
		{"model only", "gpt-5.6-sol", "", "model=gpt-5.6-sol"},
		{"priority tier", "gpt-5.6-sol", "priority", "model=gpt-5.6-sol;tier=priority"},
		{"flex tier", "gpt-5.6-luna", "flex", "model=gpt-5.6-luna;tier=flex"},
		{"tier case-insensitive", "gpt-5.6-sol", "Priority", "model=gpt-5.6-sol;tier=priority"},
		// "default" is a standard-routing sentinel upstream, not a tier to send.
		{"default tier dropped", "gpt-5.6-sol", "default", "model=gpt-5.6-sol"},
		{"unknown tier dropped", "gpt-5.6-sol", "turbo", "model=gpt-5.6-sol"},
		// No model → no hint at all, rather than a malformed one.
		{"no model", "", "priority", ""},
		{"blank model", "   ", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
			ApplyCodexCLIHeaders(req, "tok", "acct", false, tc.model, tc.tier)
			if got := req.Header.Get(CodexRoutingHintHeader); got != tc.want {
				t.Errorf("%s = %q, want %q", CodexRoutingHintHeader, got, tc.want)
			}
		})
	}
}

// A rebuilt/retried request must never carry the previous attempt's hint.
func TestApplyCodexCLIHeadersClearsStaleHint(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.6-sol", "priority")
	// Same request object, now routed to a different model with no tier.
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.5", "")
	if got := req.Header.Get(CodexRoutingHintHeader); got != "model=gpt-5.5" {
		t.Errorf("stale hint survived: got %q", got)
	}
	// And a request that resolves to no model must end up with no hint.
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "", "")
	if got := req.Header.Get(CodexRoutingHintHeader); got != "" {
		t.Errorf("hint should be cleared entirely, got %q", got)
	}
}

// A model name is a slug; anything that could break the header framing is
// dropped rather than emitted.
func TestCodexRoutingHintRejectsUnsafeModel(t *testing.T) {
	for _, bad := range []string{
		"gpt-5.6\r\nX-Injected: 1",
		"gpt-5.6\nX-Injected: 1",
		"gpt\x00null",
		"模型",
	} {
		if got := CodexRoutingHint(bad, ""); got != "" {
			t.Errorf("CodexRoutingHint(%q) = %q, want empty", bad, got)
		}
	}
}

// The UA and the Version header must agree, or the two disagree about which
// client this is.
func TestCodexVersionConsistency(t *testing.T) {
	if !strings.Contains(CodexCLIUserAgent, CodexCLIVersion) {
		t.Fatalf("User-Agent %q does not contain version %q", CodexCLIUserAgent, CodexCLIVersion)
	}
	if !strings.HasPrefix(CodexCLIUserAgent, CodexOriginator+"/"+CodexCLIVersion+" ") {
		t.Errorf("User-Agent %q must start with %s/%s", CodexCLIUserAgent, CodexOriginator, CodexCLIVersion)
	}
	// The suffix segment repeats the version; both must move together.
	if strings.Count(CodexCLIUserAgent, CodexCLIVersion) != 2 {
		t.Errorf("User-Agent %q should carry the version twice (prefix + suffix)", CodexCLIUserAgent)
	}
}
