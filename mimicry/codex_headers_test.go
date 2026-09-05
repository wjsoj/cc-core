package mimicry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real Codex sets OpenAI-Beta only on the WebSocket handshake. Through 0.153.4
// the string "responses=experimental" does not exist anywhere in codex-rs, so
// emitting it on the HTTP path is a value no genuine client sends.
func TestApplyCodexCLIHeadersSendsNoLegacyBeta(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.6-sol", "")

	if got := req.Header.Get("OpenAI-Beta"); got != "" {
		t.Errorf("OpenAI-Beta = %q; the HTTP path must send none", got)
	}
	// The default identity is codex-tui as of 2026-09-05 (it was Codex Desktop
	// until gpt-6-astra's 0.153.0 floor forced the flip — see
	// DefaultCodexProfile). Assert through the profile rather than a named
	// constant so this test follows the default instead of pinning it twice.
	def := DefaultCodexProfile()
	if got := req.Header.Get("User-Agent"); got != def.UserAgent {
		t.Errorf("User-Agent = %q, want the default profile's %q", got, def.UserAgent)
	}
	if got := req.Header.Get("Version"); got != def.Version {
		t.Errorf("Version = %q, want the default profile's %q", got, def.Version)
	}
	if got := req.Header.Get("Originator"); got != def.Originator {
		t.Errorf("Originator = %q, want the default profile's %q", got, def.Originator)
	}
}

// The three identity fields are validated against each other upstream (an
// originator that disagrees with the UA's leading segment 404s), so a profile
// must never be assembled from parts of two.
func TestCodexProfilesAreSelfConsistent(t *testing.T) {
	for _, p := range []CodexClientProfile{CodexDesktopClientProfile(), CodexTUIClientProfile()} {
		if !strings.HasPrefix(p.UserAgent, p.Originator+"/"+p.Version+" ") {
			t.Errorf("profile %q: User-Agent %q must start with %q", p.Originator, p.UserAgent, p.Originator+"/"+p.Version)
		}
	}
}

// Regression guard for the header name. cc-core sent "Session_id" for two
// capture generations while every genuine Codex client sends "session-id";
// Header.Get would mask the difference, so this reads the raw map key.
func TestApplyCodexCLIHeadersSessionIDHeaderName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("Session_id", "stale-value-from-a-previous-attempt")
	ApplyCodexCLIHeaders(req, "tok", "acct", false, "gpt-5.6-sol", "")

	if _, ok := req.Header["Session_id"]; ok {
		t.Error(`"Session_id" (underscore) must be removed, not carried alongside`)
	}
	if _, ok := req.Header["Session-Id"]; ok {
		t.Error(`"Session-Id" (canonicalized) must not be sent; the wire name is all-lowercase`)
	}
	v, ok := req.Header[CodexSessionIDHeader]
	if !ok || len(v) == 0 || v[0] == "" {
		t.Fatalf("header %q must be set, got %v", CodexSessionIDHeader, req.Header)
	}
}

// An explicit profile must override the default end to end.
func TestApplyCodexHeadersWithProfile(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	ApplyCodexHeadersWithProfile(req, CodexTUIClientProfile(), "tok", "acct", false, "", "")

	if got := req.Header.Get("Originator"); got != CodexOriginator {
		t.Errorf("Originator = %q, want %q", got, CodexOriginator)
	}
	if got := req.Header.Get("User-Agent"); got != CodexCLIUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, CodexCLIUserAgent)
	}
	if got := req.Header.Get("Version"); got != CodexCLIVersion {
		t.Errorf("Version = %q, want %q", got, CodexCLIVersion)
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

func TestCodexModelAndTier(t *testing.T) {
	for _, tc := range []struct{ name, body, wantModel, wantTier string }{
		{"both", `{"model":"gpt-5.6-sol","service_tier":"priority","input":[]}`, "gpt-5.6-sol", "priority"},
		{"model only", `{"model":"gpt-5.5","input":[]}`, "gpt-5.5", ""},
		{"neither", `{"input":[]}`, "", ""},
		{"not json", `garbage`, "", ""},
		{"empty", ``, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, tier := CodexModelAndTier([]byte(tc.body))
			if m != tc.wantModel || tier != tc.wantTier {
				t.Errorf("CodexModelAndTier() = (%q,%q), want (%q,%q)", m, tier, tc.wantModel, tc.wantTier)
			}
		})
	}
}

// The session id is the upstream prompt-cache namespace on this path. Handing
// the same conversation a new one per request is what dropped production Codex
// cache hit rate from ~87% to ~45%, so a caller-supplied id must survive
// verbatim across repeated applications.
func TestApplyCodexHeadersWithSessionIsStable(t *testing.T) {
	const sess = "01a0011b-1234-7abc-8def-0123456789ab"
	seen := make([]string, 0, 2)
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
		ApplyCodexHeadersWithSession(req, DefaultCodexProfile(), "tok", "acct", false, "gpt-5.6-sol", "", sess)
		//nolint:staticcheck // SA1008: the raw map key is the point — Header.Get
		// would canonicalize and miss the exact name we put on the wire.
		v, ok := req.Header[CodexSessionIDHeader]
		if !ok || len(v) == 0 {
			t.Fatalf("header %q must be set, got %v", CodexSessionIDHeader, req.Header)
		}
		seen = append(seen, v[0])
	}
	for _, got := range seen {
		if got != sess {
			t.Errorf("session-id = %q, want the caller's %q verbatim", got, sess)
		}
	}
}

// Empty means "no conversation to be sticky about" — still a v7, because the
// version nibble is on the wire and every id in both captures is a v7. This
// path shipped a v4 (NewRequestUUID) until the header name was corrected.
func TestApplyCodexHeadersMintsV7SessionID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	ApplyCodexHeadersWithSession(req, DefaultCodexProfile(), "tok", "acct", false, "", "", "")
	//nolint:staticcheck // SA1008: see above — asserting on the wire name.
	v := req.Header[CodexSessionIDHeader]
	if len(v) == 0 || len(v[0]) != 36 {
		t.Fatalf("session-id = %v, want a 36-char UUID", v)
	}
	if got := v[0][14]; got != '7' {
		t.Errorf("session-id %q has version nibble %q, want '7'", v[0], got)
	}
}
