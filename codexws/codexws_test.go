package codexws

import (
	"context"
	"strings"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"

	"github.com/wjsoj/cc-core/mimicry"
)

// header names are asserted as LITERAL map keys, never via Header.Get, because
// Get canonicalizes and would happily pass a header we spelled "Session-Id"
// while the wire needs "session-id". These assertions are the regression guard
// for that class of bug.
func hdr(h map[string][]string, name string) string {
	if v, ok := h[name]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func TestBuildUpstreamHeaders(t *testing.T) {
	h := BuildUpstreamHeaders("tok-abc", "acct-123", "sess-xyz", "", "gpt-5.6-sol", "priority")

	want := map[string]string{
		"chatgpt-account-id":    "acct-123",
		"authorization":         "Bearer tok-abc",
		"user-agent":            mimicry.CodexDesktopUserAgent,
		"originator":            mimicry.CodexDesktopOriginator,
		"openai-beta":           CodexOpenAIBetaWS,
		"version":               mimicry.CodexDesktopVersion,
		"x-codex-beta-features": mimicry.CodexDesktopBetaFeatures,
		"x-client-request-id":   "sess-xyz",
		"session-id":            "sess-xyz",
		"thread-id":             "sess-xyz",
		"x-codex-window-id":     "sess-xyz:0",
	}
	for name, exp := range want {
		if got := hdr(h, name); got != exp {
			t.Errorf("header %q = %q, want %q", name, got, exp)
		}
	}

	// Exactly the captured spelling — the underscore form was the old bug.
	if _, ok := h["Session_id"]; ok {
		t.Error(`"Session_id" (underscore) must not be sent; real Codex sends "session-id"`)
	}
	if _, ok := h["Session-Id"]; ok {
		t.Error(`"Session-Id" (canonicalized) must not be sent; the wire name is all-lowercase`)
	}

	// x-codex-turn-metadata: key order is part of the captured shape.
	md := hdr(h, "x-codex-turn-metadata")
	if md == "" {
		t.Fatal("x-codex-turn-metadata must be sent")
	}
	if !strings.HasPrefix(md, `{"installation_id":"`) {
		t.Errorf("turn metadata must start with installation_id, got %q", md)
	}
	for _, frag := range []string{
		`"session_id":"sess-xyz"`,
		`"thread_id":"sess-xyz"`,
		`"turn_id":""`,
		`"window_id":"sess-xyz:0"`,
		`"request_kind":"prewarm"`,
		`"thread_source":"user"`,
		`"sandbox":"seccomp"`,
	} {
		if !strings.Contains(md, frag) {
			t.Errorf("turn metadata missing %s: %s", frag, md)
		}
	}
	if strings.Contains(md, `"installation_id":""`) {
		t.Error("installation_id must be derived from the account, never empty")
	}
	// The handshake variant must NOT carry the turn-only workspace field.
	if strings.Contains(md, "workspace") {
		t.Errorf("handshake metadata must not carry workspace state: %s", md)
	}

	// Contradicted by both captures: no routing hint on the upgrade.
	if _, ok := h[mimicry.CodexRoutingHintHeader]; ok {
		t.Error("x-codex-routing-hint must not be sent on the WS handshake")
	}

	// The gorilla dialer owns these; setting them here breaks the handshake.
	for _, forbidden := range []string{"Upgrade", "Connection", "Sec-WebSocket-Key", "Content-Type", "Accept"} {
		if h.Get(forbidden) != "" {
			t.Errorf("header %q must not be set by BuildUpstreamHeaders", forbidden)
		}
	}
}

func TestBuildUpstreamHeadersDefaults(t *testing.T) {
	// Empty sessionID mints a UUID; empty accountID omits the header; explicit v1.
	h := BuildUpstreamHeaders("tok", "", "", CodexOpenAIBetaWSV1, "", "")
	sid := hdr(h, "session-id")
	if sid == "" {
		t.Fatal("empty sessionID should mint a fresh UUID, got empty")
	}
	// Real Codex session ids are UUIDv7 (time-ordered). The version nibble is
	// the 15th hex digit; a v4 there is visible to anyone who looks.
	if len(sid) != 36 || sid[14] != '7' {
		t.Errorf("session id must be a UUIDv7, got %q", sid)
	}
	if got := hdr(h, "x-client-request-id"); got != sid {
		t.Errorf("x-client-request-id = %q, want it to equal session-id %q", got, sid)
	}
	if got := hdr(h, "x-codex-window-id"); got != sid+":0" {
		t.Errorf("x-codex-window-id = %q, want %q", got, sid+":0")
	}
	if _, ok := h["chatgpt-account-id"]; ok {
		t.Error("empty accountID should omit chatgpt-account-id")
	}
	if got := hdr(h, "openai-beta"); got != CodexOpenAIBetaWSV1 {
		t.Errorf("openai-beta = %q, want v1 %q", got, CodexOpenAIBetaWSV1)
	}
}

// TestBuildUpstreamHeadersMatchesCapturedOrder asserts every header we send is
// accounted for in the captured handshake order, so a newly added header can
// never silently fall into the unordered tail.
func TestBuildUpstreamHeadersMatchesCapturedOrder(t *testing.T) {
	h := BuildUpstreamHeadersWithOptions(UpstreamHeaderOptions{
		AccessToken:    "tok",
		AccountID:      "acct",
		SessionID:      "sess",
		InstallationID: "inst",
	})
	known := map[string]bool{}
	for _, n := range HandshakeHeaderOrder() {
		known[strings.ToLower(n)] = true
	}
	for name := range h {
		if !known[strings.ToLower(name)] {
			t.Errorf("header %q is sent but missing from handshakeHeaderOrder", name)
		}
	}
}

func TestIsUnexpectedClose(t *testing.T) {
	normal := &gorillaws.CloseError{Code: gorillaws.CloseNormalClosure}
	if IsUnexpectedClose(normal) {
		t.Error("CloseNormalClosure should be expected, not unexpected")
	}
	abnormal := &gorillaws.CloseError{Code: gorillaws.CloseAbnormalClosure}
	if !IsUnexpectedClose(abnormal) {
		t.Error("CloseAbnormalClosure should be unexpected")
	}
}

func TestDialURLParseError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := Dial(ctx, DialConfig{URL: "://not a url"}); err == nil {
		t.Error("Dial with a malformed URL should return an error")
	}
}
