package codexws

import (
	"context"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"

	"github.com/wjsoj/cc-core/mimicry"
)

func TestBuildUpstreamHeaders(t *testing.T) {
	h := BuildUpstreamHeaders("tok-abc", "acct-123", "sess-xyz", "")

	if got := h.Get("Authorization"); got != "Bearer tok-abc" {
		t.Errorf("Authorization = %q, want Bearer tok-abc", got)
	}
	if got := h.Get("Chatgpt-Account-Id"); got != "acct-123" {
		t.Errorf("Chatgpt-Account-Id = %q, want acct-123", got)
	}
	if got := h.Get("Session_id"); got != "sess-xyz" {
		t.Errorf("Session_id = %q, want sess-xyz", got)
	}
	if got := h.Get("OpenAI-Beta"); got != CodexOpenAIBetaWS {
		t.Errorf("OpenAI-Beta = %q, want %q (v2 default)", got, CodexOpenAIBetaWS)
	}
	if got := h.Get("Originator"); got != mimicry.CodexOriginator {
		t.Errorf("Originator = %q, want %q", got, mimicry.CodexOriginator)
	}
	if got := h.Get("User-Agent"); got != mimicry.CodexCLIUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, mimicry.CodexCLIUserAgent)
	}
	if got := h.Get("Version"); got != mimicry.CodexCLIVersion {
		t.Errorf("Version = %q, want %q", got, mimicry.CodexCLIVersion)
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
	h := BuildUpstreamHeaders("tok", "", "", CodexOpenAIBetaWSV1)
	if h.Get("Session_id") == "" {
		t.Error("empty sessionID should mint a fresh UUID, got empty")
	}
	if _, ok := h["Chatgpt-Account-Id"]; ok {
		t.Error("empty accountID should omit Chatgpt-Account-Id")
	}
	if got := h.Get("OpenAI-Beta"); got != CodexOpenAIBetaWSV1 {
		t.Errorf("OpenAI-Beta = %q, want v1 %q", got, CodexOpenAIBetaWSV1)
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
