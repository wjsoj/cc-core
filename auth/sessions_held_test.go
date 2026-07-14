package auth

import (
	"context"
	"testing"
	"time"
)

// SessionsHeld is the input to a per-token fair-share cap on pool slots. Slots
// are held for wildly different durations (an HTTP request: seconds; a codex-tui
// WebSocket session: up to an hour), so without a cap a few WS users can sit on
// most of a provider's capacity and starve everyone else.
func TestSessionsHeldCountsPerTokenPerProvider(t *testing.T) {
	creds := []*Auth{
		{ID: "codex-a", Kind: KindOAuth, Provider: ProviderOpenAI, MaxConcurrent: 10},
		{ID: "codex-b", Kind: KindOAuth, Provider: ProviderOpenAI, MaxConcurrent: 10},
		{ID: "claude-a", Kind: KindOAuth, Provider: ProviderAnthropic, MaxConcurrent: 10},
	}
	p := NewPool(creds, nil, 10*time.Minute, false, "")
	ctx := context.Background()

	if held, already := p.SessionsHeld(ProviderOpenAI, "tok-heavy", "s1"); held != 0 || already {
		t.Fatalf("fresh pool: held=%d already=%v, want 0/false", held, already)
	}

	// Three concurrent codex sessions for one token (e.g. three open WS windows).
	for _, sid := range []string{"s1", "s2", "s3"} {
		if a := p.Acquire(ctx, ProviderOpenAI, "tok-heavy", "", "gpt-5.6", sid); a == nil {
			t.Fatalf("Acquire(%s) returned nil", sid)
		}
	}
	held, already := p.SessionsHeld(ProviderOpenAI, "tok-heavy", "s2")
	if held != 3 {
		t.Fatalf("held=%d, want 3", held)
	}
	if !already {
		t.Fatalf("s2 is an existing session; already should be true so an established session is never refused")
	}

	// A slot the token does not own yet must report already=false — that is the
	// one a fair-share cap should be allowed to refuse.
	if _, already := p.SessionsHeld(ProviderOpenAI, "tok-heavy", "s9"); already {
		t.Fatalf("s9 was never acquired; already should be false")
	}

	// Another token's sessions must not count against this one.
	if a := p.Acquire(ctx, ProviderOpenAI, "tok-light", "", "gpt-5.6", "x1"); a == nil {
		t.Fatalf("Acquire for tok-light returned nil")
	}
	if held, _ := p.SessionsHeld(ProviderOpenAI, "tok-heavy", "s1"); held != 3 {
		t.Fatalf("tok-heavy held=%d after another token acquired; want 3", held)
	}
	if held, _ := p.SessionsHeld(ProviderOpenAI, "tok-light", "x1"); held != 1 {
		t.Fatalf("tok-light held=%d, want 1", held)
	}

	// Providers are scoped separately: a client's Claude sessions must never
	// count against its Codex budget (and vice versa).
	if a := p.Acquire(ctx, ProviderAnthropic, "tok-heavy", "", "claude-opus-4-8", "c1"); a == nil {
		t.Fatalf("Acquire for anthropic returned nil")
	}
	if held, _ := p.SessionsHeld(ProviderAnthropic, "tok-heavy", "c1"); held != 1 {
		t.Fatalf("anthropic held=%d, want 1 (must not see the 3 codex sessions)", held)
	}
	if held, _ := p.SessionsHeld(ProviderOpenAI, "tok-heavy", "s1"); held != 3 {
		t.Fatalf("codex held=%d after an anthropic acquire; want 3", held)
	}
}
