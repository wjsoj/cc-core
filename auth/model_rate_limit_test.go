package auth

import (
	"context"
	"testing"
	"time"
)

func TestAnthropicModelScope(t *testing.T) {
	cases := map[string]string{
		"claude-fable-5":           ModelScopeAnthropicFable,
		"claude-fable-5-20260601":  ModelScopeAnthropicFable,
		"claude-fable-5[1m]":       ModelScopeAnthropicFable,
		"CLAUDE-FABLE-5":           ModelScopeAnthropicFable,
		"anthropic/claude-fable-5": ModelScopeAnthropicFable,
		"my-fable-model":           "",
		"claude-fable-50":          "",
		"claude-opus-4-8":          "",
		"claude-sonnet-5":          "",
		"":                         "",
	}
	for model, want := range cases {
		if got := AnthropicModelScope(model); got != want {
			t.Errorf("AnthropicModelScope(%q) = %q, want %q", model, got, want)
		}
	}
}

func TestAnthropicModelRequiresAPIKey(t *testing.T) {
	for _, model := range []string{
		"claude-fable-5",
		"claude-fable-5-20260601",
		"claude-fable-5[1m]",
		"anthropic/CLAUDE-FABLE-5",
	} {
		if !AnthropicModelRequiresAPIKey(model) {
			t.Errorf("AnthropicModelRequiresAPIKey(%q) = false", model)
		}
	}
	for _, model := range []string{"claude-opus-5", "claude-sonnet-5", "my-fable-model"} {
		if AnthropicModelRequiresAPIKey(model) {
			t.Errorf("AnthropicModelRequiresAPIKey(%q) = true", model)
		}
	}
}

func TestModelRateLimitMarkAndExpiry(t *testing.T) {
	a := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}
	now := time.Now()

	if a.IsModelRateLimited(ModelScopeAnthropicFable, now) {
		t.Fatal("fresh credential should not be model-rate-limited")
	}

	a.MarkModelRateLimited(ModelScopeAnthropicFable, now.Add(time.Hour))
	if !a.IsModelRateLimited(ModelScopeAnthropicFable, now) {
		t.Fatal("credential should be fable-limited within the cooldown window")
	}

	// A model-scoped limit must NOT flag the whole account.
	if a.IsQuotaExceeded(now) {
		t.Fatal("model-scoped limit must not set account-wide quota")
	}
	if !a.IsHealthy() {
		t.Fatal("model-scoped limit must not make the account unhealthy")
	}

	// Past the reset the entry auto-clears.
	later := now.Add(2 * time.Hour)
	if a.IsModelRateLimited(ModelScopeAnthropicFable, later) {
		t.Fatal("expired fable limit should read as cleared")
	}
	a.mu.Lock()
	_, still := a.ModelRateLimits[ModelScopeAnthropicFable]
	a.mu.Unlock()
	if still {
		t.Fatal("expired scope should be pruned from the map")
	}
}

func TestClearQuotaClearsModelScopes(t *testing.T) {
	a := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}
	a.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))
	a.ClearQuota()
	if a.IsModelRateLimited(ModelScopeAnthropicFable, time.Now()) {
		t.Fatal("ClearQuota should wipe model-scoped limits")
	}
}

// Until 2026-08-25 Anthropic sold Fable 5 through separately purchased usage
// credits and rejected subscription OAuth with credits_required, so the
// scheduler refused fable on OAuth outright. Fable is now permanently included
// in the plans and the gate is gone. The tests below pin what replaced it.
//
// The distinction that survives, and the one that matters operationally: fable
// still has its OWN quota window. A credential whose fable allotment is spent
// must be skipped FOR FABLE ONLY and the traffic must land on an API key —
// without the account being flagged account-wide, because every other model on
// that credential is still perfectly serviceable.

// TestFableUsesOAuthThenFallsBackWhenItsWindowIsSpent is the end-to-end guard
// for the post-2026-08-25 routing: OAuth first, API key only once this
// credential's fable window is actually spent.
func TestFableUsesOAuthThenFallsBackWhenItsWindowIsSpent(t *testing.T) {
	healthy := mustOAuth(t, "healthy", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}

	// A plan-included fable request now takes the OAuth credential, not the key.
	p := NewPool([]*Auth{healthy}, []*Auth{key}, time.Minute, false, "")
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c1", []string{"g"}, "claude-fable-5", "sess-1"); got == nil || got.ID != "healthy" {
		t.Fatalf("fable must route to OAuth now that it is plan-included, got %v", got)
	}

	// With every OAuth's fable window spent, the request falls back to the key.
	spent := mustOAuth(t, "spent", "anthropic", "g", 1)
	spent.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))
	p2 := NewPool([]*Auth{spent}, []*Auth{key}, time.Minute, false, "")
	if _, got := p2.AcquireMulti(context.Background(), "anthropic", "c2", []string{"g"}, "claude-fable-5", "sess-2"); got == nil || got.ID != "key" {
		t.Fatalf("a spent fable window must fall back to the API key, got %v", got)
	}

	// A credential with a spent fable window is still preferred over the key
	// for every other model — the limit is scoped, not account-wide.
	if _, got := p2.AcquireMulti(context.Background(), "anthropic", "c3", []string{"g"}, "claude-opus-4-8", "sess-3"); got == nil || got.ID != "spent" {
		t.Fatalf("non-fable traffic must still use the OAuth credential, got %v", got)
	}

	// An OAuth sibling with allotment left beats the API key for fable.
	p3 := NewPool([]*Auth{spent, healthy}, []*Auth{key}, time.Minute, false, "")
	if _, got := p3.AcquireMulti(context.Background(), "anthropic", "c4", []string{"g"}, "claude-fable-5", "sess-4"); got == nil || got.ID != "healthy" {
		t.Fatalf("fable should prefer an OAuth with allotment left, got %v", got)
	}
}

// TestFableWindowExhaustionIsNotAccountQuota is the invariant behind the
// fallback above: exhausting fable must never set the account-wide quota flag.
//
// Getting this wrong is expensive in a way that is easy to miss — the
// credential would vanish from the pool for EVERY model over a limit that
// applies to one, and IsQuotaExceeded's cooldown would keep it dark long after
// the traffic that could still be served on it had been shed elsewhere.
func TestFableWindowExhaustionIsNotAccountQuota(t *testing.T) {
	a := mustOAuth(t, "sub", "anthropic", "g", 1)
	a.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))

	now := time.Now()
	if a.IsQuotaExceeded(now) {
		t.Fatal("a spent fable window must not raise the account-wide quota flag")
	}
	if !a.IsHealthy() {
		t.Fatal("a spent fable window must leave the credential healthy")
	}

	p := NewPool([]*Auth{a}, nil, time.Minute, false, "")
	p.mu.Lock()
	fableUsable := p.oauthUsableLocked(a, now, "claude-fable-5")
	opusUsable := p.oauthUsableLocked(a, now, "claude-opus-4-8")
	p.mu.Unlock()
	if fableUsable {
		t.Error("credential must be skipped for fable while its window is spent")
	}
	if !opusUsable {
		t.Error("credential must stay usable for every other model")
	}
}

// TestFableKeepsStickyOAuthAssignment reverses a rule that only made sense
// while fable was API-key-only: a fable turn used to BREAK an existing sticky
// OAuth binding, because it could not be served there at all. It is now an
// ordinary plan-included model, so the binding — and with it the account's
// prompt cache — must survive a fable turn.
func TestFableKeepsStickyOAuthAssignment(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 2)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	const token, session = "client", "same-session"
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-opus-5", session); got == nil || got.ID != "oauth" {
		t.Fatalf("initial included model should stick to OAuth, got %v", got)
	}
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-fable-5", session); got == nil || got.ID != "oauth" {
		t.Fatalf("fable must keep the sticky OAuth route, got %v", got)
	}
}

// TestFableServedByOAuthWithoutAPIKeyFallback: a client that opted out of
// API-key billing used to get nil for every fable request, since OAuth was
// closed to it. It now gets served from OAuth like any other model — and still
// gets nil once that credential's fable window is spent, because the fallback
// it declined is the only route left.
func TestFableServedByOAuthWithoutAPIKeyFallback(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	got := p.AcquireWithOptions(context.Background(), ProviderAnthropic, "client", "g", "claude-fable-5", "session", AcquireOptions{
		AllowAPIKeyFallback: false,
	})
	if got == nil || got.ID != "oauth" {
		t.Fatalf("fable must be served from OAuth without needing the API-key opt-in, got %v", got)
	}

	oauth.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))
	if got := p.AcquireWithOptions(context.Background(), ProviderAnthropic, "client", "g", "claude-fable-5", "session2", AcquireOptions{
		AllowAPIKeyFallback: false,
	}); got != nil {
		t.Fatalf("API-key opt-out must still hold once the fable window is spent, got %s", got.ID)
	}
}
