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

// TestScheduleRoutesFableOnlyToAPIKey is the core end-to-end guard: every
// Fable request bypasses OAuth, while the same OAuth remains available to all
// included subscription models.
func TestScheduleRoutesFableOnlyToAPIKey(t *testing.T) {
	limited := mustOAuth(t, "limited", "anthropic", "g", 1)
	limited.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))

	// An OAuth-only pool cannot serve Fable at all.
	p := NewPool([]*Auth{limited}, nil, time.Minute, false, "")
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c1", []string{"g"}, "claude-fable-5", "sess-fable"); got != nil {
		t.Fatalf("fable request must bypass OAuth, got %s", got.ID)
	}

	// An included model still uses the OAuth credential.
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c2", []string{"g"}, "claude-opus-4-8", "sess-opus"); got == nil || got.ID != "limited" {
		t.Fatalf("non-fable request must still use the credential, got %v", got)
	}

	// A healthy OAuth sibling is also skipped; the API key is selected.
	healthy := mustOAuth(t, "healthy", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p2 := NewPool([]*Auth{limited, healthy}, []*Auth{key}, time.Minute, false, "")
	if _, got := p2.AcquireMulti(context.Background(), "anthropic", "c3", []string{"g"}, "claude-fable-5", "sess-fable2"); got == nil || got.ID != "key" {
		t.Fatalf("fable request should route to the API key, got %v", got)
	}
}

func TestFableBreaksStickyOAuthAssignment(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 2)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	const token, session = "client", "same-session"
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-opus-5", session); got == nil || got.ID != "oauth" {
		t.Fatalf("initial included model should stick to OAuth, got %v", got)
	}
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-fable-5", session); got == nil || got.ID != "key" {
		t.Fatalf("fable must break the sticky OAuth route and use API key, got %v", got)
	}
}

func TestFableRespectsDisabledAPIKeyFallback(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	got := p.AcquireWithOptions(context.Background(), ProviderAnthropic, "client", "g", "claude-fable-5", "session", AcquireOptions{
		AllowAPIKeyFallback: false,
	})
	if got != nil {
		t.Fatalf("API-key opt-out must return nil rather than use OAuth, got %s", got.ID)
	}
}
