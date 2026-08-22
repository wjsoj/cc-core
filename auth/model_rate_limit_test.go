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

// withFableOAuthDisabled flips the legacy blanket policy on for one test and
// restores it afterwards, so the default-path tests around it stay honest.
func withFableOAuthDisabled(t *testing.T) {
	t.Helper()
	prev := AnthropicFableOAuthDisabled
	AnthropicFableOAuthDisabled = true
	t.Cleanup(func() { AnthropicFableOAuthDisabled = prev })
}

func TestAnthropicModelRequiresAPIKey(t *testing.T) {
	fableModels := []string{
		"claude-fable-5",
		"claude-fable-5-20260601",
		"claude-fable-5[1m]",
		"anthropic/CLAUDE-FABLE-5",
	}
	otherModels := []string{"claude-opus-5", "claude-sonnet-5", "my-fable-model"}

	// Default policy: nothing is API-key-only. Fable rides OAuth like the rest,
	// and a credential that cannot serve it says so per-credential.
	for _, model := range append(append([]string{}, fableModels...), otherModels...) {
		if AnthropicModelRequiresAPIKey(model) {
			t.Errorf("default policy: AnthropicModelRequiresAPIKey(%q) = true", model)
		}
	}

	// Legacy policy: fable — and only fable — bypasses OAuth.
	withFableOAuthDisabled(t)
	for _, model := range fableModels {
		if !AnthropicModelRequiresAPIKey(model) {
			t.Errorf("legacy policy: AnthropicModelRequiresAPIKey(%q) = false", model)
		}
	}
	for _, model := range otherModels {
		if AnthropicModelRequiresAPIKey(model) {
			t.Errorf("legacy policy: AnthropicModelRequiresAPIKey(%q) = true", model)
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

// TestScheduleFableUsesOAuthUntilTheCredentialRefuses is the core end-to-end
// guard for the default policy: fable schedules onto OAuth like any other
// model, and only the credential that actually hit its fable allotment is
// skipped — for fable alone.
func TestScheduleFableUsesOAuthUntilTheCredentialRefuses(t *testing.T) {
	limited := mustOAuth(t, "limited", "anthropic", "g", 1)
	limited.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))

	// The one credential in the pool is fable-limited, so fable has nowhere
	// to go — the scoped cooldown, not a blanket rule, is what stops it.
	p := NewPool([]*Auth{limited}, nil, time.Minute, false, "")
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c1", []string{"g"}, "claude-fable-5", "sess-fable"); got != nil {
		t.Fatalf("fable-limited credential must be skipped for fable, got %s", got.ID)
	}

	// The very same credential still serves every other model.
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c2", []string{"g"}, "claude-opus-4-8", "sess-opus"); got == nil || got.ID != "limited" {
		t.Fatalf("non-fable request must still use the credential, got %v", got)
	}

	// A healthy OAuth sibling takes the fable request in preference to the
	// API key: OAuth is the cheap channel and it is not fable-limited.
	healthy := mustOAuth(t, "healthy", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p2 := NewPool([]*Auth{limited, healthy}, []*Auth{key}, time.Minute, false, "")
	if _, got := p2.AcquireMulti(context.Background(), "anthropic", "c3", []string{"g"}, "claude-fable-5", "sess-fable2"); got == nil || got.ID != "healthy" {
		t.Fatalf("fable should schedule onto the healthy OAuth, got %v", got)
	}
}

// TestScheduleRoutesFableOnlyToAPIKeyWhenDisabled pins the legacy escape hatch:
// with AnthropicFableOAuthDisabled on, every fable request bypasses OAuth even
// when a perfectly healthy credential is sitting there.
func TestScheduleRoutesFableOnlyToAPIKeyWhenDisabled(t *testing.T) {
	withFableOAuthDisabled(t)

	healthy := mustOAuth(t, "healthy", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{healthy}, []*Auth{key}, time.Minute, false, "")

	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c1", []string{"g"}, "claude-fable-5", "sess-fable"); got == nil || got.ID != "key" {
		t.Fatalf("fable request should route to the API key, got %v", got)
	}
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c2", []string{"g"}, "claude-opus-5", "sess-opus"); got == nil || got.ID != "healthy" {
		t.Fatalf("non-fable request must still use the OAuth credential, got %v", got)
	}
}

// TestFableKeepsStickyOAuthAssignment is the regression the blanket rule caused:
// because the check sat on the first line of oauthUsableLocked it also tore down
// an existing sticky binding, so a client toggling to fable and back was
// reassigned to a different account mid-conversation.
func TestFableKeepsStickyOAuthAssignment(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 2)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	const token, session = "client", "same-session"
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-opus-5", session); got == nil || got.ID != "oauth" {
		t.Fatalf("initial included model should stick to OAuth, got %v", got)
	}
	if got := p.Acquire(context.Background(), ProviderAnthropic, token, "g", "claude-fable-5", session); got == nil || got.ID != "oauth" {
		t.Fatalf("fable must reuse the sticky OAuth binding, got %v", got)
	}
}

func TestFableBreaksStickyOAuthAssignmentWhenDisabled(t *testing.T) {
	withFableOAuthDisabled(t)

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

// TestFableServesOAuthUnderDisabledAPIKeyFallback: the billing opt-out is about
// channels that bill ABOVE the client's own rate, which is what an API key can
// do (PriceMultiplier) and an OAuth credential never does. Serving fable from
// OAuth therefore honours the opt-out rather than violating it — refusing the
// request would be the actual violation of what the client asked for.
func TestFableServesOAuthUnderDisabledAPIKeyFallback(t *testing.T) {
	oauth := mustOAuth(t, "oauth", "anthropic", "g", 1)
	key := &Auth{ID: "key", Kind: KindAPIKey, Provider: ProviderAnthropic, Group: "g"}
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	got := p.AcquireWithOptions(context.Background(), ProviderAnthropic, "client", "g", "claude-fable-5", "session", AcquireOptions{
		AllowAPIKeyFallback: false,
	})
	if got == nil || got.ID != "oauth" {
		t.Fatalf("fable should be served by OAuth under an API-key opt-out, got %v", got)
	}
}

func TestFableRespectsDisabledAPIKeyFallbackWhenDisabled(t *testing.T) {
	withFableOAuthDisabled(t)

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
