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

// TestScheduleSkipsFableLimitedButKeepsOtherModels is the core end-to-end guard:
// a fable-limited credential is skipped for fable requests but still selected
// for other models, and a non-limited credential is preferred for fable.
func TestScheduleSkipsFableLimitedButKeepsOtherModels(t *testing.T) {
	limited := mustOAuth(t, "limited", "anthropic", "g", 1)
	limited.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))

	// Only the fable-limited credential exists: a fable request finds nothing…
	p := NewPool([]*Auth{limited}, nil, time.Minute, false, "")
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c1", []string{"g"}, "claude-fable-5", "sess-fable"); got != nil {
		t.Fatalf("fable request must skip the fable-limited credential, got %s", got.ID)
	}

	// …but an Opus request through the same credential is served.
	if _, got := p.AcquireMulti(context.Background(), "anthropic", "c2", []string{"g"}, "claude-opus-4-8", "sess-opus"); got == nil || got.ID != "limited" {
		t.Fatalf("non-fable request must still use the credential, got %v", got)
	}

	// With a healthy sibling present, the fable request routes to it.
	healthy := mustOAuth(t, "healthy", "anthropic", "g", 1)
	p2 := NewPool([]*Auth{limited, healthy}, nil, time.Minute, false, "")
	if _, got := p2.AcquireMulti(context.Background(), "anthropic", "c3", []string{"g"}, "claude-fable-5", "sess-fable2"); got == nil || got.ID != "healthy" {
		t.Fatalf("fable request should route to the healthy sibling, got %v", got)
	}
}
