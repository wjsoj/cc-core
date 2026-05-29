package pricing

import (
	"testing"

	"github.com/wjsoj/cc-core/usage"
)

func TestCostFormula(t *testing.T) {
	p := ModelPrice{InputPer1M: 3.00, OutputPer1M: 15.00, CacheReadPer1M: 0.30, CacheCreatePer1M: 3.75}
	c := usage.Counts{
		InputTokens:       1_000_000,
		OutputTokens:      100_000,
		CacheReadTokens:   500_000,
		CacheCreateTokens: 200_000,
	}
	// 3.00 + 0.10*15 + 0.5*0.30 + 0.2*3.75 = 3 + 1.5 + 0.15 + 0.75 = 5.40
	got := p.Cost(c)
	if got < 5.39 || got > 5.41 {
		t.Fatalf("Cost=%v want ~5.40", got)
	}
}

func TestLookupExactMatch(t *testing.T) {
	cat := NewCatalog(Config{})
	p := cat.Lookup("anthropic", "claude-opus-4-7")
	if p.InputPer1M != 5.00 {
		t.Fatalf("opus-4-7 InputPer1M=%v want 5.00", p.InputPer1M)
	}
	// opus-4-8 bills identically to opus-4-7.
	p8 := cat.Lookup("anthropic", "claude-opus-4-8")
	if p8.InputPer1M != 5.00 || p8.OutputPer1M != 25.00 {
		t.Fatalf("opus-4-8 price=%+v want input 5.00 output 25.00", p8)
	}
}

func TestLookupDateSuffixFallback(t *testing.T) {
	cat := NewCatalog(Config{})
	// Dated variant should fall back to base entry via prefix trim.
	p := cat.Lookup("anthropic", "claude-sonnet-4-6-20260401")
	if p.InputPer1M != 3.00 {
		t.Fatalf("dated sonnet fallback wrong: %+v", p)
	}
}

func TestLookupThinkingSuffixStripped(t *testing.T) {
	cat := NewCatalog(Config{})
	p := cat.Lookup("openai", "gpt-5.3-codex(high)")
	if p.InputPer1M != 1.25 {
		t.Fatalf("thinking suffix not stripped: %+v", p)
	}
}

func TestLookupProviderAlias(t *testing.T) {
	cat := NewCatalog(Config{})
	// "claude" / "chatgpt" aliases canonicalize to anthropic / openai.
	p1 := cat.Lookup("claude", "claude-haiku-4-5")
	p2 := cat.Lookup("anthropic", "claude-haiku-4-5")
	if p1 != p2 {
		t.Fatal("claude alias should match anthropic")
	}
	p3 := cat.Lookup("chatgpt", "gpt-5")
	p4 := cat.Lookup("openai", "gpt-5")
	if p3 != p4 {
		t.Fatal("chatgpt alias should match openai")
	}
}

func TestLookupProviderDefaultFallback(t *testing.T) {
	cat := NewCatalog(Config{})
	p := cat.Lookup("openai", "gpt-99-fictional")
	// Should fall back to OpenAI provider default (gpt-5 flagship pricing).
	if p.InputPer1M != 1.25 {
		t.Fatalf("provider default fallback wrong: %+v", p)
	}
}

func TestUserConfigOverrides(t *testing.T) {
	cat := NewCatalog(Config{
		Models: map[string]ModelPrice{
			"anthropic/claude-opus-4-7": {InputPer1M: 0.01, OutputPer1M: 0.02},
		},
	})
	p := cat.Lookup("anthropic", "claude-opus-4-7")
	if p.InputPer1M != 0.01 {
		t.Fatalf("user override ignored: %+v", p)
	}
}

func TestBareModelKeyDefaultsAnthropic(t *testing.T) {
	cat := NewCatalog(Config{
		Models: map[string]ModelPrice{
			"my-custom-model": {InputPer1M: 99},
		},
	})
	if cat.Lookup("anthropic", "my-custom-model").InputPer1M != 99 {
		t.Fatal("bare key should default to anthropic")
	}
}

func TestModelsAndProviderDefaultsCopies(t *testing.T) {
	cat := NewCatalog(Config{})
	m1 := cat.Models()
	m1["anthropic/claude-opus-4-7"] = ModelPrice{} // mutate copy
	m2 := cat.Models()
	if m2["anthropic/claude-opus-4-7"].InputPer1M != 5.00 {
		t.Fatal("Models() should return a copy, not the underlying map")
	}
}
