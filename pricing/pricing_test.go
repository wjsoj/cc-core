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
	// claude-fable-5 is the premium tier — exactly 2× opus.
	pf := cat.Lookup("anthropic", "claude-fable-5")
	if pf.InputPer1M != 10.00 || pf.OutputPer1M != 50.00 || pf.CacheReadPer1M != 1.00 || pf.CacheCreatePer1M != 12.50 {
		t.Fatalf("fable-5 price=%+v want input 10 output 50 cacheRead 1 cacheWrite 12.50", pf)
	}
}

// TestOpusTierCardsAreIdentical pins every Opus-tier model to the same card.
// The regression this guards is silent: a missing entry doesn't error, it falls
// through to builtInProviderDefaults[anthropic] (the Sonnet card) and
// undercharges by 5/3 with no signal anywhere.
func TestOpusTierCardsAreIdentical(t *testing.T) {
	cat := NewCatalog(Config{})
	want := ModelPrice{InputPer1M: 5.00, OutputPer1M: 25.00, CacheReadPer1M: 0.50, CacheCreatePer1M: 6.25}
	for _, m := range []string{"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5"} {
		if got := cat.Lookup("anthropic", m); got != want {
			t.Errorf("%s price=%+v want %+v", m, got, want)
		}
	}
	// A dated opus-5 variant must reach the same card, not the Sonnet default.
	if got := cat.Lookup("anthropic", "claude-opus-5-20260901"); got != want {
		t.Errorf("dated opus-5 price=%+v want %+v", got, want)
	}
}

// TestSonnet5IntroPrice locks the introductory rate. It EXPIRES 2026-08-31 —
// from 2026-09-01 the expected values become the sonnet-4-6 card
// (3.00/15.00/0.30/3.75). Update both this test and the catalog together.
func TestSonnet5IntroPrice(t *testing.T) {
	cat := NewCatalog(Config{})
	want := ModelPrice{InputPer1M: 2.00, OutputPer1M: 10.00, CacheReadPer1M: 0.20, CacheCreatePer1M: 2.50}
	if got := cat.Lookup("anthropic", "claude-sonnet-5"); got != want {
		t.Fatalf("sonnet-5 price=%+v want %+v (intro rate through 2026-08-31)", got, want)
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
	if p.InputPer1M != 1.75 {
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

// Real Claude Code labels a 1M-context request "claude-opus-5[1m]" in its
// telemetry. If that label ever reaches billing it must still resolve to the
// model's own card: the bracket suffix misses every key AND every "claude-…"
// prefix (the fallback only trims on "-"), so an unstripped name silently
// lands on the Anthropic provider default — the Sonnet card — undercharging
// an opus-5 request by 40%.
func TestLookupStripsContextModeSuffix(t *testing.T) {
	cat := NewCatalog(Config{})

	cases := []struct{ model, base string }{
		{"claude-opus-5[1m]", "claude-opus-5"},
		{"claude-sonnet-5[1m]", "claude-sonnet-5"},
		{"claude-opus-4-8[1m]", "claude-opus-4-8"},
		{"claude-opus-5-20260301[1m]", "claude-opus-5"},
	}
	for _, tc := range cases {
		got, want := cat.Lookup("anthropic", tc.model), cat.Lookup("anthropic", tc.base)
		if got != want {
			t.Errorf("Lookup(%q) = %+v, want the %q card %+v", tc.model, got, tc.base, want)
		}
	}

	// Guard the specific regression: opus-5[1m] must not bill at Sonnet rates.
	if p := cat.Lookup("anthropic", "claude-opus-5[1m]"); p.InputPer1M != 5.00 {
		t.Errorf("opus-5[1m] InputPer1M=%v want 5.00 (Sonnet default would be 3.00)", p.InputPer1M)
	}
}

// StripContextModeSuffix is the parse-layer canonicaliser. It must be safe to
// call on any model name: preserve case, leave non-suffixed names untouched,
// and — critically — never strip the "(effort)" suffix, which is routing
// information the caller still needs.
func TestStripContextModeSuffix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"claude-opus-5[1m]", "claude-opus-5"},
		{"claude-sonnet-5[1m]", "claude-sonnet-5"},
		{"claude-opus-5-20260301[1m]", "claude-opus-5-20260301"},
		{"Claude-Opus-5[1M]", "Claude-Opus-5"}, // case preserved
		{"claude-opus-5", "claude-opus-5"},     // no suffix → untouched
		{"", ""},
		// Routing-relevant suffix — must survive.
		{"gpt-5.3-codex(high)", "gpt-5.3-codex(high)"},
		// Malformed / degenerate inputs must not mangle the name.
		{"[1m]", "[1m]"},
		{"claude-opus-5]", "claude-opus-5]"},
	}
	for _, tc := range cases {
		if got := StripContextModeSuffix(tc.in); got != tc.want {
			t.Errorf("StripContextModeSuffix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Idempotent — callers may apply it early AND Lookup applies it again.
	once := StripContextModeSuffix("claude-opus-5[1m]")
	if twice := StripContextModeSuffix(once); twice != once {
		t.Errorf("not idempotent: %q → %q", once, twice)
	}
}
