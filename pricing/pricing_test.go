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

// TestSonnet5ListPrice pins sonnet-5 at list price. Its introductory rate
// (2.00/10.00/0.20/2.50) expired 2026-08-31; intro_expiry_test.go caught the
// lapse on 2026-09-02 and the card moved to the sonnet-4-6 values, which makes
// the DefaultClaudeOAuthModelMap sonnet fold billing-neutral.
func TestSonnet5ListPrice(t *testing.T) {
	cat := NewCatalog(Config{})
	want := ModelPrice{InputPer1M: 3.00, OutputPer1M: 15.00, CacheReadPer1M: 0.30, CacheCreatePer1M: 3.75}
	if got := cat.Lookup("anthropic", "claude-sonnet-5"); got != want {
		t.Fatalf("sonnet-5 price=%+v want list %+v", got, want)
	}
	if got := cat.Lookup("anthropic", "claude-sonnet-4-6"); got != want {
		t.Fatalf("sonnet-4-6 → sonnet-5 fold is no longer billing-neutral: %+v vs %+v", got, want)
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

// ─── 1-hour cache-write tier ────────────────────────────────────────────────

// TestCacheCreate1hIsOptOutByDefault is the load-bearing guarantee of the whole
// feature: shipping the CacheCreate1hPer1M axis must not move a single invoice.
// Every built-in card leaves the 1h rate zero, so even a request whose cache
// writes are ENTIRELY 1h bills exactly as it did before the field existed.
//
// If this test ever fails, a catalogue edit has silently repriced production —
// on the traffic mix measured in 2026-08 that is a ~32% increase, because cache
// writes are ~54% of the official-cost base.
func TestCacheCreate1hIsOptOutByDefault(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, m := range []string{
		"claude-haiku-4-5", "claude-sonnet-4-6", "claude-sonnet-5",
		"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5",
		"claude-fable-5",
	} {
		if got := cat.Lookup(ProviderAnthropic, m); got.CacheCreate1hPer1M != 0 {
			t.Errorf("%s ships CacheCreate1hPer1M=%v — built-in cards must leave it 0 "+
				"so enabling the split stays an explicit operator decision", m, got.CacheCreate1hPer1M)
		}
	}

	// All 200k cache-write tokens reported as 1h: with the default card the
	// bill is unchanged from the single-rate formula.
	p := cat.Lookup(ProviderAnthropic, "claude-sonnet-4-6")
	all1h := usage.Counts{CacheCreateTokens: 200_000, CacheCreate1hTokens: 200_000}
	flat := usage.Counts{CacheCreateTokens: 200_000}
	if got, want := p.Cost(all1h), p.Cost(flat); got != want {
		t.Fatalf("1h breakdown changed the bill with a zero 1h rate: %v != %v", got, want)
	}
	if want := 200_000 * 3.75 / 1e6; p.Cost(all1h) != want {
		t.Fatalf("Cost=%v want %v (5m rate applied to everything)", p.Cost(all1h), want)
	}
}

// TestCacheCreate1hSplitWhenEnabled exercises the opt-in path with Anthropic's
// published ladder for sonnet-4-6 (5m 1.25×input = 3.75, 1h 2×input = 6.00).
func TestCacheCreate1hSplitWhenEnabled(t *testing.T) {
	p := ModelPrice{
		InputPer1M: 3.00, OutputPer1M: 15.00,
		CacheReadPer1M: 0.30, CacheCreatePer1M: 3.75, CacheCreate1hPer1M: 6.00,
	}
	// 200k writes, 150k of them 1h → 50k×3.75 + 150k×6.00 = 187.5 + 900 = 1087.5 µUSD
	c := usage.Counts{CacheCreateTokens: 200_000, CacheCreate1hTokens: 150_000}
	if got, want := p.Cost(c), (50_000*3.75+150_000*6.00)/1e6; got != want {
		t.Fatalf("split Cost=%v want %v", got, want)
	}
	// No breakdown reported → everything stays on the 5m rate. An upstream that
	// omits `cache_creation` must never be repriced by guesswork.
	if got, want := p.Cost(usage.Counts{CacheCreateTokens: 200_000}), 200_000*3.75/1e6; got != want {
		t.Fatalf("absent breakdown Cost=%v want %v (5m rate)", got, want)
	}
	// Malformed upstream (1h exceeds the total) must not go negative.
	bad := usage.Counts{CacheCreateTokens: 100_000, CacheCreate1hTokens: 250_000}
	if got := p.Cost(bad); got < 0 {
		t.Fatalf("malformed breakdown produced a negative charge: %v", got)
	}
}

// TestCacheCreate1hConfigurable pins that an operator can turn the split on from
// config.yaml without touching Go code, and that doing so is what it takes.
func TestCacheCreate1hConfigurable(t *testing.T) {
	cat := NewCatalog(Config{Models: map[string]ModelPrice{
		"anthropic/claude-sonnet-4-6": {
			InputPer1M: 3.00, OutputPer1M: 15.00,
			CacheReadPer1M: 0.30, CacheCreatePer1M: 3.75, CacheCreate1hPer1M: 6.00,
		},
	}})
	if got := cat.Lookup(ProviderAnthropic, "claude-sonnet-4-6").CacheCreate1hPer1M; got != 6.00 {
		t.Fatalf("config override did not reach the card: CacheCreate1hPer1M=%v", got)
	}
	// A card whose ONLY non-zero field is the 1h rate still counts as "set", so
	// a provider_defaults entry that just enables the split isn't discarded.
	if !nonZero(ModelPrice{CacheCreate1hPer1M: 6.00}) {
		t.Error("nonZero must recognise a card carrying only a 1h cache rate")
	}
}

// TestOpenAICatalogMatchesPublishedRates pins the OpenAI cards to the rates on
// developers.openai.com/api/docs/pricing as read on 2026-08-25 (standard
// service tier, short context).
//
// This exists because the GPT-5.6 line shipped with placeholder rates derived
// from the 5.5/5.4 ladder — sol/terra/luna were assumed to reuse the previous
// tier's prices, and luna in particular billed at $1.00/$6.00 against a real
// $0.20/$1.20, overcharging every request through it by 5x for as long as the
// card stood. A catalog value that is merely plausible is indistinguishable
// from a correct one at runtime; only a table checked against the page catches
// it, so keep this table and the page in sync together.
//
// gpt-5.6-sol and its aliases are the ONE deliberate departure from the page:
// OpenAI's $4.00/$20.00 there is an API-side promotion that ChatGPT
// subscription plans do not get, and this catalogue prices the subscription
// pool. See the card's comment in pricing.go. Its expected values below are
// therefore the plan rate, not the published API rate — if you are updating
// this table from the page, do not "fix" them.
//
// gpt-6-astra is NOT such a departure. It is on the page at $10/$1/$12.50/$50
// (verified 2026-09-05) with no promotion attached, so it takes those numbers
// straight. Do not apply the sol markup to it by analogy.
func TestOpenAICatalogMatchesPublishedRates(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, tc := range []struct {
		model string
		want  ModelPrice
	}{
		{"gpt-6-astra", ModelPrice{InputPer1M: 10.00, OutputPer1M: 50.00, CacheReadPer1M: 1.00, CacheCreatePer1M: 12.50}},
		{"gpt-5.6", ModelPrice{InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50, CacheCreatePer1M: 6.25}},
		{"gpt-5.6-sol", ModelPrice{InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50, CacheCreatePer1M: 6.25}},
		{"gpt-5.6-terra", ModelPrice{InputPer1M: 2.00, OutputPer1M: 12.00, CacheReadPer1M: 0.20, CacheCreatePer1M: 2.50}},
		{"gpt-5.6-luna", ModelPrice{InputPer1M: 0.20, OutputPer1M: 1.20, CacheReadPer1M: 0.02, CacheCreatePer1M: 0.25}},
		{"gpt-5.6-cyber", ModelPrice{InputPer1M: 12.50, OutputPer1M: 75.00, CacheReadPer1M: 1.25, CacheCreatePer1M: 15.625}},
		{"gpt-5.5", ModelPrice{InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50}},
		{"gpt-5.5-pro", ModelPrice{InputPer1M: 30.00, OutputPer1M: 180.00}},
		{"gpt-5.4", ModelPrice{InputPer1M: 2.50, OutputPer1M: 15.00, CacheReadPer1M: 0.25}},
		{"gpt-5.4-mini", ModelPrice{InputPer1M: 0.75, OutputPer1M: 4.50, CacheReadPer1M: 0.075}},
		{"gpt-5.4-nano", ModelPrice{InputPer1M: 0.20, OutputPer1M: 1.25, CacheReadPer1M: 0.02}},
		{"gpt-5.4-pro", ModelPrice{InputPer1M: 30.00, OutputPer1M: 180.00}},
		{"gpt-5.3-codex", ModelPrice{InputPer1M: 1.75, OutputPer1M: 14.00, CacheReadPer1M: 0.175}},
		{"gpt-5.2", ModelPrice{InputPer1M: 1.75, OutputPer1M: 14.00, CacheReadPer1M: 0.175}},
		{"gpt-5.2-pro", ModelPrice{InputPer1M: 21.00, OutputPer1M: 168.00}},
		{"gpt-5.1", ModelPrice{InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125}},
		{"gpt-5", ModelPrice{InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125}},
		{"gpt-5-mini", ModelPrice{InputPer1M: 0.25, OutputPer1M: 2.00, CacheReadPer1M: 0.025}},
		{"gpt-5-nano", ModelPrice{InputPer1M: 0.05, OutputPer1M: 0.40, CacheReadPer1M: 0.005}},
		{"gpt-5-pro", ModelPrice{InputPer1M: 15.00, OutputPer1M: 120.00}},
		{"gpt-4.1", ModelPrice{InputPer1M: 2.00, OutputPer1M: 8.00, CacheReadPer1M: 0.50}},
		{"gpt-4.1-mini", ModelPrice{InputPer1M: 0.40, OutputPer1M: 1.60, CacheReadPer1M: 0.10}},
		{"gpt-4.1-nano", ModelPrice{InputPer1M: 0.10, OutputPer1M: 0.40, CacheReadPer1M: 0.025}},
		{"gpt-4o", ModelPrice{InputPer1M: 2.50, OutputPer1M: 10.00, CacheReadPer1M: 1.25}},
		{"gpt-4o-mini", ModelPrice{InputPer1M: 0.15, OutputPer1M: 0.60, CacheReadPer1M: 0.075}},
		{"o4-mini", ModelPrice{InputPer1M: 1.10, OutputPer1M: 4.40, CacheReadPer1M: 0.275}},
		{"o3", ModelPrice{InputPer1M: 2.00, OutputPer1M: 8.00, CacheReadPer1M: 0.50}},
		{"o3-mini", ModelPrice{InputPer1M: 1.10, OutputPer1M: 4.40, CacheReadPer1M: 0.55}},
		{"o3-pro", ModelPrice{InputPer1M: 20.00, OutputPer1M: 80.00}},
		{"o1", ModelPrice{InputPer1M: 15.00, OutputPer1M: 60.00, CacheReadPer1M: 7.50}},
		{"o1-pro", ModelPrice{InputPer1M: 150.00, OutputPer1M: 600.00}},
		{"chat-latest", ModelPrice{InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50}},
	} {
		if got := cat.Lookup(ProviderOpenAI, tc.model); got != tc.want {
			t.Errorf("openai/%s = %+v, published rate is %+v", tc.model, got, tc.want)
		}
	}
}

// TestGPT56SolPricesTheSubscriptionPlanNotThePromo pins the one card that is
// intentionally off the published API price.
//
// OpenAI's promotional API rate for sol ($4.00/$20.00, "at least through
// 2026-11-21") does not extend to ChatGPT subscription plans, which keep
// costing what the previous flagship did. The pool this catalogue prices is
// predominantly OAuth subscription credentials, so the card holds the plan
// rate and a future re-transcription from the page must not quietly reset it
// to the promo — that would under-bill the subscription pool by 20%.
func TestGPT56SolPricesTheSubscriptionPlanNotThePromo(t *testing.T) {
	cat := NewCatalog(Config{})
	plan := ModelPrice{InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50, CacheCreatePer1M: 6.25}
	promo := ModelPrice{InputPer1M: 4.00, OutputPer1M: 20.00, CacheReadPer1M: 0.40, CacheCreatePer1M: 5.00}
	for _, model := range []string{"gpt-5.6", "gpt-5.6-sol", "daybreak-blue-latest"} {
		got := cat.Lookup(ProviderOpenAI, model)
		if got == promo {
			t.Errorf("openai/%s = %+v, the API-side promotional rate; subscription plans pay %+v", model, got, plan)
		}
		if got != plan {
			t.Errorf("openai/%s = %+v, want the subscription plan rate %+v", model, got, plan)
		}
	}
	// terra and luna carry no such split — their published rates are the real
	// ones on both sides, so they must NOT be dragged up alongside sol.
	if got, want := cat.Lookup(ProviderOpenAI, "gpt-5.6-luna"), (ModelPrice{InputPer1M: 0.20, OutputPer1M: 1.20, CacheReadPer1M: 0.02, CacheCreatePer1M: 0.25}); got != want {
		t.Errorf("openai/gpt-5.6-luna = %+v, want %+v", got, want)
	}
}

// TestOpenAISKUsDoNotInheritAShorterCard guards the specific failure mode that
// makes a missing OpenAI card expensive rather than free: Lookup falls back by
// trimming trailing "-segment"s, so a size or tier variant with no card of its
// own silently bills at the base model's rate. gpt-5.4-nano is 12.5x cheaper
// than gpt-5.4 and gpt-5.5-pro is 6x dearer than gpt-5.5 — the fallback errs in
// both directions, so neither may be reachable.
func TestOpenAISKUsDoNotInheritAShorterCard(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, tc := range []struct{ variant, base string }{
		{"gpt-5.4-nano", "gpt-5.4"},
		{"gpt-5.4-pro", "gpt-5.4"},
		{"gpt-5.5-pro", "gpt-5.5"},
		{"gpt-5.2-pro", "gpt-5.2"},
		{"gpt-5-pro", "gpt-5"},
		{"gpt-4.1-nano", "gpt-4.1"},
	} {
		if got, base := cat.Lookup(ProviderOpenAI, tc.variant), cat.Lookup(ProviderOpenAI, tc.base); got == base {
			t.Errorf("openai/%s resolved to the %s card (%+v) — it has no card of its own and the prefix fallback is billing it as the base model",
				tc.variant, tc.base, got)
		}
	}
}

// TestOpenAIDatedVariantsStillResolve confirms the prefix fallback still does
// its intended job for date-suffixed names now that the catalog has many more
// hyphenated neighbours.
func TestOpenAIDatedVariantsStillResolve(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, tc := range []struct{ dated, base string }{
		{"gpt-6-astra-2026-09-01", "gpt-6-astra"},
		{"gpt-5.6-luna-2026-08-01", "gpt-5.6-luna"},
		{"gpt-5.6-sol-2026-08-01", "gpt-5.6-sol"},
		{"gpt-5.4-mini-2026-01-01", "gpt-5.4-mini"},
	} {
		if got, want := cat.Lookup(ProviderOpenAI, tc.dated), cat.Lookup(ProviderOpenAI, tc.base); got != want {
			t.Errorf("openai/%s = %+v, want the %s card %+v", tc.dated, got, tc.base, want)
		}
	}
}
