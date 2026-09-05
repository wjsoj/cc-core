package pricing

import (
	"math"
	"testing"

	"github.com/wjsoj/cc-core/usage"
)

func TestFastCostCards(t *testing.T) {
	cat := NewCatalog(Config{})
	counts := usage.Counts{InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 500, CacheCreateTokens: 100}
	for _, tc := range []struct {
		model string
		ratio float64
	}{
		{"gpt-5.5", 2.5}, {"gpt-5.5-2026-04-23", 2.5}, {"gpt-5.5-pro", 2},
		{"gpt-5.6-sol", 2}, {"gpt-6-astra", 2}, {"gpt-6-astra-2026-09-03", 2},
		{"gpt-5-mini", 1.8}, {"gpt-4.1", 1.75}, {"gpt-4o", 1.7}, {"gpt-4o-mini", 5.0 / 3},
	} {
		t.Run(tc.model, func(t *testing.T) {
			standard := cat.Cost(ProviderOpenAI, tc.model, counts)
			for _, tier := range []string{"fast", "priority", " PRIORITY "} {
				got := cat.CostWithServiceTier(ProviderOpenAI, tc.model, counts, tier)
				if math.Abs(got-standard*tc.ratio) > 1e-12 {
					t.Fatalf("%s cost %g want %g", tier, got, standard*tc.ratio)
				}
			}
			if cat.CostWithServiceTier(ProviderOpenAI, tc.model, counts, "") != standard {
				t.Fatal("standard changed")
			}
			if cat.CostWithServiceTier(ProviderOpenAI, tc.model, counts, "flex") != standard*0.5 {
				t.Fatal("flex mismatch")
			}
		})
	}
	// Independent Astra rate assertion includes cache read and write, not just
	// output tokens. The cached input is already disjoint in usage.Counts.
	if got := cat.CostWithServiceTier(ProviderOpenAI, "gpt-6-astra", counts, "priority"); math.Abs(got-0.0435) > 1e-12 {
		t.Fatalf("Astra %g want 0.0435", got)
	}
}
func TestFastBillingResolutionAndOverrides(t *testing.T) {
	cfg := Config{Models: map[string]ModelPrice{"openai/gpt-5.5": {InputPer1M: 10}}, ServiceTiers: map[string]ServiceTierPrice{"openai/gpt-5.5": {FastMultiplier: 3}}}
	cat := NewCatalog(cfg)
	cfg.ServiceTiers["openai/gpt-5.5"] = ServiceTierPrice{FastMultiplier: 9}
	counts := usage.Counts{InputTokens: 1_000_000}
	for _, tc := range []struct {
		opts CostOptions
		want float64
	}{
		// CodexOAuth is a ChatGPT subscription: the plan price is flat, so no
		// tier multiplier applies in either direction. Both of these used to
		// bill 30 and 5 respectively, which invented an upstream cost the
		// subscription never incurred.
		{CostOptions{ServiceTier: "priority", ResponseServiceTier: "default", CodexOAuth: true}, 10},
		{CostOptions{ServiceTier: "priority", ResponseServiceTier: "flex", CodexOAuth: true}, 10},
		// API key: the configured Fast multiplier applies, and an observed
		// downgrade still lowers the bill.
		{CostOptions{ServiceTier: "priority", ResponseServiceTier: "default"}, 10},
		{CostOptions{ServiceTier: "priority"}, 30},
		{CostOptions{ServiceTier: "priority", ResponseServiceTier: "flex"}, 5},
		{CostOptions{ResponseServiceTier: "priority"}, 10},
	} {
		if got := cat.CostWithOptions("openai", "gpt-5.5-high", counts, tc.opts); got.CostUSD != tc.want {
			t.Fatalf("%+v => %+v want %g", tc.opts, got, tc.want)
		}
	}
	for _, v := range []float64{-1, 0, 0.5, 1, math.NaN(), math.Inf(1)} {
		cat := NewCatalog(Config{ServiceTiers: map[string]ServiceTierPrice{"openai/gpt-5.5": {FastMultiplier: v}}})
		if got := cat.CostWithServiceTier("openai", "gpt-5.5", counts, "priority"); got != 12.5 {
			t.Fatalf("invalid override %g -> %g", v, got)
		}
	}
	if cat.CostWithServiceTier("anthropic", "claude-sonnet-4", counts, "priority") != cat.Cost("anthropic", "claude-sonnet-4", counts) {
		t.Fatal("affected Anthropic")
	}
}
