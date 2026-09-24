package pricing

import (
	"math"
	"testing"

	"github.com/wjsoj/cc-core/usage"
)

func TestGPT6FixedPricesAndServiceTiers(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, model := range []string{"gpt-6-sol", "gpt-6-luna"} {
		in, out, read, write := 2.0, 10.0, .2, 2.5
		if model == "gpt-6-luna" {
			in, out, read, write = .1, .5, .01, .125
		}
		for _, suffix := range []string{"", "(high)", "-high", "-2026-09-22"} {
			for _, writes := range []int64{11999, 12000, 12001} {
				counts := usage.Counts{InputTokens: 200000, CacheReadTokens: 60000, CacheCreateTokens: writes, OutputTokens: 1000}
				// Context length does not change our fixed price card.
				base := (200000*in + 60000*read + float64(writes)*write + 1000*out) / 1e6
				for _, tc := range []struct {
					opts  CostOptions
					ratio float64
				}{
					{CostOptions{}, 1}, {CostOptions{ServiceTier: "priority"}, 2}, {CostOptions{ServiceTier: "flex"}, .5},
					{CostOptions{ServiceTier: "priority", ResponseServiceTier: "default"}, 1},
					{CostOptions{ServiceTier: "priority", CodexOAuth: true}, 1}, {CostOptions{ServiceTier: "flex", CodexOAuth: true}, 1},
				} {
					got := cat.CostWithOptions("openai", model+suffix, counts, tc.opts).CostUSD
					if math.Abs(got-base*tc.ratio) > 1e-12 {
						t.Errorf("%s %+v writes=%d got %g want %g", model+suffix, tc.opts, writes, got, base*tc.ratio)
					}
				}
				if got := cat.Cost("openai", model+suffix, counts); math.Abs(got-base) > 1e-12 {
					t.Errorf("standard path: %g want %g", got, base)
				}
			}
		}
	}
}

func TestGPT6PricingOverridesRemainAuthoritative(t *testing.T) {
	cat := NewCatalog(Config{Models: map[string]ModelPrice{"openai/gpt-6-sol": {InputPer1M: 3, OutputPer1M: 7}}})
	if got := cat.Cost("openai", "gpt-6-sol", usage.Counts{InputTokens: 1000000, OutputTokens: 1000000}); got != 10 {
		t.Fatalf("override acquired an implicit long-context markup: %g", got)
	}
}
