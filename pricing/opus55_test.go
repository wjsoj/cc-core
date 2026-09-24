package pricing

import (
	"math"
	"testing"

	"github.com/wjsoj/cc-core/usage"
)

func TestOpus55Pricing(t *testing.T) {
	cat := NewCatalog(Config{})
	want := ModelPrice{InputPer1M: 4, OutputPer1M: 20, CacheReadPer1M: .2, CacheCreatePer1M: 5, CacheCreate1hPer1M: 8}
	if got, ok := cat.Models()["anthropic/claude-opus-5-5"]; !ok || got != want {
		t.Fatalf("explicit price card = %+v, present=%v, want %+v", got, ok, want)
	}
	for _, model := range []string{"claude-opus-5-5", "claude-opus-5-5[1m]", " CLAUDE-OPUS-5-5 ", "claude-opus-5-5-20260922", "claude-opus-5-5-20260922[1m]"} {
		if got := cat.Lookup(ProviderAnthropic, model); got != want {
			t.Errorf("%s: %+v, want %+v", model, got, want)
		}
	}
	for _, tc := range []struct {
		name   string
		counts usage.Counts
		want   float64
	}{
		{"input", usage.Counts{InputTokens: 1_000_000}, 4},
		{"output", usage.Counts{OutputTokens: 1_000_000}, 20},
		{"cache read", usage.Counts{CacheReadTokens: 1_000_000}, .2},
		{"5m write", usage.Counts{CacheCreateTokens: 1_000_000}, 5},
		{"1h write", usage.Counts{CacheCreateTokens: 1_000_000, CacheCreate1hTokens: 1_000_000}, 8},
		{"mixed long context", usage.Counts{InputTokens: 300_000, OutputTokens: 10_000, CacheReadTokens: 400_000, CacheCreateTokens: 200_000, CacheCreate1hTokens: 150_000}, 2.93},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cat.Cost(ProviderAnthropic, "claude-opus-5-5[1m]", tc.counts); math.Abs(got-tc.want) > 1e-12 {
				t.Fatalf("cost=%g, want %g", got, tc.want)
			}
		})
	}
}

func TestOpus55PriceOverride(t *testing.T) {
	want := ModelPrice{InputPer1M: 2, OutputPer1M: 10, CacheReadPer1M: .1, CacheCreatePer1M: 2.5}
	cat := NewCatalog(Config{Models: map[string]ModelPrice{"claude-opus-5-5": want}})
	if got := cat.Lookup(ProviderAnthropic, "claude-opus-5-5[1m]"); got != want {
		t.Fatalf("override=%+v, want %+v", got, want)
	}
}
