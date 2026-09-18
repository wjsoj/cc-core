package pricing

import (
	"math"
	"testing"

	"github.com/wjsoj/cc-core/usage"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

func TestImageGenBilledAtImageCardNotChatModel(t *testing.T) {
	cat := NewCatalog(Config{})
	img := usage.Counts{ImageGenTextInputTokens: 50, ImageGenImageInputTokens: 10, ImageGenOutputTokens: 1056}
	want := (50*5.0 + 10*8.0 + 1056*30.0) / 1e6
	for _, model := range []string{"gpt-5.6-sol", "gpt-5.6-luna", "gpt-6-astra"} {
		if got := cat.Cost(ProviderOpenAI, model, img); !near(got, want) {
			t.Fatalf("%s: got %v want %v", model, got, want)
		}
	}
	chat := usage.Counts{InputTokens: 1000, OutputTokens: 100}
	both := chat
	both.ImageGenOutputTokens = 1056
	if got := cat.Cost(ProviderOpenAI, "gpt-5.6-sol", both); !near(got, cat.Cost(ProviderOpenAI, "gpt-5.6-sol", chat)+1056*30.0/1e6) {
		t.Fatalf("image cost not additive: %v", got)
	}
}

func TestImageGenExemptFromServiceTierMultiplier(t *testing.T) {
	cat := NewCatalog(Config{})
	c := usage.Counts{InputTokens: 1000, OutputTokens: 100, ImageGenOutputTokens: 1000}
	std := cat.CostWithOptions(ProviderOpenAI, "gpt-5.6-sol", c, CostOptions{}).CostUSD
	fast := cat.CostWithOptions(ProviderOpenAI, "gpt-5.6-sol", c, CostOptions{ServiceTier: "priority"})
	images := 1000 * 30.0 / 1e6
	chatStd := std - images
	if fast.Tier.Billing != "priority" {
		t.Skipf("priority not resolved in this contract: %+v", fast.Tier)
	}
	if near(fast.CostUSD-images, chatStd) || !(fast.CostUSD-images > chatStd) {
		t.Fatalf("tier must scale chat cost only: std=%v fast=%v", std, fast.CostUSD)
	}
	if !near(fast.CostUSD-images, chatStd*cat.serviceTierPrice("gpt-5.6-sol").FastMultiplier) {
		t.Fatalf("image cost was tier-multiplied: std=%v fast=%v", std, fast.CostUSD)
	}
}

func TestImageGenPriceOverride(t *testing.T) {
	cat := NewCatalog(Config{ImageGen: ImageGenPrice{OutputPer1M: 40}})
	if got := cat.Cost(ProviderOpenAI, "gpt-5.6-sol", usage.Counts{ImageGenOutputTokens: 1e6}); !near(got, 40) {
		t.Fatalf("override ignored: %v", got)
	}
	if NewCatalog(Config{}).ImageGen() != DefaultImageGenPrice {
		t.Fatal("default not applied")
	}
}
