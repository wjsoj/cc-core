package pricing

import (
	"math"
	"strings"

	"github.com/wjsoj/cc-core/servicetier"
	"github.com/wjsoj/cc-core/usage"
)

// ServiceTierPrice overrides the OpenAI service-tier multipliers for a model.
// Zero means use the catalog default. Negative/non-finite values are ignored.
// A configured Fast multiplier must exceed 1: Fast is a paid upgrade.
type ServiceTierPrice struct {
	FastMultiplier float64 `yaml:"fast_multiplier,omitempty" json:"fast_multiplier,omitempty"`
	FlexMultiplier float64 `yaml:"flex_multiplier,omitempty" json:"flex_multiplier,omitempty"`
}

// CostOptions must describe the request actually sent upstream, after model
// mapping and tier policies. ResponseServiceTier must be observed before any
// downstream response scrubbing. CodexOAuth selects the private Codex contract.
type CostOptions struct {
	ServiceTier         string
	ResponseServiceTier string
	CodexOAuth          bool
}

type CostResult struct {
	CostUSD float64
	Tier    servicetier.Resolution
}

// CostWithOptions computes the base token bill and then applies exactly one
// service-tier adjustment. The caller applies its user/group multiplier AFTER
// this result, once. Cost's existing signature remains the Standard-only API.
func (c *Catalog) CostWithOptions(provider, model string, counts usage.Counts, opts CostOptions) CostResult {
	result := CostResult{CostUSD: c.Cost(provider, model, counts)}
	if canonicalProvider(provider) != ProviderOpenAI {
		return result
	}
	result.Tier = servicetier.ResolveOpenAI(opts.ServiceTier, opts.ResponseServiceTier, opts.CodexOAuth)
	policy := c.serviceTierPrice(model)
	switch result.Tier.Billing {
	case servicetier.Priority:
		result.CostUSD *= policy.FastMultiplier
	case servicetier.Flex:
		result.CostUSD *= policy.FlexMultiplier
	}
	return result
}

// CostWithServiceTier is for callers that have only an outbound tier. Use
// CostWithOptions when the upstream's response tier is available.
func (c *Catalog) CostWithServiceTier(provider, model string, counts usage.Counts, tier string) float64 {
	return c.CostWithOptions(provider, model, counts, CostOptions{ServiceTier: tier}).CostUSD
}

func (c *Catalog) serviceTierPrice(model string) ServiceTierPrice {
	m := normalizeLookupModel(model)
	// The override lookup shares the same exact/prefix behavior as the base
	// catalog, including dated and reasoning-effort model variants.
	var configured ServiceTierPrice
	for candidate := m; candidate != ""; {
		if p, ok := c.serviceTiers[ProviderOpenAI+"/"+candidate]; ok {
			configured = p
			break
		}
		i := strings.LastIndex(candidate, "-")
		if i <= 0 {
			break
		}
		candidate = candidate[:i]
	}
	fast := 2.0
	// Match the most specific registered base card; a pro or nano model must
	// not accidentally inherit its flagship's special Fast ratio.
	for candidate := m; candidate != ""; {
		if _, ok := c.models[ProviderOpenAI+"/"+candidate]; ok {
			if ratio, ok := openAIFastRatios[candidate]; ok {
				fast = ratio
			}
			break
		}
		i := strings.LastIndex(candidate, "-")
		if i <= 0 {
			break
		}
		candidate = candidate[:i]
	}
	flex := 0.5
	if validMultiplier(configured.FastMultiplier) && configured.FastMultiplier > 1 {
		fast = configured.FastMultiplier
	}
	if validMultiplier(configured.FlexMultiplier) && configured.FlexMultiplier > 0 {
		flex = configured.FlexMultiplier
	}
	return ServiceTierPrice{FastMultiplier: fast, FlexMultiplier: flex}
}

func validMultiplier(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Sub2API's catalog/policy ratios. Other OpenAI models use its generic 2x
// Priority fallback. Ratios apply to custom base cards too, avoiding stale
// absolute Priority prices when an operator overrides Standard pricing.
var openAIFastRatios = map[string]float64{
	"gpt-5.5": 2.5, "gpt-5.5-2026-04-23": 2.5,
	"gpt-5-mini": 1.8, "gpt-5.1-codex-mini": 1.8,
	"gpt-4.1": 1.75, "gpt-4.1-mini": 1.75,
	"gpt-4o": 1.7, "gpt-4o-mini": 5.0 / 3.0,
}
