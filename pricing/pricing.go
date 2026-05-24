// Package pricing maps (provider, model) pairs to per-token USD cost and
// computes request cost from a usage.Counts payload.
//
// The cost formula is:
//
//	cost = (input*P_in + output*P_out + cacheRead*P_cr + cacheCreate*P_cw) / 1e6
//
// The built-in catalog covers current Claude models plus the OpenAI / Codex
// tier-specific labels and currently-shipping API models. Forks can override
// or extend any entry via NewCatalog(Config{...}).
//
// Example user-supplied config (typically loaded from YAML):
//
//	Config{
//	    Default: ModelPrice{InputPer1M: 3.00, OutputPer1M: 15.00, ...},
//	    ProviderDefaults: map[string]ModelPrice{
//	        "openai": {InputPer1M: 1.25, OutputPer1M: 10.0},
//	    },
//	    Models: map[string]ModelPrice{
//	        "anthropic/claude-opus-4-7": {InputPer1M: 5.0, OutputPer1M: 25.0},
//	        "openai/gpt-5.3-codex":      {InputPer1M: 1.25, OutputPer1M: 10.0},
//	    },
//	}
//
// Legacy bare-model keys (e.g. `claude-opus-4-6:`) are treated as
// `anthropic/<model>` on load so existing configs keep working.
package pricing

import (
	"strings"

	"github.com/wjsoj/cc-core/usage"
)

// Canonical provider ids. Kept as constants here (rather than importing from
// cc-core/auth) so pricing stays a leaf — auth has heavier deps (uTLS).
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
)

// ModelPrice is the USD price per 1M tokens for each token class. CacheRead
// and CacheCreate are priced separately because Anthropic charges them
// differently (cache_read ~0.1× input, cache_create ~1.25× input). For
// providers without cache semantics (OpenAI), put the "cached_tokens"
// figure from the response into CacheReadTokens and use CacheReadPer1M for
// its discounted rate — typically ~0.25× input on OpenAI's API.
type ModelPrice struct {
	InputPer1M       float64 `yaml:"input_per_1m" json:"input_per_1m"`
	OutputPer1M      float64 `yaml:"output_per_1m" json:"output_per_1m"`
	CacheReadPer1M   float64 `yaml:"cache_read_per_1m" json:"cache_read_per_1m"`
	CacheCreatePer1M float64 `yaml:"cache_create_per_1m" json:"cache_create_per_1m"`
}

// Cost returns USD for the given token counts under this price card.
func (p ModelPrice) Cost(c usage.Counts) float64 {
	return (float64(c.InputTokens)*p.InputPer1M +
		float64(c.OutputTokens)*p.OutputPer1M +
		float64(c.CacheReadTokens)*p.CacheReadPer1M +
		float64(c.CacheCreateTokens)*p.CacheCreatePer1M) / 1_000_000
}

// Config is the user-supplied catalog override shape. Mirrors how
// CPA-Claude's config.yaml `pricing:` section is structured.
type Config struct {
	Default          ModelPrice            `yaml:"default" json:"default"`
	ProviderDefaults map[string]ModelPrice `yaml:"provider_defaults" json:"provider_defaults"`
	Models           map[string]ModelPrice `yaml:"models" json:"models"`
}

// Catalog resolves (provider, model) to a price card, with four-level
// fallback: exact → prefix → provider default → global default.
type Catalog struct {
	defaultPrice     ModelPrice
	providerDefaults map[string]ModelPrice
	models           map[string]ModelPrice // key = "provider/model" (lowercase)
}

// NewCatalog merges the user config (may be zero-valued) on top of the
// built-in defaults so callers always get a sensible price for common models.
func NewCatalog(c Config) *Catalog {
	cat := &Catalog{
		defaultPrice:     defaultModelPrice(),
		providerDefaults: make(map[string]ModelPrice),
		models:           make(map[string]ModelPrice, len(builtIn)+len(c.Models)),
	}
	for k, v := range builtInProviderDefaults {
		cat.providerDefaults[k] = v
	}
	for k, v := range builtIn {
		cat.models[k] = v
	}
	// User overrides last so they can shadow built-ins.
	for k, v := range c.ProviderDefaults {
		cat.providerDefaults[strings.ToLower(strings.TrimSpace(k))] = v
	}
	for k, v := range c.Models {
		cat.models[normalizeModelKey(k)] = v
	}
	if nonZero(c.Default) {
		cat.defaultPrice = c.Default
	}
	return cat
}

// Lookup returns the price card for a (provider, model) pair. Matching is
// case-insensitive and tolerates well-known prefix matches (e.g. a suffix-
// dated Claude model falls back to its undated base entry). Empty provider
// is treated as Anthropic for backward compatibility with legacy callers.
func (c *Catalog) Lookup(provider, model string) ModelPrice {
	prov := canonicalProvider(provider)
	m := strings.ToLower(strings.TrimSpace(model))
	// Strip a trailing "(value)" thinking suffix — CLIProxyAPI's convention
	// for encoding reasoning effort in the model name. "gpt-5.3-codex(high)"
	// bills the same as "gpt-5.3-codex".
	if strings.HasSuffix(m, ")") {
		if i := strings.LastIndex(m, "("); i > 0 {
			m = strings.TrimSpace(m[:i])
		}
	}
	if m != "" {
		full := prov + "/" + m
		if p, ok := c.models[full]; ok {
			return p
		}
		// Prefix fallback: trim trailing "-segment"s off the model name and
		// retry. Covers "claude-sonnet-4-6-20260401" → "claude-sonnet-4-6".
		for i := strings.LastIndex(m, "-"); i > 0; i = strings.LastIndex(m[:i], "-") {
			if p, ok := c.models[prov+"/"+m[:i]]; ok {
				return p
			}
		}
	}
	if p, ok := c.providerDefaults[prov]; ok && nonZero(p) {
		return p
	}
	return c.defaultPrice
}

// Cost is a convenience shortcut — Lookup(provider, model).Cost(counts).
func (c *Catalog) Cost(provider, model string, counts usage.Counts) float64 {
	return c.Lookup(provider, model).Cost(counts)
}

// Models returns a copy of the registered model → price map. Keys are in
// canonical "provider/model" form.
func (c *Catalog) Models() map[string]ModelPrice {
	out := make(map[string]ModelPrice, len(c.models))
	for k, v := range c.models {
		out[k] = v
	}
	return out
}

// Default returns the global fallback price card (provider-agnostic).
func (c *Catalog) Default() ModelPrice { return c.defaultPrice }

// ProviderDefaults returns a copy of the per-provider fallback cards.
func (c *Catalog) ProviderDefaults() map[string]ModelPrice {
	out := make(map[string]ModelPrice, len(c.providerDefaults))
	for k, v := range c.providerDefaults {
		out[k] = v
	}
	return out
}

// normalizeModelKey canonicalizes a user-supplied pricing.models key. Bare
// model names (no "/") are assumed to be Anthropic — matches pre-multi-
// provider configs.
func normalizeModelKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	if k == "" {
		return ""
	}
	if !strings.Contains(k, "/") {
		return ProviderAnthropic + "/" + k
	}
	return k
}

func canonicalProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "anthropic", "claude":
		return ProviderAnthropic
	case "openai", "codex", "chatgpt":
		return ProviderOpenAI
	}
	return strings.ToLower(strings.TrimSpace(p))
}

func nonZero(p ModelPrice) bool {
	return p.InputPer1M != 0 || p.OutputPer1M != 0 || p.CacheReadPer1M != 0 || p.CacheCreatePer1M != 0
}

func defaultModelPrice() ModelPrice {
	return ModelPrice{
		InputPer1M:       3.00,
		OutputPer1M:      15.00,
		CacheReadPer1M:   0.30,
		CacheCreatePer1M: 3.75,
	}
}

// builtInProviderDefaults: per-provider fallback when a specific model isn't
// in the catalog. For OpenAI we use gpt-5 flagship pricing so unknown Codex
// models don't undercharge; for Anthropic we use Sonnet (matches global).
var builtInProviderDefaults = map[string]ModelPrice{
	ProviderAnthropic: {
		InputPer1M:       3.00,
		OutputPer1M:      15.00,
		CacheReadPer1M:   0.30,
		CacheCreatePer1M: 3.75,
	},
	ProviderOpenAI: {
		InputPer1M:       1.25,
		OutputPer1M:      10.00,
		CacheReadPer1M:   0.125, // OpenAI cached input is ~0.1× input
		CacheCreatePer1M: 0,
	},
}

// builtIn is the stock (provider, model) → price catalog. Anthropic values
// track their published pricing. OpenAI values approximate the public API
// pricing; they apply to both ChatGPT-subscription OAuth credentials
// (notional cost for weekly-limit enforcement) and BYOK API-key credentials
// (real cost).
//
// Forks that don't expose a particular SKU can keep these entries — they're
// only consulted when a request actually names the model.
var builtIn = map[string]ModelPrice{
	// ─── Anthropic ──────────────────────────────────────────────────────
	ProviderAnthropic + "/claude-haiku-4-5-20251001": {
		InputPer1M:       1.00,
		OutputPer1M:      5.00,
		CacheReadPer1M:   0.10,
		CacheCreatePer1M: 1.25,
	},
	ProviderAnthropic + "/claude-haiku-4-5": {
		InputPer1M:       1.00,
		OutputPer1M:      5.00,
		CacheReadPer1M:   0.10,
		CacheCreatePer1M: 1.25,
	},
	ProviderAnthropic + "/claude-opus-4-6": {
		InputPer1M:       5.00,
		OutputPer1M:      25.00,
		CacheReadPer1M:   0.50,
		CacheCreatePer1M: 6.25,
	},
	ProviderAnthropic + "/claude-opus-4-7": {
		InputPer1M:       5.00,
		OutputPer1M:      25.00,
		CacheReadPer1M:   0.50,
		CacheCreatePer1M: 6.25,
	},
	ProviderAnthropic + "/claude-sonnet-4-6": {
		InputPer1M:       3.00,
		OutputPer1M:      15.00,
		CacheReadPer1M:   0.30,
		CacheCreatePer1M: 3.75,
	},

	// ─── OpenAI / Codex (subscription tier labels) ─────────────────────
	// Tier labels track CLIProxyAPI/internal/registry/models/models.json.
	ProviderOpenAI + "/gpt-5.2":              {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/gpt-5.3-codex":        {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/gpt-5.3-codex-spark":  {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/gpt-5.4":              {InputPer1M: 1.50, OutputPer1M: 12.00, CacheReadPer1M: 0.15},
	ProviderOpenAI + "/gpt-5.4-mini":         {InputPer1M: 0.25, OutputPer1M: 2.00, CacheReadPer1M: 0.025},
	ProviderOpenAI + "/gpt-5.5":              {InputPer1M: 2.50, OutputPer1M: 20.00, CacheReadPer1M: 0.25},

	// ─── OpenAI BYOK API models ────────────────────────────────────────
	ProviderOpenAI + "/gpt-5":      {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/gpt-5-mini": {InputPer1M: 0.25, OutputPer1M: 2.00, CacheReadPer1M: 0.025},
	ProviderOpenAI + "/gpt-5-nano": {InputPer1M: 0.05, OutputPer1M: 0.40, CacheReadPer1M: 0.005},
	ProviderOpenAI + "/gpt-4o":     {InputPer1M: 2.50, OutputPer1M: 10.00, CacheReadPer1M: 1.25},
	ProviderOpenAI + "/gpt-4o-mini":{InputPer1M: 0.15, OutputPer1M: 0.60, CacheReadPer1M: 0.075},
}
