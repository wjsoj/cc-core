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
	"math"
	"strconv"
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

	// CacheCreate1hPer1M is the rate for cache writes made with a 1-hour TTL.
	//
	// ZERO MEANS "DO NOT DISTINGUISH" — every 1h token then bills at
	// CacheCreatePer1M, which is exactly the pre-existing behaviour. All
	// built-in cards ship with it zero, so adding this field changes no
	// invoice by itself. It is opt-in per deployment via config.yaml.
	//
	// Anthropic's published ladder (independently confirmed against LiteLLM's
	// model_prices_and_context_window.json, field
	// `cache_creation_input_token_cost_above_1hr`) is:
	//
	//	cache read   = 0.10 × input
	//	5m  write    = 1.25 × input
	//	1h  write    = 2.00 × input
	//
	// so the calibrated values, should an operator choose to enable the split:
	//
	//	haiku-4-5   2.00    sonnet-4-6  6.00    sonnet-5 (intro)  4.00
	//	opus-*     10.00    fable-5    20.00
	//
	// Enabling this is a PRICE CHANGE, not a bug fix: on the current traffic
	// mix cache writes are ~54% of the official-cost base, so switching the
	// whole catalogue from 1.25× to 2.00× raises billed cost by roughly a
	// third. Decide it deliberately, per provider, and announce it.
	//
	// Only Counts.CacheCreate1hTokens is charged at this rate; the remainder
	// (Counts.CacheCreate5mTokens) stays on CacheCreatePer1M. An upstream that
	// doesn't report the breakdown leaves CacheCreate1hTokens at zero, so the
	// split silently degrades to the old single-rate behaviour rather than
	// mispricing.
	CacheCreate1hPer1M float64 `yaml:"cache_create_1h_per_1m,omitempty" json:"cache_create_1h_per_1m,omitempty"`
}

// Cost returns USD for the given token counts under this price card.
//
// Cache writes are split only when BOTH the card carries a distinct 1h rate
// AND the upstream reported a 1h breakdown; otherwise the full cache-write
// total bills at CacheCreatePer1M exactly as it always has.
func (p ModelPrice) Cost(c usage.Counts) float64 {
	cacheCreate := float64(c.CacheCreateTokens) * p.CacheCreatePer1M
	if p.CacheCreate1hPer1M > 0 && c.CacheCreate1hTokens > 0 {
		cacheCreate = float64(c.CacheCreate5mTokens())*p.CacheCreatePer1M +
			float64(c.CacheCreate1hTokens)*p.CacheCreate1hPer1M
	}
	return (float64(c.InputTokens)*p.InputPer1M +
		float64(c.OutputTokens)*p.OutputPer1M +
		float64(c.CacheReadTokens)*p.CacheReadPer1M +
		cacheCreate) / 1_000_000
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

// StripContextModeSuffix removes a trailing "[value]" context-mode label from
// a model name, preserving case and everything else: "claude-opus-5[1m]" →
// "claude-opus-5". Names without the suffix are returned unchanged.
//
// Real Claude Code tags a 1M-context request as "claude-opus-5[1m]" in its
// TELEMETRY only — the request body carries the plain name (crack/claudev2.1.220/SPEC.md
// §1a). The suffix is therefore a pure label: it selects no price tier (Anthropic
// bills the full 1M window at standard rates) and identifies no distinct upstream
// model. Left in place it is actively harmful — it misses every price card AND
// every "claude-…" prefix, because Lookup's fallback only trims on "-", so the
// name lands on the provider default (the Sonnet card) and an opus-5 request
// bills 40% short.
//
// Exported so callers can canonicalise at the request-parse layer, ahead of
// usage labels, request logs, and admin aggregation, rather than each consumer
// re-deriving it. Lookup applies it too, so calling it early is optional and
// idempotent.
//
// Deliberately narrower than what Lookup strips: the "(value)" convention
// ("gpt-5.3-codex(high)") encodes reasoning effort, which is routing-relevant.
// Only pricing may ignore that one — dropping it at parse time would discard a
// real request parameter, so it is NOT part of this helper.
func StripContextModeSuffix(model string) string {
	m := strings.TrimSpace(model)
	if !strings.HasSuffix(m, "]") {
		return model
	}
	i := strings.LastIndex(m, "[")
	if i <= 0 {
		return model
	}
	return strings.TrimSpace(m[:i])
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
	m = StripContextModeSuffix(m)
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
	return p.InputPer1M != 0 || p.OutputPer1M != 0 || p.CacheReadPer1M != 0 ||
		p.CacheCreatePer1M != 0 || p.CacheCreate1hPer1M != 0
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
	ProviderAnthropic + "/claude-opus-4-8": {
		InputPer1M:       5.00,
		OutputPer1M:      25.00,
		CacheReadPer1M:   0.50,
		CacheCreatePer1M: 6.25,
	},
	// claude-opus-5 holds the Opus tier's long-standing rate, identical to
	// opus-4-6/4-7/4-8. Without this entry Lookup's prefix fallback finds no
	// "claude-opus" key and drops to builtInProviderDefaults[anthropic] — the
	// Sonnet card — undercharging every opus-5 request by exactly 5/3 (all four
	// counters scale uniformly, so the shortfall is 40% of the true cost
	// regardless of the input/output/cache mix).
	ProviderAnthropic + "/claude-opus-5": {
		InputPer1M:       5.00,
		OutputPer1M:      25.00,
		CacheReadPer1M:   0.50,
		CacheCreatePer1M: 6.25,
	},
	// claude-fable-5 is the premium tier — exactly 2× opus-4-8, which also
	// satisfies Anthropic's standard cache ratios (read 0.1× input, write
	// 1.25× input). One undated entry suffices: Lookup's prefix-fallback maps
	// any dated variant (claude-fable-5-2026…) back to this card.
	ProviderAnthropic + "/claude-fable-5": {
		InputPer1M:       10.00,
		OutputPer1M:      50.00,
		CacheReadPer1M:   1.00,
		CacheCreatePer1M: 12.50,
	},
	ProviderAnthropic + "/claude-sonnet-4-6": {
		InputPer1M:       3.00,
		OutputPer1M:      15.00,
		CacheReadPer1M:   0.30,
		CacheCreatePer1M: 3.75,
	},
	// claude-sonnet-5's LIST price is $3/$15 — the same as sonnet-4-6. The card
	// below is the INTRODUCTORY price (2/3 of list: input $3→$2, output
	// $15→$10, cache_read $0.30→$0.20, cache_write $3.75→$2.50, still
	// Anthropic's standard 0.1×/1.25× cache ratios).
	//
	// ⚠️ EXPIRES 2026-08-31. From 2026-09-01 Anthropic bills list price; leaving
	// this card as-is past that date undercharges every sonnet-5 request by 33%.
	// On expiry, replace the four values with 3.00 / 15.00 / 0.30 / 3.75 and
	// delete this notice (the card then matches sonnet-4-6 exactly).
	//
	// One undated entry; Lookup's prefix-fallback maps dated variants
	// (claude-sonnet-5-2026…) here.
	ProviderAnthropic + "/claude-sonnet-5": {
		InputPer1M:       2.00,
		OutputPer1M:      10.00,
		CacheReadPer1M:   0.20,
		CacheCreatePer1M: 2.50,
	},

	// ─── OpenAI / Codex ────────────────────────────────────────────────
	// Official OpenAI API per-1M-token rates, re-verified 2026-08-25 against
	// developers.openai.com/api/docs/pricing (the `.md` mirror of that page is
	// the machine-readable form and is what these numbers were transcribed
	// from). They apply to both ChatGPT-subscription OAuth credentials
	// (notional cost for weekly-limit enforcement) and BYOK API-key
	// credentials (real cost).
	//
	// THREE THINGS ABOUT THIS TABLE THAT ARE EASY TO GET WRONG:
	//
	// 1. These are the STANDARD service tier at SHORT context. OpenAI now
	//    publishes four service tiers (standard / batch / flex / fast — "fast"
	//    is what "priority" was renamed to on 2026-07-30) and, for the 5.4+
	//    frontier line, a second price band that kicks in at **272K context
	//    length**: above it every rate roughly doubles (gpt-5.6-sol 4→8 in,
	//    20→30 out). ModelPrice carries one band, so a >272K request bills at
	//    the short-context rate and under-charges. See the long-context table
	//    in the source page before assuming a card is wrong.
	//
	// 2. Cache WRITES are a 5.6-line-only concept. OpenAI publishes
	//    `cache writes` for gpt-5.6-{sol,terra,luna,cyber} only, at a clean
	//    1.25× input; every older card leaves CacheCreatePer1M zero, which is
	//    correct — those models bill cached reads and nothing else.
	//
	// 3. Lookup's prefix fallback trims on "-", so a MISSING card is not a
	//    zero bill, it is the nearest shorter name's bill. That is how
	//    gpt-5.4-nano used to bill at the gpt-5.4 card (12.5× over) and
	//    gpt-5.5-pro at the gpt-5.5 card (6× under). Every published SKU below
	//    gets its own row precisely so the fallback never has to guess.

	// Frontier — GPT-5.6 line. `gpt-5.6` is the published alias for sol.
	//
	// ⚠️ gpt-5.6-sol carries PROMOTIONAL pricing that OpenAI commits to "at
	// least through November 21, 2026"; the post-promo list price is not
	// published. Registered in introductoryRates with the previous flagship
	// (gpt-5.5) card as the placeholder list price, so the build fails on
	// 2026-11-22 and someone re-reads the page rather than billing a lapsed
	// promo forever.
	ProviderOpenAI + "/gpt-5.6":       {InputPer1M: 4.00, OutputPer1M: 20.00, CacheReadPer1M: 0.40, CacheCreatePer1M: 5.00},
	ProviderOpenAI + "/gpt-5.6-sol":   {InputPer1M: 4.00, OutputPer1M: 20.00, CacheReadPer1M: 0.40, CacheCreatePer1M: 5.00},
	ProviderOpenAI + "/gpt-5.6-terra": {InputPer1M: 2.00, OutputPer1M: 12.00, CacheReadPer1M: 0.20, CacheCreatePer1M: 2.50},
	ProviderOpenAI + "/gpt-5.6-luna":  {InputPer1M: 0.20, OutputPer1M: 1.20, CacheReadPer1M: 0.02, CacheCreatePer1M: 0.25},
	ProviderOpenAI + "/gpt-5.6-cyber": {InputPer1M: 12.50, OutputPer1M: 75.00, CacheReadPer1M: 1.25, CacheCreatePer1M: 15.625},

	// Frontier — GPT-5.5 / 5.4 / 5.2 / 5.1 / 5 lines. No cache-write rate is
	// published for any of them.
	ProviderOpenAI + "/gpt-5.5":       {InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50},
	ProviderOpenAI + "/gpt-5.5-pro":   {InputPer1M: 30.00, OutputPer1M: 180.00},
	ProviderOpenAI + "/gpt-5.5-cyber": {InputPer1M: 12.50, OutputPer1M: 75.00, CacheReadPer1M: 1.25},
	ProviderOpenAI + "/gpt-5.4":       {InputPer1M: 2.50, OutputPer1M: 15.00, CacheReadPer1M: 0.25},
	ProviderOpenAI + "/gpt-5.4-mini":  {InputPer1M: 0.75, OutputPer1M: 4.50, CacheReadPer1M: 0.075},
	ProviderOpenAI + "/gpt-5.4-nano":  {InputPer1M: 0.20, OutputPer1M: 1.25, CacheReadPer1M: 0.02},
	ProviderOpenAI + "/gpt-5.4-pro":   {InputPer1M: 30.00, OutputPer1M: 180.00},
	ProviderOpenAI + "/gpt-5.2":       {InputPer1M: 1.75, OutputPer1M: 14.00, CacheReadPer1M: 0.175},
	ProviderOpenAI + "/gpt-5.2-pro":   {InputPer1M: 21.00, OutputPer1M: 168.00},
	ProviderOpenAI + "/gpt-5.1":       {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},

	// Codex tier labels. gpt-5.3-codex is on the page under "Specialized
	// models"; gpt-5.3-codex-spark (a Pro research preview) is not published
	// separately and bills at the same card per the Codex credit calculator
	// (1 credit = $0.04).
	ProviderOpenAI + "/gpt-5.3-codex":       {InputPer1M: 1.75, OutputPer1M: 14.00, CacheReadPer1M: 0.175},
	ProviderOpenAI + "/gpt-5.3-codex-spark": {InputPer1M: 1.75, OutputPer1M: 14.00, CacheReadPer1M: 0.175},

	// Daybreak aliases. OpenAI states these currently point at gpt-5.6-sol and
	// gpt-5.6-cyber respectively, and that pricing follows whatever they are
	// repointed at — so these two rows go stale silently on the next Daybreak
	// release. Re-check them whenever the 5.6 line moves.
	ProviderOpenAI + "/daybreak-blue-latest": {InputPer1M: 4.00, OutputPer1M: 20.00, CacheReadPer1M: 0.40, CacheCreatePer1M: 5.00},
	ProviderOpenAI + "/daybreak-red-latest":  {InputPer1M: 12.50, OutputPer1M: 75.00, CacheReadPer1M: 1.25, CacheCreatePer1M: 15.625},

	// ─── OpenAI BYOK API models ────────────────────────────────────────
	ProviderOpenAI + "/gpt-5":            {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/gpt-5-mini":       {InputPer1M: 0.25, OutputPer1M: 2.00, CacheReadPer1M: 0.025},
	ProviderOpenAI + "/gpt-5-nano":       {InputPer1M: 0.05, OutputPer1M: 0.40, CacheReadPer1M: 0.005},
	ProviderOpenAI + "/gpt-5-pro":        {InputPer1M: 15.00, OutputPer1M: 120.00},
	ProviderOpenAI + "/gpt-5-search-api": {InputPer1M: 1.25, OutputPer1M: 10.00, CacheReadPer1M: 0.125},
	ProviderOpenAI + "/chat-latest":      {InputPer1M: 5.00, OutputPer1M: 30.00, CacheReadPer1M: 0.50},
	ProviderOpenAI + "/gpt-4.1":          {InputPer1M: 2.00, OutputPer1M: 8.00, CacheReadPer1M: 0.50},
	ProviderOpenAI + "/gpt-4.1-mini":     {InputPer1M: 0.40, OutputPer1M: 1.60, CacheReadPer1M: 0.10},
	ProviderOpenAI + "/gpt-4.1-nano":     {InputPer1M: 0.10, OutputPer1M: 0.40, CacheReadPer1M: 0.025},
	ProviderOpenAI + "/gpt-4o":           {InputPer1M: 2.50, OutputPer1M: 10.00, CacheReadPer1M: 1.25},
	ProviderOpenAI + "/gpt-4o-mini":      {InputPer1M: 0.15, OutputPer1M: 0.60, CacheReadPer1M: 0.075},

	// o-series reasoning models. o1/o3/o4 names contain no "-" segment that
	// Lookup could trim onto a GPT card, so a missing row here lands on the
	// OpenAI provider default (the gpt-5 card) rather than anything sane —
	// o1-pro would bill at 1/120th of its real input rate.
	ProviderOpenAI + "/o4-mini": {InputPer1M: 1.10, OutputPer1M: 4.40, CacheReadPer1M: 0.275},
	ProviderOpenAI + "/o3":      {InputPer1M: 2.00, OutputPer1M: 8.00, CacheReadPer1M: 0.50},
	ProviderOpenAI + "/o3-mini": {InputPer1M: 1.10, OutputPer1M: 4.40, CacheReadPer1M: 0.55},
	ProviderOpenAI + "/o3-pro":  {InputPer1M: 20.00, OutputPer1M: 80.00},
	ProviderOpenAI + "/o1":      {InputPer1M: 15.00, OutputPer1M: 60.00, CacheReadPer1M: 7.50},
	ProviderOpenAI + "/o1-pro":  {InputPer1M: 150.00, OutputPer1M: 600.00},
}

// QuantizeUSD rounds a dollar amount to MonetaryScale decimal places, using the
// value's shortest decimal representation as the starting point.
//
// # Why this exists
//
// A charge is written to two places that must agree: the wallet balance
// (`balance = balance - x`) and the ledger row (`amount_usd = -x`). With an
// unrounded float64 the two land on different values, and the gap compounds. A
// 2026-08 audit of a production SQLite ledger with 576,049 charge rows found
// workspaces already out of balance against their own ledger:
//
//	workspace 105   balance 815.18275431   ledger 815.18275432
//	workspace  19   balance 495.03089712   ledger 495.03089713
//	workspace  30   balance 149.45152177   ledger 149.45152178
//
// Rounding every amount to a fixed scale before it reaches storage means both
// writes carry the identical number, so the residual drift is bounded by
// float64 summation alone rather than growing a fresh 1e-8 per request. It also
// makes the server's figure reproducible by a client recomputing the same
// formula, which is what lets the request-log UI compare its own arithmetic to
// the stored total at a tight tolerance instead of a 5e-4 fudge factor.
//
// Implemented via strconv rather than math.Round(v*1e8)/1e8: multiplying by 1e8
// introduces its own binary error that can push a value on a rounding boundary
// to the wrong side. Formatting with 'f' and a fixed precision rounds the
// decimal representation directly, which is the behaviour callers expect.
//
// NaN and ±Inf pass through untouched — they are bugs upstream, and silently
// turning them into 0 would hide the bug while still corrupting a balance.
func QuantizeUSD(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	q, err := strconv.ParseFloat(strconv.FormatFloat(v, 'f', MonetaryScale, 64), 64)
	if err != nil {
		return v
	}
	return q
}

// MonetaryScale is the number of decimal places every billed amount is rounded
// to before it is stored or compared. Eight places is ~1e-8 USD: far below the
// smallest real charge (a Haiku cache-read request is ~1e-6) yet coarse enough
// that a client recomputing the same formula in IEEE-754 lands on the same
// value.
const MonetaryScale = 8
