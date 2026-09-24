# Claude Opus 5.5

Official model ID: `claude-opus-5-5`. Released September 22, 2026; pricing
verified September 24, 2026 against Anthropic's
[model overview](https://platform.claude.com/docs/en/models/opus-5-5/overview)
and [API pricing](https://platform.claude.com/docs/en/about-claude/pricing).

## Standard billing

USD per million tokens, before the existing customer/workspace multiplier:

| Input | Output | Cache read | 5-minute cache write | 1-hour cache write |
| ---: | ---: | ---: | ---: | ---: |
| 4.00 | 20.00 | 0.20 | 5.00 | 8.00 |

The complete 1M context uses this card. Cache reads are 5% of input, not the
10% used by older Opus models. An explicit catalog entry prevents the prefix
lookup from silently charging the old `claude-opus-5` rates. Context labels
such as `[1m]` and dated suffixes resolve to the new card.

The new model ships its official 1-hour cache-write rate. It applies only to
the observed `usage.cache_creation.ephemeral_1h_input_tokens` subset; without
a TTL breakdown, cache writes use the 5-minute rate. Legacy models retain
their existing opt-in 1-hour policy. Configuration overrides still take
precedence, including setting the 1-hour rate to zero to disable the split.

Anthropic separately quotes Fast mode at $8/$40 input/output (2x standard),
and Batch input/output at $2/$10. This addition registers the standard card;
the existing Claude billing path does not distinguish `speed: "fast"`, Batch
or regional pricing. Those modifiers are not implemented by this change.

## Gateway integration

CPA-Claude and hypitoken forward this model through their existing Claude
routes; no Claude model allowlist needs extending. OAuth model mappings for
older generations remain unchanged. CC Switch imports now select Opus 5.5
for the Opus slot. hypitoken's public pricing API uses the shared catalog,
and its price page displays the separate 5-minute and 1-hour write rates.

Opus 5.5 uses always-on adaptive thinking. Clients should use the current
Claude Code or follow Anthropic's migration guide; the gateway does not
translate incompatible legacy thinking/tool-choice settings.

Local sibling `go.work` files replace cc-core with `../cc-core`. Published
builds use cc-core v0.8.141 or later for this card; both gateways must update
their module dependency. Run local integration with Go 1.26.2; the existing
uTLS transport is incompatible with Go 1.27.
