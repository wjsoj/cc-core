# crack/thirdparty — Claude Code on a custom base URL (INBOUND shape)

Capture: **2026-08-09**, `claude-cli/2.1.226` on Arch Linux, `ANTHROPIC_BASE_URL`
pointing at a third-party Anthropic-compatible gateway (`api.minimaxi.com/anthropic`),
`ANTHROPIC_AUTH_TOKEN` supplying the bearer. 6 `/v1/messages` requests
(5 main + 1 session-title), 2 retained as rows.

## Why this directory exists

Every other dir under `crack/` answers *"what does real Claude Code send to
Anthropic?"* — the shape we must **produce**. This one answers the complementary
question: *"what does Claude Code send to **us**?"* — the shape we must
**consume and repair**.

Both forks are reverse proxies. A user points their Claude Code at us with
`ANTHROPIC_BASE_URL`, so every inbound request has the shape recorded here; we
then forward it to `api.anthropic.com` on a real OAuth credential, which means
it must leave looking like `cc2224/rows/13-v1_messages.json`. This file is the
**left-hand side of that transform**, and `mimicry`'s genuine-rewrite path is
the transform itself.

Counterpart OAuth rows for the same comparison:

| this dir | counterpart |
|---|---|
| `rows/01-v1_messages.json` (main) | `../cc2224/rows/13-v1_messages.json` |
| `rows/02-v1_messages_title.json` (title) | — no OAuth title row in tree (**gap**) |

The OAuth side was captured 2026-08-07 on `claude-cli/2.1.224` — the two sessions
are two minor versions apart. Version-sensitive claims below are marked.

---

## §1 Request headers

Identical on both sides: `anthropic-version: 2023-06-01`, `x-app: cli`,
`anthropic-dangerous-direct-browser-access: true`, `accept: application/json`
(**even when `stream:true`**), `accept-encoding: gzip, br`,
`connection: keep-alive`, `x-claude-code-session-id`, and the full
`x-stainless-arch/lang/os/package-version/retry-count/runtime/runtime-version`
block (`x64` / `js` / `Linux` / `0.94.0` / `0` / `node` / `v26.3.0`).

Differences:

| header | OAuth (2.1.224) | custom base URL (2.1.226) | repair |
|---|---|---|---|
| `authorization` | `Bearer sk-ant-oat01-…` | `Bearer sk-cp-…` (user's own token) | always overwritten — `mimicry/headers.go:40-46` |
| `x-client-request-id` | present, fresh v4 UUID, **16/16 requests** | **absent, 0/6 requests** | generated — `mimicry/headers.go:96-99` |
| `x-stainless-timeout` | `600` | `3000` | pinned — `mimicry/request_policy.go:942` |
| `anthropic-beta` | 15 items (1M vector) | 8 items (main) / 9 (title) | see §1a |
| `user-agent` | `claude-cli/2.1.224 (external, cli)` | `claude-cli/2.1.226 (external, cli)` | pinned to `ClaudeCLIUserAgent` |

`x-client-request-id` is the single cleanest discriminator observed: 100% present
on the OAuth path, 100% absent on the custom-base-url path. Claude Code omits it
deliberately — third-party gateways reject unknown headers — which is why
`headers.go` also gates it on `isAnthropicBase`.

### §1a Beta vectors — the OAuth-only delta

The custom-base-url list is **the OAuth list minus a fixed set, with the order of
the surviving items preserved**. Nothing is added, nothing is reordered. That
makes the repair a deterministic *insertion*, not a guess.

Main request, custom base URL (8 items, `rows/01`):

```
claude-code-20250219, interleaved-thinking-2025-05-14, redact-thinking-2026-02-12,
thinking-token-count-2026-05-13, context-management-2025-06-27,
prompt-caching-scope-2026-01-05, mid-conversation-system-2026-04-07,
effort-2025-11-24
```

`mimicry.ClaudeAnthropicBetaFull` (13 items, non-1M OAuth main) minus that list =
**exactly** these five, which is `mimicry.claudeOAuthOnlyBetas`:

| beta | position in `ClaudeAnthropicBetaFull` |
|---|---|
| `oauth-2025-04-20` | 2 |
| `advisor-tool-2026-03-01` | 9 |
| `advanced-tool-use-2025-11-20` | 10 |
| `extended-cache-ttl-2025-04-11` | 12 |
| `cache-diagnosis-2026-04-07` | 13 |

The set is coherent: every member is either the OAuth marker itself or an
entitlement the gateway account cannot have. Re-deriving it is a one-liner —
`ClaudeAnthropicBetaFull` minus the captured list — and
`TestOAuthOnlyBetasMatchCapturedDelta` (`mimicry/headers_test.go`) fails the
build if the two ever disagree.

**`context-1m-2025-08-07` and `fallback-credit-2026-06-01` are deliberately NOT
in the set.** They are the 1M-context pair (`ClaudeAnthropicBeta1M` = Full + those
two), and the custom-base-url session was not in 1M mode, so this capture cannot
distinguish "gated by OAuth" from "gated by context mode". `cc2220/SPEC.md §1a`
already established they track context mode, so cc-core does not inject them:
claiming a 1M window we cannot verify is worse than not claiming it.

Title request (9 items, `rows/02`) = the 8-item main list **+
`structured-outputs-2025-12-15`**, which pairs with `output_config.format.json_schema`
in the body. It is a request-class feature bit, **not** a third-party tell — do not
strip it. This corrects an earlier reading of this capture; the repo's own
fixture at `mimicry/request_policy_test.go:385` independently treats
`structured-outputs` as belonging to a genuine OAuth title vector.

This is why the repair must be additive per request. The inbound vector still
carries the request class (main vs title vs count_tokens); replacing it wholesale
with one constant would erase that and send `structured-outputs` requests a main
vector they do not want.

---

## §2 Request body

Top-level key set is **identical** on both sides:
`model, messages, system, tools, metadata, max_tokens, thinking,
context_management, output_config, stream`. So is `thinking: {"type":"adaptive"}`
and the presence of `context_management`.

### §2a Billing block — `system[0]`

```
OAuth   : x-anthropic-billing-header: cc_version=2.1.224.779; cc_entrypoint=cli; cch=1dc46; cc_prev_req=req_011Cdo…;
custom  : x-anthropic-billing-header: cc_version=2.1.226.ab9; cc_entrypoint=cli;
```

`cch` and `cc_prev_req` are **first-party only** and never appear on the custom
base URL — Claude Code cannot chain to a `request-id` a third-party gateway never
returned. The `.779` / `.ab9` / `.fb5` suffix is the per-request
`computeClaudeCodeFingerprint` value (`mimicry/body.go:351-365`), not a version
component; it is stable for a given first user message.

Consequence for us, stated plainly: we rewrite `cc_version` to our pinned target
but **cannot** synthesize `cch` (its signer is unbroken —
`cc2224/SPEC.md §Unresolved`). Outbound requests therefore carry a billing block
that real OAuth Claude Code never emits: version + entrypoint with no `cch`. This
is a known, permanent 100%-discriminable gap, accepted because the alternative —
forwarding a fabricated `cch` — is worse. `mimicry` fails closed if either field
arrives inbound (`request_policy.go:556-560`).

### §2b `metadata.user_id`

Same JSON-string-inside-a-string shape and same field order on both sides.

```
OAuth  : {"device_id":"<64-hex>","account_uuid":"<uuid>","session_id":"<uuid>"}
custom : {"device_id":"<64-hex>","account_uuid":"","session_id":"<uuid>"}
```

`account_uuid` is the **empty string** — the client has no Anthropic account.
`device_id` is a real per-machine hash and is the downstream *user's*, not ours.
Both must be re-derived from the selected credential
(`mimicry/identity.go:33-36`, `request_policy.go:570`); note the empty
`account_uuid` cannot be detected by an is-`metadata.user_id`-empty check, which
is exactly why the legacy `ensureMetadataUserID` path (`body.go:579`) can never
fix it.

### §2c `system` blocks and `cache_control`

Recorded as `_notes.system_cache_pattern`, where `null` = no `cache_control`,
`false` = `cache_control` without `scope`, `true` = with `scope`.

| capture | blocks | pattern |
|---|---|---|
| OAuth main (`cc2224/rows/13`) | 4 | `[null, null, true, false]` → `[-, -, ephemeral+1h+global, ephemeral+1h]` |
| custom main (`rows/01`) | 3 | `[null, false, false]` → `[-, ephemeral, ephemeral]` |
| custom title (`rows/02`) | 3 | `[null, null, null]` — no breakpoints at all |

Two independent facts, easy to conflate:

1. **Block count differs for a content reason, not a mode reason.** The OAuth
   session had an extra appended system section (11001 chars) that the
   custom-base-url session did not. Do not synthesize a fourth block.
2. **Breakpoint placement is the same rule on both sides** — the last two blocks
   — but the custom base URL emits them as bare `{"type":"ephemeral"}` because
   `extended-cache-ttl-2025-04-11` and `prompt-caching-scope-2026-01-05` are not
   in its beta vector. Restore `ttl`/`scope` **only on blocks that already carry
   a `cache_control`**, never adding or removing one. Applied to `rows/01` that
   yields `[null, true, false]`, matching the OAuth pattern on the last two
   blocks; applied to `rows/02` it is a no-op, which is correct — the title
   request has no breakpoints on either path.

This repair is only legal once §1a has put `extended-cache-ttl` back in the
header, which is why the two changes ship together. It is also worth real money:
without it every forwarded request writes a 5-minute cache entry instead of a
1-hour global one.

---

## §3 Auxiliary traffic — none

The OAuth session emitted the full first-party burst plus heartbeats (see
`cc2224/SPEC.md §5`, reproduced by `sidecar/`). Across the entire custom-base-url
session there were **zero** requests to `api.anthropic.com`, `platform.claude.com`,
`downloads.claude.ai`, or the Datadog intake — only `/v1/messages` to the gateway
and unrelated local MCP traffic. The whistle buffer still held the 2026-08-07
rows throughout, so this is a real absence, not eviction.

This independently confirms the design rule that sidecars are OAuth-only
(`sidecar/sidecar.go:272-274`): a real client on a custom base URL emits no
telemetry at all, so a proxy that fires sidecars per *inbound* request would be
louder than one that fires them per *credential*.

---

## §4 Response headers

Not a fingerprint we emit, but it bounds what we can pass downstream.

OAuth returns `request-id`, `anthropic-organization-id`, `anthropic-workspace-id`,
`traceresponse`, `server: cloudflare`, and the twelve-header
`anthropic-ratelimit-unified-*` family (`status`, `5h-status/reset/utilization`,
`7d-status/reset/utilization`, `representative-claim`, `fallback-percentage`,
`reset`, `overage-status`, `overage-disabled-reason`).

The gateway returns none of them — its own `trace-id` / `x-mm-request-id` /
`minimax-request-id` / `alb_request_id` / `server: TencentEdgeOne` /
`eo-cache-status` instead, and `content-encoding: br` rather than `gzip`.

`anthropic-workspace-id` had no prior mention anywhere in this repo; it is
recorded here and in `cc2224/rows/13` for the first time.

This asymmetry is now enforced rather than merely observed: `cc-core/downstream`
allowlists the response headers a proxy returns to its client, and this section
is its evidence — a real gateway returns none of the Anthropic set, and real
Claude Code works against it unchanged, so dropping them is known-safe behaviour
rather than a guess. `Retry-After` is synthesized from the unified reset
timestamps before they are deleted, so client backoff survives.

---

## §5 Unresolved

- **No OAuth title/`count_tokens` row in tree.** The title comparison in §1a
  leans on `ClaudeAnthropicBetaFull` arithmetic plus an existing test fixture, not
  on a captured OAuth title request. `ClaudeAnthropicBetaCountTokens` remains
  carried forward from 2.1.220 and is untested against either path at 2.1.224.
- **1M gating unseparated.** Whether a custom-base-url client in 1M mode would
  declare `context-1m` is unobserved (§1a).
- **Two versions apart.** 2.1.224 vs 2.1.226. Every difference in §1/§2 is
  structural rather than version-shaped, and the Stainless block is byte-identical
  across the two, but a same-version capture would settle it.
- **2.1.226 exists.** The pinned target is still 2.1.224; bumping is a separate
  change (see `../README.md`).

## §6 Side result — quota probe confirmed at 2.1.224

The 2026-08-07 OAuth capture also caught the Haiku quota probe, now stored as
`../cc2224/rows/19-quota_probe.json`. Both `sidecar.quotaProbeBeta` (6 items) and
`sidecar.quotaProbeModel` (`claude-haiku-4-5-20251001`) match it **verbatim**.
Those constants previously cited a 2.1.170-era file that has since been pruned
from the tree, leaving them unbacked; they are now anchored at the current target.
