# Claude Code 2.1.183 — fingerprint ground truth

Captured 2026-06-20 from a live `claude-cli/2.1.183` OAuth session (whistle dump,
100 sessions, ~90 CC requests; the chat sample in this window was an Agent-SDK
sub-call, not interactive CLI — body-layer layout re-confirmed from the billing
header + metadata shape, not a fresh 4-block interactive sample). This is the
authoritative reference for the fingerprint constants in `cc-core/mimicry` and
`cc-core/sidecar`. As of cc-core's mimicry/sidecar convergence, hypitoken and
CPA-Claude both consume these via the module dep — there is **no vendored copy**
to keep in sync anymore.

Supersedes **crack/cc2170** (Claude Code 2.1.170).

Client env (from the `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.183
build_time             = 2026-06-18T23:04:10Z   (was 2026-06-09T15:09:09Z @ 2.1.170)
node_version           = v24.3.0                (unchanged)
sdk (@anthropic-ai)    = 0.94.0                 (unchanged, x-stainless-package-version)
linux_distro_id        = arch                   (capture host; host-profile pool, not pinned)
linux_kernel           = 7.0.12-arch1-1         (capture host; host-profile pool, not pinned)
default model (telem)  = claude-opus-4-8         (was claude-fable-5 @ 2.1.170 — fable-5 now
                                                  DISABLED upstream, see §7)
```

Everything below is the **2.1.170 → 2.1.183 diff**.

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header *set* is identical to 2.1.170. Only `user-agent` and `anthropic-beta`
changed. No new headers, no removed headers.

| header | value | vs 2.1.170 |
|---|---|---|
| `user-agent` | `claude-cli/2.1.183 (external, cli)` | **bumped** |
| `x-stainless-arch` | `x64` | same |
| `x-stainless-lang` | `js` | same |
| `x-stainless-os` | `Linux` | same |
| `x-stainless-package-version` | `0.94.0` | same |
| `x-stainless-retry-count` | `0` | same |
| `x-stainless-runtime` | `node` | same |
| `x-stainless-runtime-version` | `v24.3.0` | same |
| `x-stainless-timeout` | `600` | same |
| `anthropic-version` | `2023-06-01` | same |
| `anthropic-dangerous-direct-browser-access` | `true` | same |
| `x-app` | `cli` | same |
| `anthropic-beta` | **13-item list, see below** | **−2 (15→13)** |

### `anthropic-beta` request header (FULL — 13 items, exact order)

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

**Diff vs 2.1.170 (15-item list):**

- **REMOVED** `server-side-fallback-2026-06-01` and `fallback-credit-2026-06-01`
  (the pair that 2.1.170 had inserted after `effort-2025-11-24`). The server-side
  fallback machinery was short-lived on the request header — gone again by
  2.1.183. `context-1m-2025-08-07` remains absent (dropped back at 2.1.170).

→ `mimicry.ClaudeAnthropicBetaFull`.

---

## 2. `/v1/messages` — request **body** shape  (UNCHANGED vs 2.1.170)

Top-level keys real CC 2.1.183 sends — identical to 2.1.170:

```
model, messages[], system[], tools[], metadata{user_id}, max_tokens,
thinking{type:"adaptive"}, context_management{edits:[…]},
output_config{effort:…}, diagnostics{previous_message_id}, stream
```

We deliberately **do not** inject `thinking` / `output_config` /
`context_management` / `diagnostics` (beta-gated, alter response semantics for
non-CC downstream clients). Unchanged policy.

### system block layout — UNCHANGED

- billing header block carries `cc_version=2.1.183.<3hex>; cc_entrypoint=cli; cch=<5hex>;`
  (format unchanged; only the version literal moved).
- scope:global on the second-to-last system block, plain ephemeral 1h on the last
  (`sysCC = ['-','-','S1h','e1h']`). Same as 2.1.170. The chat sample this session
  was an Agent-SDK call (system[1] = "You are a Claude agent, built on Anthropic's
  Claude Agent SDK…"), which confirms the billing-header + ephemeral-cache_control
  scaffolding is unchanged.

### `metadata.user_id` (JSON string) — UNCHANGED shape

```json
{"device_id":"<sha256 hex>","account_uuid":"<uuid>","session_id":"<uuid>"}
```

Confirmed `device_id` is a 64-char sha256 hex in the live body.

---

## 3. Telemetry: `POST /api/event_logging/v2/batch`

Headers (unchanged vs 2.1.170):
- `user-agent`: `claude-code/2.1.183`
- `anthropic-beta`: `oauth-2025-04-20`
- `x-service-name`: `claude-code`
- `connection`: `close`

`env` block (event_logging) — same key set as 2.1.170; values:
`version`/`version_base` → `2.1.183`, `build_time` → `2026-06-18T23:04:10Z`,
`node_version` v24.3.0, `terminal`/`shell`/`linux_*` per host (capture host:
konsole / zsh / arch / 7.0.12-arch1-1).

### ⚠ betas in telemetry now correlate with the model's `[1m]` suffix

Per-event breakdown across this capture shows **two** telemetry beta lists
keyed by whether the event's `model` carries the `[1m]` (1M-context) suffix:

| model | betas reported | items |
|---|---|---|
| `claude-opus-4-8[1m]` | 9-item list **with** `context-1m-2025-08-07` (247 chars) | 9 |
| `claude-opus-4-8` (plain) | 8-item list **without** `context-1m` (225 chars) | 8 |

The 9-item list is **identical** to `ClaudeReportedBetas` as pinned at 2.1.170 —
unchanged. (API-lifecycle events `tengu_api_query`/`tengu_api_success` carry the
full 13-item request-header list instead; not relevant to our heartbeat.)

Our sidecar heartbeat emits a `tengu_dir_search` event with model
`claude-opus-4-8[1m]` + the 9-item list, which is exactly one of the real
observed (`[1m]`, 9-item) pairs. So:

→ `mimicry.ClaudeReportedBetas` — **NO CHANGE** (still the 9-item list with
`context-1m`). Do NOT regenerate it from `ClaudeAnthropicBetaFull`.

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07
```

---

## 4. Telemetry: `POST https://http-intake.logs.us5.datadoghq.com/api/v2/logs`

Headers (unchanged):
- `user-agent`: `axios/1.15.2`
- `dd-api-key`: `pubea5604404508cdd34afb69e6f42a05bc` — **unchanged / re-confirmed**
  this capture too (public global telemetry key, not account-bound).
- `connection`: `close`

Body is a JSON array of flat events. Key set **unchanged** vs 2.1.170 (45 keys,
incl. `process_metrics`, the `swe_bench_*` triad, `subscription_type`, `rh`,
`user_bucket`, `feature_name`). Values that moved: `model` → `claude-opus-4-8`,
`version`/`version_base` → `2.1.183`, `build_time` → new, `linux_kernel` per host.
`subscription_type:max`, `ddtags` carries `model:claude-opus-4-8`,
`rateLimitTier`/`organization_rate_limit_tier` = `default_claude_max_20x`.

---

## 5. Startup / sidecar requests

The request set is identical to 2.1.170 (no new endpoints, none removed):
eval_sdk (GrowthBook) · grove · bootstrap · penguin · mcp-registry · mcp_servers ·
releases/latest · code_triggers · plugins_latest · event_logging · datadog.

- **`POST /api/eval/sdk-<id>`** (GrowthBook feature flags) — UA bumped
  **`Bun/1.3.14` → `Bun/1.4.0`**. Beta `oauth-2025-04-20` (unchanged). Body
  attributes carry `appVersion:2.1.183`, `subscriptionType:max`,
  `rateLimitTier:default_claude_max_20x`.
- **`GET /api/claude_cli/bootstrap?entrypoint=cli&model=<m>`** — UA
  `claude-code/2.1.183`, beta `oauth-2025-04-20`. The `model=` param tracks the
  user's launch model; this session launched `claude-opus-4-8` (was
  `claude-fable-5` @ 2.1.170). Response `additional_model_options[0]` still lists
  Fable but now with `disabled_reason: "Claude Fable 5 is currently unavailable.
  …"` — i.e. **fable-5 is disabled upstream**, which is why the live default model
  fell back to opus-4-8 everywhere.
- **`GET /v1/code/triggers`** — beta `ccr-triggers-2026-01-30`, header
  `anthropic-client-platform: claude_code_cli`, response `{"data":[],"has_more":false}`.
  Unchanged from 2.1.170.
- **`GET …/plugins/claude-plugins-official/latest`** — UA `axios/1.15.2`, bare
  git SHA response. Unchanged.

---

## 6. `dd-api-key` / host profile

- Datadog key unchanged (see §4).
- The machine-identifying axes (`linux_distro_id`, `linux_kernel`, `terminal`,
  `shell`) are NOT pinned constants — they come from the per-account
  `auth.HostProfile` pool (`auth/hostprofile.go`). The capture host's
  `7.0.12-arch1-1` is one sample, not a constant to bump.

---

## Edit checklist (cc-core only — no vendored copies remain)

| # | where | change |
|---|---|---|
| 1 | `mimicry.CLICurrentVersion` | `2.1.170` → `2.1.183` (cascades into all `claude-code/<ver>` UAs) |
| 2 | `mimicry.ClaudeCLIUserAgent` | `claude-cli/2.1.183 (external, cli)` |
| 3 | `mimicry.ClaudeAnthropicBetaFull` | **13-item list (§1)** — drop `server-side-fallback-2026-06-01` + `fallback-credit-2026-06-01` |
| 4 | `mimicry.ClaudeReportedBetas` | **NO CHANGE** — still 9 items incl. `context-1m` (§3) |
| 5 | `mimicry.ClaudeAnthropicBetaApikey` | no 2.1.183 api-key capture — left verbatim |
| 6 | body/mimicry: system layout + cch | unchanged (§2) — already correct |
| 7 | `sidecar.ccBuildTime` | `2026-06-09T15:09:09Z` → `2026-06-18T23:04:10Z` |
| 8 | `sidecar.ccTelemetryModel` | `claude-fable-5[1m]` → `claude-opus-4-8[1m]` |
| 9 | `sidecar.ccDatadogModel` | `claude-fable-5` → `claude-opus-4-8` |
| 10 | sidecar bootstrap `model=` param | `claude-fable-5` → `claude-opus-4-8` |
| 11 | `sidecar.uaBun` | `Bun/1.3.14` → `Bun/1.4.0` |
| 12 | `sidecar.uaAxios` | `axios/1.15.2` — unchanged |
| 13 | sidecar datadog/event_logging `betas` | `ClaudeReportedBetas` — unchanged |
| 14 | host profile (`auth/hostprofile.go`) | unchanged — kernel/distro/terminal/shell are pool-driven, not pinned |
| 15 | comments | `2.1.170` → `2.1.183`; `crack/cc2170/SPEC.md` → `crack/cc2183/SPEC.md` |
