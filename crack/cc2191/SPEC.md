# Claude Code 2.1.191 — fingerprint ground truth

Captured 2026-06-25 from a live `claude-cli/2.1.191` OAuth session (whistle dump,
fresh capture window 15:06–15:08, 36 sessions). **This round captured the full
OAuth *login* flow from scratch** (logout → `/login` → browser consent → token
exchange → startup), so the rows include `oauth_hello` / `oauth_token` /
`oauth_profile` / `oauth_roles` and the two new login probes `api_hello` /
`oauth_account_settings` — which the 2.1.170 / 2.1.183 steady-state captures
lacked. This is the authoritative reference for the fingerprint constants in
`cc-core/mimicry` and `cc-core/sidecar`. hypitoken and CPA-Claude both consume
these via the module dep — there is **no vendored copy** to keep in sync.

Supersedes (and replaces) all prior per-version captures — cc2183 / cc2170 /
cc2167 were pruned once 2.1.191 landed; their diffs live in git history.

Client env (from the `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.191
build_time             = 2026-06-24T11:24:03Z   (was 2026-06-18T23:04:10Z @ 2.1.183)
node_version           = v26.3.0                (was v24.3.0 @ 2.1.183 — RUNTIME JUMP)
sdk (@anthropic-ai)    = 0.94.0                 (unchanged, x-stainless-package-version)
default model (telem)  = claude-opus-4-8         (unchanged; fable-5 still disabled upstream)
linux_distro_id        = arch                   (capture host; host-profile pool, not pinned)
linux_kernel           = 7.0.12-arch1-1         (capture host; host-profile pool, not pinned)
```

Everything below is the **2.1.183 → 2.1.191 diff**. The headline is small: the
only fingerprint-bearing change on the chat path is the bundled **Node runtime
v24.3.0 → v26.3.0**. Beta lists, body shape, system layout, telemetry models,
and all sidecar UAs are byte-for-byte unchanged.

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header *set* identical to 2.1.183. Only `user-agent` and
`x-stainless-runtime-version` changed. `anthropic-beta` is UNCHANGED.

| header | value | vs 2.1.183 |
|---|---|---|
| `user-agent` | `claude-cli/2.1.191 (external, cli)` | **bumped** |
| `x-stainless-arch` | `x64` | same |
| `x-stainless-lang` | `js` | same |
| `x-stainless-os` | `Linux` | same |
| `x-stainless-package-version` | `0.94.0` | same |
| `x-stainless-retry-count` | `0` | same |
| `x-stainless-runtime` | `node` | same |
| `x-stainless-runtime-version` | `v26.3.0` | **bumped (was v24.3.0)** |
| `x-stainless-timeout` | `600` | same |
| `anthropic-version` | `2023-06-01` | same |
| `anthropic-dangerous-direct-browser-access` | `true` | same |
| `x-app` | `cli` | same |
| `anthropic-beta` | **13-item list (below)** | **UNCHANGED** |

### `anthropic-beta` request header (FULL — 13 items, exact order) — UNCHANGED

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

Byte-identical to the 2.1.183 list. (2.1.170 had briefly carried
`server-side-fallback-2026-06-01` + `fallback-credit-2026-06-01`; gone since
2.1.183 and still gone.)

→ `mimicry.ClaudeAnthropicBetaFull` — **NO CHANGE**.
→ `mimicry.ClaudeStainlessRuntimeV` — `v24.3.0` → **`v26.3.0`** (this one
constant feeds both the header above AND telemetry `env.node_version` in §3/§4).

---

## 2. `/v1/messages` — request **body** shape  (UNCHANGED vs 2.1.183)

Top-level keys real CC 2.1.191 sends — identical to 2.1.183:

```
model, messages[], system[4], tools[], metadata{user_id}, max_tokens,
thinking{type:"adaptive"}, context_management{edits:[{type:"clear_thinking_20251015",keep:"all"}]},
output_config{effort:"high"}, diagnostics{previous_message_id}, stream
```

We deliberately **do not** inject `thinking` / `output_config` /
`context_management` / `diagnostics` (beta-gated, alter response semantics for
non-CC downstream clients). Unchanged policy.

### system block layout (4 blocks) — UNCHANGED

Live interactive sample this round (model `claude-opus-4-8`):

```
[0] text  cc=none            "x-anthropic-billing-header: cc_version=2.1.191.<3hex>; cc_entrypoint=cli; cch=<5hex>;"
[1] text  cc=none            "You are Claude Code, Anthropic's official CLI for Claude."
[2] text  cc=ephemeral 1h scope:global    <- second-to-last
[3] text  cc=ephemeral 1h    (no scope)    <- last
```

Confirmed `sysCC = ['-','-','S1h','e1h']` (system_cache_pattern
`[null,null,true,false]`). Billing-header literal is now
`cc_version=2.1.191.<3hex>` (only the version moved). Same as 2.1.183.

### `metadata.user_id` (JSON string) — UNCHANGED shape

```json
{"device_id":"<sha256 hex>","account_uuid":"<uuid>","session_id":"<uuid>"}
```

---

## 3. Telemetry: `POST /api/event_logging/v2/batch`

Headers (unchanged vs 2.1.183):
- `user-agent`: `claude-code/2.1.191`
- `anthropic-beta`: `oauth-2025-04-20`
- `x-service-name`: `claude-code`
- `connection`: `close`

`env` block — same key set as 2.1.183; values that moved:
`version`/`version_base` → `2.1.191`, `build_time` → `2026-06-24T11:24:03Z`,
**`node_version` → `v26.3.0`**. `terminal`/`shell`/`linux_*` per host (capture
host: konsole / zsh / arch / 7.0.12-arch1-1 — pool-driven, not pinned).

### betas in telemetry — UNCHANGED (still correlate with the model `[1m]` suffix)

Observed per-event beta strings this capture (raw, un-redacted from the dump):

| event class | model | betas | chars |
|---|---|---|---|
| heartbeat (`tengu_dir_search` etc.) | `claude-opus-4-8[1m]` | 9-item **with** `oauth-2025-04-20` + `context-1m` | 247 |
| api-lifecycle (`tengu_api_*`) | `claude-opus-4-8[1m]` | 8-item, no `oauth-2025-04-20`, **with** `context-1m` | 230 |
| plain events | `claude-opus-4-8` | 8-item **without** `context-1m` | 225 |
| `tengu_api_*` (full) | `claude-opus-4-8` | 13-item = the request-header list | 353 |

The 247-char `[1m]` list is **identical** to `ClaudeReportedBetas` as pinned at
2.1.183. Our sidecar heartbeat emits a `tengu_dir_search` with model
`claude-opus-4-8[1m]` + this 9-item list — exactly one of the real observed
pairs.

→ `mimicry.ClaudeReportedBetas` — **NO CHANGE** (9-item incl. `context-1m`). Do
NOT regenerate it from `ClaudeAnthropicBetaFull`.

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07
```

---

## 4. Telemetry: `POST https://http-intake.logs.us5.datadoghq.com/api/v2/logs`

Headers (unchanged):
- `user-agent`: `axios/1.15.2`
- `dd-api-key`: `pubea5604404508cdd34afb69e6f42a05bc` — **unchanged / re-confirmed**
  (public global telemetry key, not account-bound).
- `connection`: `close`

Body is a JSON array of flat events. Key set **unchanged** vs 2.1.183
(`process_metrics`, the `swe_bench_*` triad, `subscription_type`, `rh`,
`user_bucket`, `feature_name`, …). Values that moved: `version`/`version_base`
→ `2.1.191`, `build_time` → new, **`node_version` → `v26.3.0`**. `model` stays
`claude-opus-4-8`. `subscription_type:max`, `organization_rate_limit_tier` =
`default_claude_max_20x`. New `feature_name` values seen this login capture:
`oauth_callback_listener`, `oauth_token_exchange`, `ide_detect` (login-phase
flags only; no structural change).

---

## 5. OAuth login flow (captured fresh this round)

The CLI login burst, in order — bodies value-masked, structure verbatim:

| # | request | UA | notes |
|---|---|---|---|
| 1 | `GET platform.claude.com/v1/oauth/hello` | `claude-cli/2.1.191` | response `{"message":"hello"}` |
| — | `GET api.anthropic.com/api/hello` | `claude-cli/2.1.191` | **NEW probe**, no auth, `{"message":"hello"}` |
| 2 | `POST platform.claude.com/v1/oauth/token` | `axios/1.15.2` | PKCE code exchange (below) |
| 3 | `GET api.anthropic.com/api/oauth/profile` | `axios/1.15.2` | |
| 4 | `GET api.anthropic.com/api/oauth/claude_cli/roles` | `axios/1.15.2` | |
| 5 | `GET api.anthropic.com/api/oauth/account/settings` | `claude-cli/2.1.191` | **NEW**, beta `oauth-2025-04-20` |

**`POST /v1/oauth/token` is on `platform.claude.com`** (migrated late-2025).
cc-core's `auth/oauth.go` already pins
`anthropicTokenURL = "https://platform.claude.com/v1/oauth/token"` and refreshes
through `doAxiosOAuthRequest` (axios UA) — **so the refresh path is already
aligned; no code change.** The login capture just re-confirms it.

Request body keys (token exchange): `grant_type=authorization_code`, `code`,
`redirect_uri=http://localhost:<port>/callback`, `client_id` (public constant
`9d1c250a-e61b-44d9-88ed-5944d1962f5e`), `code_verifier`, `state`.
Response keys: `token_type=Bearer`, `access_token`, `expires_in=28800`,
`refresh_token`, `scope="user:file_upload user:inference user:mcp_servers
user:profile user:sessions:claude_code"`, `token_uuid`,
`organization{uuid,name}`, `account{uuid,email_address}`.

The `api_hello` + `account_settings` probes are login-time only; the proxy uses
stored tokens (no replayed login burst), so they are recorded for ground-truth
completeness but need no code/sidecar change.

---

## 6. Startup / sidecar requests

Request set identical to 2.1.183 (no new endpoints, none removed) — eval_sdk
(GrowthBook) · grove · bootstrap · penguin · mcp-registry · mcp_servers ·
releases/latest · code_triggers · event_logging · datadog.

- **`POST /api/eval/sdk-<id>`** — UA `Bun/1.4.0` (unchanged). Beta
  `oauth-2025-04-20`. Body attributes `appVersion:2.1.191`,
  `subscriptionType:max`, `rateLimitTier:default_claude_max_20x`.
- **`GET /api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8`** — UA
  `claude-code/2.1.191`, beta `oauth-2025-04-20`. Response body **evolved**
  (informational only — we don't synthesize it): now carries
  `client_data:{cedar_lagoon,cedar_basin}`, `model_access:null`,
  `auto_compact_windows:null`, and `cwk_cfg_key:null` (was `"marigold"` @ 2.1.170).
  `additional_model_options[0]` still lists Fable with a `disabled_reason`.
- **`GET /v1/code/triggers`** — beta `ccr-triggers-2026-01-30`, header
  `anthropic-client-platform: claude_code_cli`, `{"data":[],"has_more":false}`.
  Unchanged.
- mcp-registry / mcp_servers / releases — UA `axios/1.15.2` / `claude-cli`,
  unchanged.

---

## 7. host profile

The machine-identifying axes (`linux_distro_id`, `linux_kernel`, `terminal`,
`shell`) are NOT pinned constants — they come from the per-account
`auth.HostProfile` pool (`auth/hostprofile.go`). The capture host's
`arch`/`7.0.12-arch1-1`/`konsole`/`zsh` is one sample, not a constant to bump.
The runtime axes (`node_version`, `is_running_with_bun`, the `Bun/<ver>` UA) DO
move with the release — node bumped to v26.3.0 here (Bun stays 1.4.0).

---

## Edit checklist (cc-core only — no vendored copies remain)

| # | where | change |
|---|---|---|
| 1 | `mimicry.CLICurrentVersion` | `2.1.183` → `2.1.191` (cascades into all `claude-code/<ver>` + `claude-cli/<ver>` UAs) |
| 2 | `mimicry.ClaudeCLIUserAgent` | `claude-cli/2.1.191 (external, cli)` |
| 3 | `mimicry.ClaudeStainlessRuntimeV` | **`v24.3.0` → `v26.3.0`** (feeds the X-Stainless-Runtime-Version header AND telemetry `env.node_version`) |
| 4 | `mimicry.ClaudeAnthropicBetaFull` | **NO CHANGE** — 13-item list byte-identical (§1) |
| 5 | `mimicry.ClaudeReportedBetas` | **NO CHANGE** — 9-item incl. `context-1m` (§3) |
| 6 | `mimicry.ClaudeAnthropicBetaApikey` | no 2.1.191 api-key capture — left verbatim |
| 7 | body/mimicry: system layout + cch | unchanged (§2) — already correct |
| 8 | `sidecar.ccBuildTime` | `2026-06-18T23:04:10Z` → `2026-06-24T11:24:03Z` |
| 9 | `sidecar.ccTelemetryModel` | `claude-opus-4-8[1m]` — **unchanged** |
| 10 | `sidecar.ccDatadogModel` | `claude-opus-4-8` — **unchanged** |
| 11 | sidecar bootstrap `model=` param | `claude-opus-4-8` — **unchanged** |
| 12 | `sidecar.uaBun` / `sidecar.uaAxios` | `Bun/1.4.0` / `axios/1.15.2` — **unchanged** |
| 13 | `auth/oauth.go` token URL | `platform.claude.com/v1/oauth/token` — **already correct** (§5) |
| 14 | host profile (`auth/hostprofile.go`) | kernel/distro/terminal/shell pool-driven; comment node bumped to v26.3.0 |
| 15 | comments | `2.1.183` → `2.1.191`; `crack/cc2183/SPEC.md` → `crack/cc2191/SPEC.md` |
