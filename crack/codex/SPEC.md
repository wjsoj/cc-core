# Codex CLI fingerprint — capture target `codex-tui/0.135.0` (identity bumped to `0.144.4`)

Ground truth captured 2026-05-30 via Whistle from a live `codex` (Rust TUI) session on a
ChatGPT **Pro** subscription. All secrets (Bearer JWT, cookies, account UUID, user id, email,
workspace path, git origin) are redacted in `rows/`. Non-secret fingerprint values are kept verbatim.

## 2026-07-14 — identity bumped `0.144.1` → `0.144.4` + 5h quota window retired

No fresh capture. Two changes, both wire-neutral:

1. **Version bump `0.144.1` → `0.144.4`.** 0.144.4 is the latest stable Codex CLI release
   (`github.com/openai/codex`, released 2026-07-14; 0.144.2/.3/.4 are patch releases with *no
   user-facing changes*, 0.145 is still alpha-only). UA/Version format is byte-identical to
   0.144.1, so the bump is purely `CodexCLIVersion`/`CodexCLIUserAgent` in `mimicry/codex.go`.
   sub2api still pins `0.144.1` (`657c4f97`); 0.144.4 is the same 0.144.x wire, just fresher.

2. **ChatGPT quota-policy change — 5h window retired (weekly-only).** As of the 2026-07 policy
   change the primary 5h rate-limit window (`limit_window_seconds` 18000) was removed; `wham/usage`
   and the `x-codex-*` response headers now typically carry ONLY the weekly window (604800). No
   cc-core code change is required: `Auth.FetchCodexUsage` gating is window-agnostic (earliest
   `reset_at` across whichever `primary_window`/`secondary_window` are non-nil), so a nil 5h slot
   just drops out of the min(); `CaptureCodexRateLimits` mirrors whatever `x-codex-*` headers
   arrive verbatim. Comments in `auth/codex_usage.go` updated to record the retirement. sub2api's
   `Normalize()` classifies windows by `limit_window_seconds` (smaller = 5h) rather than trusting
   the primary/secondary field names — cc-core reaches the same robustness via the nil-safe
   earliest-reset gating instead of an explicit 5h/7d split, since it only *displays* the raw
   windows and gates on limit_reached, never on a per-window threshold.

## 2026-07-10 — identity bumped `0.135.0` → `0.144.1` + gpt-5.6 models

No fresh capture; the version target was advanced to `0.144.1` — the **latest stable Codex
CLI release** per `github.com/openai/codex` (tag `rust-v0.144.1`; 0.145 is alpha-only). Real
0.144.x UAs are byte-identical to the 0.135.0 template modulo the version number and the
OS/terminal segment (which is our synthetic `Arch Linux Rolling Release … Konsole` identity),
e.g. a real UA looks like `codex-tui/0.144.1 (Mac OS 15.5.0; arm64) ghostty/1.3.1 (codex-tui;
0.144.1)`. So the bump is purely `CodexCLIVersion`/`CodexCLIUserAgent` `0.135.0`→`0.144.1` in
`mimicry/codex.go`; the transport, `OpenAI-Beta`, and body shape are unchanged.

The `0.144.1` line exposes the **gpt-5.6-{sol,terra,luna}** family (the three tiers ARE the
variants — no `-high`/`-codex` sub-variant; reasoning effort is a request field). Added to
`auth.CodexModelCatalog` on plus/pro/team (following gpt-5.5's placement, withheld from free)
and to `pricing.builtIn`.

**Pricing is a per-tier ladder, not one shared rate** — verified 2026-07-10 against
OpenRouter's live models API (`openrouter.ai/api/v1/models`), the official per-token standard:

| model | input /1M | output /1M | cache-read /1M | cache-write /1M | equals |
|---|---|---|---|---|---|
| gpt-5.6-sol   | $5.00 | $30.00 | $0.50 | $6.25  | gpt-5.5 (flagship) |
| gpt-5.6-terra | $2.50 | $15.00 | $0.25 | $3.125 | gpt-5.4 (mid) |
| gpt-5.6-luna  | $1.00 | $6.00  | $0.10 | $1.25  | light tier |

cache-write is a clean 1.25× input across all three. (An earlier draft priced all three at the
sol/gpt-5.5 rate — that overcharged terra 2× and luna 5×; corrected here.)

### §5 — `parallel_tool_calls` must be passed through, not forced (gpt-5.6 Responses-Lite)

The gpt-5.6 line runs the backend's **Responses-Lite** mode (`X-OpenAI-Internal-Codex-Responses-Lite`,
set by the OpenAI edge for this model family). That mode HARD-rejects any request whose
`parallel_tool_calls` is not `false`:

```
invalid_request_error: X-OpenAI-Internal-Codex-Responses-Lite requires `parallel_tool_calls` to be false.
```

Real `codex-tui` 0.144.1 sends `parallel_tool_calls: false` for gpt-5.6. cc-core's
`SanitizeCodexRequestBody` used to hard-code `parallel_tool_calls = true` on the `/responses`
path (and the `/compact` whitelist dropped the field entirely), which clobbered that `false` and
triggered the error. **Fix: pass the client's value through verbatim** on both paths — matching
sub2api (origin/main `ad8afc8a` "Add parallel_tool_calls compatibility mapping" preserves the
client value through Chat-Completions↔Responses conversion instead of forcing a default). The
`/compact` whitelist was also widened from 4 → 8 fields (adds `tools`, `parallel_tool_calls`,
`reasoning`, `text`) to mirror sub2api's current `normalizeOpenAICompactRequestBody`.

sub2api confirms the 0.144.1 target too: `657c4f97` "升级 Codex 客户端版本至 0.144.1，修复
gpt-5.6-luna 404".

**Second Responses-Lite constraint — `tools`.** Lite also 400s on server built-in tools:

```
invalid_request_error: X-OpenAI-Internal-Codex-Responses-Lite only supports function tools,
custom tools, and client-executed tool search.
```

cc-core's `ensureImageGenerationTool` blanket-injects an `image_generation` built-in on every
non-spark model — that trips this on gpt-5.6. Fix: skip the injection for the gpt-5.6 family
(predicate `codexResponsesLiteModel`), passing the client's tools through untouched — same as
sub2api, which never injects `image_generation` into outbound Codex requests (it gates image gen
via a separate group permission, not a forced tool). Older models keep the injection.

---



## Original 0.135.0 capture

## TL;DR — what changed vs the code's current target (`codex_cli_rs/0.125.0`)

| Field | Old (in code) | **New (this capture)** |
|---|---|---|
| client / `originator` | `codex_cli_rs` | **`codex-tui`** |
| `User-Agent` | `codex_cli_rs/0.125.0` | **`codex-tui/0.135.0 (Arch Linux Rolling Release; x86_64) Konsole/260401 (codex-tui; 0.135.0)`** |
| `version` header | `0.125.0` | **`0.135.0`** |
| transport | HTTP POST + SSE | **WebSocket** (`wss://chatgpt.com/backend-api/codex/responses`) |
| `OpenAI-Beta` | `responses=experimental` | **`responses_websockets=2026-02-06`** (WS handshake) |
| default model | — | **`gpt-5.5`**, reasoning_effort `high`, service_tier `default` |
| extra headers | — | `x-codex-beta-features`, `x-codex-turn-metadata`, `x-codex-window-id`, `session-id`, `thread-id`, `x-client-request-id` |

> **Transport note:** 0.135.0 streams the turn over a **WebSocket**, not HTTP POST/SSE. The
> WS frames carrying the Responses payload were **not** captured (Whistle did not record frame
> bodies for this session). The legacy HTTP `POST /backend-api/codex/responses` with
> `OpenAI-Beta: responses=experimental` is what every codex2api proxy (and our existing code)
> uses and is still accepted by the backend; this capture updates the *headers/identity* but the
> request-body shape for HTTP POST is unchanged from the Responses API contract.

## OAuth (unchanged, confirmed)

- token endpoint: `https://auth.openai.com/oauth/token`
- client_id: `app_EMoamEEZ73f0CkXaXp7hrann`  ← confirmed in JWT `client_id`
- id_token claims under `https://api.openai.com/auth`:
  `chatgpt_account_id`, `chatgpt_account_user_id`, `chatgpt_plan_type` (here `pro`),
  `chatgpt_user_id`, `chatgpt_compute_residency`. `aud: ["https://api.openai.com/v1"]`,
  `iss: https://auth.openai.com`, scopes include `offline_access`.
- (The OAuth PKCE login round-trip was outside the capture buffer; not re-captured here.)

## `/backend-api/codex/responses` — WS handshake headers (`rows/01`)

Request (header casing/order preserved from capture):
```
Host: chatgpt.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
chatgpt-account-id: <account_uuid>
authorization: Bearer <id-or-access token>
user-agent: codex-tui/0.135.0 (Arch Linux Rolling Release; x86_64) Konsole/260401 (codex-tui; 0.135.0)
originator: codex-tui
openai-beta: responses_websockets=2026-02-06
version: 0.135.0
x-codex-beta-features: terminal_resize_reflow
x-codex-turn-metadata: {"session_id","thread_id","thread_source":"user","turn_id":"","workspaces":{<cwd>:{associated_remote_urls,latest_git_commit_hash,has_changes}},"sandbox":"seccomp","request_kind":"prewarm","window_id":"<session>:0"}
x-client-request-id: <session uuidv7>
session-id: <session uuidv7>
thread-id: <session uuidv7>   (== session-id for a new thread)
x-codex-window-id: <session uuidv7>:0
```
- `session-id`/`thread-id`/`x-client-request-id`/`x-codex-window-id` are all derived from one
  **UUIDv7** generated per CLI session (`019e7740-…` form). For a brand-new thread, thread-id == session-id.
- response: `101 Switching Protocols`, `sec-websocket-extensions: permessage-deflate`,
  plus `x-models-etag`, `x-openai-proxy-wasm: v0.1` (OpenAI's edge marker).

## `GET /backend-api/wham/usage` — usage/rate-limit (`rows/02`)

The CLI calls this with **only** `authorization: Bearer`, `chatgpt-account-id`, `cookie`, the
codex-tui `user-agent`, `accept: */*`. **No** `oai-client-version` / `oai-client-build-number` /
`x-openai-target-*` headers (those belong to the *web portal* variant, which is what the
user-supplied browser curl shows — do not mimic the web headers from the CLI path).

Response 200 JSON shape:
```jsonc
{
  "user_id","account_id","email","plan_type":"pro",
  "rate_limit": {
    "allowed":true,"limit_reached":false,
    "primary_window":  {"used_percent",  "limit_window_seconds":18000, "reset_after_seconds", "reset_at"},
    "secondary_window":{"used_percent",  "limit_window_seconds":604800,"reset_after_seconds", "reset_at"}
  },
  "code_review_rate_limit": null,
  "additional_rate_limits": [ {"limit_name":"GPT-5.3-Codex-Spark","metered_feature":"codex_bengalfox","rate_limit":{…same window shape…}} ],
  "credits": {"has_credits","unlimited","overage_limit_reached","balance","approx_local_messages":[n,n],"approx_cloud_messages":[n,n]},
  "spend_control": {"reached","individual_limit"},
  "rate_limit_reached_type": null,
  "promo": null, "referral_beacon": null,
  "rate_limit_reset_credits": {"available_count":0}
}
```
New vs cc-core's current `CodexUsageInfo`: `additional_rate_limits[]`, `code_review_rate_limit`,
`rate_limit_reset_credits`, `promo`, `referral_beacon`, `spend_control.individual_limit`.

## `POST /backend-api/codex/analytics-events/events` — telemetry (`rows/03`)

`{"events":[{"event_type":"codex_turn_event","event_params":{…}}]}`. Notable params:
`app_server_client:{product_client_id:"codex-tui",client_name:"codex-tui",client_version:"0.135.0",rpc_transport:"in_process",experimental_api_enabled:true}`,
`runtime:{codex_rs_version:"0.135.0",runtime_os:"linux",runtime_os_version:"Rolling Release",runtime_arch:"x86_64"}`,
`model:"gpt-5.5"`, `model_provider:"openai"`, `reasoning_effort:"high"`, `service_tier:"default"`,
`approval_policy:"on-request"`, `sandbox_policy:"workspace_write"`, `personality:"pragmatic"`,
plus token counters (`input_tokens`,`cached_input_tokens`,`output_tokens`,`reasoning_output_tokens`,`total_tokens`).

## Other CLI background traffic (not needed for proxy parity)

- `POST /backend-api/wham/apps` — MCP-style `{"jsonrpc":"2.0","method":"notifications/initialized"}` (`rows/04`).
- `GET /backend-api/ps/plugins/installed?scope=GLOBAL|WORKSPACE[&includeDownloadUrls=true]` (`rows/05`).
- `POST https://ab.chatgpt.com/otlp/v1/metrics` — OTLP metrics.

## Models seen

`gpt-5.5` (default this session), `gpt-5.3-codex-spark` (metered feature `codex_bengalfox`).
Matches cc-core `CodexModelCatalog` Pro tier. No new model names beyond the catalog.
