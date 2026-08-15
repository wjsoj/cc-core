# Claude Code 2.1.224 — OAuth fingerprint ground truth

Captured 2026-08-07 from real `claude-cli/2.1.224` OAuth traffic on Arch Linux, through Whistle on `127.0.0.1:8899` (HTTPS interception via the Whistle CA through `NODE_EXTRA_CA_CERTS`; TLS verification was never disabled). 93 sessions covering the **complete chain from a fresh OAuth login through startup bootstrap to steady-state conversation traffic** — the first capture in this archive that includes the login leg end to end.

The controlled model was `claude-opus-5`, running **in 1M-context mode for the whole session**. That is the user's model/context setting and is not evidence of a version-driven default change. It is also the source of this capture's one significant gap — see §Unresolved.

## Verdict: a version-string-only bump

Every structural fingerprint cc-core reproduces is **byte-identical to 2.1.220**. The only values that moved are the ones that move with any release: the version string, the build timestamp, and the model the client happens to report.

| axis | 2.1.220 | 2.1.224 | cc-core action |
|---|---|---|---|
| `CLICurrentVersion` / `ClaudeCLIUserAgent` | `2.1.220` | **`2.1.224`** | updated |
| telemetry `build_time` (`ccBuildTime`) | `2026-07-24T22:17:45Z` | **`2026-08-06T01:05:53Z`** | updated |
| reported model (`ccTelemetryModel` / `ccDatadogModel`) | `claude-opus-4-8[1m]` / `claude-opus-4-8` | **`claude-opus-5[1m]` / `claude-opus-5`** | updated |
| Stainless lang/runtime/pkg/arch | js / node v26.3.0 / 0.94.0 / x64 | identical | none |
| `ClaudeAnthropicBeta1M` (15 items) | — | identical, item for item | none (now 2-version verified) |
| `ClaudeReportedBetas` (9 items) | — | identical, verbatim | none (now 3-version verified) |
| request body top-level key set | `context_management, max_tokens, messages, metadata, model, output_config, stream, system, thinking, tools` | identical | none |
| 4-block `system` layout | billing → CC prompt → 2 cached blocks | identical | none |
| `cache_control` | `{ephemeral, ttl:1h, scope:global}` + `{ephemeral, ttl:1h}` | identical | none |
| billing block format | `cc_version=X.Y.Z.{3-hex}; cc_entrypoint=cli; cch={5-hex}; cc_prev_req=req_…` | identical | none |
| sidecar 10-step burst (URLs, order, per-step UA + beta) | — | identical | none |
| `quotaProbeBeta` (6 items) / `quotaProbeModel` | cited a pruned 2.1.170 file | **captured verbatim**, `rows/19-quota_probe.json` | none (now anchored at the current target) |

## Client environment

```
version / version_base = 2.1.224
build_time             = 2026-08-06T01:05:53Z
node_version           = v26.3.0
SDK package            = 0.94.0
axios                  = 1.15.2
X-Stainless OS/arch    = Linux / x64
```

`Linux` here is a capture-host property. `ClaudeStainlessOS` is pinned to `Linux` for independent reasons (it must agree with `auth.HostProfile` and the sidecar telemetry platform fields) — this capture agreeing with it is a coincidence, not a new constraint. Do not start tracking the capture host.

## 1. Main `/v1/messages?beta=true`

Headers on the controlled main requests (`rows/13-v1_messages.json`):

```
User-Agent: claude-cli/2.1.224 (external, cli)
Accept: application/json
Content-Type: application/json
Accept-Encoding: gzip, br
Anthropic-Version: 2023-06-01
Anthropic-Dangerous-Direct-Browser-Access: true
X-App: cli
X-Stainless-Lang: js
X-Stainless-Package-Version: 0.94.0
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v26.3.0
X-Stainless-OS: Linux
X-Stainless-Arch: x64
X-Stainless-Timeout: 600
X-Stainless-Retry-Count: 0
```

Request `Anthropic-Beta`, 1M mode active — **byte-identical to `ClaudeAnthropicBeta1M` (15 items)**, including `context-1m-2025-08-07` at position 3 and `fallback-credit-2026-06-01` between `effort` and `extended-cache-ttl`:

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

This promotes `ClaudeAnthropicBeta1M` from a single 2.1.220 sample to two independent captures across two versions.

## 2. Request body

Top-level keys, in the order emitted:

```
model, max_tokens, messages, system, tools, metadata, stream, thinking, context_management, output_config
```

Unchanged from the 2.1.220 Linux capture (`claudev2.1.220/rows-2026-07-31/08-v1_messages.json`), including:

```json
"thinking":            {"type": "adaptive"},
"context_management":  {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
"metadata":            {"user_id": "<opaque>"},
"max_tokens":          64000
```

The `system` array is the same 4-block layout cc-core rebuilds:

1. `x-anthropic-billing-header: cc_version=2.1.224.779; cc_entrypoint=cli; cch=1dc46; cc_prev_req=req_…;`
2. `You are Claude Code, Anthropic's official CLI for Claude.`
3. cached block, `cache_control: {type: ephemeral, ttl: "1h", scope: "global"}`
4. cached block, `cache_control: {type: ephemeral, ttl: "1h"}`

The build tag in the billing block is still 3 hex (`2.1.224.779`, cf. `2.1.220.b7d`) and `cch` is still 5 hex. The multi-turn `cc_prev_req=req_…` chain is present and unchanged in form.

## 3. Telemetry (`event_logging/v2/batch`, datadog)

`env.version_base = 2.1.224`, `env.build_time = 2026-08-06T01:05:53Z`, `env.node_version = v26.3.0`.

Three distinct `betas` strings appear across the batch, exactly as at 2.1.220:

- **9 items** — `ClaudeReportedBetas`, verbatim, paired with `claude-opus-5[1m]`. This is what the sidecar emits and it is unchanged.
- 8 items — the same list minus `oauth-2025-04-20`, the non-1M telemetry variant.
- 15 items — the full request-header list echoed on some events.

Datadog reports the model without the `[1m]` suffix (`claude-opus-5`), matching `ccDatadogModel`.

## 4. Login chain (new in this archive)

`rows/01`–`rows/06` capture the leg no previous dump held end to end:

| # | request | UA | notes |
|---|---|---|---|
| 01 | `GET platform.claude.com/v1/oauth/hello` | `claude-cli/2.1.224` | reachability ping, `{"message":"hello"}` |
| 02 | `POST platform.claude.com/v1/oauth/token` | `axios/1.15.2` | PKCE `authorization_code`; params `grant_type, code, redirect_uri, client_id, code_verifier, state`; loopback `redirect_uri` on an ephemeral port; response carries `token_type, access_token, expires_in: 28800, refresh_token, scope, token_uuid, refresh_token_expires_in` |
| 03 | `GET api.anthropic.com/api/oauth/profile` | `axios/1.15.2` | `account{uuid, full_name, display_name, email, has_claude_max, has_claude_pro, created_at}` + `organization{…}` |
| 04 | `GET api.anthropic.com/api/oauth/claude_cli/roles` | `axios/1.15.2` | `organization_uuid/name/role`, `workspace_*` (null for a non-workspace account) |
| 05 | `GET api.anthropic.com/api/oauth/account/settings` | `claude-cli/2.1.224` | `Anthropic-Beta: oauth-2025-04-20` |
| 06 | `GET api.anthropic.com/api/hello` | `claude-cli/2.1.224` | no beta |

The granted `scope` is `user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code`, and the public client_id is the documented constant `9d1c250a-e61b-44d9-88ed-5944d1962f5e`. All of this matches what `auth/login.go` + `auth/login_probes.go` already implement; no change was required.

## 5. Startup burst — sidecar cross-check

Observed order and per-step identity, which `sidecar/sidecar.go` reproduces exactly:

| step | endpoint | UA | beta |
|---|---|---|---|
| growthbook_eval | `POST /api/eval/sdk-…` | `Bun/1.4.0` | `oauth-2025-04-20` |
| oauth_account_settings | `GET /api/oauth/account/settings` | `claude-cli/2.1.224` | `oauth-2025-04-20` |
| claude_code_grove | `GET /api/claude_code_grove` | `claude-cli/2.1.224` | `oauth-2025-04-20` |
| quota_probe | `POST /v1/messages` | `claude-cli/2.1.224` | `oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05` (`rows/19`) |
| claude_cli_bootstrap | `GET /api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-5` | `claude-code/2.1.224` | `oauth-2025-04-20` |
| claude_code_penguin_mode | `GET /api/claude_code_penguin_mode` | `axios/1.15.2` | `oauth-2025-04-20` |
| mcp_registry | `GET /mcp-registry/v0/servers?…` | `claude-cli/2.1.224` | — |
| v1_mcp_servers | `GET /v1/mcp_servers?limit=1000` | `axios/1.15.2` | `mcp-servers-2025-12-04` |
| code_triggers | `GET /v1/code/triggers` | `claude-cli/2.1.224` | `ccr-triggers-2026-01-30` |
| claude_code_releases | `GET downloads.claude.ai/claude-code-releases/latest` | `axios/1.15.2` | — |

The three-way UA split (`claude-cli` / `claude-code` / `axios`, plus `Bun` for GrowthBook) is unchanged.

Two sidecar edits **were** needed and were missed when this file was first written:

- The bootstrap `model=` parameter tracks the model the client is starting with —
  `claude-opus-5` here, matching the telemetry model in §3. `sidecar.go` had it
  hardcoded to the 2.1.220-era `claude-opus-4-8`, so a single simulated process
  announced `opus-4-8` at bootstrap and `opus-5` in its telemetry.
- `quotaProbeBeta` / `quotaProbeModel` are now captured verbatim
  (`rows/19-quota_probe.json`) instead of citing a pruned 2.1.170 file.

## Unresolved

- **Non-1M main request beta.** The session ran entirely in 1M mode, so `ClaudeAnthropicBetaFull` (the 13-item non-1M list) was **not observed at 2.1.224**. It carries forward from 2.1.220 unverified. Nothing here contradicts it, but a non-1M capture is the way to settle it.
- **`count_tokens`.** No `POST /v1/messages/count_tokens` was fired, so `ClaudeAnthropicBetaCountTokens` (5 items) and the "no `X-Stainless-Timeout`" rule are likewise carried forward unverified at 2.1.224.
- **`cch` signer.** Still unresolved, as at 2.1.220 — the values are captured (`2.1.224.779` / `cch=1dc46`) but the signer is not reproduced.
- **No custom-base-url counterpart in this session.** Captured separately on 2026-08-09 at 2.1.226 — see `../claudev2.1.226-inbound/SPEC.md`, which is the inbound shape both forks receive and repair.
- **Forward signals seen but not acted on.** The bootstrap response carries `client_data.cedar_lagoon = {"claude-fable": true, "claude-mythos": true}` and `cedar_basin: "2026-08-31"`, and `additional_model_options` lists `claude-fable-5[1m]`. `claude-mythos` is an unreleased label; no cc-core constant depends on it yet.

## Redaction

`rows/` was produced by `crack/scripts/extract_live.py`, which keeps fingerprint-bearing structure and replaces prose, code, tool descriptions, identity values, UUIDs, emails, and tokens with `<masked …>` / `<text:N chars>` placeholders. Authorization, cookies, session ids, request ids, and organization ids are masked at the header level. The raw Whistle dump was never committed and lives only under the session scratchpad.
