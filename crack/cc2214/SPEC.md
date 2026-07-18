# Claude Code 2.1.214 — fingerprint ground truth

Captured 2026-07-18 from a live `claude-cli/2.1.214` session that included a full
**OAuth re-login + startup bootstrap burst + chat** (whistle `get-data`,
full-body). `rows/` are structurally-redacted via `crack/scripts/extract_live.py`
— **18 rows**, the most complete Claude capture since `cc2191` (login-flow and
bootstrap rows are back in-window because the re-login happened right before the
pull). Supersedes `cc2211`.

**2.1.211 → 2.1.214 is a pure version + `build_time` bump on the wire.** The
request-header betas, telemetry betas, stainless versions, body layout, and the
billing-block fp algorithm are all byte-identical. The one *extra* deliverable
here is a correction: three bootstrap-sidecar User-Agents that cc-core had wrong
since 2.1.191 (see §2), now verified against two independent captures.

Client env (from `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.214                (was 2.1.211)
build_time             = 2026-07-17T23:24:50Z   (was 2026-07-15T16:34:37Z @ 2.1.211)
node_version           = v26.3.0                (UNCHANGED)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED, x-stainless-package-version)
bun / axios            = Bun/1.4.0 / axios/1.15.2 (UNCHANGED)
```

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

UA `claude-cli/2.1.214 (external, cli)`. Full stainless set unchanged (`0.94.0` /
`v26.3.0` / Linux / x64 / timeout 600 / retry 0).

**`anthropic-beta` UNCHANGED from 2.1.211** — the same 14-item list, verified
byte-for-byte on all 3 full chat frames in the capture:

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

Body layout UNCHANGED (4-block system, cache_control `{ephemeral,ttl:1h,
scope:global}` on `[2]` / `{ephemeral,ttl:1h}` on `[3]`, `thinking:{adaptive}`,
`context_management.clear_thinking_20251015`, `output_config.effort`).

**Billing block `cc_version=2.1.214.17e`** — fp algorithm UNCHANGED and
re-validated: `sha256("59cf53e54c78" + chars@[4,7,20] of the first non-meta user
text + "2.1.214")[:3]` reproduces `17e` byte-for-byte on the opus chat frame. The
Haiku quota-probe frames correctly carry NO billing block (body mimicry skipped
for Haiku). `cch=` still a per-request `xxhash64(body)[:5]`.

## 2. Bootstrap burst + OAuth login flow — UA CORRECTIONS

This capture finally re-anchors the bootstrap/login UAs (last seen in cc2191).
Endpoint → UA, verified against the live traffic:

```
POST /api/eval/sdk-zAZezfDKGoZuXXKe       Bun/1.4.0
GET  /api/oauth/account/settings          claude-cli/2.1.214 (external, cli)   ← NOT claude-code
GET  /api/claude_code_grove               claude-cli/2.1.214 (external, cli)   ← NOT claude-code
GET  /api/claude_cli/bootstrap            claude-code/2.1.214
GET  /api/claude_code_penguin_mode        axios/1.15.2
GET  /mcp-registry/v0/servers             claude-cli/2.1.214 (external, cli)   ← NOT axios  (8 samples)
GET  /v1/mcp_servers                      axios/1.15.2
GET  /v1/code/triggers                    claude-cli/2.1.214 (external, cli)
GET  downloads.claude.ai/.../latest       axios/1.15.2
```

**cc-core bug fixed here:** `oauth_account_settings` and `claude_code_grove` were
sending `claude-code/<ver>`, and `mcp_registry` was sending `axios/1.15.2`. All
three should be the main `claude-cli` UA — and they were ALSO `claude-cli` in the
2.1.191 baseline (`cc2191/rows/{05,08,11}`), so cc-core shipped these wrong from
the start; the `grove` code comment claiming a "2.1.141 switch to claude-code"
was incorrect. Fixed in `sidecar.realBootstrapSteps` + `sidecar_test.go`.

**OAuth login flow — already correct, re-confirmed.** `auth/login_probes.go` +
`auth/oauth.go` match the capture exactly:

```
GET  platform.claude.com/v1/oauth/hello   claude-cli   (pre-probe)
GET  api.anthropic.com/api/hello          claude-cli   (pre-probe)
POST platform.claude.com/v1/oauth/token   axios/1.15.2 (token exchange)
GET  api/oauth/profile                    axios/1.15.2 (post-probe)
GET  api/oauth/claude_cli/roles           axios/1.15.2 (post-probe)
GET  api/oauth/account/settings           claude-cli   (post-probe, +oauth beta)
POST platform.claude.com/v1/oauth/token/revoke  axios/1.15.2  (logout of prior session)
```

Token-exchange body param order verified verbatim: `grant_type, code,
redirect_uri, client_id, code_verifier, state` — exactly the struct order in
`finishAnthropicLogin`. `client_id = 9d1c250a-e61b-44d9-88ed-5944d1962f5e`
(public constant, kept). `token/revoke` is the logout of the previous session on
re-login; cc-core does not emit it (login-only, not proxied traffic) — out of
scope.

## 3. Telemetry — `event_logging` + datadog

`event_logging/v2/batch` UA `claude-code/2.1.214` (bare, no suffix — the
`claude-code/2.1.214 (cli)` UA seen in the dump is CC's *local MCP client*
calling a localhost MCP server, NOT Anthropic traffic). `event_data.betas` =
the 9-item `ClaudeReportedBetas` list, RE-CONFIRMED identical, paired with model
`claude-opus-4-8[1m]`. datadog `/api/v2/logs` UA `axios/1.15.2`, key
`pubea5604404508cdd34afb69e6f42a05bc`, `version`/`version_base` `2.1.214`,
`build_time 2026-07-17T23:24:50Z`, `node_version v26.3.0`. Machine axes
(`linux_kernel`, `linux_distro_id`, `terminal`, `shell`) stay per-account
synthetic via `auth.HostProfile`.

---

## cc-core edit checklist (done in this bump)

- `mimicry/fingerprint.go`: `CLICurrentVersion` + `ClaudeCLIUserAgent` →
  `2.1.214`. `ClaudeAnthropicBetaFull` (14-item), `ClaudeReportedBetas` (9-item),
  stainless `0.94.0` / `v26.3.0` all UNCHANGED (re-confirmed).
- `sidecar/sidecar.go`: `ccBuildTime` → `2026-07-17T23:24:50Z`; **UA fix** on
  `oauth_account_settings`, `claude_code_grove` (uaClaudeCode → uaClaudeCLI) and
  `mcp_registry` (uaAxios → uaClaudeCLI); UA-groupings comment corrected.
- `sidecar/sidecar_test.go`: bootstrap UA assertions updated for the three fixed
  endpoints (claude-cli).
- No change to `mimicry/body.go` (fp algorithm + salt + cchSeed re-validated),
  `auth/login_probes.go` / `auth/oauth.go` (login flow already matched the
  capture), or the fp/beta constants.
