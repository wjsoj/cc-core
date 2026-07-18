# Claude Code 2.1.211 — fingerprint ground truth

Captured 2026-07-18 from a live `claude-cli/2.1.211` OAuth session (whistle
`get-data`, full-body, 100-entry buffer). `rows/` are structurally-redacted via
`crack/scripts/extract_live.py`. Supersedes `cc2206`.

The buffer held only the **runtime tail** (24 `/v1/messages` + 24
`event_logging` + 30 datadog frames); the OAuth login flow and the startup
bootstrap burst had already rolled out of whistle's 100-entry window, so those
rows still live in `cc2191/` (login) and `cc2206`/`oauth/` (bootstrap) — none of
which carry a CC version number, so nothing there moves for 2.1.211.

**The 2.1.206 → 2.1.211 diff has one wire-visible change: the request-header
`anthropic-beta` list was rewritten (15 → 14 items).** The version string and
telemetry `build_time` also move (as every release does). Everything else on the
wire — body layout, billing-block fp algorithm, stainless headers, telemetry
betas, sidecar UAs, axios/Bun versions — is byte-identical.

Client env (from `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.211                (was 2.1.206)
build_time             = 2026-07-15T16:34:37Z   (was 2026-07-09T01:39:20Z @ 2.1.206)
node_version           = v26.3.0                (UNCHANGED)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED, x-stainless-package-version)
bun / axios            = Bun/1.4.0 / axios/1.15.2 (UNCHANGED)
```

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header set/order identical to 2.1.206 except UA and the beta list. `user-agent`
bumped to `claude-cli/2.1.211 (external, cli)`. `x-stainless-runtime-version:
v26.3.0`, `x-stainless-package-version: 0.94.0` — both unchanged. Full stainless
set unchanged (`X-Stainless-Arch: x64`, `-Lang: js`, `-OS: Linux`, `-Runtime:
node`, `-Timeout: 600`, `-Retry-Count: 0`).

**`anthropic-beta` rewritten 15 → 14 items.** vs 2.1.206:

- **ADDS** `context-1m-2025-08-07` (at position 3, right after `oauth-2025-04-20`)
- **DROPS** `server-side-fallback-2026-06-01` and `fallback-credit-2026-06-01`
  (the two betas 2.1.206 had just added)

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

**All 24** full `/v1/messages` requests in the capture carried this **exact**
14-item list — zero variation, one UA (`claude-cli/2.1.211 (external, cli)`).
The session ran WITH 1M context (telemetry model `claude-opus-4-8[1m]`, §3), and
unlike 2.1.206 the request header now **does** carry `context-1m` under 1M. Since
real 2.1.211 no longer sends the two fallback betas, keeping them would now be
the fingerprint MISMATCH — `ClaudeAnthropicBetaFull` is set to this 14-item list
verbatim.

Body layout UNCHANGED (4-block system: `[0]` billing header, `[1]` CC prompt,
`[2]` cache_control `{ephemeral, ttl:1h, scope:global}`, `[3]` cache_control
`{ephemeral, ttl:1h}`; `thinking:{adaptive}`, `context_management.edits[0] =
clear_thinking_20251015`, `output_config.effort`, `metadata.user_id` shape).

**Billing block `cc_version=2.1.211.3c8`** — fp algorithm UNCHANGED and
re-validated against this capture: `sha256(salt "59cf53e54c78" + chars@[4,7,20]
of the first non-meta user text + "2.1.211")[:3]` reproduces `3c8` byte-for-byte
(all 24 frames share `3c8` — the fp is per-conversation, keyed on the constant
first user message, not per-request). The `cch=` field is still a per-request
`xxhash64(body, seed 0x6E52736AC806831E)[:5]` — 24 distinct values across the 24
frames, confirming it is a body hash, not version-derived. Real CC also appends
`cc_prev_req=req_…;` (prior upstream response id, session-chained); cc-core does
not synthesize this — unchanged, out of scope, and only relevant to non-CC OAuth
clients (real CC passthrough keeps its own billing block).

## 2. Bootstrap burst + OAuth login flow — NOT in this capture, UNCHANGED

The login/token-exchange flow (`anthropicClientID
9d1c250a-e61b-44d9-88ed-5944d1962f5e`, `axios/1.15.2` UA, PKCE param order) and
the startup bootstrap burst carry **no CC version number**, so 2.1.211 moves
nothing there. Baselines remain `cc2191/` (login) and `oauth/` (bootstrap).

## 3. Telemetry — `event_logging` + datadog

- `event_logging/v2/batch` UA `claude-code/2.1.211`; `event_data.betas` =
  the **9-item** `ClaudeReportedBetas` list, **RE-CONFIRMED identical** to
  2.1.156→2.1.206 (`…,mid-conversation-system-2026-04-07`, stops there; keeps
  `context-1m`), paired with model `claude-opus-4-8[1m]`.
- datadog `/api/v2/logs` UA `axios/1.15.2`, key
  `pubea5604404508cdd34afb69e6f42a05bc` (unchanged, public constant), `betas` =
  same 9-item list, `version`/`version_base` = `2.1.211`, `build_time` =
  `2026-07-15T16:34:37Z`, `node_version v26.3.0`, `deployment_environment
  unknown-linux`. Machine axes (`linux_kernel`, `linux_distro_id`, `terminal`,
  `shell`) stay per-account synthetic via `auth.HostProfile` — NOT copied from
  the capture host.

---

## cc-core edit checklist (done in this bump)

- `mimicry/fingerprint.go`: `CLICurrentVersion` + `ClaudeCLIUserAgent` →
  `2.1.211`; `ClaudeAnthropicBetaFull` → the 14-item list above.
  `ClaudeReportedBetas`, `ClaudeStainlessPackageV` (0.94.0),
  `ClaudeStainlessRuntimeV` (v26.3.0) UNCHANGED.
- `sidecar/sidecar.go`: `ccBuildTime` → `2026-07-15T16:34:37Z`. Everything else
  (uaClaudeCode/version/version_base) auto-tracks `mimicry.CLICurrentVersion`.
- No change to `mimicry/body.go` (fp algorithm + salt + cchSeed re-validated),
  `auth/oauth.go` (axios UA + client_id unchanged), or any test (all reference
  `CLICurrentVersion` symbolically).
