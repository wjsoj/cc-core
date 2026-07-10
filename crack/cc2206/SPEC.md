# Claude Code 2.1.206 — fingerprint ground truth

Captured 2026-07-10 from a live `claude-cli/2.1.206` OAuth session (whistle
`get-data`, full-body, 100-entry buffer). `rows/` are structurally-redacted via
`crack/scripts/extract_live.py`. Supersedes `cc2201`.

**The 2.1.201 → 2.1.206 diff has one wire-visible change: two new betas on the
request header.** The version string and telemetry `build_time` also move (as
every release does). Everything else on the wire is byte-identical.

Client env (from `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.206                (was 2.1.201)
build_time             = 2026-07-09T01:39:20Z   (was 2026-07-03T19:53:38Z @ 2.1.201)
node_version           = v26.3.0                (UNCHANGED)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED, x-stainless-package-version)
bun / axios            = Bun/1.4.0 / axios/1.15.2 (UNCHANGED)
```

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header set/order identical to 2.1.201 except UA and the beta list. `user-agent`
bumped to `claude-cli/2.1.206 (external, cli)`. `x-stainless-runtime-version:
v26.3.0`, `x-stainless-package-version: 0.94.0` — both unchanged.

**`anthropic-beta` grows 13 → 15 items** — two new betas
(`server-side-fallback-2026-06-01`, `fallback-credit-2026-06-01`) inserted
between `effort-2025-11-24` and `extended-cache-ttl-2025-04-11`:

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,server-side-fallback-2026-06-01,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

All 6 full `/v1/messages` chat requests in the capture carried this exact
15-item list. **Still NO `context-1m-2025-08-07` on the request header** even
though this session ran WITH 1M context (telemetry model = `claude-opus-4-8[1m]`,
see §3) — confirming context-1m stays telemetry-only on the wire header, so the
15-item list is the correct synthetic default (`ClaudeAnthropicBetaFull`).

The Haiku **quota probe** (`content-length: 323`, first request) carries its own
6-item list, unchanged and still matching `sidecar.quotaProbeBeta`:
`oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05`.

Body layout UNCHANGED (4-block system, cache_control scope:global on the
second-to-last block, `thinking:{adaptive}`, `metadata.user_id` shape). billing
header `cc_version=2.1.206.<fp>` — fp algorithm unchanged (version is an input;
see cc2197/SPEC.md §5a for the extracted `xtf`/`awo`).

## 2. Bootstrap burst + sidecar endpoints — UNCHANGED

`bootstrap`, `penguin_mode`, `mcp-registry`, `v1/mcp_servers`, `code/triggers`,
`eval/sdk`, `releases` all present with unchanged UAs / headers. The version in
the UA is driven by the single `CLICurrentVersion` constant. The OAuth login /
grove rows had already rolled out of whistle's 100-entry buffer by capture time
(same as cc2201), so they aren't re-serialized here.

## 3. Telemetry — build_time moves; 1M pairing RE-CONFIRMED

`event_logging` + datadog env carry `version=2.1.206`,
`build_time=2026-07-09T01:39:20Z`, `node_version=v26.3.0`.

**This capture's session ran WITH 1M context**, so telemetry directly
re-confirms the `[1m]` pairing that cc2201 could not (its session ran without
1M). The `claude-opus-4-8[1m]` event carries the exact **9-item** `betas` list
cc-core pins as `ClaudeReportedBetas`:

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07
```

(`claude-fable-5` events in the same batch carry the shorter 8-item / longer
15-item variants — config/model-dependent, consistent with prior notes.) Our
sidecar keeps emitting the `[1m]` + 9-item pair (event_logging
event_data.model) and the plain `claude-opus-4-8` datadog model — unchanged.

## 4. Still-open items (carried from cc2197/cc2201)

- **cch 5-hex billing signature** — still unresolved (bytecode signer,
  Bun-version-dependent wyhash). Unchanged. See cc2197/SPEC.md §5b.
- **dateline steganography beacon** — `mimicry.NormalizeDateline` still erases it
  (logic unchanged in 2.1.206). See cc2197/SPEC.md §6.

## Edit checklist (applied to cc-core this round)

- [x] `mimicry/fingerprint.go` — `CLICurrentVersion`/`ClaudeCLIUserAgent`
      2.1.201→2.1.206; `ClaudeAnthropicBetaFull` 13→15 items (+server-side-fallback,
      +fallback-credit); `ClaudeReportedBetas` unchanged (re-confirmed by capture);
      comment refs → 2.1.206.
- [x] `sidecar/sidecar.go` — `ccBuildTime` → `2026-07-09T01:39:20Z`; version refs.
- [x] `go test ./...` green.
- [ ] Tag cc-core release + bump dep in hypitoken **and** CPA-Claude.
