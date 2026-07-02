# Claude Code 2.1.198 — fingerprint ground truth

Captured 2026-07-02 from a live `claude-cli/2.1.198` OAuth session (whistle
`get-data?ids=…`, full-body). `rows/` are structurally-redacted via
`crack/scripts/extract_live.py`. Supersedes `cc2197`.

**The 2.1.197 → 2.1.198 diff is tiny — a patch release.** Only three things move,
and one of them is a correction to a 2.1.197 over-fit.

Client env (from `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.198                (was 2.1.197)
build_time             = 2026-07-01T06:09:31Z   (was 2026-06-29T19:08:42Z @ 2.1.197)
node_version           = v26.3.0                (UNCHANGED)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED)
bun / axios            = Bun/1.4.0 / axios/1.15.2 (UNCHANGED)
default model (telem)  = claude-opus-4-8[1m]    (UNCHANGED)
```

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header set/order identical to 2.1.197. `user-agent` bumped to
`claude-cli/2.1.198 (external, cli)`.

**`anthropic-beta` DROPPED `context-1m-2025-08-07` → back to 13 items** (identical
to the 2.1.191 list). This corrects the 2.1.197 target: that round added
context-1m from a single 1M-context capture, but it is REQUEST-conditional
(present only when the 1M window is active). All **six** 2.1.198 business
`/v1/messages` requests (3.1 MB each, `claude-code-20250219` present) carried the
13-item list WITHOUT context-1m; only the tiny quota-probe carried its own 6-item
list. So the correct synthetic `ClaudeAnthropicBetaFull` is 13 items:

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

Body layout UNCHANGED (4-block system, cache_control scope:global on the
second-to-last block, `thinking:{adaptive}`, `metadata.user_id` shape, plus the
client-driven `context_management`/`output_config`/`diagnostics` top-level
fields). billing header `cc_version=2.1.198.<fp>` — the fp algorithm is unchanged
(version is an input; see cc2197/SPEC.md §5a for the extracted `xtf`/`awo`).

## 2. Bootstrap burst + sidecar endpoints — UNCHANGED

All UAs/betas/headers byte-identical to 2.1.197 (only the version in the UA
moves): `api/hello`, `oauth/hello`+`oauth/token` (platform.claude.com),
`oauth/profile`, `oauth/claude_cli/roles`, `eval/sdk-…` (Bun/1.4.0,
oauth-2025-04-20), `bootstrap?entrypoint=cli&model=claude-opus-4-8`,
`penguin_mode`, `mcp-registry`, `v1/mcp_servers` (+`anthropic-mcp-client-capabilities:
eyJyb290cyI6e30sImVsaWNpdGF0aW9uIjp7fX0=` +`MCP-Protocol-Version: 2025-11-25`),
`code/triggers` (ccr-triggers-2026-01-30, claude_code_cli). Datadog still active
in real CC; cc-core heartbeat still deliberately disabled.

The full OAuth login flow was verified header-for-header against the live 2.1.198
capture and is **byte-identical to cc2197/rows/01-08** except the version string
in the UAs — the early login rows had already rolled out of whistle's 100-entry
buffer by capture time, so they aren't re-serialized here.

## 3. Telemetry — UNCHANGED

`event_logging` + datadog env carry `version=2.1.198`,
`build_time=2026-07-01T06:09:31Z`, `node_version=v26.3.0`, model
`claude-opus-4-8[1m]`. `betas` (ClaudeReportedBetas) UNCHANGED — the 9-item list
still INCLUDES `context-1m-2025-08-07` (telemetry reports it; the request header
does not — the two are distinct).

## 4. Still-open items (carried from cc2197)

- **cch 5-hex billing signature** — still unresolved (bytecode signer,
  Bun-version-dependent wyhash). Unchanged. See cc2197/SPEC.md §5b.
- **dateline steganography beacon** — `mimicry.NormalizeDateline` still erases it
  (logic unchanged in 2.1.198). See cc2197/SPEC.md §6.

## Edit checklist (applied to cc-core this round)

- [x] `mimicry/fingerprint.go` — `CLICurrentVersion`/`ClaudeCLIUserAgent`
      2.1.197→2.1.198; `ClaudeAnthropicBetaFull` DROP context-1m (14→13 items).
- [x] `sidecar/sidecar.go` — `ccBuildTime` → `2026-07-01T06:09:31Z`; version refs.
- [x] `mimicry/{body,headers}.go` — version comment refs → 2.1.198.
- [ ] Tag cc-core release + bump dep in hypitoken **and** CPA-Claude.
