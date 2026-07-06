# Claude Code 2.1.201 — fingerprint ground truth

Captured 2026-07-06 from a live `claude-cli/2.1.201` OAuth session (whistle
`get-data`, full-body, 100-entry buffer). `rows/` are structurally-redacted via
`crack/scripts/extract_live.py`. Supersedes `cc2198`.

**The 2.1.198 → 2.1.201 diff is minimal — a patch release.** Only two things
move: the version string and the telemetry `build_time`. Everything else on the
wire is byte-identical.

Client env (from `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.201                (was 2.1.198)
build_time             = 2026-07-03T19:53:38Z   (was 2026-07-01T06:09:31Z @ 2.1.198)
node_version           = v26.3.0                (UNCHANGED)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED, x-stainless-package-version)
bun / axios            = Bun/1.4.0 / axios/1.15.2 (UNCHANGED)
```

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header set/order identical to 2.1.198. `user-agent` bumped to
`claude-cli/2.1.201 (external, cli)`. `x-stainless-runtime-version: v26.3.0`,
`x-stainless-package-version: 0.94.0` — both unchanged.

**`anthropic-beta` is the same 13-item list (no `context-1m-2025-08-07`)** — byte
identical to 2.1.198 / 2.1.191:

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

All `/v1/messages` requests in the capture carried this 13-item list.
`count_tokens` carries its own 5-item list
(`claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,token-counting-2024-11-01`)
— unchanged. Body layout UNCHANGED (4-block system, cache_control scope:global on
the second-to-last block, `thinking:{adaptive}`, `metadata.user_id` shape). billing
header `cc_version=2.1.201.<fp>` — fp algorithm unchanged (version is an input;
see cc2197/SPEC.md §5a for the extracted `xtf`/`awo`).

## 2. Bootstrap burst + sidecar endpoints — UNCHANGED

The bootstrap/oauth/mcp rows had already rolled out of whistle's 100-entry buffer
by capture time (same as 2.1.198), so they aren't re-serialized here. All UAs /
betas / headers are unchanged from cc2198 except the version in the UA (driven by
the single `CLICurrentVersion` constant): `bootstrap`, `penguin_mode`,
`mcp-registry`, `v1/mcp_servers`, `code/triggers`. `plugins/latest`
(axios/1.15.2) IS in the capture and unchanged.

## 3. Telemetry — build_time moves; betas config-dependent

`event_logging` + datadog env carry `version=2.1.201`,
`build_time=2026-07-03T19:53:38Z`, `node_version=v26.3.0`.

**This capture's session ran WITHOUT 1M context.** Telemetry therefore shows the
plain 8-item `betas` variant (no `context-1m-2025-08-07`) and the bare
`claude-opus-4-8` model (no `[1m]` suffix). This is CONFIG-dependent, not a
version change: it neither confirms nor contradicts the 9-item `[1m]`
ClaudeReportedBetas pairing verified in cc2198 §3. cc-core's sidecar keeps
emitting the `[1m]` + 9-item pair (event_logging event_data.model) and the plain
`claude-opus-4-8` datadog model — unchanged.

## 4. Still-open items (carried from cc2197/cc2198)

- **cch 5-hex billing signature** — still unresolved (bytecode signer,
  Bun-version-dependent wyhash). Unchanged. See cc2197/SPEC.md §5b.
- **dateline steganography beacon** — `mimicry.NormalizeDateline` still erases it
  (logic unchanged in 2.1.201). See cc2197/SPEC.md §6.

## Edit checklist (applied to cc-core this round)

- [x] `mimicry/fingerprint.go` — `CLICurrentVersion`/`ClaudeCLIUserAgent`
      2.1.198→2.1.201; beta lists unchanged; comment refs → 2.1.201.
- [x] `sidecar/sidecar.go` — `ccBuildTime` → `2026-07-03T19:53:38Z`; version refs.
- [x] `mimicry/{body,headers}.go` — layout comment refs → 2.1.201 (fp-bundle and
      history notes left at their real versions).
- [ ] Tag cc-core release + bump dep in hypitoken **and** CPA-Claude.
