# Claude Code 2.1.197 — fingerprint ground truth

Captured 2026-07-01 from a live `claude-cli/2.1.197` OAuth session (whistle dump
`get-data?ids=…`, full-body capture). This round captured the **complete flow
from scratch**: logout → `/login` → browser consent → token exchange → startup
bootstrap burst → first business `/v1/messages` → steady-state telemetry. Rows
in `rows/` are structurally-redacted via `crack/scripts/extract_live.py`
(prose/code/identity masked, fingerprint structure kept). The raw dump is never
committed.

**Authoritative reference** for the fingerprint constants in `cc-core/mimicry`
and `cc-core/sidecar`. hypitoken and CPA-Claude both consume these via the
module dep — there is no vendored copy. Supersedes `cc2191` (kept in-tree this
round for the historical `code_triggers` / `mcp_servers` comment refs; prune on
next cleanup).

Client env (from the `event_logging` / datadog telemetry bodies):

```
version / version_base = 2.1.197                (was 2.1.191)
build_time             = 2026-06-29T19:08:42Z   (was 2026-06-24T11:24:03Z @ 2.1.191)
node_version           = v26.3.0                (UNCHANGED — no runtime jump)
sdk (@anthropic-ai)    = 0.94.0                 (UNCHANGED, x-stainless-package-version)
bun                    = Bun/1.4.0              (UNCHANGED, eval-sdk UA)
axios                  = axios/1.15.2           (UNCHANGED, probe/telemetry UA)
default model (telem)  = claude-opus-4-8[1m]    (UNCHANGED; datadog carries claude-opus-4-8, no [1m])
```

The 2.1.191 → 2.1.197 diff is **small on the wire**. The only fingerprint-bearing
changes on the chat path are (a) `context-1m-2025-08-07` now present in the
`anthropic-beta` request header, and (b) `build_time`. Body layout, system
blocks, cache_control, telemetry betas, and all sidecar UAs are unchanged.

---

## 1. `/v1/messages?beta=true` — request headers (OAuth chat path)

Header *set* and order identical to 2.1.191. `user-agent` bumped; **`anthropic-beta`
gained `context-1m-2025-08-07`** (inserted at position 3, after `oauth-2025-04-20`).

| header | value | vs 2.1.191 |
|---|---|---|
| user-agent | `claude-cli/2.1.197 (external, cli)` | version bump |
| x-stainless-runtime-version | `v26.3.0` | unchanged |
| x-stainless-package-version | `0.94.0` | unchanged |
| anthropic-version | `2023-06-01` | unchanged |
| anthropic-beta | 14-item list (below) | **+context-1m-2025-08-07** |

Full 2.1.197 request-header beta (14 items → `mimicry.ClaudeAnthropicBetaFull`):

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

The quota-probe `/v1/messages` (sidecar warmup) carries a SHORTER 6-item beta
(`oauth-2025-04-20,interleaved-thinking…,…,prompt-caching-scope`, no
`claude-code-20250219`, no `context-1m`) — a distinct code path, not our
BetaFull.

### Body (`rows/11-v1_messages.json`) — layout UNCHANGED

- `model=claude-opus-4-8`, `max_tokens=64000`, `stream=true`, `thinking={"type":"adaptive"}`.
- 4-block `system`: `[0]` billing header (bare, no cache_control), `[1]` "You are
  Claude Code…" (bare), `[2]` interactive-agent prose w/ `cache_control
  {ephemeral, ttl:1h, scope:global}`, `[3]` last block w/ `{ephemeral, ttl:1h}`.
- `metadata.user_id` = JSON string `{device_id, account_uuid, session_id}`.
- **New top-level fields** vs older captures: `context_management`, `output_config`,
  `diagnostics`. These are client-driven and pass through our body mimicry
  untouched (we only rewrite `system` + `metadata`); no cc-core change needed.

---

## 2. Startup bootstrap burst + sidecar endpoints

Ordering/UAs unchanged from 2.1.191. Confirmed endpoints (see `rows/`):

| endpoint | UA | beta | notes |
|---|---|---|---|
| `GET /api/hello` (api.anthropic.com) | claude-cli/2.1.197 | — | pre-login probe |
| `GET /v1/oauth/hello` (platform.claude.com) | claude-cli/2.1.197 | — | pre-login probe |
| `POST /v1/oauth/token` (platform.claude.com) | axios/1.15.2 | — | token exchange |
| `GET /api/oauth/profile` | axios/1.15.2 | — | post-login |
| `GET /api/oauth/claude_cli/roles` | axios/1.15.2 | — | post-login |
| `POST /api/eval/sdk-zAZezfDKGoZuXXKe` | Bun/1.4.0 | oauth-2025-04-20 | keep-alive |
| `GET /api/claude_cli/bootstrap?entrypoint=cli&model=claude-opus-4-8` | claude-code/2.1.197 | oauth-2025-04-20 | model param = `claude-opus-4-8` |
| `GET /api/claude_code_penguin_mode` | axios/1.15.2 | oauth-2025-04-20 | |
| `GET /mcp-registry/v0/servers?…` (+cursor pagination) | claude-cli/2.1.197 | — | |
| `GET /v1/mcp_servers?limit=1000` | axios/1.15.2 | mcp-servers-2025-12-04 | **+2 headers, see below** |
| `GET /v1/code/triggers` | claude-cli/2.1.197 | ccr-triggers-2026-01-30 | +anthropic-client-platform=claude_code_cli, x-organization-uuid |
| `GET downloads.claude.ai/claude-code-releases/latest` | axios/1.15.2 | — | |

**`v1_mcp_servers` header fix (cc-core omission, not a 2.1.197 change):** real CC
sends TWO extra headers on this probe that our sidecar never wired — present in
the cc2191 capture too:

```
anthropic-mcp-client-capabilities: eyJyb290cyI6e30sImVsaWNpdGF0aW9uIjp7fX0=   (base64 {"roots":{},"elicitation":{}})
MCP-Protocol-Version: 2025-11-25
```

Wired via `extraHeaders` on the `v1_mcp_servers` step (`sidecar/sidecar.go`).

---

## 3. Telemetry (`event_logging` + datadog) — env & betas

- `event_logging` + datadog env: `version/version_base=2.1.197`,
  `build_time=2026-06-29T19:08:42Z`, `node_version=v26.3.0`, `platform=linux`,
  `entrypoint=cli`.
- Telemetry model: `claude-opus-4-8[1m]` (event_logging), `claude-opus-4-8`
  (datadog) — unchanged → `ccTelemetryModel` / `ccDatadogModel`.
- **`betas` (telemetry) UNCHANGED** — the `[1m]` events carry the same 9-item
  list as 2.1.191 (`mimicry.ClaudeReportedBetas`):
  `claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07`.
  An 8-item variant (drops `oauth-2025-04-20`) appears on some non-1M events.
- **Datadog is ACTIVE in real CC** (`POST http-intake.logs.us5.datadoghq.com/api/v2/logs`,
  UA `axios/1.15.2`, `DD-API-KEY: pubea5604404508cdd34afb69e6f42a05bc`, 202,
  interleaved with event_logging). cc-core's `runDatadogHeartbeat` remains
  **deliberately disabled** (operator decision 2026-07-01: the hardcoded public
  intake key is a pinned signal Anthropic could rotate/monitor). Constants stay
  aligned for correctness.

---

## 4. Login / OAuth host

`platform.claude.com` for `oauth/hello` + `oauth/token` — already the cc-core
default (`auth/oauth.go`, `auth/login_probes.go`). No change. This capture
did NOT include `/api/oauth/account/settings` (cached this session); the probe
stays in `auth/login_probes.performPostLoginProbes` from the 2.1.191 capture.

---

## 5. Billing-header signatures — reversed from the real CLI source

Ground truth from `rows/11`: `cc_version=2.1.197.17a; cch=1a398;`. cc-core's
original functions produced `72f` / `67efb` over the exact wire body — BOTH
wrong. Rather than guess, the real algorithm was **extracted from the CC 2.1.197
standalone binary** (`~/.local/share/claude/versions/2.1.197`, a Bun-compiled
ELF that embeds the readable JS source). Confirmed cross-checked against the last
JS-distributed npm bundles (2.1.63, 2.1.112; native-binary switch landed at
2.1.113).

### 5a. `cc_version` 3-hex fp — SOLVED & FIXED

Real CLI (2.1.197, minified names `xtf`/`awo`/`ctl`):

```js
function xtf(e){let t=e.find(r=>r.type==="user"&&!r.isMeta);if(!t)return"";
  let n=t.message.content; if(typeof n==="string")return n;
  if(Array.isArray(n)){let r=n.find(o=>o.type==="text"); if(r?.type==="text")return r.text} return""}
function awo(e,t){let r=[4,7,20].map(i=>e[i]||"0").join(""),o=`${SALT}${r}${t}`;
  return createHash("sha256").update(o).digest("hex").slice(0,3)}   // SALT="59cf53e54c78"
```

salt / positions [4,7,20] / sha256[:3] were all **already correct** in cc-core.
The bug was the INPUT: cc-core took the wire `messages[0]` first text block,
which is the injected **`<system-reminder>`** context. The CLI computes the fp
over the first **`!isMeta`** user message — i.e. the user's REAL first text,
because the fp is computed BEFORE the reminder is injected. On the wire, isMeta
messages are merged as leading blocks of `messages[0]`.

Worked sample: `messages[0].content = [<system-reminder>…, "logout\n",
"Continue…"]`. Old cc-core → `"<system-reminder>…"` → chars `t- ` → `72f`.
Fixed (skip reminder) → `"logout\n"` → chars `u00` → **`17a` ✓** (verified via
throwaway test). Fix = `mimicry/body.go extractFirstUserText` skips leading
blocks starting with `<system-reminder>`.

### 5b. `cch` 5-hex — placeholder in code; real signer not statically recoverable

The billing-header BUILDER in every version (2.1.63 → 2.1.197) emits a literal
`cch=00000` placeholder (only when `(authType==="firstParty"&&Eu())||vertex`;
otherwise NO cch), e.g. 2.1.197:

```js
s = (o==="firstParty"&&Eu())||o==="vertex" ? " cch=00000;" : "";
c = `x-anthropic-billing-header: cc_version=${n}; cc_entrypoint=${r};${s}${a}${l}`;
```

2.1.63/2.1.112 have NO signer — they send `cch=00000` verbatim on the wire. A
real cch (`1a398`) only appears at 2.1.197. Deep binary trace of the whole
readable path — `tTn` (builder, emits `cch=00000`) → `Ec` (identity, `Ec(e){return e}`)
→ `qdc` (telemetry sha256, no mutation) → `Wlm`/`W9o` (adds cache_control only) →
anthropic-sdk `buildRequest`/`buildBody` — shows **nothing rewrites the cch** in
readable JS. The bytecode copy of `tTn` (string pool @ ELF 97.6M) carries the
same strings (only `cch=00000`, no hash label). So the value-substitution lives
in a **Bun-bytecode-compiled module** (not statically decompilable here) that
splices by fixed offset (references neither `"cch"` nor `"00000"`).

Empirically, `cch=1a398` is **SESSION-CONSTANT** — identical across 18 captured
`/v1/messages` bodies of different sizes (408–485 KB) in one session, and NOT a
per-body hash. It tracks something session-stable (first user text / system /
account / session id). An exhaustive real-Bun sweep (crypto {md5,sha1,sha256,…}
+ Bun.hash {wyhash, xxHash64/32/3, cityHash64/32, murmur64v2/32, crc32, adler32}
× many session-stable inputs × slicings) gave **0 hits** — the 2.1.197 bundle
ships a newer Bun whose `Bun.hash` (wyhash) differs from any locally installed
Bun, so the value can't be reproduced off-box.

**Status:** `cch` left as-is in cc-core — do NOT ship a guess. **Impact bounded:**
cc-core skips body mimicry on real-CC passthrough (the client's own header flows
through), so only SYNTHESIZED OAuth requests carry a wrong `cch`; no mass bans
observed → cch likely lenient/unchecked. **To finish cch:** runtime-instrument
the real 2.1.197 binary (hook `Bun.hash`/`createHash` to capture input→output),
or disassemble the bytecode billing module. Static extraction is blocked by
bytecode. `cchSeed` unchanged.

---

## 6. Dateline steganography beacon — REVERSED & ERASED (new)

Real CC embeds a **3-bit steganographic beacon** in the `Today's date is
YYYY-MM-DD.` sentence of the environment context (top-level `system` on turn 1,
`<system-reminder>` blocks on later turns) **whenever it detects a non-official
base URL** — i.e. any forwarding gateway (hypitoken included). Extracted from the
2.1.197 binary (`rdp`/`odp`/`qla`, readable JS):

```js
function rdp(){ if(vrt()) return null;                 // official base URL → NO beacon
  let e=<non-official host>, n=(tz==="Asia/Shanghai"||tz==="Asia/Urumqi");
  return { known:<host in known-gateway list edp()>, labKw:<host has lab kw tdp()>, cnTZ:n } }
function odp(known,labKw){ 00→"'"(U+0027)  10→"’"(U+2019)  01→"ʼ"(U+02BC)  11→"ʹ"(U+02B9) }
function qla(d){ let t=rdp(); return `Today${odp(t.known,t.labKw)}s date is
                 ${t.cnTZ ? d.replaceAll("-","/") : d}.` }
```

- **apostrophe** (2 bits) — `known` = OUR host matches Anthropic's known-gateway
  list; `labKw` = OUR host contains a known-reseller keyword.
- **date separator** (1 bit) — `cnTZ` = the client's timezone is China
  (`Asia/Shanghai` / `Asia/Urumqi`).

`vrt()` (same official-endpoint check as `Eu()` in §5) gates it: direct-to-
`api.anthropic.com` traffic gets the canonical ASCII form (`'` + `-`), which is
exactly what our direct capture shows (`Today's date is 2026-07-01.`, U+0027 +
`-`). Proxied traffic leaks the beacon straight to Anthropic — a "this is a
gateway" flag on every message.

**Fix (shipped):** `mimicry.NormalizeDateline` (ported from Wei-Shaw/sub2api
commit `59e9356c`) rewrites the sentence back to canonical ASCII, erasing all 3
bits. Byte-surgical (two RE2 passes with agreeing separators; only non-canonical
forms are rewritten so canonical user prose is untouched), no JSON reparse.
Wired into hypitoken `proxy.go` OAuth path on `/v1/messages`, running even for
real-CC passthrough (the beacon is in the client's own body).

---

## Edit checklist (applied to cc-core this round)

- [x] `mimicry/fingerprint.go` — `CLICurrentVersion` 2.1.191→2.1.197;
      `ClaudeCLIUserAgent`; `ClaudeAnthropicBetaFull` +`context-1m-2025-08-07`
      (13→14 items); comments.
- [x] `mimicry/{body,headers}.go` — version comment refs → 2.1.197 (layout
      re-verified UNCHANGED).
- [x] `sidecar/sidecar.go` — `ccBuildTime` → `2026-06-29T19:08:42Z`;
      `v1_mcp_servers` +`anthropic-mcp-client-capabilities` +`MCP-Protocol-Version`;
      version comment refs.
- [x] `mimicry/body.go` — `extractFirstUserText` now skips `<system-reminder>`
      (isMeta) blocks → `cc_version` 3-hex fp now reproduces real `17a` (§5a).
- [x] `mimicry/dateline.go` (+test) — `NormalizeDateline` erases the dateline
      steganography beacon (§6); wired into hypitoken `proxy.go` /v1/messages.
- [ ] Datadog heartbeat — left disabled (operator decision).
- [ ] `cch` 5-hex — still wrong (§5b); needs live multi-sample reversal. No change.
- [ ] Tag cc-core release + bump dep in hypitoken **and** CPA-Claude.
