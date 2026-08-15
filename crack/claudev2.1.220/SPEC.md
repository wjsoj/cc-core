# Claude Code 2.1.220 — OAuth fingerprint ground truth

Captured 2026-07-30 from real `claude-cli/2.1.220` OAuth traffic on macOS x64. Login used the local HTTP egress on `127.0.0.1:7891`; capture sessions used Whistle on `127.0.0.1:8899`, with both paths verified to have the same public egress. HTTPS interception used the Whistle CA through `NODE_EXTRA_CA_CERTS`; TLS verification was never disabled.

The controlled model was `claude-sonnet-5`. This was the user's explicit model setting and is **not** evidence of a version-driven default-model change.

## Capture set and redaction

- 10 independent first-turn sessions, one controlled user message each.
- One new conversation with 10 consecutive turns in the same process/session.
- Separate startup/bootstrap capture before the first controlled request.
- 20/20 controlled main requests completed with HTTP 200.
- 37 billing requests total: 20 controlled main, 11 title/Haiku, 6 automatic prompt-suggestion.
- All 37 have a non-zero `cch`; all 37 values are unique and retained in `chain-redacted.json`. The `rows/` archive keeps one representative row per repeated request class plus all 10 multi-turn main requests.
- Raw Whistle dumps remain only under `/private/tmp/cc2220-raw/` with mode 0700/0600 and are not part of Git.
- Identity, authorization, cookies, user/assistant prose, tool descriptions, local paths, UUIDs, request IDs, and session IDs are removed or replaced with stable 16-hex comparison hashes.

## Client environment

```
version / version_base = 2.1.220
build_time             = 2026-07-24T22:17:45Z
node_version           = v26.3.0
SDK package            = 0.94.0
axios                  = 1.15.2
X-Stainless OS/arch    = MacOS / x64
terminal / shell       = Apple_Terminal / bash
```

`MacOS`, terminal, and shell are capture-host properties, not version changes. Do not replace cc-core's synthetic per-account host profile solely from this capture.

## Main `/v1/messages?beta=true` request

Headers on all 20 controlled main requests and 6 prompt-suggestion requests:

```
User-Agent: claude-cli/2.1.220 (external, cli)
Accept: application/json
Content-Type: application/json
Accept-Encoding: gzip, br
X-Stainless-Lang: js
X-Stainless-Package-Version: 0.94.0
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v26.3.0
X-Stainless-OS: MacOS
X-Stainless-Arch: x64
X-Stainless-Timeout: 600
X-Stainless-Retry-Count: 0
```

Main request `Anthropic-Beta`, exact order (13 items):

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

This capture used ordinary Sonnet 5 rather than an explicit 1M-context selector. The absence of `context-1m-2025-08-07` is therefore treated as model/context-mode dependent and is not used as a 2.1.220 version fingerprint. **§1a below resolves this** with a second 2.1.220 capture that observed both modes.

## 1a. Second capture (2026-07-31, Linux) — the request beta list is context-mode dependent

A follow-up `claude-cli/2.1.220` session captured on Arch Linux (Whistle `127.0.0.1:8899`, konsole/zsh) caught **both context modes in one process**, resolving the "Unresolved" item above. Rows are in `rows-2026-07-31/`.

| mode | model in body | telemetry model | request `anthropic-beta` | samples |
|---|---|---|---|---|
| non-1M | `claude-opus-4-8` | `claude-opus-4-8` | **13 items** (below) | 5 |
| 1M active | `claude-opus-5` | `claude-opus-5[1m]` | **15 items** (below) | 1 |

Non-1M (13 items) — **byte-identical to the macOS Sonnet 5 list in §1**, so this shape now has 25+ requests across two hosts, two models, and two OSes behind it:

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

1M active (15 items) — adds `context-1m-2025-08-07` at position 3 and `fallback-credit-2026-06-01` between `effort` and `extended-cache-ttl` (`rows-2026-07-31/15-v1_messages_1m.json`):

```
claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07
```

Consequences for cc-core:

- The pre-existing 14-item constant (13 + `context-1m`, no `fallback-credit`), inherited from the 1M-active 2.1.211 capture, matched **neither** 2.1.220 variant. `fallback-credit-2026-06-01` — dropped at 2.1.211 — is back, but only in the 1M list.
- `ClaudeAnthropicBetaFull` is now the 13-item non-1M list (the injected default); `ClaudeAnthropicBeta1M` holds the 15-item list.
- The 1M list is **single-sample** — re-verify on the next capture.
- **A request body carries no 1M marker**: the `[1m]` suffix exists only in telemetry (`event_data.model`), while the 1M request's body model was the plain string `claude-opus-5`. cc-core therefore cannot infer the mode from a proxied request and does not auto-select the 1M list; a downstream client opts in by sending its own beta list, exactly as the real CLI does.

One anomaly worth recording: the **first** main request after login (`rows-2026-07-31/08-v1_messages.json`) carried only **12** betas — the 13-item list minus `extended-cache-ttl-2025-04-11` — and its `system[2]`/`system[3]` `cache_control` blocks correspondingly had **no `ttl` field** (plain `{ephemeral,scope:global}` / `{ephemeral}`). Every later request in the session had both the beta and the `ttl:1h`. The extended-cache-ttl beta and the body's `ttl` field move together and appear to switch on once the post-login bootstrap config lands. cc-core always emits `ttl:1h`, so it correctly always sends the beta.

## 1b. `POST /v1/messages/count_tokens` is a distinct request class

Four `count_tokens` requests were captured. They are **not** shaped like a main request:

```
anthropic-beta: claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,token-counting-2024-11-01
```

- 5 items, identical across all 4 samples, including `token-counting-2024-11-01` which appears on no other class.
- Body keys are exactly `model,messages,tools` — no `system` (so **no billing block**), no `max_tokens`, no `stream`, no `thinking`, no `metadata`.
- `Accept: application/json`.
- **`X-Stainless-Timeout` is absent** while `X-Stainless-Retry-Count` is present; every main request carries both. This is the easiest tell to get wrong.

`mimicry/headers.go` now detects the `/v1/messages/count_tokens` path and reproduces both the shorter beta list and the missing timeout header. The apikey path is unaffected (no apikey `count_tokens` capture exists).

Main body shape:

- Keys: `model,messages,system,tools,metadata,max_tokens,thinking,context_management,output_config,diagnostics,stream`.
- `model=claude-sonnet-5`, `max_tokens=64000`, `stream=true` in this controlled environment.
- Four system blocks: billing; canonical Claude Code introduction; stable prompt block with `{ephemeral,ttl:1h,scope:global}`; final prompt block with `{ephemeral,ttl:1h}`.
- `thinking={type:adaptive}`.
- `context_management.edits=[{type:clear_thinking_20251015,keep:all}]`.
- `output_config={effort:high}`.
- `diagnostics` contains `previous_message_id` structurally; its value is redacted.
- The controlled sessions exposed 12 tools; tool names/descriptions are not treated as version constants.

## 2. OAuth login flow (2026-07-31 capture)

The 2026-07-31 session included a **complete fresh `authorization_code` login**, re-anchoring the login path for the first time since claudev2.1.214. Observed order:

```
POST platform.claude.com/v1/oauth/token   axios/1.15.2   (token exchange)
GET  api.anthropic.com/api/oauth/profile  axios/1.15.2   (post-probe)
GET  api.anthropic.com/api/oauth/claude_cli/roles  axios/1.15.2  (post-probe)
POST api.anthropic.com/api/eval/sdk-…     Bun/1.4.0      (startup)
GET  api.anthropic.com/api/claude_cli/bootstrap?entrypoint=cli&model=…  claude-code/2.1.220
```

**Token exchange — matches cc-core verbatim.** Body param order confirmed again as `grant_type, code, redirect_uri, client_id, code_verifier, state` (the struct order in `finishAnthropicLogin`), `grant_type=authorization_code`, `client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e`. Headers are exactly `Accept: application/json, text/plain, */*` + `Content-Type: application/json` + `User-Agent: axios/1.15.2` + `Accept-Encoding: gzip, br` — **no `anthropic-beta`, no `anthropic-version`**. Matches `applyAxiosOAuthHeaders`.

**`redirect_uri` is a random loopback port** — `http://localhost:33007/callback` here vs `46473` in the older `crack/claudev2.1.126-login/` capture. The port is chosen per-login by the CLI's temporary callback server, so cc-core pinning its own `54545` is correct: the only requirement is that the authorize and token requests echo the same value. **No change needed.**

**Post-probe headers are NOT uniform** — the one correction this capture produced:

| probe | Accept | Content-Type | Cache-Control | UA |
|---|---|---|---|---|
| `/api/oauth/profile` | `application/json, text/plain, */*` | `application/json` | **`no-cache`** | axios |
| `/api/oauth/claude_cli/roles` | `application/json, text/plain, */*` | *(absent)* | *(absent)* | axios |

cc-core sent one identical header set for both, so `profile` was missing `Content-Type` and `Cache-Control`. `doLoginProbe` now takes a per-probe `extra` map; `roles` keeps neither. Response shapes (`account`/`organization`/`application` on profile, `organization_role` etc. on roles) are unchanged from claudev2.1.214.

**Not re-anchored by this capture:** `/v1/oauth/hello`, `/api/hello`, and the `/api/oauth/account/settings` post-probe did not appear in the 64-frame window. Whistle's buffer had already rolled past the start of the login, so this is **absence of evidence, not evidence of absence** — those probes are left exactly as claudev2.1.214 established them.

## Title/Haiku request

Eleven title requests were captured: one for each of the 10 independent sessions and one for the multi-turn conversation.

- `model=claude-haiku-4-5-20251001`, `max_tokens=32000`, `stream=true`.
- Three system blocks, including a genuine billing block with `cc_version` and dynamic `cch`.
- `thinking={type:disabled}`, `temperature=0`.
- `output_config.format` is a JSON schema requiring a single string field `title`.
- No tools.
- `Accept: application/json`.

Exact title beta list (9 items), distinct from both main and process telemetry:

```
oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,structured-outputs-2025-12-15,cache-diagnosis-2026-04-07
```

## Quota probe

Nine completed quota probes were observed; one representative row is retained:

- `model=claude-haiku-4-5-20251001`, `max_tokens=1`.
- No system/billing block, thinking, tools, or streaming flag.
- `Accept: application/json` exactly.
- Exact beta list:

```
oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05
```

## Billing, fingerprint suffix, and `cch`

Billing format:

```
x-anthropic-billing-header: cc_version=2.1.220.<3hex>; cc_entrypoint=cli; cch=<5hex>; [cc_prev_req=<request-id>;]
```

- 37/37 billing requests carry a dynamic non-zero `cch`.
- 37/37 captured `cch` values are distinct.
- cc-core's current guessed signer — seeded xxhash64 over the exact body after replacing genuine `cch` with `00000`, masked to 20 bits — matches **0/37**.
- The genuine values are preserved; no sample was changed to fit the guess.

The 3-hex `cc_version` suffix matches JavaScript UTF-16 code-unit indexing at positions `[4,7,20]` for all 10 controlled first-turn messages. Rune indexing matches ordinary ASCII/BMP cases but fails the three emoji cases (rounds 3–5). Byte indexing additionally fails non-ASCII BMP cases. The four repeated ASCII messages (rounds 1, 8, 9, 10) all produced the same suffix `ac9` while their cch, session ID, and client request ID changed.

Static extraction from the installed 2.1.220 bundle independently recovered the
two relevant functions. The fingerprint helper uses JavaScript string indexing
at `[4,7,20]` and SHA-256 with salt `59cf53e54c78`. The billing builder emits a
`cch=00000` placeholder and appends `cc_prev_req` only for first-party OAuth
when a previous upstream request ID is supplied. Replacement of the cch
placeholder happens deeper in the private request stack and remains unresolved.

## Identity and session invariants

- One stable device hash and one stable account hash across all 37 billing requests.
- Eleven session hashes: ten independent single-turn sessions plus one multi-turn session.
- Header `X-Claude-Code-Session-Id` and parsed `metadata.user_id.session_id` match 37/37.
- All 37 `x-client-request-id` values are unique.
- Main, title, and prompt-suggestion requests in one conversation share the same session identity.

### `cch` — exhaustive static analysis of the 2.1.220 bundle (2026-07-31)

The installed 2.1.220 executable (Bun single-file ELF, 263 MB, **not stripped**) was searched exhaustively. The result closes the "how is cch computed" question in the negative, with proof rather than a failed guess.

The one and only builder is (deminified names kept as-is):

```js
function k7n(e,t,r){                       // e = fp suffix, t = agentContext, r = prev request id
  if(su(process.env.CLAUDE_CODE_ATTRIBUTION_HEADER)) return "";
  let n=`${VERSION}.${e}`,
      o=process.env.CLAUDE_CODE_ENTRYPOINT??"unknown",
      i=Hn(),                              // "firstParty" | "vertex" | …
      s=i==="firstParty"&&Yd()||i==="vertex" ? " cch=00000;" : "",
      a=HYn(), l=a?` cc_workload=${a};`:"",
      c=mde(t)&&!t.isMainSession ? " cc_is_subagent=true;" : "",
      u=r&&i==="firstParty"&&Yd() ? ` cc_prev_req=${r};` : "";
  return `x-anthropic-billing-header: cc_version=${n}; cc_entrypoint=${o};${s}${l}${c}${u}`;
}
```

Counts over the full JS region (the bundle's readable source, absolute offsets ≈230–275 MB):

| token | occurrences | verdict |
|---|---|---|
| `cc_version=` | **1** | only `k7n` builds the header |
| `cc_prev_req` | **1** | same site |
| `x-anthropic-billing-header` | **5** | 1 builder + 1 `SPy` const + 3 cache-scope classifiers, none mutating |
| `00000` | 3449 | **all** unrelated (CSS colors, float constants); no `"00000"` replace target |
| billing/cch native symbols (`nm`) | **0** | not a native export either |

The three non-builder sites only *read* the block: `Esd()` tests `startsWith("x-anthropic-billing-header:")` so the cache-diagnosis tracker can **exclude** the billing block from its `systemHash`/`toolsHash`, and `Aqs()` classifies it as the `cacheScope:null` block. `Tdr()` there is `Bun.hash` (wyhash) masked to **32** bits — not 20 — and is written to a local diagnostics file, never to the wire.

**Conclusion: the JavaScript layer emits the literal placeholder `cch=00000` and contains no code path that replaces it.** Every observed wire value is non-zero and unique, so the substitution happens below the JS bundle, in the private request stack. Static JS extraction cannot recover it; this is not a matter of searching harder.

Two consequences that are actionable today:

1. **Do not "fix" cc-core to send `cch=00000`.** It is what the bundle's source literally contains, but no real request ever carries it — 43/43 captured values (37 at 2.1.220 macOS + 6 at 2.1.220 Linux) are non-zero and distinct. Emitting the placeholder would be a value Anthropic's edge never sees from a genuine client.
2. cc-core's deterministic seeded-xxhash `cch` remains a **best-effort stand-in**: wrong algorithm, right shape (5 hex, non-zero, unique per request). Keep it until a capture-plus-instrumentation approach (not static analysis) recovers the real one.

Also worth recording from the same function: `cch` and `cc_prev_req` are emitted **only** when the endpoint resolves to `firstParty` (`api.anthropic.com`) or `vertex`. A client pointed at a third-party base URL sends neither — which is exactly why the apikey/gateway path in `crack/claudev2.1.126-apikey/` shows no `cch`.

## Multi-turn `cc_prev_req`

`cc_prev_req` is inside the billing text, not a JSON field and not an ingress header.

- Multi-turn round 1 main request has no `cc_prev_req`.
- Rounds 2–10 main requests match the immediately previous main request's **upstream response `request-id`**: 9/9.
- Six captured prompt-suggestion requests point to the same round's main response `request-id`: 6/6.
- The same session ID remains stable for all multi-turn requests while cch and client request ID change per request.

## Telemetry classes

`POST /api/event_logging/v2/batch` uses:

```
User-Agent: claude-code/2.1.220
Accept: application/json, text/plain, */*
Content-Type: application/json
Accept-Encoding: gzip, br
```

Observed API telemetry includes `tengu_api_query` and `tengu_api_success`. Their `event_data.betas` echo the corresponding request class's exact beta list (main, title, quota, and the non-billing startup model calls observed before formal filtering). This must not be replaced by one global telemetry constant.

Process/feature/skill events use the shorter reported-beta family. For the controlled OAuth Sonnet sessions the 8-item list is:

```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07
```

This differs from the title list: title drops `claude-code` and `mid-conversation-system`, and adds `advisor-tool`, `structured-outputs`, and `cache-diagnosis`.

Observed process/API event names are summarized in the telemetry rows and `ANALYSIS.md`; prose and identity-bearing event values are not archived.

## Startup/bootstrap surface

The formal startup window includes oauth/account settings, grove, bootstrap, quota, penguin, MCP registry pages, `/v1/mcp_servers`, `/v1/code/triggers`, releases, event logging, and Datadog. GrowthBook/eval did not appear in the formal post-login startup window and is therefore not re-anchored by this capture.

## 3. Startup corrections from the 2026-07-31 capture

Two long-standing sidecar mismatches were caught by re-reading this window:

- **`/mcp-registry/v0/servers` carries NO `Authorization`.** All 4 samples are unauthenticated — it is a public catalog. cc-core had been attaching a Bearer, which is a tell in the opposite direction of the usual failure mode (too much fidelity, not too little). Fixed with `noAuth: true`.
- **`anthropic-mcp-client-capabilities` on `/v1/mcp_servers`** decodes to `{"roots":{"listChanged":true},"elicitation":{}}`. cc-core shipped the base64 of `{"roots":{},"elicitation":{}}` — a capability set the real client never advertises. Corrected.

The rest of the pair is confirmed unchanged: `/v1/mcp_servers` uses `axios/1.15.2` + `anthropic-beta: mcp-servers-2025-12-04` + `anthropic-version: 2023-06-01` + `MCP-Protocol-Version: 2025-11-25`, and `/mcp-registry` uses the `claude-cli` UA with no beta.

Verified UA families remain endpoint-specific:

- oauth/account settings, grove, MCP registry, and code triggers: `claude-cli/2.1.220 (external, cli)`.
- `/api/claude_cli/bootstrap`: `claude-code/2.1.220`.
- penguin, `/v1/mcp_servers`, and releases/download checks: `axios/1.15.2`.
- event logging: `claude-code/2.1.220`.

## Confirmed 2.1.214 → 2.1.220 wire changes

1. Version/UA and telemetry `version`/`version_base`: `2.1.214` → `2.1.220`.
2. Build time: `2026-07-17T23:24:50Z` → `2026-07-24T22:17:45Z`.

## Newly established by the expanded capture

- Title is independently fingerprinted: 9-item beta list with `structured-outputs-2025-12-15`, three-block billed body, disabled thinking, and JSON-schema output. The earlier 2.1.214 archive did not retain enough turns to establish whether this is new in 2.1.220.
- Current cc-core cch guess, previously documented as valid at 2.1.214, is 0/37 on genuine 2.1.220 requests. This may be a version change or a correction to the earlier reconstruction.
- UTF-16 code-unit indexing is confirmed; rune/byte indexing is not equivalent around emoji. This is a correctness fix in cc-core, not evidence that the CLI algorithm changed in 2.1.220.
- The 10-turn chain establishes `cc_prev_req` semantics for main and prompt-suggestion requests; the earlier single-turn archive could not expose this relationship.

Model (`claude-sonnet-5`), macOS axes, terminal, shell, and tool inventory are environment/configuration observations and are excluded from the version-difference list.

## Unresolved

- The genuine 2.1.220 cch algorithm remains unknown.
- Whether the cch algorithm changed after 2.1.214 or the earlier reconstruction was never generally valid requires old raw bodies and cross-version validation.
- ~~`context-1m-2025-08-07` was not exercised because the direct OAuth account exposed no explicit 1M model selector.~~ **Resolved by the 2026-07-31 capture — see §1a.** The request list is context-mode dependent: 13 items non-1M, 15 items (with `context-1m` and `fallback-credit`) when the 1M window is active. The 1M variant is still single-sample.
- GrowthBook/eval and interactive OAuth token-exchange traffic were not in the formal post-login startup window; this capture does not update those constants.
- Prompt-suggestion scheduling is asynchronous; six suggestion requests landed inside the per-round tail windows, while others may have occurred after an independent process was closed.

## cc-core edit checklist (applied in this bump)

- `mimicry/fingerprint.go`: `CLICurrentVersion` and `ClaudeCLIUserAgent` bumped to 2.1.220. Existing `context-1m` behavior is unchanged.
- `mimicry/body.go`: fingerprint character selection now follows JavaScript UTF-16 semantics, with ASCII, BMP, and emoji regression vectors.
- `sidecar/sidecar.go`: `ccBuildTime` bumped to `2026-07-24T22:17:45Z`; bootstrap UA families were re-checked and remain unchanged.
- Request classes remain documented separately: main, title, and quota beta/body shapes are not interchangeable. The proxy does not synthesize Claude's internal title or prompt-suggestion calls.
- Multi-turn evidence is retained in `chain-redacted.json`: main-chain `cc_prev_req` linkage is 9/9 and prompt-suggestion linkage is 6/6. Stateful `cc_prev_req` synthesis for non-Claude downstream clients is not introduced by this version-only bump because it requires the consuming server to retain successful upstream response IDs.
- The seeded-xxhash cch signer is explicitly documented as a legacy best-effort reconstruction, not genuine 2.1.220 behavior. The 37-value captured corpus is preserved for continued research.
- MacOS/terminal/shell observations were not copied into the synthetic per-account Linux host profile.
- No tag, downstream dependency bump, commit, or push is part of the capture archive itself.

### Follow-up edits from the 2026-07-31 Linux capture

- `mimicry/fingerprint.go`: `ClaudeAnthropicBetaFull` replaced with the 13-item non-1M list; new `ClaudeAnthropicBeta1M` (15 items) and `ClaudeAnthropicBetaCountTokens` (5 items). Version, UA, stainless set, `ClaudeReportedBetas`, and `ccBuildTime` were all re-verified **unchanged** against this capture.
- `mimicry/headers.go`: `/v1/messages/count_tokens` now gets its own beta list and omits `X-Stainless-Timeout`. Client-supplied beta lists still win on every path.
- `auth/login_probes.go`: `doLoginProbe` gained a per-probe `extra` header map; `profile` sends `Content-Type` + `Cache-Control: no-cache`, `roles` sends neither.
- `sidecar/sidecar.go`: `mcp_registry` step is now `noAuth`; `anthropic-mcp-client-capabilities` corrected to the `roots.listChanged` encoding.
- Tests: `mimicry/headers_test.go` (beta-list exact values + count_tokens class + passthrough), `auth/login_probes_test.go` (per-endpoint headers), `sidecar/sidecar_test.go` (`TestMCPProbeAuthAndCapabilities`).
- Machine axes from this capture (`linux_kernel 7.1.2-arch3-1`, `terminal konsole`, `shell zsh`) are capture-host properties and were **not** copied into `auth.HostProfile`'s synthetic per-account values.
