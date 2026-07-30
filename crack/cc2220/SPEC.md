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

This capture used ordinary Sonnet 5 rather than an explicit 1M-context selector. The absence of `context-1m-2025-08-07` is therefore treated as model/context-mode dependent and is not used as a 2.1.220 version fingerprint.

Main body shape:

- Keys: `model,messages,system,tools,metadata,max_tokens,thinking,context_management,output_config,diagnostics,stream`.
- `model=claude-sonnet-5`, `max_tokens=64000`, `stream=true` in this controlled environment.
- Four system blocks: billing; canonical Claude Code introduction; stable prompt block with `{ephemeral,ttl:1h,scope:global}`; final prompt block with `{ephemeral,ttl:1h}`.
- `thinking={type:adaptive}`.
- `context_management.edits=[{type:clear_thinking_20251015,keep:all}]`.
- `output_config={effort:high}`.
- `diagnostics` contains `previous_message_id` structurally; its value is redacted.
- The controlled sessions exposed 12 tools; tool names/descriptions are not treated as version constants.

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
- `context-1m-2025-08-07` was not exercised because the direct OAuth account exposed no explicit 1M model selector. Its presence or absence is intentionally excluded from this version diff.
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
