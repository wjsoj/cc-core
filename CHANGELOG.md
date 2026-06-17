# Changelog

## v0.8.21 — Codex WebSocket upstream transport (`codexws`)

Adds the Codex-over-WebSocket upstream that real codex-tui 0.135.0 uses
(`responses_websockets=2026-02-06`, `wss://chatgpt.com/backend-api/codex/
responses`). A long-lived WS carries protocol-level ping/pong, so it survives
the multi-second silent gaps that truncate the legacy HTTP SSE path and surface
to clients as `stream disconnected before completion`. Consumed by hypitoken
and CPA-Claude to add a Codex WS ingress endpoint.

### New — `codexws/`

- `Dial(ctx, DialConfig) (Conn, *http.Response, error)` — WebSocket handshake
  over the **Chrome uTLS fingerprint** (not standard TLS), via gorilla's
  `Dialer.NetDialTLSContext`. ALPN is forced to `http/1.1` (a WS Upgrade cannot
  run over h2). Keeps the WS path byte-identical to the HTTP path that already
  evades Cloudflare JA3/JA4 fingerprinting.
- `Conn` interface (Read/Write/Ping/deadlines/`HandshakeResponse`), `ReadLimit`
  16 MiB, message-type constants, `IsUnexpectedClose`.
- `BuildUpstreamHeaders` + `CodexOpenAIBetaWS`/`CodexOpenAIBetaWSV1` — reuses the
  pinned codex-tui identity from `mimicry`; omits the TUI-only workspace headers.

### Changed — `auth/utls.go`

- Exported `DialTLSConn(ctx, host, addr, proxyURL, useUTLS, nextProtos)` — the
  shared dial primitive behind both the pooled HTTP transport and `codexws`, so
  the Chrome fingerprint stays identical across HTTP and WS. The private
  `(*utlsTransport).dialTLS` is now a thin wrapper; zero behavior change for the
  existing Anthropic/Codex-HTTP paths.

### Dependencies

- Adds `github.com/gorilla/websocket v1.5.3` (no transitive deps beyond stdlib).

## v0.8.19 — apikey beta list + unified crack/ archive

Lets hypitoken drop its vendored fingerprint copy (`internal/server/
{fingerprint,mimicry,sidecar}.go`) and consume `cc-core/{mimicry,sidecar}`
directly, the way CPA-Claude already does — the two were byte-identical except
for the API-key beta selection added here.

### New — `mimicry/fingerprint.go`

- `ClaudeAnthropicBetaApikey` — the shorter Anthropic-Beta request header real
  CC sends on the **API-key** path (3rd-party gateways with `x-api-key`). Drops
  the OAuth-only / strict-gateway-rejected tokens (`oauth-2025-04-20`,
  `advanced-tool-use-*`, `cache-diagnosis-*`). Verbatim from `crack/apikey/`.

### Changed — `mimicry/headers.go`

- `ApplyClaudeCodeHeaders` now selects `ClaudeAnthropicBetaApikey` when
  `kind == KindAPIKey` (and the client supplied no beta of its own), instead of
  always sending `ClaudeAnthropicBetaFull`. OAuth behavior is unchanged. This
  matches real CC's apikey capture and is the last behavioral gap between the
  shared header layer and hypitoken's vendored copy.

### New — `crack/` (fingerprint ground truth, consolidated)

- Merged the capture archives from both downstream apps into `cc-core/crack/`
  so the rows live next to the constants they pin (`cc2170`, `cc2167`, `codex`,
  `kiro`, `oauth`, `apikey`, `login`, `scripts`, `COMPARE.md`). cc-core is now
  the single source of truth; the app repos drop their `crack/` dirs. No raw
  whistle dumps were moved (history-only). See `crack/README.md`.

## v0.8.18 — bump CC fingerprint target 2.1.167 → 2.1.170

Re-pinned `mimicry` + `sidecar` to a live Claude Code **2.1.170** OAuth capture
(whistle dump 2026-06-10; ground truth in hypitoken `crack/cc2170/`).

### Changed — `mimicry/fingerprint.go`

- `CLICurrentVersion` / `ClaudeCLIUserAgent` → `2.1.170`.
- `ClaudeAnthropicBetaFull` (the `/v1/messages` request header) — now **15
  items**: **dropped** `context-1m-2025-08-07`, **added**
  `server-side-fallback-2026-06-01` + `fallback-credit-2026-06-01` after
  `effort-2025-11-24`.
- `ClaudeReportedBetas` (telemetry `betas`) — **unchanged** (still 9 items incl.
  `context-1m`). ⚠ As of 2.1.170 the request-header list and the telemetry list
  have **DIVERGED** — telemetry is no longer the first-9-of-Full. Do not
  regenerate one from the other.

### Changed — `sidecar/sidecar.go`

- `ccBuildTime` → `2026-06-09T15:09:09Z`; `ccTelemetryModel` /
  `ccDatadogModel` → `claude-fable-5[1m]` / `claude-fable-5`.
- Bootstrap probe URL model param → `claude-fable-5`.
- `/v1/code/triggers` bootstrap step UA fixed `axios/…` → the main `claude-cli/…`
  agent (real CC 2.1.170 uses claude-cli here, not axios).

## v0.8.12 — `clientguard` ingress blocklist

### New — `clientguard` package

A shared ingress filter that rejects non-interactive SDK / scripting clients
(raw Anthropic/OpenAI SDKs, LiteLLM, python-requests, curl, Postman, …) by
User-Agent while letting the interactive client family through (Claude Code CLI
+ IDE/Web, Claude Desktop, Cursor, and any UA not on the blocklist). Blocklist —
not allowlist — so unknown legitimate clients keep working; it stops low-effort
abuse, not a determined UA spoofer.

- `clientguard.New(extra []string, blockEmptyUA bool)` / `NewDefault()`
- `(*Guard).Inspect(http.Header) Decision` / `InspectUA(string) Decision`
- `DefaultBlockedUASubstrings` — overridable/extendable default fragment list.

Consumed by CPA-Claude (new `client_guard` config toggle, Claude endpoint only)
and hypitoken (replaced its strict claude-cli/claude-code allowlist with this
blocklist so desktop/IDE clients are no longer rejected).

## v0.8.7 — model_map for OAuth + default Claude opus upgrade

### Changed — `model_map` now applies to OAuth credentials too

`parseFile`/`saveAuth` read & persist `model_map` for OAuth (was API-key only;
`ResolveUpstreamModel` already honored it). A **Claude (Anthropic) OAuth**
credential with no `model_map` key gets `DefaultClaudeOAuthModelMap` injected
(`claude-opus-4-6` & `claude-opus-4-7` → `claude-opus-4-8`) — api.anthropic.com
retired 4-6/4-7, so they're transparently served by 4-8. An explicit map (even
empty `{}`) suppresses the default, so operators can override/disable it; the
field is now always persisted (empty → `{}`) so a cleared map stays cleared.
API-key credentials get no defaults.


## v0.8.6 — Persistent per-credential strip-thinking flag

### New — `Auth.StripThinking` + `MarkStripThinking()` / `StripThinkingEnabled()`

A persisted boolean on the credential. Relays that pool/rotate backend accounts
per request (e.g. an aws2-style vllmproxy) reject every echoed `thinking`
signature, so each request fails once with a thinking-block signature error and
recovers via replay. Consumers call `MarkStripThinking()` after the first
successful sanitize-recovery to persist the decision (written to the credential
file as `strip_thinking: true`, append-only / old files default false), then
proactively sanitize on subsequent forwards — eliminating the recurring failing
first attempt. `StripThinkingEnabled()` is the lock-guarded reader.

Works for both OAuth and file-backed API-key credentials (`saveAuth` persists
the field for both kinds).


## v0.8.5 — Claude Code 2.1.156 fingerprint refresh

Re-pins the mimicry + sidecar fingerprint to a live CC 2.1.156 capture
(2026-05-29). Full 2.1.146→2.1.156 diff in the consuming repos'
`crack/cc2156/SPEC.md`.

### New — `mimicry.ClaudeReportedBetas`

The 9-item beta list real CC reports in its telemetry bodies
(`event_logging` / datadog `betas`), distinct from the 14-item
`ClaudeAnthropicBetaFull` request header. Telemetry was previously
(incorrectly) reusing the full header list — itself a fingerprint mismatch.

### Changed

- `CLICurrentVersion` / `ClaudeCLIUserAgent` → `2.1.156`.
- `ClaudeAnthropicBetaFull` gains `thinking-token-count-2026-05-13` and
  `mid-conversation-system-2026-04-07` (14 items, exact order).
- **Fix**: inverted system cache scope. `scope:global` now sits on the
  second-to-last system block and a plain ephemeral 1h breakpoint on the
  last — matching all 18 captured `/v1/messages` (was reversed).
- Sidecar: `axios/1.13.6`→`axios/1.15.2`; bootstrap + telemetry model
  `claude-opus-4-7`→`claude-opus-4-8`; telemetry `betas`→`ClaudeReportedBetas`;
  env `build_time` bumped + new `linux_distro_id` / `linux_kernel`; datadog
  body gains `renderer_mode` / `feature_name`.

No breaking API changes (additive const only).

## v0.8.0 — Multi-group tokens + Pool.AcquireMulti

Enables per-token credential-group fallthrough. A token can declare an
ordered list of groups; the credential picker tries each in priority order
until one yields a healthy credential. Required for forks routing the
same token through multiple upstream channels (e.g. official Anthropic →
Kiro fallback).

### Breaking — `clienttoken.Store.Update` signature

`Update` gained a trailing `groups *[]string` parameter. Pass `nil` to
leave groups untouched, `&[]string{...}` to replace, `&[]string{}` to clear.

### New — `clienttoken.Token.Groups`

- New `Groups []string` field on `Token` and `View`. Priority-ordered.
- `Token.EffectiveGroups()` helper: returns `Groups` if non-empty,
  else promotes the legacy single `Group` field, else `[""]` (public pool).
- Storage layer dedupes + normalizes (`auth.NormalizeGroup`) entries on
  load and save.
- `tokens.json` schema is additive: old files (Group only, no Groups)
  load unchanged; saves only emit `groups` when non-empty.

### New — `auth.Pool.AcquireMulti`

```go
group, cred := pool.AcquireMulti(ctx, provider, clientToken,
    []string{"kiro-anthropic", "claude-official"},
    model, sessionID, excludeIDs...)
```

Walks groups in order, calling `Acquire` until one returns a credential.
Returns the chosen group name (for billing/dispatch routing) plus the
credential. Empty/nil groups slice is treated as `[""]` (public pool).

The `Release` / `Unstick` / `ReportUpstreamError` APIs are unchanged —
they key on session, not group.

---

## v0.7.1 — kirobridge parity with kiro.rs + Kiro credits API

Catches up to kiro.rs feature-set + adds the per-credential quota endpoint.
The v0.7.0 ModelMap had the wrong Kiro IDs (used uppercase placeholders);
this release corrects them against the captured ListAvailableModels response.

### Breaking — ModelMap rewrite

**v0.7.0 returned bogus IDs.** Real Kiro modelIds are lowercase + dotted:
`claude-opus-4.7`, `claude-sonnet-4.6`, `claude-haiku-4.5`, etc. Anyone who
shipped against v0.7.0 will get `ValidationException` upstream; the v0.7.1
IDs match captured `ListAvailableModels` responses verbatim.

- `MapModel("claude-opus-4-7")` → **`"claude-opus-4.7"`** (was `"CLAUDE_OPUS_4_1_20250805_V1_0"`).
- New constants: `ModelClaudeOpus47 / Opus46 / Opus45 / Sonnet46 / Sonnet45 / Sonnet4 / Haiku45`.
- New non-Anthropic models in the catalog: `deepseek-3.2 / minimax-m2.5 / m2.1 / glm-5 / qwen3-coder-next`.
- `ContextWindow(modelID)` returns 1,000,000 for Opus 4.6 / 4.7 / Sonnet 4.6, else 200,000.
- `SupportedInputTypes(modelID)` returns `["TEXT"]` for `glm-5` / `minimax-m2.5`, else `["TEXT", "IMAGE"]`.

### Breaking — Convert return shape

`Convert` now returns `*ConvertResult` (instead of `*KiroRequest`) so the
caller can recover the tool-name shortening map. Access the request as
`result.Request`.

### kirobridge — kiro.rs parity work

- **Image content blocks** (`type=image`): converted to `KiroImage` entries
  on the user message when `ConvertOptions.AllowImages=true`. Supports
  `source.type=base64` with media_type → format inference
  (jpeg/png/gif/webp). `source.type=url` is intentionally NOT fetched at
  this layer; the caller pre-downloads and re-emits as base64.
- **JSON-schema normalization** (`NormalizeJSONSchema`): coerces malformed
  MCP tool schemas (`required: null`, missing `type`, etc.) to the canonical
  shape Kiro accepts, instead of letting the server return 400. Applied
  automatically inside `Convert`.
- **Prefill stripping**: a trailing assistant message in `req.messages` is
  silently dropped before translation (Claude 4.x deprecated prefill; Kiro
  rejects it).
- **Tool pairing validation**: orphan `tool_use` (no matching `tool_result`)
  is scrubbed from history; orphan `tool_result` (no matching `tool_use`)
  is dropped from the current message.
- **Placeholder tools for history**: any tool name referenced in history
  but missing from `req.tools[]` gets a stub `Tool` entry so Kiro accepts
  the request.
- **Tool name shortening** (`ShortenToolName`): names > 63 chars get
  `prefix[:54] + "_" + sha256(name)[:8]`; original → short mapping is
  returned in `ConvertResult.ToolNameMap` so a fork can rename `tool_use`
  events on the response side.
- **Session ID extraction** (`ExtractSessionID`): pulls the session UUID
  out of Anthropic `metadata.user_id` so multi-turn conversations stay
  coherent server-side. Supports both JSON form
  `{"session_id":"UUID"}` and the legacy `user_xxx_account__session_<UUID>`
  string-tag form.

### kirobridge — WebSearch

New side-channel for the Anthropic `web_search` tool:

- `IsWebSearchRequest(req)` detects `tools.length == 1 && tools[0].name ==
  "web_search"` and returns the extracted query (strips the
  "Perform a web search for the query: " prefix Anthropic clients use).
- `WebSearchClient.Execute(ctx, query)` POSTs a `tools/call` MCP request
  to `q.<region>.amazonaws.com/mcp`, parses the inner search results.
- `SynthesizeWebSearchSSE(model, query, results, inputTokens)` produces
  the 11-event Anthropic SSE sequence (`message_start` → text block →
  `server_tool_use` → `web_search_tool_result` → summary text →
  `message_delta`/`message_stop`).

### kiroapi — credits / usage-limits

- `Client.GetCredits(ctx, profileARN)` calls
  `GET https://q.<region>.amazonaws.com/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST`
  (FlavorCLI uses `origin=KIRO_CLI`).
- `CreditsResponse` exposes `Plan()`, `UsageTotal()`, `LimitTotal()`,
  `Remaining()`, `NextResetAt()`. Totals correctly sum the base bucket plus
  any active free-trial or bonus credits (skipping `EXPIRED` entries).

### Tests

35+ new test cases across `kirobridge` and `kiroapi`. Full `go test ./...`
green across all 17 packages.

### Still deferred

- `source.type=url` image fetching (caller's responsibility for now).
- Anthropic `metadata.user_id` is now parsed for session_id but other
  metadata fields are still ignored.

---

## v0.7.0 — kirobridge: Anthropic /v1/messages ↔ Kiro translation

Lets a fork proxy `/v1/messages` requests to a Kiro credential pool without
hand-rolling 4000+ lines of conversion logic.

### New package

- **`kirobridge`** — Anthropic ↔ Kiro translation layer.
  - `Convert(req *AnthropicRequest, opts ConvertOptions) (*KiroRequest, error)`
    — folds Anthropic `system` into the current user message as a
    `--- CONTEXT ENTRY BEGIN ---` block (Kiro has no top-level system field);
    converts `messages[…]` history (including `tool_use` / `tool_result`
    blocks) into Kiro's `history[]` + `userInputMessageContext.toolResults`;
    maps Anthropic tools to Kiro `toolSpecifications`.
  - `MapModel(anthropicName) string` — table-driven model mapping with
    prefix fallback to `"auto"`.
  - `StreamTranslator(src *kiroapi.Stream, model, msgID)` — converts a Kiro
    event-stream into the Anthropic SSE event sequence: `message_start`,
    `content_block_start` / `content_block_delta` / `content_block_stop`
    (for both text and tool_use blocks), `message_delta`, `message_stop`.
  - Typed Anthropic + Kiro request/response models so the translation has
    no `interface{}` in its hot path.

### Verified

10 unit tests including round-trip of text deltas, multi-block tool_use,
history with tool_result, model mapping, and conversation_id derivation.
End-to-end test exercises `Convert` → `kiroapi.GenerateAssistantResponse`
(httptest) → `StreamTranslator` → SSE event sequence.

### Deferred to v0.7.x

- Image content block translation (currently emitted as a stub line).
- Full JSON-schema normalization for MCP-defined tools (schema is passed
  through verbatim; works for well-formed schemas).
- WebSearch tool transform (kiro.rs `anthropic/websearch.rs` is ~760 LOC of
  domain logic; ship separately once a fork actually needs it).

### Versioning

v0.7.x is the bridge; v1.0.0 still waits on hypitoken to consume Phase 3
mimicry+sidecar (independent of kiro work).

---

## v0.6.0 — Kiro / Amazon Q foundation

Adds the four-package isolated subtree for talking to the Kiro / kiro-cli
AI service (AWS CodeWhisperer + Amazon Q). Independent from the existing
Anthropic / Codex packages — no shared imports.

### New packages

- **`kiroauth`** — Kiro credential lifecycle.
  - PKCE helpers (`NewPKCE`, `SignInURL`) + `Client.ExchangeCode` for the
    `app.kiro.dev/signin` → `/oauth/token` flow.
  - `Client.RefreshSocial` (Kiro-native `/refreshToken`, body `{refreshToken}`).
  - `Client.RefreshIdC` (AWS SSO OIDC, standard `grant_type=refresh_token`).
  - `Client.Logout` to revoke a refresh chain server-side.
  - `Credentials` struct + `File` loader/saver (camelCase JSON, single-object
    or array form, atomic write with refresh-token rotation writeback).

- **`kirotransport`** — transport primitives shared by all Kiro clients.
  - `eventstream` subpackage: AWS event-stream binary frame codec
    (12B prelude + headers + CRC32 + payload + CRC32), `Decoder` with
    `Skip` / `SkipFrame` recovery for malformed bytes.
  - Pinned fingerprint constants for IDE (kiro.rs-style: aws-sdk-js +
    KiroIDE) and CLI (capture-style: aws-sdk-rust + AmazonQ-For-CLI) flavors.
  - `SignV4` — minimal AWS Signature V4 v4 implementation (sufficient for
    the toolkit-telemetry endpoint; we don't implement chunked signing or
    presigned URLs).
  - Header helpers: `UserAgent`, `XAmzUserAgent`, `ApplyCommonAWSHeaders`,
    `ApplySmithyHeaders`, `ApplyBearerAuth`.

- **`kirocognito`** — anonymous STS provider.
  - `Provider` wraps `GetId` + `GetCredentialsForIdentity` against the
    public anonymous pool (`us-east-1:820fd6d1-…`). Caches creds with
    5-min pre-expiry refresh.

- **`kiroapi`** — typed CodeWhisperer / Amazon Q clients.
  - `Client.ListAvailableModels` (sync RPC, Smithy x-amz-json-1.0).
  - `Client.GenerateAssistantResponse` (streaming; returns `Stream` iterator
    over decoded event-stream frames).
  - `Client.SendTelemetryEvent` (per-turn business metrics).
  - `ToolkitTelemetryClient.Send` (SigV4-signed `/metrics` via Cognito creds).
  - Typed event payloads: `AssistantResponseEvent`, `ToolUseEvent`,
    `ContextUsageEvent`, `MessageMetadataEvent`; structured
    `RemoteError` / `RemoteException` for non-event frames.

### Wire verification

All shapes verified against `crack/kiro/rows/` captures (kiro-cli 2.4.1,
2026-05-24 session). Bumping the kiro client target requires updating one
constants file (`kirotransport/fingerprint.go`) — version, UA segments,
profile ARN.

### Versioning policy

v0.6.x is foundation-only; `kirobridge` (Anthropic /v1/messages translation
layer) lands in v0.7.0. v1.0.0 still waits on hypitoken consuming Phase 3
mimicry+sidecar.

---

## v0.5.0 — Feature-complete; API audit

No new packages. Codifies the API surface that resulted from the
v0.2.0–v0.4.0 absorption work and adds a `Stability` section to the
README so downstream forks know what they can rely on.

### 11 packages, all exported APIs reviewed

```
auth         credential pool + OAuth refresh + Codex JWT + uTLS + login
thinkingsig  thinking-block signature sanitization on credential switch
usage        token consumption ledger (Counts + Store)
pricing      (provider, model) → USD calculator
requestlog   daily-rotated JSONL + Filter/Query/Aggregate
clienttoken  bearer-token registry (Token + Store, Lookup returns (Token, bool))
ratelimit    RPM + Concurrency gates (zero-value-usable)
advisor      advisor-tool-2026-03-01 iterations[] parser
stream       Decompress(*http.Response) + SSEScanner
mimicry      Claude Code header + body fingerprint (CC 2.1.146 pinned)
sidecar      bootstrap + heartbeat Manager
```

### Versioning policy (post-v0.5.0)

- v0.5–v0.x: API may still change as forks finish consuming. Each break
  is called out in CHANGELOG, but no deprecation cycle is guaranteed.
- v1.0.0: once both CPA-Claude AND hypitoken consume mimicry + sidecar
  end-to-end, public API freezes; subsequent breaks go through a
  deprecation cycle.

### Notes

- CPA-Claude consumes Phase 1+2+3 in full (data layer + ratelimit +
  advisor + stream + mimicry + sidecar). `internal/server/` no longer
  has `fingerprint.go`, `mimicry.go`, `sidecar.go`, `ratelimit.go`.
- hypitoken consumes Phase 1+2 (data layer + ratelimit). Local
  fingerprint/mimicry/sidecar still byte-identical to cc-core's —
  switch is a mechanical follow-up, not a correctness gap.

---

## v0.4.0 — Phase 3 mimicry + sidecar (high-value, fingerprint-sensitive)

Pulls the two CC-fingerprint-heavy packages out of CPA-Claude
internal/server/ so any fork can present as a real Claude Code client
without re-implementing the body/header dance.

### New packages

- **`mimicry`** — header + body Claude Code mimicry.
  - `ApplyClaudeCodeBodyMimicry(body, model, SimIdentity)`: rewrites
    `/v1/messages` body to the 3-block CC system layout, signs the cch
    billing header via xxhash64-with-seed, populates `metadata.user_id`
    in CC >= 2.1.78 JSON form. Skipped on Haiku and on bodies that
    already look like real CC.
  - `ApplyClaudeCodeHeaders(req, token, kind, stream, isAnthropicBase,
    SimIdentity, body)`: pinned UA / X-Stainless / Anthropic-Beta /
    X-App / session-id headers. `kind` is `mimicry.KindOAuth` or
    `mimicry.KindAPIKey` (plain strings — no auth-package coupling).
  - `SimIdentity`: stable per-account fingerprint anchor (AccountKey,
    AccountUUID, ClientToken).
  - `DeviceIDFor` / `SessionIDFor` / `BuildJSONUserID`: content-addressed
    helpers so device_id, session_id, and metadata.user_id agree across
    headers and body.
  - Constants `CLICurrentVersion`, `ClaudeCLIUserAgent`,
    `ClaudeAnthropicBetaFull`, ... pinned to CC 2.1.146.
  - 8 golden tests verifying the structural invariants captured in
    `crack/oauth/rows/17`.

- **`sidecar`** — full sidecar Manager pulled wholesale from
  `internal/server/sidecar.go` (1278 LOC).
  - `Manager` tracks one virtual session per OAuth account. `Notify(a,
    clientToken)` fires the 9-step CC bootstrap (Phase B), the quota
    probe, and the event_logging heartbeat (Phase C). Datadog phase
    intentionally left disabled (the public intake key is a pinned
    fingerprint Anthropic could rotate or monitor).
  - `Config{Enabled, UseUTLS, BaseURL}` exported for plain construction.
  - Re-uses `mimicry.CLICurrentVersion`, `mimicry.ClaudeCLIUserAgent`,
    `mimicry.NewRequestUUID`, `mimicry.DeviceIDFor`, etc. — single
    source of truth for the CC version target.
  - 8 tests from CPA-Claude moved verbatim and pass (23s wall-clock —
    they exercise real bootstrap+heartbeat timing).

### Test coverage

`go test ./...` from a clean check-out: 9 packages green
(`advisor / clienttoken / mimicry / pricing / ratelimit / requestlog /
sidecar / stream / thinkingsig / usage`).

---

## v0.3.0 — Phase 2 framework-agnostic gates + parsers

Extracts three pure helpers that were inlined in CPA-Claude `internal/server/`.
None depend on HTTP frameworks, so they drop into any Go project.

### New packages

- **`ratelimit`** — sliding-window RPM gate (`RPM.Allow(key, limit)`) and
  in-flight concurrency gate (`Concurrency.Begin(key)`) keyed on arbitrary
  strings. Both zero-value-usable and `sync.Map`-backed. `Concurrency.Begin`
  returns an idempotent release closure so `defer` patterns are leak-free.

- **`advisor`** — parser/aggregator for `usage.iterations[]` added by the
  `advisor-tool-2026-03-01` beta. `SubUsage.ReplaceFrom` overwrites on every
  SSE observation (server emits cumulative iterations) to prevent double
  counting. Billing/storage stays in the fork — this package is parsing only.

- **`stream`** — `Decompress(*http.Response)` transparently swaps `gzip`/`br`
  upstream bodies for plain readers + strips Content-Encoding/Length, so
  downstream consumers see plain bytes. `SSEScanner` is a tiny event-aware
  line scanner that lets callers re-emit lines verbatim while also parsing
  `data:` payloads (the dual mode CPA-Claude's streamSSE needs).

### Test coverage

Each new package has unit tests. Combined LOC: ~400 (source) + ~400 (tests).

---

## v0.2.0 — Phase 1 lower the foundations

Adds the four "infrastructure" packages that were previously duplicated
between CPA-Claude and hypitoken. Single-source-of-truth for the data
layer (token counts, prices, request log records, bearer token registry).

### New packages

- **`usage`** — per-credential and per-client-token consumption ledger.
  Daily / hourly / weekly buckets, atomic persistence, background flusher.
  Includes hypitoken's reliability improvements: probe-write at open (fast
  fail on misconfigured `state_dir`) and dirty-flag restore on flush
  failure (prevents silent state loss).

- **`pricing`** — `(provider, model) → USD` calculator with built-in
  Anthropic + Codex / OpenAI catalog. CPA-Claude's full table is taken as
  the baseline; forks that don't surface a particular SKU can ignore it
  (entries are only consulted when a request actually names the model).

- **`requestlog`** — daily-rotated JSONL with channel-buffered writer +
  retention GC + token-mask rewrite. `Record` is the unified superset
  shape across CPA-Claude (BilledUSD/Multiplier) and hypitoken (UserID).
  All SaaS-only fields are `omitempty`, so single-user JSONL output is
  byte-compatible with previous versions.

- **`clienttoken`** — bearer token registry with per-token policy
  (RPM, concurrency, weekly USD, credential group).

### Breaking changes

- **`clienttoken.Store.Lookup` signature changed** from
  `(name string, maxConc int, group string, ok bool)` to
  `(Token, bool)`. Future Token fields no longer ripple into the call
  signature. Callers should switch to `tok, ok := s.Lookup(...)` and read
  the fields they need from `tok`.

### Bug fixes

- `auth/codex_usage.go`: `fmt.Errorf("%s", a.Kind)` → `%v` (vet warning).

### Test coverage

Every new package ships with unit tests (~600 lines across 4 packages).
`go test ./...` passes from a clean check-out.
