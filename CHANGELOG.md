# Changelog

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
