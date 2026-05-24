# Changelog

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
