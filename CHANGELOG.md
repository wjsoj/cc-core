# Changelog

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
