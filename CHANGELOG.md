# Changelog

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
