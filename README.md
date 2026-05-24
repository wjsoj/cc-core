# cc-core

Shared core for [CPA-Claude](https://github.com/wjsoj/CPA-Claude) and downstream forks. Tracks the stable layer of credential management and identity-bound request safety so the integration layer (admin UI, proxy wiring, business logic) can diverge per fork without forking the core.

## Packages

### `auth`

Credential pool, scheduling, OAuth refresh (Anthropic + Codex/ChatGPT), JWT parsing, uTLS Chrome client, session-cookie login flow, daily reset job, group routing.

- `auth.Pool` — sticky-session credential scheduler keyed on `(provider | clientToken)`. Handles fewest-active selection, API-key fallback, group filtering.
- `auth.Auth` — credential record. OAuth and API-key kinds.
- `auth.ClientFor(proxyURL, useUTLS)` — uTLS Chrome-fingerprinted HTTP client.
- `auth.LoginWithSessionCookie` — server-side OAuth via a `claude.com` `sessionKey` cookie.
- `auth.ParseCodexIDToken` — extract `chatgpt_account_id` / `chatgpt_plan_type` from Codex OAuth id_token.

### `thinkingsig`

Mid-conversation account-switch detection plus `thinking`-block signature sanitization. Anthropic binds the cryptographic `signature` on `thinking` blocks to the issuing account; rotating credentials mid-stream yields `400 signature in thinking` unless prior assistant blocks are scrubbed.

- `thinkingsig.NewSwitchTracker()` — per-(clientToken, conversation) last-auth observation.
- `thinkingsig.SanitizeForSwitch(body)` — drop signed `thinking` blocks from past assistant messages and strip proxy-injected `tool_use.signature` fields.

### `usage`

Per-credential and per-client-token consumption ledger. Daily / hourly / weekly buckets, atomic file persistence (fsync + rename), background flusher with 5s tick, automatic retention trimming. Used by both single-user and multi-tenant deployments.

- `usage.Counts` — input/output/cache_read/cache_create/requests/errors token counters with `Add()` and cost-weighted `WeightedTotal()` for the OAuth load balancer.
- `usage.Open(path)` — file-backed store with periodic flush.
- `usage.OpenInMemory()` — same API, no goroutine, no disk I/O (tests + ephemeral processes).
- `usage.Store.Sum5h(authID)` / `Sum24h(authID)` — rolling-window aggregates for the credential picker.

### `pricing`

`(provider, model) → USD` cost calculator. Built-in catalog covers current Claude + Codex / OpenAI models; user `Config{Default, ProviderDefaults, Models}` overrides on top. Four-level fallback (exact → prefix → provider default → global default), thinking-suffix and dated-variant aware.

- `pricing.NewCatalog(Config)` — build a Catalog with built-ins merged with overrides.
- `pricing.Catalog.Cost(provider, model, usage.Counts) float64` — direct lookup + dollar math.

### `requestlog`

One-JSON-line-per-terminal-request log with daily file rotation (`requests-YYYY-MM-DD.jsonl`), bounded buffered channel, retention GC, and a token-mask rewrite tool. Record schema is the unified shape for single-user + SaaS-tier deployments (SaaS-only `UserID / BilledUSD / Multiplier` fields are `omitempty`).

- `requestlog.Open(dir, retentionDays)` — start the writer.
- `requestlog.Query(Filter)` — paged + aggregated query across rotated files.
- `requestlog.AggregateHourly(dir, hours)` / `AggregateByAuth(dir, from, to)` — dashboards.
- `requestlog.Writer.RewriteClientMask(old, new)` — historical telemetry migration for token rotation.

### `kiroauth` / `kirotransport` / `kirocognito` / `kiroapi` — Kiro / Amazon Q (CodeWhisperer) primitives

Isolated subtree for talking to the **Kiro / kiro-cli** AI service (AWS
CodeWhisperer + Amazon Q). Independent from the Anthropic / Codex packages
above; the only shared import is `thinkingsig` (used by `kirobridge` in v0.7.0).

- `kiroauth` — PKCE login (`/oauth/token`), Social refresh (`/refreshToken`),
  IdC refresh (AWS SSO OIDC `/token`), `/logout`. Multi-credential JSON file
  (single-object or array) with priority-sort, atomic save, and rolling-refresh
  writeback.
- `kirotransport` — pinned client fingerprints (KIRO-CLI 2.4.1 / KiroIDE 0.2.43,
  aws-sdk-rust 1.3.16 / aws-sdk-js 1.0.34), AWS SigV4 v4 signer (for the
  toolkit-telemetry endpoint), and `eventstream` subpackage with the binary
  frame codec (12B prelude + headers + CRC32 + payload + CRC32).
- `kirocognito` — `GetId` + `GetCredentialsForIdentity` against the public
  anonymous pool (`us-east-1:820fd6d1-…`). Yields short-lived STS creds
  used only for signing toolkit-telemetry; never touches the business API.
- `kiroapi` — typed clients for `ListAvailableModels`, `GenerateAssistantResponse`
  (streaming, returns a frame iterator), `SendTelemetryEvent` (per-turn
  business metrics), and `ToolkitTelemetry` (SigV4-signed `/metrics`).
- `kirobridge` (v0.7.0) — Anthropic `/v1/messages` ↔ Kiro translation.
  `Convert()` builds a `KiroRequest` from an `AnthropicRequest` (system →
  context entry, messages → history, tools → toolSpecifications, tool_result
  → toolResults). `StreamTranslator` turns the Kiro event-stream into the
  Anthropic SSE event sequence (`message_start` → `content_block_*` →
  `message_delta` → `message_stop`).

Verified against `crack/kiro/rows/` (real kiro-cli 2.4.1 captures). Bumping
the kiro client target is a one-place change in `kirotransport/fingerprint.go`.

### `clienttoken`

Runtime store of accepted client bearer tokens (`Authorization: Bearer sk-…`) and per-token policy (concurrency cap, RPM, weekly USD cap, credential group).

- `clienttoken.Open(path)` / `OpenInMemory()` — JSON-file-backed or memory store.
- `clienttoken.Store.Lookup(tok) (Token, bool)` — full Token by value; future fields don't break callers.
- `clienttoken.Generate()` — fresh `sk-<48 char>` token.

## Layering

```
auth ─┐
       ├─► clienttoken (auth.NormalizeGroup)
       └─► thinkingsig (uses auth.Auth in callers)
usage ─► pricing (usage.Counts is the cost input)
requestlog (independent)
```

No cyclic deps. Every package is independently testable. All packages avoid HTTP framework lock-in (pure `net/http` / no `gin`, `echo`, etc.).

## Versioning & stability

Semver. **v0.5.0 = feature-complete; API frozen for consuming forks,
modulo follow-up cleanup**. Breaking changes between v0.5.x and v1.0.0
will be called out in `CHANGELOG.md` but won't go through a deprecation
cycle. v1.0.0 will be tagged once both CPA-Claude and hypitoken consume
the mimicry + sidecar packages end-to-end (currently CPA-Claude fully
consumes Phase 1+2+3; hypitoken consumes Phase 1+2).

### Stability matrix

| Package | API stability | Notes |
|---|---|---|
| `auth` | **stable** | Pool / Auth / login flows; battle-tested in two production forks |
| `thinkingsig` | **stable** | Used in every chat turn; no recent changes |
| `usage` | **stable** | State.json wire format unchanged since pre-cc-core |
| `pricing` | **stable** | Built-in catalog may grow but signatures won't |
| `requestlog` | **stable** | Record wire format is the unified superset across forks |
| `clienttoken` | **stable** | Lookup returns `(Token, bool)` so new Token fields don't break callers |
| `ratelimit` | **stable** | Pure value-types, zero-value-usable |
| `advisor` | **stable** | Parser only; billing decisions stay in fork |
| `stream` | **stable** | Thin wrappers over net/http + bufio |
| `mimicry` | **may evolve** | CC version target bumps will change the pinned constants in lockstep; signatures stable |
| `sidecar` | **may evolve** | Same as mimicry — bumping CC version may add bootstrap steps |
| `kiroauth` | **may evolve** | Public API of `Client` is stable; multi-credential pool helpers may be added |
| `kirotransport` | **may evolve** | SigV4 + event-stream codec are stable; fingerprint constants track upstream releases |
| `kirocognito` | **stable** | Wraps two AWS-side calls; surface won't grow |
| `kiroapi` | **may evolve** | Typed model fields may grow as new event-types appear in captures |
| `kirobridge` | **may evolve** | v0.7.0 covers text + tool_use round-trips; image / websearch / schema-normalization land in v0.7.x |

## License

MIT. Anthropic OAuth refresh and uTLS transport originally adapted from [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (MIT).
