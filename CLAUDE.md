# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

cc-core (`github.com/wjsoj/cc-core`) is the **shared library** behind two sibling reverse-proxy forks — **CPA-Claude** (`/home/wjs/Documents/project/Go/CPA-Claude`, the leaner one) and **hypitoken** (`/home/wjs/Documents/project/Go/hypitoken`, which adds SaaS/shop/market/Kiro product layers). Both Go modules are confusingly *both* named `CPA-Claude`; both import this module. It has **no binary and no `main`** of its own — it is consumed, not run.

Everything that is identity-, credential-, billing-, or fingerprint-bearing lives here so the two forks can't drift apart on the parts that must stay byte-identical to a real client. A change here reaches production only when a fork **bumps the `cc-core` dependency and redeploys** — so the release unit is a git tag (`v0.8.x`), and "fix it in cc-core, then bump both forks" is the standard loop.

Derivative of [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (MIT); the Anthropic OAuth refresh, Codex JWT parsing, and uTLS Chrome transport originated upstream.

## Build & test

No Makefile, no bun, no in-repo CI — this is a pure Go library (go 1.25).

```bash
go build ./...                              # compile everything
go test ./...                               # all tests
go test ./auth/ -run TestSessionsHeld -v    # a single test
go test ./sidecar/ -timeout 60s             # sidecar suite runs ~23s of real timing
go vet ./...
```

### Releasing (the important workflow)

```bash
git tag v0.8.NN && git push origin main v0.8.NN
```

Then in each consuming fork: `go get github.com/wjsoj/cc-core@v0.8.NN && go mod tidy`, rebuild, redeploy. Tags are lightweight, on a commit whose subject already describes the change. **Both forks share this repo as their working tree's sibling** — if another agent/session is mid-change here, only commit and push your own files (check `git status` before tagging), and use the next free tag number if yours is taken.

## Architecture — the subsystems that span files

### `auth` — the credential scheduler + health state machine (most load-bearing, most edited)

`auth.Pool` (`pool.go`) schedules OAuth/API-key credentials. `Acquire(ctx, provider, clientToken, group, model, exclude...)`: sticky reuse of a healthy assignment → fewest-active-sessions among healthy OAuth in the group with spare `max_concurrent` → API-key fallback. `Release`/`Unstick`/`ReportUpstreamError` take the same `sessionID`. A "session" is one `(provider, clientToken, sessionID)` slot within `ActiveWindow`; `SessionsHeld` reports how many slots a token holds (input to the forks' per-token WS fair-share cap).

**Health lives on `auth.Auth` (`types.go`) and every rule here has bitten production — treat this as a spec, not a heuristic:**
- `MarkSuccess/Failure/HardFailure/RateLimited/UsageLimitReached/ClientCancel`. `ConsecutiveFailures ≥ hardFailureThreshold` (**5**) auto-hard-fails an OAuth credential; **API keys never auto-hard-fail** (`Kind == KindAPIKey` short-circuits `IsHealthy`) — only a manual disable takes them offline. `Consecutive429s ≥ 15` → suspected stealth-ban hard-fail.
- **`IsHealthy` degraded self-recovery** (`degradedProbeAfter`, **5 min**): a credential with `ConsecutiveFailures ≥ 2` is quarantined, but re-probed once the interval elapses — otherwise unhealthy → never Acquired → never a success to reset the counter → *permanently* dark. `HealthSnapshot` (admin panel) duplicates this logic without re-locking; **keep the two in sync.**
- `MarkClientCancel` records a timestamp only — client disconnects must NOT touch failure counters or cooldowns.
- `ReportUpstreamError` maps 429 → rate-limit + cooldown, 401/403 → cooldown (no `MarkFailure`), 529/≥500 → `MarkFailure`.

**Transient-vs-credential classification** (`retry.go`, `IsTransientNetErr` + `transientErrFragments`): wire-level flaps (`connection reset`, `broken pipe`, `unexpected EOF`, h2 `GOAWAY`/`PROTOCOL_ERROR`/`REFUSED_STREAM`, `http2: client conn not usable`/`no cached connection`/`client connection lost`) are retried on the **same** credential by `retryRoundTripper` and must never `MarkFailure`. Missing a string here is how a CF-edge h2-connection death once cascaded into a whole Codex pool going dark (a dead pooled conn fails every in-flight stream at once → a burst of `MarkFailure` → threshold crossed). Add regression cases to `retry_test.go` with the *verbatim* error string.

Also in `auth`: Anthropic login (`login.go` PKCE, `login_session.go` session-cookie flow, `oauth.go` credential-file `parseFile`), Codex OAuth (`codex_jwt.go` plan/account claims, `codex_refresh.go`, `codex_models.go` per-plan `/v1/models`, `codex_usage.go` wham/usage windows), `hostprofile.go` (per-account synthetic Linux host), `utls.go` (Chrome-fingerprint HTTP client, cached per proxy URL).

### `mimicry` — the Claude fingerprint (header + body)

`ApplyClaudeCodeHeaders` + `ApplyClaudeCodeBodyMimicry` make a request look like a real Claude Code **2.1.211** client. Version constants (`CLICurrentVersion`, `ClaudeCLIUserAgent`, `ClaudeAnthropicBetaFull`, telemetry-only `ClaudeReportedBetas`) are in `fingerprint.go` — **they all move together** on a version bump or the User-Agent disagrees with the body's `cc_version=` billing block. `SimIdentity{AccountKey, AccountUUID, ClientToken}` is the identity anchor: `DeviceIDFor` (sha256, identical for all traffic on one OAuth account), `SessionIDFor` (per-conversation, feeds both the body `metadata.user_id.session_id` and the `X-Claude-Code-Session-Id` header). Body mimicry is **skipped for Haiku** and for systems already starting with the CC prompt. Codex has its own constants (`codex.go`, `CodexCLIVersion` = **0.144.4**).

### `sidecar` — auxiliary traffic emulation

`Manager.Notify(auth, clientToken)` fires, on first touch of an `(account, clientToken)` pair, the bootstrap burst + heartbeats real CC emits at startup (GrowthBook, oauth/account/settings, bootstrap, quota probe, mcp-registry, event_logging `/v2/batch` every ~18s, …), each with its own captured `User-Agent`/`Anthropic-Beta`. Per-account host telemetry comes from `auth.HostProfile` so distinct accounts don't all advertise one identical machine. **API-key credentials never trigger sidecars.** The Datadog heartbeat is defined but deliberately unwired. Tests run against a live `httptest.Server` with real timing (~23s).

### `crack/` — capture archive = fingerprint ground truth

Recorded real-client traffic anchoring every constant in `mimicry`/`sidecar`/`auth/codex_*`/`kiro*`. Current Claude target **2.1.211** in `crack/cc2211/` (`SPEC.md` = authoritative constants + diff + edit checklist; `rows/` = structurally-redacted requests). `codex/` (`codex-tui/0.144.4`), `kiro/`, `oauth/`, `apikey/`, `login/` cover the rest. `scripts/extract_live.py` keeps fingerprint-bearing structure and `<masked>`s all identity/prose; raw dumps are never committed.

**Bumping the CC version target** (a cc-core-only change): capture a fresh dump → `extract_live.py <dump> crack/cc<ver>/rows` → write `crack/cc<ver>/SPEC.md` → update constants in `mimicry`/`sidecar` (User-Agent, betas, body layout, sidecar steps all together) → tag a release → bump the dependency in **both** forks. See `crack/cc2211/SPEC.md` for a worked diff.

### The ledger + gates

- `usage` — per-auth and per-client-token consumption (`Store.Record` for auth token totals + load-balancing weight via `WeightedTotal`; `RecordClient`/`WeeklyCostUSD` for client billing). `Counts` carries token counts (+`Requests`); cost is passed alongside, not stored in `Counts`.
- `pricing` — `(provider, model)` → per-token USD (input 1× / cache_create 1.25× / cache_read 0.1× / output 5× weighting mirrors the load-balance signal). Catalog is append-only; new models must be added or they bill at 0.
- `requestlog` — one JSON line per terminal request to a daily file; the forks' admin "total cost per credential" is a scan-and-aggregate over these.
- `ratelimit` — keyed `RPM` + `Concurrency` (pure counters; policy/limit lives in the caller).
- `clienttoken` — runtime store of client access tokens.
- `clientguard` — shared ingress UA blocklist.

### Other transports & helpers

- `codexws` — Codex-over-WebSocket upstream transport (real codex-tui speaks `/v1/responses` over WS; forks relay per-turn).
- `kiroapi` / `kirobridge` / `kiroauth` / `kirocognito` / `kirotransport` — the AWS CodeWhisperer / Kiro bridge (typed client + Anthropic↔Kiro translation + Cognito PKCE), used by hypitoken's Kiro path.
- `thinkingsig` — mid-conversation credential-switch detection + `thinking`-signature sanitization/recovery.
- `advisor` — parses `message_delta.usage.iterations[]` (advisor sub-call billing).
- `stream` — framework-agnostic SSE relay (keepalive + lazy commit + terminal detection); the forks' streamers wrap it.
- `backup` — off-host encrypted (NaCl) snapshot of an app's critical SQLite/state.

## Conventions worth knowing

- **All identity derivation is content-addressed** — no random UUIDs except `X-Client-Request-Id` and the internal `event_id`. New stable identifiers derive from `accountKey` (or `accountKey + clientToken` when they should differ per downstream user), so they survive credential-file rotation.
- **OAuth credential-file fields are append-only** — `parseFile` (`auth/oauth.go`) tolerates missing fields via the `_ = raw["new_field"].(...)` pattern so old files keep loading.
- **Pricing & health thresholds are behavioural constants** — changing `hardFailureThreshold`, `degradedProbeAfter`, the pricing weights, or a `transientErrFragments` entry changes production behaviour in both forks at once. Pair every such change with a test.
- **Fingerprint constants must match `crack/`** — never hand-edit a User-Agent/beta/body-shape without a capture backing it; the diff belongs in `crack/cc<ver>/SPEC.md`.
