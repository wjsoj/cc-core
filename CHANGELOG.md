# Changelog

## v0.8.103 — the model list a Codex client actually reads

A Codex client pointed at a third-party gateway does not populate its model
picker from the plain OpenAI `/v1/models` listing. It refreshes from
`GET {base_url}/models?client_version=<ver>` in custom-provider mode, or
`GET /backend-api/codex/models` in chatgpt_base_url mode, and both want the
ChatGPT backend's own manifest shape — `{"models":[{slug, display_name,
minimal_client_version, supported_reasoning_levels, context_window, …}]}`,
not `{"object":"list","data":[{"id":…}]}`.

Answering with the OpenAI list does not fail loudly. The client cannot parse it,
silently falls back to the model set compiled into that build, and the user
never sees anything the gateway added after their CLI shipped. That is exactly
why gpt-6-astra stayed invisible after it was added to the catalog and priced.

`auth/codex_manifest.go` adds:

- `CodexModelsRequest` — the discriminator. Presence of `client_version` is the
  signal, not its value; CLIProxyAPI keys on presence alone and exercises a bare
  `?client_version` in its own tests.
- `FetchCodexModelsManifest` — proxies the real manifest from upstream with an
  OAuth credential, returning the body verbatim. Verbatim because the payload is
  ~400 KB of capability flags and instruction templates on a schema the backend
  revises without notice; decoding it into a struct would drop precisely the
  fields the client needs. This is sub2api's approach and it is self-maintaining
  — a model the backend adds tomorrow appears with no code change here.
- `SynthesizeCodexModelsManifest` — the fallback for deployments with no OAuth
  credential to borrow, built from `CodexModelCatalog` plus transcribed
  structural specs. Omits the instruction templates on purpose: only the real
  backend can author those, and a client that does not get them falls back to
  its own, which is the correct degradation.
- `FilterCodexManifest` — honours each entry's `minimal_client_version`, because
  upstream filters by the account's plan but not by the caller's version, and
  trims xhigh/max/ultra for pre-0.144 clients that refuse to render a model
  advertising an effort they do not know.
- `CodexManifestCache` — per-version singleflight and TTL, and a failed refresh
  serves the stale body rather than an empty picker. Catalogs change on the
  order of weeks; stale always beats empty here.

`mimicry` gains `CodexModelsOriginator` / `CodexModelsUserAgent`. The models
fetch is a different client component from the turn: the capture shows it going
out as `codex_cli_rs` with a User-Agent that drops the trailing
`(codex-tui; <ver>)` parenthetical the WebSocket upgrade carries. The UA is
derived from `CodexCLIUserAgent` so a version bump cannot move one and leave the
other behind.

## v0.8.102 — a ChatGPT subscription pays no Fast premium

`ResolveOpenAI` billed a ChatGPT-subscription turn at the Fast (né priority)
2x rate whenever the client had asked for it, on the reasoning that Codex OAuth
reports `default` even for a Fast turn so the observation is not authoritative.

Seven hours of production disagreed with both halves of that. 1567 subscription
turns took the 2x branch: the upstream reported `default` 1565 times and `auto`
70 times and `priority` zero times, and inside a single client token the
priority turns ran at 19.06 tok/s against 22.79 for the same model with no tier
— slower, not faster. $197 of upstream cost was invented, and because
`billed_usd` derives from it, ~$10 of that reached customer wallets.

The cause is not the observation, it is the price model. Fast and Flex are
OpenAI **API price-page** tiers: an API key can buy faster service at 2x or
cheaper at 0.5x. A ChatGPT Plus/Pro plan buys neither — the plan price is flat,
priority routing is already part of it, and the upstream charges us the same
either way. So on the `CodexOAuth` path the tier now never moves the bill in
either direction. `Requested` and `Observed` are still reported, because the
request log and the routing hint both read them.

The API-key path is unchanged: requested tier bills, an observation may only
lower it.

## v0.8.101 — gpt-6-astra, the Codex 0.153.4 fingerprint, and Fast/Priority billing

Two changes landed together because neither is safe alone: the model is useless
without a price, and the price is unreachable without the version bump.

**gpt-6-astra.** The model appeared in the upstream Codex catalog with no card
here, so it billed at `builtInProviderDefaults[openai]` — 12.5% of published
input, 20% of output, and nothing at all for cache writes. Its card is now the
published rate ($10.00 in / $1.00 cached / $12.50 cache-write / $50.00 out,
developers.openai.com/api/docs/pricing, verified 2026-09-05). No sol-style
subscription markup: sol departs from the page because its page price is an
API-only promotion, and astra has none. No bare `gpt-6` alias, because the
prefix fallback would then capture every future `gpt-6-*` SKU at flagship rates.

astra also joins `auth.CodexModelCatalog` on all four plans — justified by the
capture's per-model `available_in_plans`, not by analogy with gpt-5.5 — and that
file gained its first test.

Two silent mis-classifications went with it. `codexResponsesLiteModel` guessed
Responses-Lite from a `gpt-5.6` prefix, but the backend declares it per model
(`use_responses_lite`), and astra is Lite: every astra turn without client tools
would have had the `image_generation` built-in injected and 400ed. It is an
explicit set now. `apicompat.isReasoningModel` likewise stopped at `gpt-5`, so a
chat-completions client could forward `temperature` into a rejection.

**Codex fingerprint 0.147.0 → 0.153.4**, from a live capture in
`crack/codexv0.153.4/` (the CLI profile; the Desktop archive still governs
Desktop). Version, User-Agent — both version segments *and* `Konsole/260401` →
`260800` — and `x-codex-beta-features`, which converged with Desktop's
`remote_compaction_v2`.

`DefaultCodexProfile()` moved from Desktop to codex-tui. astra's
`minimal_client_version` is `0.153.0` and Desktop self-reports `0.147.0`, so a
Desktop identity cannot reach the flagship; Desktop cannot be bumped from a CLI
capture, because its version, build number and terminal segment are three values
the backend cross-validates. Re-visit when a Desktop capture ≥ 0.153.0 exists.

`x-codex-routing-hint` is sent on the WebSocket handshake again. It was removed
on the strength of the 0.135.0 and 0.147.0 captures; all three upgrades in the
0.153.4 capture carry it, between `x-codex-turn-metadata` and
`sec-websocket-extensions`. It is **not** defaulted to `tier=priority` despite
every captured handshake showing that value — claiming a tier the request did
not ask for is served as an upgrade and billed as standard.

`x-codex-turn-metadata` grew from 8 fields to 15 (17 on a subagent connection).
Three are not strings, so `Encode` needed a typed writer; `window_id` re-anchors
on the thread rather than the session, which only a capture separating the two
could show; `context_window_id` is derived to share the thread id's first four
groups, as the real client's does.

`codexws/capture_parity_test.go` now checks the synthesized handshake against
the capture *file* rather than against constants copied out of it — the check
that would have caught the routing-hint claim two releases earlier.

**OpenAI Fast/Priority billing.** Normalize `fast` to `priority` across Chat
translation, Codex HTTP and WS. `pricing.CostWithOptions` applies the
service-tier rate before the host applies its customer multiplier, with
credential-aware response downgrades. Standard `Cost` remains compatible.
Request logs retain requested, observed and billed tiers in JSONL and SQLite.
astra needs no entry in `openAIFastRatios`: its published Fast band is exactly
2× standard, which is the generic fallback.


## v0.8.97 — codex: a session id the upstream prompt cache can hold on to

The HTTP Codex path minted a fresh `session-id` per **request**. That header is
how the backend places a conversation in its prompt cache, so every turn of a
live conversation announced itself as a brand-new one and re-uploaded a context
the account already had cached.

This was harmless for as long as it was invisible. cc-core sent the id under the
misspelled name `Session_id` for two capture generations; the backend ignores a
header name no client sends, so the unstable value never reached it. v0.8.88
(`7bb59a3`) corrected the spelling to `session-id` — and production Codex cache
hit rate fell from ~87% to ~45% over the following days, with a third of all
turns arriving at `cache_read == 0` while carrying more than 10k of context.
Measured over six hours on one deployment: 3953 cold turns, 457M input tokens
re-sent for nothing.

The diagnosis is worth recording because the obvious suspect was wrong. Credential
stickiness was fine — turns that stayed on one credential went cold at 39.8%,
turns that switched at 37.8%, which is no difference at all. Two conversations
running concurrently on the same credential told the story: one read 100736
tokens out of cache while the other, its input climbing 1000 tokens a turn,
never read a single one.

- **`ApplyCodexHeadersWithSession`** takes the conversation's session id from
  the caller. Derive it with `CodexSessionUUIDFor`, or let a
  `codexws.SessionRegistry` own the `(anchor, startedAt)` bookkeeping — the
  registry is not WebSocket-specific despite where it lives, and its doc comment
  now says so. `ApplyCodexCLIHeaders` / `ApplyCodexHeadersWithProfile` keep their
  signatures and still mint per request, which is correct only for a caller with
  no conversation to name.

- **The minted fallback is a UUIDv7**, not the v4 `NewRequestUUID` produced.
  Every session id in both Codex captures is a v7 and the version nibble is
  visible on the wire; `7bb59a3` moved the WS path to v7 and left this one
  behind.

## v0.8.77 — requestlog: answer whole-day windows from the cube

The admin panel's date pickers produce whole-day windows, but a window is
only cube-answerable if the caller says it in days: `cubeEligible` rejected
any timestamp bound, because a pair of instants cannot be shown to be
day-aligned without assuming a bucketing zone. So the panel's default 7-day
view — and every filter applied inside it — took the row-by-row path over
`req`. On the production archive (1M rows, 151k in the window) that was
**1.8s per query, against 48ms from the cube**.

- **`Filter.FromDay` / `Filter.ToDay`** state the window as inclusive
  `YYYY-MM-DD` labels in the bucketing zone — the same labels `ByDay` is
  keyed on and `agg_cube.bday` stores. `resolveDays` expands them into the
  exact `From`/`To` instants every other path already compares against, so
  the scanning path, the entries page and the cube all see one window.

  Alignment is declared, never inferred. Whether an instant is a day
  boundary depends on the display zone, so inferring it would silently
  change which grain answers a query the day an operator changes the zone.

  Supplying labels *and* timestamps is a contradiction rather than a
  refinement: the timestamps win and the labels are dropped, so the cube can
  never answer a window `req` would not.

## v0.8.75 — relay: carry the downstream caller across one trusted hop

When one of our proxies forwards to another using a single API key, the
receiver sees one client. Its scheduler keys sticky assignments on
(provider, client token, session), so every user behind the relay collapses
onto one upstream credential no matter how many are free — the relay's users
get the throughput of one account while the receiver's pool sits idle.

- **New package `relay`** — three headers (`X-Relay-Client-Peer`,
  `X-Relay-Client-Id`, `X-Relay-Client-Session`) plus `Apply` / `Read` /
  `Strip` / `Identity.SlotID`. The client id is a salted hash of the
  downstream token, so the receiver can tell users apart without learning the
  sender's credentials.

  Recovered values are used for **routing only**. Limits, quotas and billing
  stay keyed on the relay's own token: the relay is one customer however many
  users sit behind it, and a limit keyed on a header is a limit anyone can
  evade by inventing a new value.

  `Apply` clears the headers before stamping (an inbound value must never
  survive a hop) and refuses to stamp a blank identity for an unidentified
  caller — one shared blank id would re-create the very pinning this fixes.
  Values are restricted to bounded printable ASCII because they become map
  keys in the receiver's scheduler.

- **`auth.Auth.RelayPeer`** (`relay_peer` in an API-key credential file) — the
  sender's opt-in. Only a credential known to point at a cooperating peer is
  handed our users' identity; to anyone else the headers are noise that leaks
  topology. Append-only, and the round trip is tested: never dropped by a
  rewrite, never invented in a file that lacked it.

- **`clienttoken.Token.TrustedRelay`** (`trusted_relay`) — the receiver's
  opt-in, and the trust boundary. Honour the headers only from a caller
  authenticated as a trusted relay; `Strip` them from everything else.

## v0.8.74 — one place to decide what a shed frame looks like to the client

`DemoteCapacityCode` gave callers the rewrite but left them to assemble the
policy around it, and both consumers assembled the same one independently: a
WS relay cannot fail over, so it must forward the frame with only the two
session-ending capacity codes demoted. That policy is now `codexerr.ClientFrame`.

- **`ClientFrame(payload) (out, shed, capacity)`** — for a relay with no
  failover left (a WebSocket session, or an HTTP stream that already committed
  output). Returns the frame as the client should see it, whether upstream shed
  the turn, and whether the shed was capacity.

  `capacity` splits `ClassRetryable` in half and the split decides who is to
  blame: `server_is_overloaded` / `slow_down` belong to the model and the
  moment — the same request would shed on any account, so nothing about the
  credential should change — while quota and rate codes are account-scoped and
  are the only half worth moving a session off its credential for. Those are
  never demoted; the CLI handles them non-terminally and parses its retry delay
  off the original code.

  Withholding the frame is still strictly better when the caller *can* fail
  over; use `Classify` directly there.

The frame this exists for was captured in production once CPA-Claude's WS relay
finally logged it — inside an otherwise-healthy 200 socket:

```
{"type":"error","error":{"type":"service_unavailable_error",
 "code":"server_is_overloaded","message":"Our servers are currently
 overloaded. Please try again later."}}
```

followed by `response.failed`. Relayed verbatim it reaches codex-rs as
`ApiError::ServerOverloaded`, which is terminal — the session dies with
"Selected model is at capacity. Please try a different model."

## v0.8.73 — apicompat differentially verified against sub2api

`apicompat` was written from the two APIs' semantics, so the mapping was only
as good as the unit tests around it. This release checks it the honest way:
the same corpus is pushed through sub2api's production converter and through
ours, and the outputs are compared field by field. (sub2api runs this exact
bridge for ChatGPT OAuth accounts, where the internal API only speaks
Responses — so it is a real oracle, not a second opinion.)

Request direction, 18 cases: 15 semantically identical, and the corpus found
one real divergence, now fixed.

- **System messages are no longer folded into `instructions`.** They stay as
  input items, in order, exactly where the proven implementation puts them.
  `instructions` is now passed through only when the client sent it. On the
  Codex backend that field always carries the CLI's own system prompt, so
  overwriting it with an arbitrary client prompt was both a fingerprint
  deviation and a departure from the shape that is known to work.
- `tools[].strict` defaults to `false` when the client omitted it, rather than
  being left to the backend.

Three differences are deliberate and kept, in both cases because the reference
looks under-specified rather than intentional:

- `tool_choice` for a forced function is flattened to the documented Responses
  shape `{"type":"function","name":…}`; sub2api passes Chat's nested
  `{"type":"function","function":{"name":…}}` straight through.
- A tool whose `parameters` are absent gets `{"type":"object","properties":{}}`;
  Responses requires `properties` on object schemas, and sub2api applies that
  normalization on its Anthropic path but not this one.

Response direction, 7 streaming cases: identical on every field a client
consumes — text, reasoning, `finish_reason` (including length / content_filter
/ failed), usage, and parallel tool calls' ids, names, assembled arguments and
indexes. The only difference is that this package emits the `[DONE]` sentinel
from the converter while sub2api writes it in its transport layer.

Cosmetic, verified equivalent: this package emits `"type":"message"` on input
items and the `[{"type":"input_text",…}]` content form, where sub2api omits the
type and uses the bare-string form. Both are accepted; the array form is what
real codex-tui sends and what `mimicry.SanitizeCodexRequestBody` already
promotes bare strings into.

## v0.8.72 — chat/completions ⇄ Responses bridge + a lint gate

### New — `apicompat/`

The ChatGPT Codex backend hosts only `/codex/responses`. Every
OpenAI-compatible client that speaks `/v1/chat/completions` (Cherry Studio,
OpenWebUI, LangChain, a bare `openai` SDK) was therefore *structurally*
unroutable to a subscription OAuth credential and could only be served by a paid
relay API key — no matter how idle the subscription accounts were. That is a
protocol gap, not a scheduling one, so no amount of pool tuning could fix it.

`apicompat` is pure data translation in both directions: no HTTP, no gin, no
credential awareness. Callers own transport, keepalive and billing.

- `ChatCompletionsToResponses(body)` — request direction. Handles system/
  developer messages folding into out-of-band `instructions`, tool round-trips
  (`tool_calls` → `function_call`, `role:"tool"` → `function_call_output`),
  legacy `functions[]` / `function_call`, tool-schema normalization (Responses
  requires `properties` on object schemas), multimodal input with empty base64
  data URIs dropped, prior assistant reasoning preserved across turns,
  `reasoning_effort` → `reasoning.effort`, `json_schema` `response_format` →
  `text.format`, `max_tokens`/`max_completion_tokens` → `max_output_tokens` with
  a 128 floor, and sampling parameters withheld from reasoning models (which
  reject them).
- `ResponsesToChatCompletion(response, model, created)` — non-streaming reply,
  with reasoning surfaced as `reasoning_content` rather than folded into the
  answer, and `incomplete_details` mapped onto `finish_reason`.
- `NewStreamState` / `Translate` / `Finalize` / `IsDoneFrame` — the streaming
  state machine, mapping each Responses SSE event onto zero or more
  `chat.completion.chunk` frames. Parallel tool calls keep distinct indexes
  (tracked by both `output_index` and `item_id`, since backends disagree about
  which they populate), and `Finalize` closes a truncated upstream so the client
  sees a short answer instead of a disconnect.

Callers targeting the Codex backend should still run the converted body through
`mimicry.SanitizeCodexRequestBody`, which owns that backend's narrower
whitelist.

Field mappings follow the behaviour of the LGPL project
github.com/Wei-Shaw/sub2api, which covers the same protocol pair in production.
The mappings are facts about the two APIs; this is an independent MIT
implementation of them, not a port of that code.

### Chore — lint gate

cc-core had no lint config, no CI and no Makefile. Adds `.golangci.yml` (default
linter set + gofmt/goimports) and clears all 44 findings it reported. Notable:
`auth.fileFormat` is deleted — dead since `parseFile` went map-based, and already
drifted out of sync with the real on-disk shape.

## v0.8.66 — ChatGPT subscription/billing probe

Adds the commercial-state counterpart to the wham/usage quota probe: which plan
a ChatGPT OAuth credential is on, when its current term was paid for, whether it
renews, whether it is actually free, and whether it is about to lapse for
billing reasons. Delinquency in particular is invisible to every existing
signal — a delinquent account serves traffic normally until its grace period
ends, then stops — so this is the only warning a fork can act on ahead of time.

### New — `auth/codex_subscription.go`

- `(*Auth).FetchCodexSubscription(ctx, useUTLS) (*CodexSubscriptionInfo, error)`
  — merges two portal endpoints in one call:
  `GET /backend-api/subscriptions?account_id=` (term start/end, billing period,
  `will_renew`, seats, delinquency) and
  `GET /backend-api/accounts/check/v4-2023-04-27` (discounts, trial, account
  created_time, purchase platform). Neither is a superset of the other.
  **Partial success is a success** — they fail independently and either alone is
  worth rendering; the error is non-nil only when both fail.
- Stored on the credential as `CodexSubscription` / `CodexSubscriptionAt` and
  exposed through `Snapshot()` / `AuthInfo`, same pointer-swap discipline as
  `CodexUsage`.
- Derived helpers so both forks answer identically: `PurchasedAt()`,
  `ExpiresAt()`, `Plan()`, `IsFree()`, `AtRisk()`. `IsFree` reads both the
  gratis flag **and** a 100%-off promo — a comped-by-discount account reports
  `is_active_subscription_gratis: false` while paying $0, so the flag alone
  misreports it.
- Like `FetchCodexUsage`, a probe failure **never** touches credential health
  (no `MarkFailure`, no cooldown) and delinquency does not auto-disable.
- Requests are presented as a browser XHR (`browserUA` + `Sec-Ch-Ua*` /
  `Sec-Fetch-*` / `Referer`, no `Origin` — browsers omit it on a same-origin
  GET). Leaving User-Agent unset is not neutral: Go substitutes
  `Go-http-client/1.1`, which on an OAuth subscription account is the loudest
  third-party-client signal there is, and combining it with browser markers is
  more anomalous than either alone. `TestCodexBillingRequestIdentity` pins it.
- `AtRisk()` reads `will_renew` from either reporter — requiring the portal
  made `last_active_subscription` dead code for exactly the credentials that
  have no account id and therefore no portal payload. A cancelled renewal is
  reported only with a **known** term end and an entitlement that is not
  already inactive; without that, every never-paid free account warned that it
  was about to lapse, dated `0001-01-01`.

Field shapes are pinned to live captures in `auth/codex_subscription_test.go`.
Full documentation, traps, and the fork wiring snippet: `docs/codex-subscription.md`.

Consumed by adding a `POST /auths/:id/codex-subscription` admin route in each
fork, mirroring the existing `codex-usage` handler.

## v0.8.63–v0.8.65 — request log: aggregate cube, dual write, optional JSONL

Finishes what the SQLite index started. The index made *unfiltered* aggregates
cheap; filtered ones still walked `req` row by row, so the panel's `?model=…`
view cost ~2.9s on a 984k-record production archive. And the index was still
strictly derived — every record reached it by being re-read from a file.

### New — `agg_cube` (migration 3), replacing `agg_day`

- One pre-summed table keyed by every low-cardinality dimension at once:
  `(day, bday, model, client, client_token, provider, auth_id, status,
  user_id)`. On production that is **10,382 rows for 984,049 records** (~199 on
  the busiest day), so any filter built from those columns is answered by
  grouping the cube: **1.1s → 0.01s** measured on a copy of the real database.
- `cubeEligible` diverts a query to `req` if it carries *any* time bound — a day
  is the cube's finest grain, and guessing which bounds happen to land on a day
  boundary would depend on the caller's zone.
- Verified against a copy of the production database: 44 filter shapes
  (per-model, per-token, per-auth, per-status, per-provider, and combinations),
  every counter and both money columns **byte-identical** to the row-level
  aggregate.
- `agg_day` is dropped by the migration. An index built by an older binary has
  rows but no cube; `ensureCube` fills it from `req` at open (~7s for 90 days)
  rather than re-parsing the archive, in the background so startup does not wait.

### New — writer inserts directly (`store_write.go`)

- `Writer` folds each batch into `req` as it appends it, instead of waiting for
  the scanner. Idempotent against that scanner via a unique `(src_file,
  src_off)` — the byte offset the line was written at — so whichever producer
  offers a line second is a no-op.
- `Writer.curOff` resumes from the file's existing length on open; an offset
  restarting at zero would collide with rows a previous run already indexed.
- While the archive is on this is only an optimisation: anything an insert loses
  is re-read from the file on the next pass.

### New — `Options{JSONLArchive: false}` and `Export`

- `OpenWithOptions(dir, Options{...})`; `Open(dir, retentionDays)` unchanged and
  still defaults the archive on. With the archive off there are no `.jsonl`
  files, `pruneBefore` (`DELETE` + `incremental_vacuum`) enforces retention, and
  `RewriteClientMask` becomes one `UPDATE` instead of rewriting every archived
  file. The writer refuses to start in this mode without an open index.
- `OpenStoreForRead(dir)` + `(*Store).Export(fromDay, toDay, w)` write the
  stored rows back out as JSONL, so turning the archive off stays reversible.
  The read-only open matters: an export normally runs on a box where the server
  already has the database open, and the read-write `OpenStore` would start a
  second ingest loop competing with it.

### Changed — `store_query.go`

- `aggregatesFromReq` (the path time-bounded queries still take) computes the
  summary and all three groupings in one `MATERIALIZED` CTE instead of four
  passes. `MATERIALIZED` is explicit: SQLite may otherwise inline a CTE used
  more than once and silently restore the four passes.

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
  `advanced-tool-use-*`, `cache-diagnosis-*`). Verbatim from `crack/claudev2.1.126-apikey/`.

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
    `crack/claudev2.1.126/rows/17`.

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
