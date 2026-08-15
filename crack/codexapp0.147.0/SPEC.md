# Codex Desktop fingerprint — capture target `Codex Desktop/0.147.0-alpha.6.6`

Ground truth captured 2026-08-14 via Whistle from a live Codex Desktop session on a ChatGPT
**Plus** subscription: 293 HTTP sessions and 541 WebSocket frames over 12 minutes, including a
full sign-in. A second run on **2026-08-15** (same machine, same account, same build) added 176
HTTP sessions and 543 frames across three WS sessions and supplied the turn-opening
`response.create` frames the first run lost (`rows/15`–`18`, §2.3). All secrets are redacted in
`rows/`; non-secret fingerprint values are verbatim.

This archive supersedes `crack/codexv0.135.0/` as the **default** identity. That archive is not
obsolete — it remains the ground truth for the CLI profile, which is a genuinely different
client, not an older version of this one.

---

## 1. Identity constants

| | Codex Desktop (this archive) | codex-tui (`crack/codexv0.135.0/`) |
|---|---|---|
| `originator` | `Codex Desktop` *(note the space)* | `codex-tui` |
| `version` | `0.147.0-alpha.6.6` | `0.147.0` |
| `user-agent` | `Codex Desktop/0.147.0-alpha.6.6 (Arch Linux Rolling Release; x86_64) Konsole/260403 (Codex Desktop; 26.803.81509)` | `codex-tui/0.147.0 (… ) Konsole/260401 (codex-tui; 0.147.0)` |
| trailing paren | `(Codex Desktop; <BUILD>)` — a **build number** | `(codex-tui; <VERSION>)` — the version again |
| `x-codex-beta-features` | `remote_compaction_v2` | `terminal_resize_reflow` (at 0.135.0) |
| `openai-beta` (WS only) | `responses_websockets=2026-02-06` | same |
| OAuth `client_id` | `app_EMoamEEZ73f0CkXaXp7hrann` | same |

Four traps in that table:

1. **`originator` contains a space.** It is `Codex Desktop`, not `codex-desktop`.
2. **The UA's trailing parenthetical means different things.** The CLI repeats its version;
   Desktop puts its **app build number** (`26.803.81509`) there, which is not a semver and is
   not equal to `version`. The analytics body confirms the split:
   `app_server_client.client_version = 26.803.81509` alongside
   `runtime.codex_rs_version = 0.147.0-alpha.6.6`.
3. **`version` is a pre-release string and must not be "cleaned".** The backend parses this
   field — clients below a floor get 404 — and a `version`/UA mismatch is a one-header tell.
4. **`x-codex-beta-features` drifts every release and is not derivable.** Re-capture on bump.

Mapped to code: `mimicry.CodexDesktop*` in `mimicry/codex_identity.go`;
`mimicry.CodexCLI*` / `mimicry.CodexOriginator` in `mimicry/codex.go`.
`mimicry.DefaultCodexProfile()` returns Desktop.

### The version-string mismatch is real

`GET /backend-api/codex/models?client_version=0.147.0` sends the **base** version in the query
while the `version` header on the same request carries `0.147.0-alpha.6.6`. This is the
client's own behaviour, reproduced rather than reconciled
(`mimicry.CodexDesktopModelsClientVersion`).

---

## 2. Transport: WebSocket, not HTTP

**The Desktop capture contains no HTTP `POST /backend-api/codex/responses` at all.** Every turn
goes over `wss://chatgpt.com/backend-api/codex/responses`. Six upgrades, all 101; three were
pure prewarm connections that never carried a turn.

Everything on `chatgpt.com` is **HTTP/1.1 with `Connection: close`** — Codex Desktop does not
negotiate h2 to this host. (The `gh` CLI appearing in the same capture does, which is one of the
ways to tell the two apart; see §6.)

### 2.1 Handshake request headers — exact order

```
Host / Connection / Upgrade / Sec-WebSocket-Version / Sec-WebSocket-Key
chatgpt-account-id / authorization / user-agent / originator / openai-beta
version / x-codex-beta-features / x-client-request-id / session-id / thread-id
x-codex-window-id / x-codex-turn-metadata / sec-websocket-extensions
```

Identical in `crack/codexv0.135.0/rows/01`, so this order has survived a release cycle.
**Re-verified 2026-08-15**: the three new upgrades carry the same 18 header names, in the same
order, with the same case and the same non-identity values as `rows/10` — no drift, nothing to
add. The only per-handshake variation is inside `x-codex-turn-metadata`.

The first five (protocol) headers are capitalised; the thirteen application headers are **all
lowercase** — a Rust `reqwest` HeaderMap trait. `sec-websocket-extensions` is lowercase *and*
last, which says the client appends it itself rather than letting its WS library emit it.

Three details that cost cc-core real fidelity before this capture:

- **`session-id`, with a hyphen.** cc-core sent `Session_id` (underscore, capitalised) for two
  capture generations. Go's header canonicalization leaves an underscore alone, so it went out
  that way on the wire. One header name is enough to separate us from every genuine client.
  Fixed in `mimicry.CodexSessionIDHeader` + `codexws`; regression-tested by reading the raw map
  key, because `Header.Get` would mask it.
- **All ids are UUIDv7**, not v4. The version nibble is visible in the string.
  `x-client-request-id == session-id == thread-id` on a fresh thread, and
  `x-codex-window-id == "<session-id>:0"`. They are not four independent values.
- **No `x-codex-routing-hint` on the upgrade.** cc-core used to send it here on the strength of
  a reading of codex-rs's `build_websocket_headers`. Neither capture supports that, and
  CLIProxyAPI sends it nowhere. Removed from `codexws`; retained on the HTTP path, where the
  source reading is uncontradicted (and where we have no capture either way, since both
  captured clients use the WebSocket).

### 2.2 `x-codex-turn-metadata`

Handshake ("prewarm") variant, key order verbatim:

```json
{"installation_id":"<uuid v4>","session_id":"<v7>","thread_id":"<v7>","turn_id":"",
 "window_id":"<v7>:0","request_kind":"prewarm","thread_source":"user","sandbox":"seccomp"}
```

`turn_id` is present-and-empty, not absent. `request_kind` is `prewarm` on every captured
handshake (6 + 3), but **`thread_source` is not always `user`** — the 2026-08-15 capture shows
`system` (the title-generation session) and `ambient_suggestions` (the suggestion session)
alongside `user`. It labels *why* the app opened the socket. Key order is part of the shape, so
`mimicry.CodexTurnMetadata.Encode` writes the fields positionally rather than marshalling a map.

**This is the change that unblocked five headers.** At 0.135.0 this object carried a
`workspaces` map holding the user's cwd, git remote URL, latest commit hash and dirty flag —
genuinely unforgeable by a proxy, and the documented reason cc-core omitted the header
entirely. At 0.147.0 Desktop that map is gone (workspace state moved to a `workspace_kind`
string on the turn variant only), leaving nothing in the handshake variant a proxy cannot
legitimately own. Omitting five headers every real client sends became the larger tell.

The **turn** variant (in-band, not a header) adds `code_mode_tool_names` — a 71-entry map of
every tool and MCP server the user has installed, including third-party ones. That is a
substantial *user-side* fingerprint and a proxy has no business inventing it.

### 2.3 `response.create` client frame

Top-level keys, in order (bracketed keys are conditional, see below):

`type` · `model` · `[previous_response_id]` · `input` · `tool_choice` ·
`parallel_tool_calls` · `reasoning` · `store` · `stream` · `[stream_options]` ·
`include` · `prompt_cache_key` · `text` · `[generate]` · `client_metadata`

Notable values: `tool_choice: "auto"`, `parallel_tool_calls: false`, `store: false`,
`stream: true`, `include: ["reasoning.encrypted_content"]`, `reasoning: {effort, [summary],
context:"all_turns"}`, `stream_options: {"reasoning_summary_delivery":"sequential_cutoff"}`,
`text: {"verbosity":"low"[, format]}`.

**There is no top-level `instructions` key and no top-level `tools` key — not on any of the 8
client frames in the 2026-08-15 re-capture, opening or continuation.** The earlier reading
("the server holds them via `previous_response_id`") was an artefact of having captured only
continuation frames. Both are carried inside `input[]`:

- **Tools** are `input[0]`: `{"type":"additional_tools","role":"developer","tools":[…]}` —
  exactly three keys, `role` is `developer`. On `gpt-5.6-sol` that array holds four tools:
  `custom`/`exec` (a Lark grammar under `format`, not `parameters`; 29809-char description),
  `function`/`wait`, `function`/`request_user_input`, and `namespace`/`collaboration` — a tool
  **type that is not in the public Responses schema**, wrapping six nested `function` tools.
  The list is **model-scoped**: the auxiliary `gpt-5.6-luna` session sent three tools (no
  `collaboration`) and a 13229-char `exec` description, same client, same account, same minute.
  Full structure: `rows/16`.
- **The system prompt** is the next `input[]` item: `{"type":"message","role":"developer",
  "content":[{"type":"input_text","text":"You are Codex, an agent based on GPT-5. …"}]}`,
  17730 chars, byte-identical across the sol and luna sessions. `rows/17`.

`message` items come in **two shapes**, split by turn-scope, not by role:

| shape | keys | what it is |
|---|---|---|
| base | `type, role, content` | the system prompt above — no `id`, no passthrough. The cacheable prefix; identical every turn. |
| turn-scoped | `type, id, role, content, internal_chat_message_metadata_passthrough` | everything a turn produced: per-turn developer context blocks and the user's own messages. `id` is `msg_<uuid v7>`; the passthrough is `{"turn_id":"<uuid v7>"}`, shared by every item of that turn. |

**`generate: false`** is a prompt-cache prime, not a turn. It appears only on the frame a
session sends immediately after the 101 — `input` is exactly `[additional_tools, system
prompt]` with no user item — and sits between `text` and `client_metadata`. The server answers
with a full `response.created/.in_progress/.completed` sequence whose response object has
`output: []`, `output_tokens: 0`, `completed_at == created_at`, and an echoed `generate: false`;
the next real frame then reports `cached_tokens` ≈ that frame's `input_tokens` (11838 primed →
11008 cached). `x-codex-turn-metadata.request_kind` is `prewarm` on exactly these frames and
`turn` on all others.

**`stream_options` is not the complement of `generate`.** It co-occurs exactly with
`reasoning.summary: "detailed"` — 5/5 frames that send one send the other, 4/4 frames whose
`reasoning` is `{effort, context}` send neither. Auxiliary calls (title generation on
`gpt-5.6-luna`, ambient suggestions on `gpt-5.6-terra`) drop the summary, drop `stream_options`,
and add `text.format: {type:"json_schema", strict:true, schema:…, name:"codex_output_schema"}`.

Still **absent** everywhere: `service_tier`, `temperature`, `top_p`, `max_output_tokens`,
`truncation`, `safety_identifier` (the server adds the last three to its echo).

`prompt_cache_key == session_id == thread_id == the handshake's x-client-request-id`. In the
captured turn that bought 22272 of 22735 input tokens from cache — a proxy that omits it pays
list price for the same conversation. Continuation frames drop `additional_tools` and the system
prompt entirely (`rows/18`); that prefix is precisely what the cache key is buying.

`client_metadata` is a Rust `HashMap`, so **its key order varies between frames and is not a
fingerprint** (unlike every other ordering in this document). It carries
`ws_request_header_x_openai_internal_codex_responses_lite: "true"` — the channel by which an
HTTP header is smuggled into a WS frame body, since WS cannot set per-message headers.

Two cc-core body rules are contradicted by these frames and now have opening-frame evidence
behind them: `mimicry/codex_body.go` deletes `stream_options` (the real client sends it whenever
it asks for a detailed reasoning summary) and backfills `instructions: ""` (no real frame has
that key, and the server echoes `instructions: null`). See §7.

---

## 3. Response direction — the leak inventory

This is why `downstream/codex.go` exists. The Anthropic side of that package works because
everything sensitive arrives as a response *header*; Codex leaks through two channels a header
allowlist never sees.

### 3.1 Handshake 101 headers

Withheld: `cf-ray` (**its suffix is the Cloudflare datacentre — it locates our egress**),
`set-cookie` (`__cf_bm`), `x-models-etag` (per-account catalogue version; correlates two
requests to one account), `x-openai-proxy-wasm`, `cf-cache-status`, `server`, `report-to`,
`nel`, and the assorted security headers our own edge should own.

Relayed: `connection`, `upgrade`, `sec-websocket-accept`, `sec-websocket-extensions` — the
protocol needs them and nothing else.

### 3.2 In-band event frames

14 server event types observed (`rows/13`). **Re-checked against the 543 frames of the
2026-08-15 capture: no new server event type appeared**, so there is no `rows/19`. (The only
non-JSON frame per session is the empty close frame.) Three never reach the client intact:

| frame | disclosure | disposition |
|---|---|---|
| `codex.rate_limits` | `plan_type`, `used_percent`, `window_minutes`, `reset_after_seconds`, `reset_at`, `credits.balance`, `promo` | **rewritten** to `{allowed, limit_reached}` |
| `codex.response.metadata` | `x-models-etag`, encrypted `x-codex-turn-state`, `x-codex-safety-buffering-faster-model` | **dropped** |
| `responsesapi.websocket_timing` | `engine_ids` (e.g. `gpt56sol-codex-a-c321`), `engine_queue_max_ms`, per-engine cached/uncached prompt token totals | **dropped** |

`codex.rate_limits` is Codex's exact equivalent of Anthropic's twelve
`anthropic-ratelimit-unified-*` headers, arriving where the allowlist cannot reach.

Additionally, the `response` object echoed on `response.created` / `.in_progress` /
`.completed` carries **`safety_identifier`, which is literally `user-<chatgpt_user_id>` of the
serving account**, plus `service_tier` and `prompt_cache_retention`. Those three fields are
deleted.

Gating matters: 495 of the 541 frames in the captured turn (91%) are `*.delta`, and they must
cost one substring scan, not a JSON parse.

`response.completed.usage` is the billing field:
`{input_tokens, input_tokens_details{cache_write_tokens, cached_tokens}, output_tokens,
output_tokens_details{reasoning_tokens}, total_tokens}`.

---

## 4. `/backend-api/codex/models`

`GET …?client_version=0.147.0`, 329 KB, eight models: `gpt-5.6-sol`, `gpt-5.6-sol-wm` (hidden),
`gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`, `codex-auto-review`
(hidden). Each entry carries `use_responses_lite`, `tool_mode`, `prefer_websockets`,
`context_window`, `minimal_client_version`, `supported_reasoning_levels`, and the full
`model_messages.instructions_template`.

**`use_responses_lite` is the authoritative lite predicate.** `mimicry/codex_body.go` currently
infers it from `strings.HasPrefix(model, "gpt-5.6")`; `codex-auto-review` is lite and does not
match that prefix, so a counter-example already exists in this catalogue.

`supports_parallel_tool_calls: true` on `gpt-5.6-sol` is a **capability** bit, not a value to
send — the real client sends `parallel_tool_calls: false`.

---

## 5. OAuth

`POST auth.openai.com/oauth/token` carries exactly four headers, in order:
`content-type: application/x-www-form-urlencoded` · `accept: */*` · `host` · `content-length`.

**There is no User-Agent, and that is load-bearing.** Leaving it unset in Go is not neutral —
net/http substitutes `Go-http-client/1.1`, the loudest third-party tell in the whole login flow.
`Header.Del` and `Set("User-Agent", "")` both fail to suppress it; only assigning a nil slice
works (`auth.applyCodexTokenEndpointHeaders`). CLIProxyAPI has the same defect.

Authorization-code exchange body, field order: `grant_type` · `code` · `redirect_uri` ·
`client_id` · `code_verifier`. No `client_secret`, no `scope`, no `state`.

Response fields: `access_token`, `token_type`, `expires_in` (**864000 — ten days**), `scope`,
`id_token` (1 h), `earliest_refresh_at` (= issue + 9 days), `refresh_token` (opaque `rt.1.*`,
not a JWT), `oai_is` (opaque, mirrors the `x-oai-is-update` response header).

**Granted scope is wider than cc-core requests**: it adds `api.connectors.read
api.connectors.invoke`. Whether Desktop asks for those at `/authorize` is unverified — that leg
was not captured (README §1).

### JWT claims

The **id_token** carries, under `https://api.openai.com/auth`:
`chatgpt_account_id`, `chatgpt_plan_type`, `chatgpt_subscription_active_start` /
`_active_until` / `_last_checked` (RFC3339), and `organizations[{id, is_default, role, title}]`.
The subscription claims are a free, zero-risk fallback for `FetchCodexSubscription`, which is
the most exposed probe cc-core runs — but they are frozen at issue time, so they supplement it
rather than replace it.

The **access_token** carries `chatgpt_account_id` / `chatgpt_plan_type` / `chatgpt_user_id`
under the same namespace, plus `email` under `…/profile`. This matters because a refresh is only
guaranteed to return an access_token: cc-core read account id from the id_token alone, so a
refresh without one left `AccountID` pinned forever. Now backfilled from the access token.

### The token-exchange probe

One second after login, Desktop sends an RFC 8693 exchange (`requested_token=openai-api-key`)
and gets **401 `invalid_subject_token: missing organization_id`** on a personal Plus account.
Traffic continues normally. **This is a probe, not a credential failure** — anything modelling
it must not touch credential health.

---

## 6. Auxiliary traffic — six incompatible header sets

Only 6 of 293 sessions are `/codex/responses`. The other ~98% is plugin, MCP, analytics and
telemetry traffic (`rows/20`–`33`). It splits into **six mutually incompatible header sets**
across eight endpoints. The repo already forbids unifying the three `auth/codex_*` probe header
sets; the same rule applies here, and more sharply:

1. `oai-product-sku` vs `x-openai-product-sku` — same value, different name, split by
   **client** (the Desktop HTTP client vs the MCP client), not by endpoint family.
2. Only `ps/plugins/*` and `apps/batch`/`connectors` send a product SKU at all.
3. `originator` sits **first** on the plugins endpoints, **sixth** on
   `analytics-events`/`apps/batch`, and is **absent** on `wham/settings/user`.
4. `wham/settings/user` is the only endpoint sending `cache-control: no-cache, no-store`.
5. `connectors/directory/list` sends `content-type: application/json` **on a GET**.
6. `plugins/featured` has a genuine unauthenticated form (12 pre-login 401s); always attaching
   a Bearer would be wrong.
7. `ps/mcp` uses a different User-Agent entirely (`codex-mcp-client/0.147.0-alpha.6.6`) and is
   the one place where header **order is not stable** across calls.

`ab.chatgpt.com/otlp/v1/metrics` is the odd one out: different host, **no credential at all**,
authenticated by a publishable `statsig-api-key`. Verified to contain no user/account/path
identifiers in either payload.

### Timeline

Nothing but `plugins/featured` and the Sentry/OTLP heartbeats runs while signed out. On login a
tight bootstrap burst fires within ~10 s, in this order:

```
suggested → installed(×3) → list(paging) → models → featured → analytics
          → apps/batch → mcp handshake → WS upgrade
```

After that there is **no periodic auxiliary heartbeat on chatgpt.com** — everything is
reactive. The only fixed-period traffic in the whole capture is Sentry (60 s) and OTLP
(600 s, DELTA-gated).

### Should cc-core emulate any of it?

**No general Codex sidecar.** The decision and its reasoning are recorded here because the
volume argument (2% traffic profile vs a real client's 100%) is superficially compelling:

- Unlike Claude Code — where `crack/claudev2.1.226-inbound/` proves a real client on a custom
  base URL still emits a recognisable shape — this traffic all targets `chatgpt.com` and
  `ab.chatgpt.com` **directly**, never through the relay. A genuine Codex-compatible client
  behind a proxy produces exactly the pattern cc-core produces today. Absence is normal for the
  population cc-core sits in.
- `analytics-events` reports `thread_id`/`turn_id`/`model`/tool counts that the backend can join
  against real `/responses` traffic. Fabricating them produces *impossible* metadata — strictly
  worse than silence. This is the half-mimicry trap.
- `ps/plugins/list` would cost ~500 KB × N pages per account.
- OTLP would tie every proxied account to one `statsig-api-key` identity — a worse correlator
  than sending nothing.

If it is ever revisited, only `plugins/featured` and `ps/plugins/installed` qualify (cheap,
stateless, no ids to invent), and they need a **parallel** `realCodexBootstrapSteps()` table —
never a generalization of the Anthropic one, whose `bootstrapStep` carries `beta` /
`anthropicVer` fields and would invite exactly the header unification this section forbids.

### `codex_reset.go`'s "Desktop" header set is unconfirmed

`auth/codex_reset.go` claims to mirror Codex Desktop and sends `browserUA` (Chrome 131) plus
`Sec-Fetch-*` and `Priority`. **Real Codex Desktop 0.147.0 sends none of that on any
`/backend-api/*` call** — it sends its own UA, `originator`, and `oai-product-sku`, and no
Sec-Fetch headers at all. The set may still be right for
`wham/rate-limit-reset-credits` specifically (a different capture, possibly an older build, not
exercised in this run), but it should not be treated as the Desktop reference until a targeted
capture settles it. Nothing here contradicts `codex_usage.go` or `codex_subscription.go`.

### `api.github.com` in this capture is not Codex

Eight requests, all from the `gh` CLI (self-identifying UA, `gho_` token, HTTP/2,
`time-zone: Asia/Shanghai`, unstable header order, queries scoped to a user repo). Codex almost
certainly spawned it as a shell tool, but it is a separate process with its own HTTP stack —
cross-talk, not fingerprint. The two `…oaiusercontent.com/files/…/raw` fetches are excluded for
the same reason.

---

## 7. Known deltas we do NOT currently match

| delta | why |
|---|---|
| `Sec-WebSocket-Extensions` value | We advertise gorilla's hardcoded `permessage-deflate; server_no_context_takeover; client_no_context_takeover`; real Codex sends `permessage-deflate; client_max_window_bits`. Aligning the string would be a **correctness bug**: gorilla implements only the no-context-takeover mode, and a server not asked to disable context takeover may keep compressor state that gorilla's inflater cannot decode. Needs a compression change, not a string change. |
| per-account UA machine identity | Every account advertises the same synthetic Arch/Konsole host, the "many users, one rare machine" signal `auth.HostProfile` exists to defuse on the Anthropic side. Fixing it means inventing an `os_type`/`os_version` per distro and a `terminal_ua` version per terminal — values no capture backs, and guessing them is worse than uniformity. Needs captures from other distros/terminals. |
| `Retry-After` synthesis on Codex 429 | `downstream.ensureRetryAfter` derives it from `Anthropic-Ratelimit-Unified-*` only. No Codex 429 appears in this capture, so there is nothing to derive from yet. |
| `stream_options` / `instructions` in the request body | **Evidence is now complete; the code has not caught up.** `mimicry/codex_body.go` still deletes `stream_options` and backfills `instructions: ""`. The 2026-08-15 capture has the turn-opening frames (`rows/15`) and they settle both: the real client sends `stream_options` whenever `reasoning.summary` is `detailed`, and no frame at all — opening, prewarm or continuation — carries `instructions`. Tools and the system prompt ride in `input[]` (`rows/16`, `rows/17`), so a body rewrite that reasons about a top-level `tools` key is reasoning about a key that does not exist. |
| `generate` / `additional_tools` / `namespace` tool type | New in §2.3 and not modelled anywhere in `mimicry/codex_body.go`. A body-shaping pass that drops unknown top-level keys would strip `generate`, and one that validates tool objects against the public Responses schema would reject `namespace`. |
| `use_responses_lite` | Still inferred from a `gpt-5.6` prefix rather than read from the models catalogue (§4). |
