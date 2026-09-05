# Codex CLI fingerprint — capture target `codex-tui/0.153.4`

Ground truth captured **2026-09-05** via Whistle from a live Codex CLI session on a ChatGPT
**Pro** subscription: 73 HTTP sessions over a ~2-minute run, including three WebSocket upgrades
and the full model catalog. All secrets are redacted in `rows/`; non-secret fingerprint values
are verbatim. Reproduce with `crack/scripts/extract_codex_live.py` (see README).

This archive is the ground truth for the **CLI** profile (`mimicry.CodexCLI*`) and, as of this
capture, for `mimicry.DefaultCodexProfile()` as well — see §6. It does **not** supersede
`crack/codexapp0.147.0/`, which covers the Desktop app: a different client, not an older
version of this one.

---

## 1. Identity constants

| | codex-tui (this archive) | codex-tui @ 0.135.0 | Codex Desktop @ 0.147.0 |
|---|---|---|---|
| `originator` | `codex-tui` | `codex-tui` | `Codex Desktop` |
| `version` | `0.153.4` | `0.135.0` | `0.147.0-alpha.6.6` |
| `user-agent` | `codex-tui/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (codex-tui; 0.153.4)` | `… Konsole/2604xx …` | `Codex Desktop/0.147.0-alpha.6.6 (…) Konsole/260403 (Codex Desktop; 26.803.81509)` |
| `x-codex-beta-features` | `remote_compaction_v2` | `terminal_resize_reflow` | `remote_compaction_v2` |
| `openai-beta` (WS only) | `responses_websockets=2026-02-06` | same | same |

Four traps:

1. **The UA changed in two places, not one.** Both version segments moved `0.147.0` → `0.153.4`
   *and* the terminal segment moved `Konsole/260401` → `Konsole/260800`. A bump that only
   rewrites the version leaves a terminal build number no 0.153.4 client emits.
2. **`x-codex-beta-features` converged.** The TUI sent `terminal_resize_reflow` at 0.135.0 and
   now sends the Desktop value `remote_compaction_v2`. It is not derivable from the version and
   it does drift between releases — re-capture it every bump rather than carrying it forward.
3. **A third client component exists.** `GET /backend-api/codex/models` in this same session is
   sent with `originator: codex_cli_rs` and a **truncated** UA (no trailing
   `(codex-tui; 0.153.4)` parenthetical), while the WS upgrade uses `originator: codex-tui` with
   the full UA. This is a component split *within one process*, not an endpoint split, and
   cc-core models only the second. Do not reuse `CodexCLIUserAgent` for a models fetch.
4. **The `?client_version=` query carries the plain version** (`0.153.4`), matching the `version`
   header here. Desktop's do not match each other — do not "reconcile" them across profiles.

Mapped to code: `mimicry.CodexCLIVersion` / `CodexCLIUserAgent` / `CodexOriginator` /
`CodexCLIBetaFeatures` in `mimicry/codex.go`.

---

## 2. Model catalog

`GET /backend-api/codex/models?client_version=0.153.4` → `rows/01`. Nine models, in wire order:

| slug | display | visibility | priority | `minimal_client_version` | `supported_in_api` | `use_responses_lite` |
|---|---|---|---|---|---|---|
| `gpt-6-astra` | GPT-6-Astra | list | 1 | **0.153.0** | true | true |
| `gpt-reserve` | GPT-Reserve | **hide** | 3 | 0.144.0 | true | true |
| `gpt-5.6-sol` | GPT-5.6-Sol | list | 6 | 0.144.0 | true | true |
| `gpt-5.6-terra` | GPT-5.6-Terra | list | 7 | 0.144.0 | true | true |
| `gpt-5.6-luna` | GPT-5.6-Luna | list | 8 | 0.144.0 | true | true |
| `gpt-5.5` | GPT-5.5 | list | 12 | 0.124.0 | true | false |
| `gpt-5.4-mini` | GPT-5.4-Mini | list | 23 | 0.98.0 | true | false |
| `gpt-5.3-codex-spark` | GPT-5.3-Codex-Spark | list | 26 | 0.100.0 | **false** | false |
| `codex-auto-review` | Codex Auto Review | **hide** | 43 | 0.98.0 | true | true |

Diff vs the 0.147.0 Desktop catalog: **added** `gpt-6-astra`, `gpt-reserve`,
`gpt-5.3-codex-spark`; **gone** `gpt-5.6-sol-wm`, `gpt-5.4`. `max_context_window` rose from
272000 to **872000** across the frontier line. A new reasoning effort **`ultra`** appears on
astra and on gpt-5.6-sol.

Three things this catalog settles that guesswork got wrong:

* **Plan availability is declared per model.** Each row carries `available_in_plans`. astra's
  lists free, plus, pro, team, go and business — and the field is genuinely discriminating,
  since `codex-auto-review`'s omits `free`/`free_workspace`. So astra belongs on every tier of
  `auth.CodexModelCatalog`, and that is evidence rather than analogy with gpt-5.5.
  (Caveat: this is a static property of the model row. Only a capture from a non-Pro token
  proves the *response* to such a token contains astra.)
* **Responses-Lite is per model, not a version prefix.** `use_responses_lite` is true for astra,
  reserve, the three 5.6 models and auto-review; false for 5.5, 5.4-mini and codex-spark.
  `mimicry.codexResponsesLiteModel` was `HasPrefix(model, "gpt-5.6")`, which matched the old
  catalog by accident and would have injected the `image_generation` built-in into every astra
  request — a 400 on every turn where the client sent no tools of its own.
* **astra's version floor is load-bearing.** `minimal_client_version: 0.153.0` means a client
  self-reporting below it cannot be routed to the current flagship at all. See §6.

The catalog carries **no pricing**. astra's published rates ($10 in / $1 cached / $12.50
cache-write / $50 out per 1M, standard tier, short context) come from
`developers.openai.com/api/docs/pricing`, verified 2026-09-05, and live in `pricing/pricing.go`.

---

## 3. WebSocket handshake

Three upgrades to `wss://chatgpt.com/backend-api/codex/responses`, all 101 — `rows/10` (ordinary
user thread), `rows/11` (system-initiated thread), `rows/12` (auto-review guardian subagent).
No HTTP `POST /backend-api/codex/responses` appears anywhere in the capture.

Wire order, verbatim from `req.rawHeaderNames` (19 headers; the guardian sends 21):

```
Host, Connection, Upgrade, Sec-WebSocket-Version, Sec-WebSocket-Key,
chatgpt-account-id, authorization, user-agent, originator, openai-beta, version,
x-codex-beta-features, x-client-request-id, session-id, thread-id,
x-codex-window-id, x-codex-turn-metadata,
  [x-codex-parent-thread-id, x-openai-subagent]   ← subagent only
x-codex-routing-hint,
sec-websocket-extensions
```

### 3.1 `x-codex-routing-hint` is on the upgrade

**This is the correction this archive exists to make.** `codexws/headers.go` deliberately omitted
the hint from the handshake, and carried a comment justifying it: *"neither the 0.135.0 CLI
upgrade nor the 0.147.0 Desktop upgrade carries it (both send 18 headers, and the hint is not one
of them)."* All three upgrades here carry it, in the format the HTTP path already used:

```
x-codex-routing-hint: model=gpt-5.6-sol;tier=priority      (rows/10)
x-codex-routing-hint: model=gpt-5.6-luna;tier=priority     (rows/11)
x-codex-routing-hint: model=codex-auto-review;tier=priority (rows/12)
```

The older captures were **older, not contradictory**. Do not re-derive its absence from them.
`tier=priority` on all three is the only tier value any capture has shown on an upgrade.

Position matters as much as presence: emitting the header without adding it to
`handshakeHeaderOrder` puts it *after* `sec-websocket-extensions`, which is a worse shape than
omitting it.

### 3.2 The subagent pair

`x-codex-parent-thread-id` and `x-openai-subagent: guardian` appear only on `rows/12`, between
`x-codex-turn-metadata` and `x-codex-routing-hint`. cc-core does not send them: a proxy is not a
subagent, and announcing one without the thread topology behind it is worse than its absence.

### 3.3 Ids

On `rows/10` and `rows/11`, `x-client-request-id == session-id == thread-id` — a fresh thread.
`rows/12` separates them (session `01a06fa9-a7f8-…`, thread `01a06fa9-a85e-…`), and that row is
what shows **`x-codex-window-id` follows the THREAD id, not the session id**. cc-core anchored
it on the session; indistinguishable until a capture separated the two.

---

## 4. `x-codex-turn-metadata`

15 keys on a plain thread, 17 on a subagent. Decoded side-by-side in `rows/13`. Order:

```
installation_id, session_id, thread_id, agent_name, turn_id, window_id, window_number,
context_window_id, request_kind, [parent_thread_id, subagent_kind,] thread_source,
sandbox, sandbox_mode, auto_review_enabled, node_repl_auto_review_required, node_repl_disabled
```

0.147.0 sent eight of these (`installation_id, session_id, thread_id, turn_id, window_id,
request_kind, thread_source, sandbox`). The seven new ones and their traps:

| field | type | observed | note |
|---|---|---|---|
| `agent_name` | string | `/root` on all three | The client's working directory. **A proxy has no honest value for it.** |
| `window_number` | **number** | `0` | Not a string. `"window_number":"0"` is a one-character tell. |
| `context_window_id` | string | UUIDv7 | **Shares `thread_id`'s first four groups**, differing only in the trailing 12 hex digits — the client mints it from the same timestamp and random-high bits. An unrelated UUID here is a structural mismatch. |
| `sandbox_mode` | string | `workspace-write` (user) / `read-only` (system, guardian) | Pairs with `thread_source`. |
| `auto_review_enabled` | **bool** | `true` (user) / `false` (system, guardian) | |
| `node_repl_auto_review_required` | **bool** | `false` everywhere | |
| `node_repl_disabled` | **bool** | `false` everywhere | |

Three of the seven are not strings, which is why `CodexTurnMetadata.Encode` needs a typed writer
rather than seven more `writeJSONPair` calls, and why any test unmarshalling the embedded
metadata into `map[string]string` now fails on the first number.

`turn_id` is emitted **even when empty** (`"turn_id":""`, not an absent key). The subagent pair
is the opposite: absent entirely on a plain thread, rather than present-and-empty.

### `agent_name` — the one field we cannot source honestly

Every genuine client sends its own working directory. A proxy knows the downstream client's only
when that client sends its own `x-codex-turn-metadata`, which `RewriteCodexClientFrame` carries
through. Otherwise cc-core emits `mimicry.CodexDefaultAgentName` (`/root`, the captured value),
uniform across accounts — the same trade the synthetic User-Agent already makes, on the same
reasoning: a wrong-shaped guess is a worse fingerprint than a real value shared by many
accounts. It is a recorded gap, not a solved problem.

---

## 5. What this capture does NOT contain

1. **No WebSocket payload frames.** Whistle's `get-data` API returns handshakes but no frame log,
   so no 0.153.4 `response.create` body was observed. The turn-variant `client_metadata` in
   `mimicry/codex_frame.go` is **extrapolated** from the handshake variant; the 0.147.0 Desktop
   capture (`crack/codexapp0.147.0/rows/11`, `15`–`18`) remains the only frame ground truth, and
   it is from a different client. **This is the top gap.**
2. **No HTTP `POST /codex/responses`.** Still true at 0.153.4: no captured Codex client uses the
   HTTP path. Everything cc-core does there is source-derived.
3. **No token refresh, no 429, no error frame.** A short session on an unexhausted Pro plan
   produces none.
4. **Pro plan only.** Which models a Free / Plus / Team account is actually *served* is unproven;
   only `available_in_plans` is evidence, and it is a static model property.
5. **No OAuth login leg.** The sign-in flow was not exercised.

---

## 6. Decisions this capture forced

Recorded here because each is a judgement call, not a transcription.

1. **`DefaultCodexProfile()` flipped from Desktop to codex-tui.** astra's
   `minimal_client_version` is `0.153.0`; Desktop self-reports `0.147.0-alpha.6.6`, below the
   floor, so a Desktop-identified request cannot reach the current flagship. Desktop cannot
   simply be bumped: its version, build number (`26.803.81509`) and terminal segment are three
   independent values the backend cross-validates, and no Desktop capture at or above 0.153.0
   exists. The choice was a stale-but-real Desktop that cannot reach astra, or a
   current-and-real CLI that can. **Re-visit if a Desktop capture ≥ 0.153.0 is taken** — Desktop
   is the more common client and was the default for that reason.
2. **`agent_name` defaults to the captured `/root`.** See §4.
3. **The subagent headers are not sent.** See §3.2.
4. **`gpt-reserve` and `codex-auto-review` are priced but not listed.** Both are visibility
   `hide`; `auth.CodexModelCatalog` feeds a customer-facing `/v1/models`, so advertising a model
   no genuine Codex client offers is a divergence with no upside. Pricing is consulted whenever
   a request *names* a model, listed or not, so the two concerns are separable. Neither has a
   published rate today, so both still fall to the provider default.
5. **The routing hint is not defaulted to `tier=priority`.** All three captured
   handshakes carry it, so defaulting looks like the better fingerprint. It is
   the worse bill: `pricing.CostWithOptions` charges the Fast multiplier off the
   tier the request asked for, so a hint claiming priority on a standard-billed
   request buys a paid upgrade nobody pays for. The captured account genuinely
   requested priority. Callers wanting the captured shape pass it explicitly.
6. **The stale catalog rows were left alone.** cc-core still lists `gpt-5.2`, `gpt-5.3-codex`
   and `gpt-5.4`, none of which this catalog returns. Pruning them breaks any customer pinning
   one and does not belong in the same change as an add.

---

## 7. Edit checklist for the next bump

- [ ] `mimicry/codex.go` — `CodexCLIVersion`, `CodexCLIUserAgent` (**both** version segments and
      the terminal segment), `CodexCLIBetaFeatures`.
- [ ] `mimicry/codex_identity.go` — Desktop constants **only** from a Desktop capture; re-check
      whether `DefaultCodexProfile` should move back.
- [ ] `mimicry/codex_identity.go` — `CodexTurnMetadata` field set, order and TYPES against
      `rows/13`.
- [ ] `codexws/headers.go` — `handshakeHeaderOrder` against `rows/10`'s `req_header_order`.
- [ ] `mimicry/codex_body.go` — `codexResponsesLiteModels` against `use_responses_lite` in
      `rows/01`.
- [ ] `auth/codex_models.go` — catalog against `rows/01`, plan placement against
      `available_in_plans`.
- [ ] `pricing/pricing.go` — a card for every new slug, from the published page, never inferred
      from a neighbour's ratio.
- [ ] `codexws/capture_parity_test.go` — repoint `capturedHandshakeRow` at the new dir. That test
      reads the capture rather than a copy of it, which is what would have caught the routing-hint
      claim in §3.1 two releases earlier.
