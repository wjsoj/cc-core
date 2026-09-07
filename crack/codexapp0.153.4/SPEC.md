# Codex Desktop fingerprint + OAuth login — capture target `Codex Desktop/0.153.4`

Ground truth captured **2026-09-07** via Whistle from a live Codex Desktop session on a ChatGPT
**Plus** plan (Arch Linux, Konsole): 247 sessions over 17 minutes spanning a **complete
re-login** — an invalidated refresh token, nine minutes of 401 backoff, a fresh authorization,
and a failed API-key exchange.

This archive supersedes `crack/codexapp0.147.0/` as the Desktop ground truth. That archive is
not deleted: it remains the only record of the 0.147.0 handshake shape, which **materially
differs** from this one (§3).

A codex-tui client was running on the same machine during the capture, so three CLI handshakes
appear alongside sixteen Desktop ones. That is a gift, not noise: the two clients' shapes can be
diffed at the same backend version with no version drift as a confound. The CLI rows live in
`crack/codexv0.153.4/`; only the Desktop ones are here.

---

## 1. Identity constants

| | Codex Desktop 0.153.4 (this archive) | Codex Desktop 0.147.0 (`codexapp0.147.0`) |
|---|---|---|
| `originator` | `Codex Desktop` | same |
| `version` | `0.153.4` | `0.147.0-alpha.6.6` |
| build (UA tail) | `26.901.51231` | `26.803.81509` |
| terminal segment | `Konsole/260800` | `Konsole/260403` |
| full UA | `Codex Desktop/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (Codex Desktop; 26.901.51231)` | — |

**Four User-Agent forms coexist in one process.** They are per-component and must never be
mixed — pairing an originator with the wrong UA is a one-header tell:

| Component | `originator` | User-Agent |
|---|---|---|
| WS upgrade, `codex/models`, `plugins/*` | `Codex Desktop` | the full UA above |
| `wham/remote/control/*`, `oauth/token` refresh | `Codex Desktop` | the full UA **minus** the trailing `(Codex Desktop; <build>)` |
| `ps/mcp` | present on some, absent on others | `codex-mcp-client/0.153.4` |
| OTLP metrics | — | `OTel-OTLP-Exporter-Rust/0.31.0` |

Mapped to code: `mimicry.CodexDesktop*` in `mimicry/codex_identity.go`.

---

## 2. OAuth — the three grants do NOT share a request shape

This is the most load-bearing fact in the archive. cc-core applied one shared header helper
(`applyCodexTokenEndpointHeaders`) to every grant on the assumption that they were identical.
They are not.

| grant | rows | content-type | identity headers | body field order |
|---|---|---|---|---|
| `refresh_token` | `01` | **`application/json`** | **`originator` + `user-agent` PRESENT** | `client_id`, `grant_type`, `refresh_token` |
| `authorization_code` | `02` | `application/x-www-form-urlencoded` | **ABSENT** | `grant_type`, `code`, `redirect_uri`, `client_id`, `code_verifier` |
| token-exchange (RFC 8693) | `04` | `application/x-www-form-urlencoded` | **ABSENT** | `grant_type`, `client_id`, `requested_token`, `subject_token`, `subject_token_type` |

Request header order, `refresh_token` (row `01`):
`content-type, accept, originator, user-agent, host, content-length`

Request header order, the other two (rows `02`, `04`):
`content-type, accept, host, content-length`

Three traps:

1. **The refresh grant sends no `scope`.** cc-core sends `"openid profile email"`. The real
   client sends exactly three fields.
2. **Field order is not alphabetical.** `url.Values.Encode()` sorts, which produces
   `client_id, code, code_verifier, grant_type, redirect_uri` for the auth-code leg — an order
   no genuine client emits.
3. **The refresh grant is the only one that identifies itself.** Adding `originator`/UA to the
   auth-code leg would be as wrong as omitting it from the refresh leg.

Constants kept verbatim in the rows: `client_id=app_EMoamEEZ73f0CkXaXp7hrann`,
`redirect_uri=http://localhost:1455/auth/callback`.

### 2.1 Token response and refresh timing

Row `02`'s response (200):

| field | value | note |
|---|---|---|
| `token_type` | `Bearer` | |
| `expires_in` | `864000` | **10 days**, not the ~30 cc-core's comment assumes |
| `earliest_refresh_at` | `iat + 777600` | **9 days** — the server saying when a refresh is permitted |
| `scope` | `openid profile email offline_access api.connectors.read api.connectors.invoke` | **wider than requested** (cc-core asks for the first four) |
| `refresh_token` | `rt.1.<base64url>`, 196 chars | rotates on every refresh |
| `oai_is` | `ois1.<JWT>` | not parsed by cc-core at all |

**`earliest_refresh_at` is the operationally important one.** cc-core refreshes at
`MinRefreshLeeway` = 5 days remaining, i.e. day 5 of 10 — four days before the server says a
refresh is permitted, and it never reads the field. Given the repeated
`refresh_token_invalidated` incidents in production, this is the first thing to align.

### 2.2 The token-exchange 401 is expected, not a fault

Row `04` fails with `invalid_subject_token: "Invalid ID token: missing organization_id"`. Row
`03` shows why: the `id_token` carries `organizations: [{id, is_default, role, title}]` but **no
top-level `organization_id`**. On a personal account there is nothing to exchange. This is a
probe, and anything modelling it must not touch credential health — nor is there any reason to
implement it.

---

## 3. WebSocket handshake — Desktop ≠ CLI

Both clients hit `wss://chatgpt.com/backend-api/codex/responses` at the same version during this
capture, and they send different header sets in a different order.

**Desktop, 18 headers** (row `10`):
```
Host, Connection, Upgrade, Sec-WebSocket-Version, Sec-WebSocket-Key,
chatgpt-account-id, authorization, user-agent, originator,
x-client-request-id, version, session-id, thread-id,
[x-openai-subagent,]
x-codex-window-id, openai-beta,
x-openai-internal-codex-responses-lite,
sec-websocket-extensions
```

**CLI, 19 headers** (`crack/codexv0.153.4/rows/10`):
```
… originator, openai-beta, version, x-codex-beta-features,
x-client-request-id, session-id, thread-id, x-codex-window-id,
x-codex-turn-metadata, [x-codex-parent-thread-id, x-openai-subagent,]
x-codex-routing-hint, sec-websocket-extensions
```

Desktop sends **none** of `x-codex-beta-features`, `x-codex-turn-metadata`,
`x-codex-routing-hint`. It instead carries **`x-openai-internal-codex-responses-lite: true` as
an HTTP header** — the switch the CLI smuggles inside the frame body, because a WebSocket cannot
set per-message headers and the CLI's design puts it there.

Note this is a change within Desktop too: `codexapp0.147.0`'s Desktop handshake *did* send
`x-codex-turn-metadata`. Between 0.147.0 and 0.153.4 Desktop dropped the metadata trio and
adopted the lite header.

**Consequence for cc-core**: `DefaultCodexProfile()` and `codexws.handshakeHeaderOrder` are a
matched pair. Selecting the Desktop profile while emitting the CLI header set produces a shape
neither client sends, which is worse than either alone.

---

## 4. Endpoints this archive adds

### 4.1 `POST /backend-api/wham/remote/control/server/refresh` (row `20`) — previously unknown

63 samples. Body `{"server_id": "srv_e_<hex>", "installation_id": "<uuid>"}`. Carries
**`x-codex-installation-id`**, a header cc-core sends nowhere.

All 63 are **401** (`token_revoked`) because the session's token had been invalidated, so the
success shape is unknown. The polling cadence is visible though: roughly 1, 2, 3, 4, 7, 13, 27
seconds, resetting about every 30 seconds — 63 attempts across nine minutes.

Not implementable today: the `server_id` is minted by a registration step this capture does not
contain.

### 4.2 Headers seen for the first time

`x-codex-installation-id`, `oai-product-sku` / `x-openai-product-sku`, `statsig-api-key`,
`mcp-protocol-version`, `x-openai-internal-codex-responses-lite`.

### 4.3 Auxiliary traffic volume

Over 17 minutes one Desktop client emitted ~215 upstream requests. cc-core emits three kinds
(forward, refresh, operator probe). The rest, all captured here with bodies:

| endpoint | count | rows |
|---|---|---|
| `wham/remote/control/server/refresh` | 63 | `20` |
| `ps/plugins/installed` | 42 | `41` |
| `ps/plugins/list` | 23 | `42` |
| `codex/responses` (WS) | 19 | `10`, `11` |
| `otlp/v1/metrics` | 15 | `50` |
| `ps/mcp` | 13 | `40-*` |
| `plugins/featured` | 11 | `43` |
| `codex/analytics-events/events` | 10 | `30-*` |
| `codex/models` | 9 | `12` |
| `ps/plugins/suggested/codex` | 5 | `44` |
| `oauth/token` | 3 | `01`, `02`, `04` |
| `wham/settings/user` | 2 | `21` |
| Sentry (CONNECT) | 19 | — not decryptable |

Two constraints any emulation inherits from these rows:

- **`analytics-events` carries `thread_id` / `session_id`** that the backend can join against
  real `/responses` traffic. Ids must be reused from turns that actually happened; invented ones
  produce metadata no real client could emit.
- **OTLP resource attributes carry host identity** (`service.name: codex-app-server`, os
  version, …) alongside a shared `statsig-api-key`. Sending one identical attribute blob for
  every credential correlates them; it has to vary per account.

---

## 5. Known gaps

1. **`/oauth/authorize` is still uncaptured.** The consent page opens in the system browser and
   the callback lands on `http://localhost:1455`, so neither traverses the proxy. The request
   `scope`, the PKCE parameters and the `id_token_add_organizations` /
   `codex_cli_simplified_flow` flags remain unverified — the same gap `codexapp0.147.0` records.
   Closing it needs the browser itself pointed at the proxy.
2. **No successful `refresh_token` response.** Row `01` is a 401; the request shape is now known,
   the success response shape is still source-derived.
3. **No successful `wham/remote/control` response** (§4.1).
4. **Sentry stays opaque.** A CONNECT every 60 s, never decrypted.
5. **No 429 or error frame.** Unrelated to login; needs an exhausted window.

---

## 6. Edit checklist

- [ ] `auth/codex_refresh.go` — refresh body to JSON, drop `scope`, split the header helper so
      only this grant carries originator + UA, parse `earliest_refresh_at` and `oai_is`
- [ ] `auth/codex_login.go` — order-preserving auth-code body, persist the two new fields
- [ ] `auth/oauth.go` — honour `earliest_refresh_at`; the "~30 days" comment is wrong (10)
- [ ] `mimicry/codex_identity.go` — Desktop version / build / Konsole segment, all three
- [ ] `codexws/headers.go` — a Desktop handshake shape distinct from the CLI's (§3)
- [ ] parity tests that read `rows/` rather than constants copied out of it
