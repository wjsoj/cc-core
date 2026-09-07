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

**Four User-Agent forms coexist**, and only two of the four map cleanly to an endpoint:

| User-Agent | `originator` | where |
|---|---|---|
| `codex-mcp-client/0.153.4` | present on some, absent on others | `ps/mcp` only |
| `OTel-OTLP-Exporter-Rust/0.31.0` | — | `ab.chatgpt.com/otlp/v1/metrics` only |
| the full Desktop UA above | `Codex Desktop` | see below |
| the full UA **minus** the trailing `(Codex Desktop; <build>)` | `Codex Desktop` | see below |

⚠️ **The full-vs-base split is NOT per-endpoint.** An earlier draft of this section claimed it
was; the rows disprove it. `codex/models`, `plugins/featured`, `ps/plugins/installed`,
`ps/plugins/suggested` and `wham/remote/control/server/refresh` each appear with **both** forms
in this one capture. The two that never vary are `oauth/token` and the WebSocket upgrade, and
both use the **full** UA.

The likeliest reading is that two components of the Desktop app — the app-server and the
codex-rs core — reach the same endpoints under the same originator with slightly different UA
construction. This capture cannot separate them, so do not encode a per-endpoint rule. What it
does settle: **`oauth/token` sends the full UA**, and the base form is not an OAuth thing.

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

## 3. WebSocket handshake — ordinary vs guardian, NOT Desktop vs CLI

⚠️ **An earlier draft of this section was wrong, and the error was load-bearing.** It read the
two handshake shapes here as a Desktop-vs-CLI client split. They are not: **all 19 upgrades in
this capture carry `originator: Codex Desktop`.** There is no codex-tui handshake here at all.
The real split:

| shape | count | `x-openai-subagent` | turn-metadata | beta-features | routing-hint | lite header | headers |
|---|---|---|---|---|---|---|---|
| ordinary | 2 | — | ✓ | ✓ | ✓ | — | 19 |
| guardian | 1 | `guardian` | ✓ | ✓ | ✓ | — | 21 |
| guardian + lite | 16 | `guardian` | — | — | — | ✓ | 18 |

**The ordinary Desktop shape (19 headers) is identical in header set AND order to the CLI shape
in `crack/codexv0.153.4/rows/10`.** Desktop and codex-tui send the same handshake for an
ordinary thread, so whatever we emit for a normal turn is already right, and choosing between
the two client profiles does not change the handshake at all.

The 18-header shape is a **guardian subagent running Responses-Lite**. It drops the metadata
trio and carries `x-openai-internal-codex-responses-lite: true` as an HTTP header instead — the
switch the ordinary path puts in the frame body, because a WebSocket cannot set per-message
headers. Sixteen of them appear because auto-review ran repeatedly during the capture.

**Do not implement the 18-header shape as a client profile.** A proxy is never a subagent, and
the single 21-header row proves a guardian can also use the ordinary shape — so the lite variant
is not even universal among subagents. Emitting it for ordinary turns would produce a shape seen
only on auto-review connections, minus the `x-openai-subagent` marker that identifies them:
a combination no real client sends.

What this section does establish, both confirming `crack/codexv0.153.4`: `x-codex-routing-hint`
is present on every ordinary upgrade, and `x-codex-window-id` follows the **thread** id rather
than the session id — visible on the 21-header row, the only one where the two differ.

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
      only this grant carries originator + UA (the **full** UA — see §1), parse
      `earliest_refresh_at` and `oai_is`
- [ ] `auth/codex_login.go` — order-preserving auth-code body, persist the two new fields
- [ ] `auth/oauth.go` — honour `earliest_refresh_at`; the "~30 days" comment is wrong (10)
- [ ] `mimicry/codex_identity.go` — Desktop version / build / Konsole segment, all three.
      Flipping DefaultCodexProfile is NOT implied: per §3 the handshake is the same either way.
- [x] `codexws/headers.go` — NOTHING TO DO. §3's first draft was wrong: the ordinary
      Desktop handshake already equals what we send. Do not add a second profile shape.
- [ ] parity tests that read `rows/` rather than constants copied out of it
