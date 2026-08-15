# crack/codexapp0.147.0

Live capture of the **Codex Desktop app** (`Codex Desktop/0.147.0-alpha.6.6`) talking to the
ChatGPT subscription backend. This is the ground truth for the identity cc-core now presents
upstream by default — see `mimicry.DefaultCodexProfile`.

Sibling archive `crack/codexv0.135.0/` covers the **CLI** (`codex-tui`). The two are different
clients with different `originator` / User-Agent / `version` triples, and the backend validates
them against each other, so **their constants must never be mixed**.

- `SPEC.md` — authoritative constant list, the Desktop-vs-CLI diff, the WebSocket protocol,
  the six incompatible auxiliary header sets, and the response-direction leak inventory.
  **Read this first.**
- `rows/` — structurally-redacted representative requests. Secrets (Bearer JWT, refresh token,
  cookies, account/user/org UUID, email, name, installation id, session/thread/turn UUIDs,
  `resp_`/`ctc_`/`call_` ids, user prose, filesystem paths) are `<masked>`; non-secret
  fingerprint values (User-Agent, originator, version, betas, model names, header names and
  order, numeric metrics) are verbatim.

Row numbering:

| range | subject |
|---|---|
| `01`–`03` | OAuth / token endpoint / JWT claim shapes |
| `10`–`14` | `/backend-api/codex/responses` (WebSocket) and `/backend-api/codex/models` |
| `15`–`18` | turn-opening `response.create` frames and their `input[]` items (2026-08-15 run) |
| `20`–`33` | auxiliary traffic: plugins, MCP, analytics, telemetry |

Capture target: `Codex Desktop/0.147.0-alpha.6.6` (build `26.803.81509`, codex-rs core
`0.147.0-alpha.6.6`) on a ChatGPT **Plus** plan, Arch Linux, via Whistle.

- **2026-08-14** — 293 HTTP sessions plus 541 WebSocket frames over a 12-minute run that
  included a full sign-in. Source of `rows/01`–`14` and `20`–`33`.
- **2026-08-15** — a second run on the same machine and account: 176 HTTP sessions plus 543
  frames across three WS sessions. Source of `rows/15`–`18`. Whistle was **not** restarted and
  its frame cache was left at the default 512 — the opening frames survived this time only
  because no single session exceeded it (461 / 49 / 33 frames). The 512-frame ceiling is still
  live and will evict openers again on a longer turn.

## Known gaps in this capture

1. **`/oauth/authorize` was not captured.** The consent page opens in the system browser,
   which does not go through the proxy. The authorize-side `scope`, PKCE parameters, and the
   `id_token_add_organizations` / `codex_cli_simplified_flow` flags are therefore unverified
   for Desktop; the granted scope in the token response is the only evidence, and it is wider
   than what cc-core requests (it adds `api.connectors.read api.connectors.invoke`).
2. ~~**The first `response.create` frame of a turn is missing.**~~ **CLOSED by the 2026-08-15
   run.** In the first capture Whistle's 512-frame default cache had evicted the openers of a
   541-frame turn, leaving only `previous_response_id` continuations. The second run captured
   three complete sessions including their opening frames — see `rows/15`–`18` and SPEC §2.3.
   What they show is that the premise was wrong: there is no `instructions` key and no
   top-level `tools` array anywhere. Tools ride in `input[0]` as `additional_tools`, the system
   prompt is a `role: "developer"` message, and a session opens with a `generate: false`
   cache-priming frame. Still worth passing `w2 restart -F 200000` on the next capture — the
   default ceiling was not raised, we simply had shorter turns.
3. **Sentry is opaque.** A CONNECT to `o33249.ingest.us.sentry.io:443` fires every 60.0s for
   the entire run, including while signed out. It is the only fixed-period heartbeat in the
   capture and its payload is unknown.
4. **No token refresh.** `expires_in` is 10 days, so a single session never triggers one. The
   refresh request/response shape is still source-derived.

## Still missing after both runs

Four things neither capture contains. Listed together because each needs a *deliberately
constructed* capture, not another ordinary session:

1. **`/oauth/authorize`.** The consent page opens in the system browser, outside the proxy.
   Needs the browser pointed at the proxy (or the flow driven manually) to see the real
   `scope`, the PKCE parameters, and the `id_token_add_organizations` /
   `codex_cli_simplified_flow` flags. Gap 1 above.
2. **A token refresh.** Needs a credential aged past `earliest_refresh_at` (issue + 9 days) or
   an access token invalidated by hand. Gap 4 above.
3. **Any 429 or error response.** Both runs stayed at `used_percent: 0` on a Plus plan, so
   every `/responses` turn succeeded. We therefore have no Codex `Retry-After`, no error frame,
   and no `response.failed`/`error` event shape — which is why `downstream.ensureRetryAfter`
   still derives only from the Anthropic headers (SPEC §7). Needs a deliberately exhausted
   window.
4. **The Sentry payload.** A CONNECT to `o33249.ingest.us.sentry.io:443` every 60.0 s in both
   runs, contents unknown. Needs TLS interception for that host specifically. Gap 3 above.
