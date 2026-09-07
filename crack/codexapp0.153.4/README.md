# crack/codexapp0.153.4

Live capture of the **Codex Desktop app** (`Codex Desktop/0.153.4`, build `26.901.51231`)
talking to the ChatGPT subscription backend, taken **2026-09-07** on a ChatGPT **Plus** plan
(Arch Linux, Konsole, via Whistle). 247 sessions over 17 minutes.

What makes this one worth having is that it spans a **complete re-login**: the session's refresh
token had been invalidated upstream, so the capture contains nine minutes of 401 backoff, a
fresh authorization-code exchange, and the API-key token-exchange probe that follows it. All
three OAuth grants are here, and they turn out not to share a request shape.

- `SPEC.md` — authoritative constant list, the three grant shapes, the Desktop-vs-CLI handshake
  diff, the newly-discovered endpoints, and the edit checklist. **Read this first.**
- `rows/` — structurally-redacted representative requests.

This archive **supersedes `crack/codexapp0.147.0/`** as the Desktop ground truth. That directory
stays: it is the only record of the 0.147.0 handshake, which differs materially from this one.

It does **not** supersede `crack/codexv0.153.4/`, which covers the **CLI** (`codex-tui`) at the
same version. A codex-tui client happened to be running on the same machine during this capture,
so the two shapes can be compared with no version drift between them — see SPEC §3. Their
constants must never be mixed: the backend validates originator against the User-Agent's leading
segment.

## Row numbering

| range | subject |
|---|---|
| `01`–`04` | OAuth: refresh grant, authorization-code grant, decoded JWT claims, token-exchange probe |
| `10`–`12` | WebSocket handshakes (ordinary + subagent) and the model catalog |
| `20`–`21` | `wham/*`: the previously-unknown remote-control refresh, and user settings |
| `30`–`39` | `codex/analytics-events/events` — the client's own telemetry |
| `40`–`49` | plugin store: `ps/mcp`, `ps/plugins/*`, `plugins/featured` |
| `50` | `ab.chatgpt.com/otlp/v1/metrics` |

## Redaction

Secrets and identity values are replaced with **typed** placeholders that preserve shape, so a
reader can tell one kind of token from another without the value:

| original | placeholder |
|---|---|
| access / id token | `<JWT_REDACTED>` |
| `refresh_token` | `<masked:opaque "rt.1.<base64url>" refresh_token>` |
| `oai_is` | `ois1.<JWT_REDACTED>` (the `ois1.` prefix is fingerprint, not secret) |
| OAuth `code` | `<masked:oauth authorization code "ac_...">` |
| PKCE verifier | `<masked:PKCE code_verifier, 96-byte base64url>` |
| remote-control `server_id` | `<masked:remote-control server_id "srv_e_<hex>">` |
| account / user / org id | `<ACCOUNT_UUID>`, `<OPAQUE_ID>` |
| session / thread / window ids | `<UUID>`, `<UUID_n>` — **stable across rows**, so equalities like `x-client-request-id == session-id == thread-id` survive redaction |
| installation id | `<INSTALLATION_ID>` |
| email | `<EMAIL>` |
| cookies, `cf-ray`, ETags | `<REDACTED>` |

Kept verbatim because they are fingerprint rather than secret: `client_id`, `redirect_uri`,
granted `scope`, `expires_in`, the `statsig-api-key` publishable key, every capability flag, and
all header names, casing and **order**.

Whistle's own injected headers (`x-whistle-*`, `Proxy-Authorization`, `Proxy-Connection`) are
stripped from both the header maps and the order arrays — header order is the thing this archive
exists to record, and interleaving the proxy's own names corrupts it.

## Reproducing

The source is Whistle's own API rather than a UI export. Note that whistle's server keeps only
the most recent ~100 sessions while its **web UI accumulates far more**, so a capture older than
that has to be harvested from the browser (scroll the network list to collect `data-id`
attributes, then fetch them back in batches via `/cgi-bin/get-data?ids=`) rather than from a
single API call. Unwrap the harvest to `{"data": {"data": {<id>: <session>, …}}}` and then:

```bash
python3 crack/scripts/extract_codex_live.py --profile=desktop-login \
    /tmp/login-dump.json crack/codexapp0.153.4/rows
python3 crack/scripts/sanitize.py
```

`--profile=desktop-login` selects the rule set for a capture that spans a login; the default
`cli-session` profile reproduces `crack/codexv0.153.4/` instead. The raw dump is never
committed.

## Known gaps

1. **`/oauth/authorize` is still uncaptured** — the consent page opens in the system browser and
   the callback lands on `http://localhost:1455`, so neither traverses the proxy. The requested
   `scope`, the PKCE parameters and the `id_token_add_organizations` /
   `codex_cli_simplified_flow` flags remain unverified. Closing this needs the browser itself
   pointed at the proxy.
2. **No successful refresh response.** The refresh request shape is now known; its 200 shape is
   not — the one sample here is the 401 that triggered the re-login.
3. **No successful `wham/remote/control/server/refresh`.** All 63 samples are 401, so the
   endpoint's success shape and its `server_id` registration step are both unknown.
4. **Sentry is opaque.** A CONNECT to `o33249.ingest.us.sentry.io:443` every 60 s, never
   decrypted.
5. **No 429 or error frame.** Needs a deliberately exhausted window; unrelated to login.
