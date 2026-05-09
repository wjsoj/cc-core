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

## Versioning

Semver. v0.x.y until the public API stabilizes.

## License

MIT. Anthropic OAuth refresh and uTLS transport originally adapted from [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (MIT).
