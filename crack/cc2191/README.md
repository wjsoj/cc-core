# crack/cc2191 — Claude Code 2.1.191 live capture

Captured 2026-06-25 from a real `claude-cli/2.1.191` OAuth session (whistle dump,
fresh login window, 36 sessions). **The sole CC-version capture kept** — the
ground truth for the fingerprint constants. Older per-version dirs (cc2183 /
cc2170 / cc2167) were pruned; see `SPEC.md` for the 2.1.183 → 2.1.191 diff and
the edit checklist, and git history for the earlier captures.

This round **captured the OAuth login flow from scratch** (logout → `/login` →
browser consent → token exchange → startup → chat), so `rows/` now includes the
`oauth_hello` / `oauth_token` / `oauth_profile` / `oauth_roles` requests plus two
new login probes (`api_hello`, `oauth_account_settings`) that the 2.1.170 /
2.1.183 steady-state captures lacked.

As of cc-core's mimicry/sidecar convergence, **both** CPA-Claude and hypitoken
consume `cc-core/mimicry` + `cc-core/sidecar` via the module dependency — there is
no vendored copy to keep in sync. Bumping the fingerprint is a one-place cc-core
edit + dep bump.

- **`SPEC.md`** — the authoritative 2.1.183 → 2.1.191 diff + edit checklist. Read
  this first.
- **`rows/`** — structurally-redacted representative requests, one per endpoint
  class, produced by `crack/scripts/extract_live.py` (18 rows; `count_tokens`
  absent again this session — no token-counting in the window).

## Headline changes vs 2.1.183

- **Node runtime `v24.3.0` → `v26.3.0`** — the *only* fingerprint-bearing change
  on the chat path. Moves `x-stainless-runtime-version` (request header) AND
  telemetry `env.node_version` together (one constant: `ClaudeStainlessRuntimeV`).
- **`build_time`** → `2026-06-24T11:24:03Z`.
- **OAuth token exchange/refresh confirmed on `platform.claude.com`** — cc-core's
  `auth/oauth.go` already targets it (`anthropicTokenURL`), so no code change; the
  fresh login capture just re-confirms alignment.
- **Unchanged:** request-header `anthropic-beta` (13 items, byte-identical),
  telemetry `betas` (9-item `[1m]` list), default model `claude-opus-4-8`, SDK
  0.94.0, x-stainless-* (except runtime version), datadog `dd-api-key` + body key
  set, body-layer system layout + `cch`, GrowthBook UA `Bun/1.4.0`, axios 1.15.2,
  the startup endpoint set.

## Privacy note

Same as prior captures: `extract_live.py` keeps only fingerprint-bearing
**structure** and replaces conversation prose / code / identity values
(device_id / account_uuid / organization_uuid / session_id / email / event_id /
OAuth `code`/`code_verifier`/`state`/tokens) with `<text:…>` / `<masked:…>`
placeholders. The raw dump is never committed. The only verbatim secret-looking
value retained is the Datadog `dd-api-key` (`pub…`), a public global telemetry
key, plus the public Claude Code `client_id` constant.

To re-extract from a fresh whistle dump:

```bash
python3 crack/scripts/extract_live.py /path/to/whistle-dump.json crack/cc2191/rows
```
