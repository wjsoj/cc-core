# crack/ — fingerprint ground truth (unified archive)

Captured client traffic that anchors every fingerprint constant in this module
(`mimicry/`, `sidecar/`, `auth/codex_*`, `kirotransport/`, `kiroapi/`,
`kirobridge/`). Consolidated here on 2026-06-10 from the two downstream app
repos (hypitoken, CPA-Claude) so the captures live next to the code they pin —
this directory is now the **single source of truth**; the app repos no longer
carry a `crack/`.

## Layout

| dir | provider / client | capture target | status |
|---|---|---|---|
| `cc2211/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.211`, 2026-07-18 | **current Claude target — read `cc2211/SPEC.md` first.** Chat-path diff vs cc2206: `anthropic-beta` rewritten 15→14 items (+context-1m, −server-side-fallback, −fallback-credit); `build_time` → 2026-07-15T16:34:37Z; billing-block fp algorithm re-validated (reproduces `2.1.211.3c8`). Runtime tail only — OAuth login flow + startup burst rows still live in `cc2191/`. |
| `cc2206/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.206`, 2026-07-10 | Superseded by cc2211. Chat-path diff vs cc2201: `anthropic-beta` grows 13→15 items (+server-side-fallback, +fallback-credit); `[1m]` telemetry pairing re-confirmed. |
| `cc2191/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.191`, 2026-06-25 | Login-flow + startup-burst baseline (kept because later captures roll those rows out of whistle's buffer). Full OAuth login flow (hello/token/profile/roles + api_hello/account_settings probes) and startup burst (eval_sdk/grove/bootstrap/penguin/mcp). Older per-version dirs (cc2167/cc2170/cc2183) were pruned — see git history. Later diffs: cc2197/cc2198/cc2201/cc2206. |
| `codex/` | OpenAI ChatGPT backend / Codex CLI | `codex-tui/0.135.0`, 2026-05-30 | **current Codex target** — identity bumped to `0.144.4`; 5h quota window retired 2026-07 (weekly-only). See `codex/SPEC.md`. |
| `kiro/` | Amazon Q / Kiro CLI | 2026-05/06 sessions + image-tool flow + PKCE login | **current Kiro target** |
| `oauth/` | Anthropic / Claude Code 2.1.126-era benign OAuth session | historical | beta-list / body-shape provenance |
| `apikey/` | Anthropic via x-api-key (3rd-party gateway path) | historical | provenance for the **apikey beta list** (strict gateways reject unknown betas) |
| `login/` | Anthropic OAuth login flow (hello → token → profile → roles → bootstrap) | 2.1.158-era | login-path fingerprint; UA on login sidecars = axios |
| `scripts/` | tooling | — | `extract_live.py` (structural redactor; pass `cc2191/rows` as outdir), `split.py`/`sanitize.py`/`gen.py` (older pipeline) |
| `COMPARE.md` | — | — | oauth-vs-apikey path diff notes |

## Redaction policy

Committed rows are **structurally redacted**: request/response *shape* (keys,
block layout, `cache_control`, betas, versions, env axes, metadata shape) is
verbatim; all identity and prose (device_id, account/organization UUIDs,
session ids, emails, conversation content, tokens) is `<masked>`/`<redacted>`.
The dd-api-key `pubea5604404508cdd34afb69e6f42a05bc` is a public client-side
constant and is kept verbatim on purpose.

**Raw whistle dumps are never committed here.** Pre-consolidation raw dumps
remain only in the git histories of hypitoken (`crack/raw/`, `crack/login/raw/`)
and CPA-Claude (`crack/kiro/raw/`). `scripts/redaction_map.json` (real captured
secrets, local-only) is gitignored.

## Bumping a fingerprint target (e.g. new Claude Code version)

1. Capture a fresh session through whistle; export the dump JSON.
2. `python3 crack/scripts/extract_live.py <dump.json> crack/cc<ver>/rows`
3. Write `crack/cc<ver>/SPEC.md` as the diff vs the previous target.
4. Update the constants in `mimicry/` + `sidecar/` (and `auth/codex_*` /
   `kiro*` for the other providers), run `go test ./...`, tag a release.
5. Bump the `cc-core` dependency in hypitoken and CPA-Claude.

See `cc2191/SPEC.md` for the worked 2.1.183 → 2.1.191 example.
