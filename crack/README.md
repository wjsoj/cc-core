# crack/ — fingerprint ground truth (unified archive)

Captured client traffic that anchors every fingerprint constant in this module
(`mimicry/`, `sidecar/`, `auth/codex_*`). Consolidated here on 2026-06-10 from the two downstream app
repos (hypitoken, CPA-Claude) so the captures live next to the code they pin —
this directory is now the **single source of truth**; the app repos no longer
carry a `crack/`.

## Directory naming

Every capture dir is named **`<client>v<version>[-<path>]`**, where the version is
the one in the captured `User-Agent` — not the one we happen to ship, and not the
one the dir was created for. Where several dirs share a client version, a `-<path>`
suffix names the auth path or traffic direction; the plain OAuth path carries no
suffix. Renamed from the old `cc<ver>` / role-named scheme on 2026-08-15:

| old | new |
|---|---|
| `cc2224/` | `claudev2.1.224/` |
| `cc2220/` | `claudev2.1.220/` |
| `cc2214/` | `claudev2.1.214/` |
| `oauth/` | `claudev2.1.126/` |
| `apikey/` | `claudev2.1.126-apikey/` |
| `login/` | `claudev2.1.126-login/` |
| `thirdparty/` | `claudev2.1.226-inbound/` |
| `codex/` | `codexv0.135.0/` |

`-inbound` is load-bearing: that dir's version (2.1.226) is *newer* than the current
OAuth target (2.1.224), and without the suffix it would read as a newer outbound
target when it is in fact the opposite direction.

## Layout

| dir | provider / client | capture target | status |
|---|---|---|---|
| `claudev2.1.224/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.224`, 2026-08-07 | **current Claude target — read `claudev2.1.224/SPEC.md` first.** Arch Linux, `claude-opus-5` in 1M mode throughout, 93 sessions. The only capture in the archive holding the **complete chain from a fresh OAuth login through startup bootstrap to steady-state traffic** (login leg = `rows/01`–`06`), and the first to anchor `quotaProbeBeta`/`quotaProbeModel` on a verbatim row (`rows/19`) instead of a pruned 2.1.170 file. Verdict vs 2.1.220: a **version-string-only bump** — version, `ccBuildTime`, reported telemetry model. Gaps: the non-1M 13-item beta vector and `count_tokens` were not exercised, so both carry forward from 2.1.220 unverified. |
| `claudev2.1.220/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.220`, 2026-07-30 + 2026-07-31 | Previous Claude target; still the **most detailed SPEC in the tree**. Two independent captures: `rows/` (macOS, Sonnet 5) and `rows-2026-07-31/` (Linux, opus-4-8 + opus-5 1M, plus a full fresh OAuth login). The second one established that the request beta list is context-mode dependent (13 non-1M / 15 with 1M), that `count_tokens` is its own request class, and corrected the login `profile` probe headers and two MCP-probe details (§1a/§1b/§2/§3). Startup plus 10 independent first turns and one continuous 10-turn conversation, consolidated to 28 representative/data rows while retaining all 10 multi-turn main requests. `chain-redacted.json` preserves all 37 billing requests and hashed `cc_prev_req` → upstream response `request-id` linkage (main 9/9, prompt suggestion 6/6). Version/build_time bumped; UTF-16 billing suffix semantics fixed. `context-1m` is intentionally excluded from the version diff. |
| `claudev2.1.214/` | Anthropic / Claude Code CLI (OAuth) | `claude-cli/2.1.214`, 2026-07-18 | Superseded by claudev2.1.220 but **kept as the login-flow baseline**: it is the only in-tree capture with the `oauth_hello`, `api_hello` and `oauth_account_settings` probe rows, which claudev2.1.220 does not have. Full re-login + bootstrap + chat (18 rows). Wire vs 2.1.211: pure version + `build_time` bump; also fixed 3 bootstrap-sidecar UAs (account/settings, grove, mcp-registry). Older per-version dirs (cc2167/cc2170/cc2183, then cc2191/cc2197/cc2198/cc2201/cc2206/cc2211) were pruned — see git history. |
| `codexv0.135.0/` | OpenAI ChatGPT backend / Codex CLI | `codex-tui/0.135.0`, 2026-05-30 | **the only Codex capture.** The shipped identity has since moved to **`0.147.0`** (`mimicry/codex.go`) across three source-verified bumps — 0.144.1 → 0.144.4 → 0.147.0, each checked against the codex-rs release rather than a fresh capture, so the dir name stays at the last version actually on the wire here. Also records the 5h quota window's retirement (2026-07, weekly-only). See `codexv0.135.0/SPEC.md`. |
| `claudev2.1.226-inbound/` | Anthropic / Claude Code CLI pointed at a **custom base URL** | `claude-cli/2.1.226`, 2026-08-09 | **the inbound shape both forks actually receive** — read `claudev2.1.226-inbound/SPEC.md` alongside the current Claude target. Every other dir records what we must *produce*; this one records what we must *repair*. Establishes the OAuth-only beta delta (5 items), the empty `account_uuid`, the bare-`ephemeral` cache breakpoints, the absent `x-client-request-id`, and that a real client on a custom base URL emits **no** sidecar traffic at all. |
| `claudev2.1.126/` | Anthropic / Claude Code, benign OAuth session | `claude-cli/2.1.126`, historical | beta-list / body-shape provenance; `sidecar`'s 10-step bootstrap timings come from its `rows/01..10` |
| `claudev2.1.126-apikey/` | Anthropic via x-api-key (3rd-party gateway path) | `claude-cli/2.1.126`, historical | provenance for the **apikey beta list** (strict gateways reject unknown betas) |
| `claudev2.1.126-login/` | Anthropic OAuth login flow (hello → token → profile → roles → bootstrap) | `claude-cli/2.1.126`, historical | login-path fingerprint; UA on login sidecars = axios |
| `scripts/` | tooling | — | `extract_live.py` (structural redactor; default outdir = the current target's `rows/`), `sanitize.py`/`gen.py` (older pipeline) |
| `COMPARE.md` | — | — | oauth-vs-apikey path diff notes, **2.1.126-era and never re-verified since**. For the oauth-vs-custom-base-url diff at the current target use `claudev2.1.226-inbound/SPEC.md` instead. |

The three `claudev2.1.126*` dirs are one client version captured over three different
auth paths, which is why they share a version and differ only by suffix.

## Redaction policy

Committed rows are **structurally redacted**: request/response *shape* (keys,
block layout, `cache_control`, betas, versions, env axes, metadata shape) is
verbatim; all identity and prose (device_id, account/organization UUIDs,
session ids, emails, conversation content, tokens) is `<masked>`/`<redacted>`.
The dd-api-key `pubea5604404508cdd34afb69e6f42a05bc` is a public client-side
constant and is kept verbatim on purpose.

**Raw whistle dumps are never committed here.** Pre-consolidation raw dumps
remain only in the git histories of hypitoken (`crack/raw/`, `crack/login/raw/`).
`scripts/redaction_map.json` (real captured
secrets, local-only) is gitignored.

## Bumping a fingerprint target (e.g. new Claude Code version)

1. Capture a fresh session through whistle; export the dump JSON.
2. `python3 crack/scripts/extract_live.py <dump.json> crack/claudev<ver>/rows`
3. Write `crack/claudev<ver>/SPEC.md` as the diff vs the previous target.
4. Update the constants in `mimicry/` + `sidecar/` (and `auth/codex_*`
   for the Codex path), run `go test ./...`, tag a release.
5. Bump the `cc-core` dependency in hypitoken and CPA-Claude.
6. **Re-capture the custom-base-url side too** and refresh the `-inbound` dir.
   The inbound shape is half of every transform `mimicry` performs, and it moves
   on its own schedule: a Claude Code release can add a beta to the custom-base-url
   vector without touching the OAuth one, which silently widens the OAuth-only
   delta in its `SPEC.md §1a`. Point a client at any Anthropic-compatible
   gateway with `ANTHROPIC_BASE_URL` and run
   `extract_live.py <dump.json> crack/claudev<ver>-inbound/rows`.

A capture dir is named for the version it captured, so a re-capture at a new
version means a **new dir**, not an in-place overwrite — and the old one is either
kept (as `claudev2.1.214/` is, for its unique probe rows) or pruned outright.

See `claudev2.1.224/SPEC.md` for the worked 2.1.220 → 2.1.224 example, and
`claudev2.1.220/SPEC.md` for the 2.1.214 → 2.1.220 one (backed by two independent
captures and a 10-turn conversation).
