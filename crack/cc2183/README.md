# crack/cc2183 — Claude Code 2.1.183 live capture

Captured 2026-06-20 from a real `claude-cli/2.1.183` OAuth session (whistle dump,
100 sessions). **Supersedes crack/cc2170** (2.1.170) as the ground truth for the
fingerprint constants. See `SPEC.md` for the 2.1.170 → 2.1.183 diff and the edit
checklist.

As of cc-core's mimicry/sidecar convergence, **both** CPA-Claude and hypitoken
consume `cc-core/mimicry` + `cc-core/sidecar` via the module dependency — there is
no longer a vendored copy in hypitoken to keep in sync. Bumping the fingerprint is
a one-place cc-core edit + dep bump.

- **`SPEC.md`** — the authoritative 2.1.170 → 2.1.183 diff + edit checklist. Read
  this first.
- **`rows/`** — structurally-redacted representative requests, one per endpoint
  class, produced by `crack/scripts/extract_live.py`. Same class set as cc2170
  (`count_tokens` absent again this session).

## Headline changes vs 2.1.170

- **Request-header `anthropic-beta`** (`/v1/messages`): dropped
  `server-side-fallback-2026-06-01` + `fallback-credit-2026-06-01` (15 → 13
  items). Those two were only ever present at 2.1.170.
- **Default model is now `claude-opus-4-8`** (bootstrap param + telemetry) — was
  `claude-fable-5`. Fable 5 is **disabled upstream** (bootstrap response:
  `disabled_reason: "Claude Fable 5 is currently unavailable…"`).
- **Telemetry `betas` now correlates with the `[1m]` model suffix** — `[1m]`
  events report the 9-item list (with `context-1m`), plain-model events report an
  8-item list (without). The 9-item list is unchanged from 2.1.170; our heartbeat
  uses the (`[1m]`, 9-item) pair, so `ClaudeReportedBetas` does not move.
- **`build_time`** → `2026-06-18T23:04:10Z`.
- **GrowthBook eval UA** `Bun/1.3.14` → `Bun/1.4.0`.
- Unchanged: SDK 0.94.0, node v24.3.0, x-stainless-*, datadog `dd-api-key`, datadog
  body key set, quota-probe betas/model, body-layer system layout, the startup
  endpoint set.

## Privacy note

Same as prior captures: `extract_live.py` keeps only fingerprint-bearing
**structure** and replaces conversation prose / code / identity values
(device_id / account_uuid / organization_uuid / session_id / email / event_id)
with `<redacted …>` / `<masked:…>` placeholders. The raw dump is never committed.
The only verbatim secret-looking value retained is the Datadog `dd-api-key`
(`pub…`), a public global telemetry key.

To re-extract from a fresh whistle dump:

```bash
python3 crack/scripts/extract_live.py /path/to/whistle-dump.json crack/cc2183/rows
```
