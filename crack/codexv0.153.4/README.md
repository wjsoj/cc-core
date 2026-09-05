# crack/codexv0.153.4

Live capture of the **Codex CLI** (`codex-tui/0.153.4`) talking to the ChatGPT subscription
backend, taken 2026-09-05 on a ChatGPT **Pro** plan (Arch Linux, Konsole, via Whistle).

This is the current ground truth for the **CLI** profile — `mimicry.CodexCLI*` in
`mimicry/codex.go`. It supersedes `crack/codexv0.135.0/`, which covered the same client at an
older version.

**It does not supersede `crack/codexapp0.147.0/`.** That archive covers the **Desktop app**,
which is a genuinely different client with a different `originator` / User-Agent / `version`
triple, and it is what `mimicry.DefaultCodexProfile()` returns. The backend validates those
three against each other, so **the two profiles' constants must never be mixed** — do not bump
a Desktop constant from a CLI capture.

- `SPEC.md` — authoritative constant list, the 0.147.0 → 0.153.4 diff, and the edit checklist.
  **Read this first.**
- `rows/` — structurally-redacted representative requests. Secrets and identity values (Bearer
  JWT, cookies, account/user/org id, email, installation id, session/thread/context UUIDs,
  `cf-ray`, ETags) are replaced with stable `<PLACEHOLDER>`s; non-secret fingerprint values
  (User-Agent, originator, version, betas, model slugs and capability flags, header names and
  their wire order) are verbatim. The placeholders are stable across rows, so the handshake
  equality `x-client-request-id == session-id == thread-id` survives redaction.

Row numbering:

| range | subject |
|---|---|
| `01` | `GET /backend-api/codex/models` — the 9-model catalog a Pro account sees |
| `10`–`13` | `/backend-api/codex/responses` WebSocket handshakes + decoded `x-codex-turn-metadata` |
| `21`–`25` | `/backend-api/codex/analytics-events/events` — the CLI's own telemetry |
| `30`–`32` | `/backend-api/wham/*` — quota probe, credit reset, user settings |
| `40`–`44` | plugin store: `ps/mcp`, `ps/plugins/*`, `ps/apps/batch`, `plugins/featured` |
| `50` | `ab.chatgpt.com/otlp/v1/metrics` |

## Reproducing this archive

The capture came from Whistle's own API rather than a UI export, so it has a different shape
from what `crack/scripts/extract_live.py` (the Claude extractor) consumes. Use the Codex
extractor, which reads that shape directly:

```bash
curl -s 'http://127.0.0.1:8899/cgi-bin/get-data?ids=' -o /tmp/codex-dump.json
python3 crack/scripts/extract_codex_live.py /tmp/codex-dump.json crack/codexv0.153.4/rows
```

It is idempotent — delete `rows/` and re-run. The raw dump is never committed.

## What this capture contains that 0.147.0 did not

1. **`gpt-6-astra`** in the model catalog (`minimal_client_version` 0.153.0, priority 1), plus
   a hidden `gpt-reserve`, and a new `ultra` reasoning-effort level on several models.
2. **`x-codex-routing-hint` on the WebSocket handshake.** All three upgrades carry it.
   `codexws/headers.go` omits it, citing the 0.135.0 and 0.147.0 captures; that reasoning is
   superseded here. See SPEC §3.
3. **Seven more fields in `x-codex-turn-metadata`**, and two more headers
   (`x-codex-parent-thread-id`, `x-openai-subagent`) on subagent connections. See SPEC §4 and
   `rows/13`.

## Known gaps in this capture

1. **No WebSocket frames.** Whistle's `get-data` API returns the handshake but not the frame
   log, so there is no `response.create` body here. The frame shapes in
   `crack/codexapp0.147.0/rows/11`, `15`–`18` remain the only ground truth for those, and they
   are from the Desktop client. A frame-level re-capture is the top gap.
2. **No token refresh, no 429, no error frame.** A single short session on an unexhausted Pro
   plan produces none of them — same gap the 0.147.0 archive lists.
3. **`agent_name` in the turn metadata was the client's working directory** (`/root`). It is
   kept unmasked because it is not a secret, but it is a field a proxy has no honest value for.
4. **Pro plan only.** The model catalog a Free / Plus / Team account sees is not captured, so
   which plans list `gpt-6-astra` cannot be concluded from this archive alone.
