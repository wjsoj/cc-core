# crack/codexv0.135.0

Live capture of the **Codex CLI** (`codex-tui`, the Rust TUI) talking to the ChatGPT
subscription backend. Ground truth for the OpenAI/ChatGPT OAuth fingerprint, parallel to
`crack/claudev2.1.224/` (Anthropic).

**The shipped identity is `0.147.0`, not `0.135.0`.** `mimicry.CodexCLIVersion` has moved
three times since this capture — `0.144.1` → `0.144.4` → `0.147.0` — each verified against
the codex-rs release source rather than a fresh capture (see the dated sections at the top
of `SPEC.md`). The dir keeps the version that was actually on the wire here; anything
newer is source-derived and lives in `SPEC.md`.

- `SPEC.md` — authoritative constant list + the `0.125.0 → 0.135.0` diff and the
  HTTP-vs-WebSocket transport note. **Read this first.**
- `rows/` — structurally-redacted representative requests (one per distinct endpoint).
  Secrets (Bearer JWT, cookies, account UUID, user id, email, workspace path, git origin)
  are replaced with placeholders; non-secret fingerprint values are verbatim.

Capture target: `codex-tui/0.135.0` on a ChatGPT **Pro** plan, 2026-05-30, via Whistle.

Not captured this round: the OAuth PKCE login round-trip (outside the rolling buffer) and the
WebSocket frame bodies carrying the Responses payload (Whistle did not record WS frames).
