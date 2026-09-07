// Package codexsidecar emulates the auxiliary upstream traffic a genuine
// Codex Desktop client emits alongside its /backend-api/codex/responses
// turns.
//
// Ground truth is crack/codexapp0.153.4/ (Codex Desktop/0.153.4, build
// 26.901.51231, captured 2026-09-07 — 247 sessions over 17 minutes spanning a
// complete re-login). Over those 17 minutes ONE Desktop client emitted ~215
// upstream requests. cc-core on its own emits three kinds: the business
// forward, a token refresh, and an operator probe. Everything else in that
// list is a hole in the shape, and this package fills the part of it that can
// be filled honestly.
//
// # Relationship to package sidecar
//
// This is a PARALLEL implementation of the Anthropic sidecar, not a
// generalisation of it. The two clients share no endpoint, no User-Agent, no
// auth header, no body shape and no cadence; crack/codexapp0.147.0/SPEC.md §6
// argues the abstraction would cost more than it saves. Structure and
// lifecycle (first-touch Notify, per-account anchor, bootstrap cooldown,
// idle-scaled steady state, cancellable goroutines, GC sweep) are deliberately
// mirrored so a reader of one can read the other.
//
// # What is emitted
//
// Bootstrap burst, on first touch of an (account, clientToken) pair — offsets
// derived from the capture, see bootstrapSteps:
//
//	GET  /backend-api/ps/plugins/installed?limit=200
//	GET  /backend-api/ps/plugins/list?scope=GLOBAL&limit=200
//	GET  /backend-api/plugins/featured?platform=codex
//	GET  /backend-api/ps/plugins/suggested/codex?scope=GLOBAL
//	GET  /backend-api/codex/models?client_version=<ver>
//	POST /backend-api/ps/mcp            (initialize, notifications/initialized,
//	                                     tools/list, resources/list,
//	                                     resources/templates/list)
//	GET  /backend-api/wham/settings/user
//
// Steady state, each behind a per-endpoint rate floor taken from the captured
// counts (see capturedMinInterval): the plugin-store polls, the model catalog
// re-fetch, the periodic ps/mcp refresh, the settings re-read, a 60s OTLP
// metrics export to ab.chatgpt.com, and — only when the caller reports a turn
// that actually happened — codex/analytics-events/events.
//
// # What is deliberately NOT emitted
//
// Sentry. The Desktop client opens a CONNECT tunnel to
// o33249.ingest.us.sentry.io every ~60s, 19 times in the capture. It was never
// decrypted, so its payload is unknown, and it terminates at a third party
// rather than at OpenAI. Emitting invented crash-reporter traffic to someone
// else's servers is not something this package will do at any fidelity target.
// There is no flag for it. Do not add one.
//
// POST /backend-api/wham/remote/control/server/refresh. 63 samples in the
// capture, all 401 (token_revoked), so the success shape is unknown. Worse,
// the body is {"server_id":"srv_e_<hex>","installation_id":"<uuid>"} and the
// server_id is minted by a registration step the capture does not contain —
// there is no way to derive one, and a fabricated server_id is a value the
// backend can trivially fail to recognise. Re-visit only with a capture that
// includes the registration and at least one non-401 response.
//
// The codex_command_execution_event / codex_dynamic_tool_call_event /
// codex_hook_run analytics events. They describe local shell commands, plugin
// hook handlers and dynamic tool calls executed on the client's own machine. A
// proxy runs none of that, so every field would be invented. Only
// codex_thread_initialized and codex_turn_event are emitted, both built
// strictly from a turn the caller observed.
//
// # Three invariants
//
//  1. Real ids only. The analytics envelope carries thread_id / session_id /
//     turn_id that the backend can join against real /responses traffic.
//     Invented ids produce metadata no genuine client could emit — strictly
//     worse than sending nothing. The event builders take a verifiedTurn,
//     an unexported type with no exported fields whose only constructor is
//     newVerifiedTurn, which rejects anything that is not a well-formed
//     UUID triple with a coherent time range. There is no path from raw
//     strings to a request body.
//
//  2. Per-account identity. The OTLP resource block carries host identity
//     (os, os_version) and the analytics/turn bodies carry an
//     installation_id. One identical blob for every credential correlates
//     every credential into one machine — the same failure auth.HostProfile
//     exists to defuse on the Anthropic side. Both derive from the account
//     anchor: os/os_version from auth.HostProfile, installation_id from
//     mimicry.CodexInstallationIDFor.
//
//  3. Never faster than the real client. Every outbound call passes through
//     a per-(account, endpoint) rate floor set from the captured counts, so
//     no scheduling bug can make one account noisier than one genuine
//     Desktop. The configured steady-state intervals sit well below those
//     floors; the floors are the backstop, not the schedule.
//
// API-key credentials never trigger any of this, and neither do Anthropic
// credentials. Both guards mirror sidecar.Notify: a real Desktop app on an API
// key emits none of this traffic, and every endpoint here is a ChatGPT
// subscription endpoint that must never see an Anthropic bearer.
package codexsidecar
