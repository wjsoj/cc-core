# Codex OAuth API alignment

Reference: the local CLIProxyAPI v7.3.10 checkout at `a5ab6952`.
This change aligns agent-facing protocol behaviour; it does not replace the
credential scheduler, OAuth refresh policy, or the WebSocket session registry.

## Shared contract

`codexoauth.PrepareCodexRequest` validates the requested service tier, translates
Chat Completions when needed, and applies the Codex request normalizer. Both
CPA-Claude and HypiToken call this entry point. The original request remains
available to the application's API-key fallback path.

- `/v1/chat/completions`: OAuth now supports both streaming and non-streaming
  clients in both apps, without requiring an API-key credential.
- `/v1/responses`: upstream remains streaming; non-streaming clients receive an
  aggregated Responses object.
- `/v1/responses/compact`: remains a separate JSON request/response path.
- Local request-preparation failures return 400 rather than forwarding an
  unsanitized payload or exhausting healthy credentials.

Request normalization now forces `parallel_tool_calls=false` for the known
Responses-Lite models, removes unsupported cache-breakpoint hints and `generate`,
translates recognized model effort suffixes to `reasoning.effort`, preserves large
integer schema values, and avoids injecting a duplicate image-generation tool
when the equivalent function/namespace tool is already present.

The reference deliberately is not copied blindly: existing session/account
identity, `previous_response_id` continuation, native WebSocket frame handling,
service-tier billing rules and explicit client tool-parallelism choices on
non-Lite models remain owned by cc-core's existing contracts.

## Response handling

`codexoauth.OutputAccumulator` deduplicates output items by index, restores empty
terminal output, and fills absent item ids from the matching done event. Both
apps use it for HTTP aggregation and native SSE, including WebSocket egress
rendered as SSE. `response.incomplete` is a terminal partial result with usage.

`apicompat.StreamState` now handles tool arguments supplied in added/done events,
argument completion events, and terminal output, without replaying arguments
already emitted as deltas. Refusal text is preserved. Duplicate terminal events
are ignored. Failure/cancellation and explicit finalization after truncation emit
an error envelope rather than a successful `finish_reason=stop`.

The application bridge still withholds retryable failures before output so the
existing failover policy applies. Once output is committed it forwards an error;
it does not replay the turn. Upstream failures are recorded separately from
successful completions. Pricing continues to use observed upstream usage.

## Local integration and release

Each consuming repository has its own ignored `go.work` using the sibling
`../cc-core` checkout. A single workspace cannot `use` both applications because
they share the same Go module path. No relative replacement was added to go.mod.

Released in cc-core `v0.8.137`, consumed by HypiToken `v0.36.158` and
CPA-Claude `v0.19.161`. Release validation uses `GOWORK=off` so both applications
resolve the published module instead of the sibling checkout. Production builds
use the application-pinned Go toolchains (HypiToken 1.25.6, CPA-Claude 1.26.2);
Go 1.27 is excluded because of the existing uTLS/http2 incompatibility.

## Regression coverage

- Core: tool-call reconstruction and deduplication; numeric WebSocket errors;
  terminal failure/truncation; precise tool schemas; Lite defaults; cache hints;
  invalid JSON; full multi-turn tool input; output restoration/id hydration.
- Each application: real HTTP ingress with an OAuth-only pool, streaming and
  non-streaming Chat tool calls, incomplete aggregation, explicit stream errors,
  invalid local requests, and native Responses terminal reconstruction.
- Existing core suites and both applications' server suites are also exercised.

Tests use local mock upstreams; real subscription accounts are not exercised.
