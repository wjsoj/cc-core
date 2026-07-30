# Claude Code 2.1.220 capture analysis

This file records validation methodology and counts behind `SPEC.md`. It deliberately separates controlled main requests, title calls, prompt suggestions, quota probes, API telemetry, process telemetry, and bootstrap traffic.

## Completeness and boundaries

- Formal bootstrap: 17 requests after the recorded start marker. The stored bootstrap dump itself was re-filtered to the marker; the earlier full-buffer copy was not used.
- Independent sessions: 10/10 successful controlled first turns.
- Multi-turn session: 10/10 successful consecutive turns in one unchanged process and session.
- Formal unique rows after deduplication: 307.
- Classified rows: 141 auxiliary, 57 Datadog, 63 event-logging batches, 9 quota probes, 37 billing message requests.
- Billing breakdown: 20 controlled main, 11 title, 6 prompt suggestion.
- HTTP status for all 37 billing requests: 200.
- A missed user action initially labeled single round 9 was quarantined under `/private/tmp/cc2220-raw/discarded-missing-message/`; a fresh round 9 was captured and bounded at its own latest bootstrap.
- The first capture attempt that did not use an explicit `--settings` argument was quarantined under `/private/tmp/cc2220-raw/discarded-run1/` and excluded.

## Export verification

- Every formal round stores its own Whistle row IDs and start times in `meta.json`.
- Round exports use a strict previous-round `startTime` cutoff. The corrected single round 9 uses its latest process bootstrap as the cutoff to exclude an unused intermediate window.
- Deduplication key is `(Whistle row ID, startTime)`.
- All 37 billing requests in raw formal dumps appear once in `chain-redacted.json`. Structurally redacted rows keep one representative per repeated request class plus all 10 multi-turn main requests.
- `cch` and the complete `cc_version` are retained.
- `cc_prev_req` is retained as a stable hash, and response `request-id` is hashed with the same function for chain comparison.
- Header and body session IDs are hashed independently, then compared: 37/37 match.

## Request classification rules

- Controlled main: Sonnet billing request whose multi-turn message count is `2 × round`; every Sonnet billing request in an independent single-turn session is main.
- Title: Haiku billing request with disabled thinking and JSON-schema `title` output.
- Prompt suggestion: additional Sonnet billing request in a multi-turn round whose message count exceeds `2 × round`.
- Quota: non-billing Haiku request with `max_tokens=1` and no system field.
- API telemetry: event-logging batches containing `tengu_api_query`/`tengu_api_success`.
- Process telemetry: feature, skill, startup, prompt-suggestion, title-generated, and other lifecycle events.

This prevents title, quota, process telemetry, and business traffic from being collapsed into one constants table.

## cch validation

For every billing request:

1. Decode the exact Whistle request bytes.
2. Locate the genuine five-hex cch in the billing block.
3. Replace only those five bytes with `00000`.
4. Compute cc-core's current `xxhash64` with seed `0x6E52736AC806831E` over the resulting exact bytes.
5. Compare the low 20-bit hex value with the captured cch.

Result: **0/37**. There was no JSON reserialization and no sample rewriting beyond the five-byte placeholder substitution.

## Fingerprint suffix validation

The controlled first messages were evaluated three ways at indices `[4,7,20]`: byte indexing, Unicode code-point/rune indexing, and JavaScript UTF-16 code-unit indexing. The hash input was `59cf53e54c78 + selected characters + 2.1.220`, SHA-256 hex prefix length three.

| Round | Vector class | Actual | UTF-16 | Rune | Byte |
|---:|---|---:|---:|---:|---:|
| 1 | ASCII | ac9 | ac9 | ac9 | ac9 |
| 2 | Chinese BMP | e67 | e67 | e67 | 154 |
| 3 | emoji starts at index 4 | e25 | e25 | 7ae | 3fa |
| 4 | emoji starts before index 4 | e25 | e25 | 319 | ddf |
| 5 | Chinese + emoji | e08 | e08 | cce | c11 |
| 6 | ASCII sentence | 37b | 37b | 37b | 37b |
| 7 | Chinese punctuation | 002 | 002 | 002 | 084 |
| 8 | repeated ASCII | ac9 | ac9 | ac9 | ac9 |
| 9 | repeated ASCII | ac9 | ac9 | ac9 | ac9 |
| 10 | repeated ASCII | ac9 | ac9 | ac9 | ac9 |

UTF-16 matches 10/10. Rune indexing matches 7/10 and fails every emoji vector. Byte indexing also fails BMP non-ASCII vectors.

## Multi-turn chain validation

- Main round 1: no predecessor, as expected.
- Main rounds 2–10: 9/9 `cc_prev_req` hashes equal the immediately prior main response `request-id` hash.
- Prompt-suggestion requests: 6/6 predecessor hashes equal the same round's main response `request-id` hash.
- Multi-turn session hash: one stable value across all main/title/suggestion requests.
- cch: changes on every captured request.

## Telemetry observations

Formal event-logging data includes `tengu_api_query`, `tengu_api_success`, `tengu_feature_ok`, `tengu_skill_loaded`, `tengu_started`, `tengu_startup_telemetry`, `tengu_dir_search`, `tengu_session_title_generated`, and `tengu_prompt_suggestion`, among other events listed in the representative rows.

API query/success beta payloads match the associated request class. Process telemetry instead uses a short reported-beta family. This directly confirms that title, process telemetry, and API telemetry cannot share one constant.

## Redaction audit

The archive contains 30 JSON files: 28 representative/data rows, `_manifest.json`, and `chain-redacted.json`. Automated scans found:

- bearer values: 0
- email addresses: 0
- UUIDs: 0
- OAuth access/refresh token values: 0
- raw `req_*` request IDs: 0
- raw 64-hex identity hashes: 0

The scanner intentionally permits public versions, betas, cch values, field names, event names, models, status codes, and 16-hex comparison hashes.

## Contamination assessment

The concurrently existing old Claude process used hypitoken directly and did not route through Whistle 8899. Formal rows show the expected Claude Code 2.1.220 UA/version and the controlled process/session boundaries. The non-explicit-settings first attempt, connectivity probes, login-direct traffic, and the missed-message round are separately quarantined and excluded from the archive draft.
