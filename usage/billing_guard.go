package usage

import "encoding/json"

const (
	// MissingUsageError is the stable request-log marker used when an upstream
	// succeeds without returning billable usage.
	MissingUsageError = "missing usage"

	// ClientCanceledError marks a stream the CLIENT abandoned. It is NOT a
	// missing-usage fault: the credential did nothing wrong, so it must not be
	// cooled down, and whatever usage was observed before the hang-up is what
	// gets billed — never an estimate.
	ClientCanceledError = "client canceled mid-stream"
)

// EnsureOpenAIStreamUsage rewrites a Chat Completions JSON request so
// stream_options.include_usage is true, guaranteeing a terminal usage chunk.
// Non-JSON bodies are returned unchanged with the decode error so callers can
// decide whether to continue passthrough.
//
// It injects ONLY for Chat Completions requests (identified by a `messages`
// field). `stream_options` is a Chat Completions parameter — the Responses API
// (/v1/responses) does not accept it (it already reports usage in its own
// response.completed event), and strict upstreams (e.g. new-api gateways)
// reject the unknown parameter with a 400. So a Responses request is returned
// unchanged: its usage is already ensured by the protocol.
func EnsureOpenAIStreamUsage(body []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, err
	}
	if _, isChatCompletions := raw["messages"]; !isChatCompletions {
		return body, nil
	}
	opts, _ := raw["stream_options"].(map[string]any)
	if opts == nil {
		opts = map[string]any{}
	}
	opts["include_usage"] = true
	raw["stream_options"] = opts
	out, err := json.Marshal(raw)
	if err != nil {
		return body, err
	}
	return out, nil
}

// MissingUsage reports whether a successful upstream response produced no
// usage accounting. Successful billable responses should increment Requests
// when usage is observed; zero means billing cannot be computed accurately.
//
// # Why there is no estimate to pair with this
//
// An earlier revision answered "no usage" on an already-streamed response with
// MissingUsageFallbackCounts: input ≈ len(requestBody)/4, output a flat 1000,
// both floored at 1000. It was removed in v0.8 after a production audit of
// 825,929 request-log rows showed what it actually did across 233 charged rows:
//
//	estimated input   p50 140,712   p90 272,575   max 2,258,861 tokens
//	charged           $170.28 total, largest single request $11.32
//
// The estimate was wrong in both directions at once. It billed 100% of the
// prompt at the uncached rate when Codex-CLI traffic runs ~92% cache-hit
// (≈10× over on the input axis), while pinning output to 1000 regardless of
// what the stream had actually delivered (86% under on a long generation that
// died near the end). Worse, it could not tell "the relay dropped the usage
// chunk" from "the user pressed Ctrl-C", so every client cancellation was
// billed a full-prompt estimate AND tripped the credential's circuit breaker.
//
// The replacement policy — matching what sub2api settled on — is:
//
//	client canceled        → bill the partial usage observed, health-neutral
//	upstream sent no usage → bill nothing, log the row, cool the credential
//
// Losing a fraction of a cent on a broken relay is cheap; the circuit breaker
// bounds how many such requests can happen. Presenting a fabricated token count
// to a customer as an itemised invoice line is not cheap. Do not reintroduce an
// estimator here: if a number cannot be observed, it must not be billed.
func MissingUsage(c Counts) bool {
	return c.Requests == 0
}

// StreamOutcome classifies how a streamed upstream response ended, so callers
// can apply the three different billing/health policies without each re-deriving
// the distinction (which is how the Anthropic, Codex-OAuth and Codex-API-key
// paths drifted apart in the first place).
type StreamOutcome int

const (
	// StreamComplete — a terminal event arrived and usage was observed. Bill it.
	StreamComplete StreamOutcome = iota

	// StreamClientCanceled — the downstream client went away mid-stream. Bill
	// whatever partial usage was observed (possibly zero); leave credential
	// health untouched. This is the user's choice, not a fault.
	StreamClientCanceled

	// StreamUpstreamNoUsage — the stream completed or truncated on the upstream
	// side without ever reporting usage. Bill nothing, emit a request-log row
	// carrying MissingUsageError, and report a fault so the breaker can rotate
	// away from a relay that cannot account for what it serves.
	StreamUpstreamNoUsage
)

// ClassifyStreamOutcome maps an observed (counts, clientGone) pair onto the
// policy above. clientGone should come from the request context / write-side
// error, never from the read error alone — an upstream RST and a client hang-up
// surface identically at the reader.
func ClassifyStreamOutcome(c Counts, clientGone bool) StreamOutcome {
	switch {
	case clientGone:
		return StreamClientCanceled
	case MissingUsage(c):
		return StreamUpstreamNoUsage
	default:
		return StreamComplete
	}
}

// Billable reports whether a request that ended this way should reach the
// pricing catalogue at all. Only observed usage is ever billed.
func (o StreamOutcome) Billable(c Counts) bool {
	return o != StreamUpstreamNoUsage && !MissingUsage(c)
}

// CredentialFault reports whether this outcome should be charged against the
// serving credential's health. A client hang-up must not be.
func (o StreamOutcome) CredentialFault() bool { return o == StreamUpstreamNoUsage }

// LogError returns the stable request-log `error` marker for this outcome, or
// "" when the request ended normally.
func (o StreamOutcome) LogError() string {
	switch o {
	case StreamClientCanceled:
		return ClientCanceledError
	case StreamUpstreamNoUsage:
		return MissingUsageError
	default:
		return ""
	}
}
