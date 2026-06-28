package usage

import "encoding/json"

const (
	// MissingUsageError is the stable request-log marker used when an upstream
	// succeeds without returning billable usage.
	MissingUsageError = "missing usage"

	// MissingUsageFallbackMinInputTokens and MissingUsageFallbackMinOutputTokens
	// are deliberately small, non-zero floors for already-streamed responses
	// where the content reached the client before the missing usage could be
	// detected. Non-streaming callers should fail closed instead.
	MissingUsageFallbackMinInputTokens  int64 = 1000
	MissingUsageFallbackMinOutputTokens int64 = 1000
)

// EnsureOpenAIStreamUsage rewrites an OpenAI-compatible JSON request so
// stream_options.include_usage is true. Non-JSON bodies are returned unchanged
// with the decode error so callers can decide whether to continue passthrough.
func EnsureOpenAIStreamUsage(body []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, err
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
func MissingUsage(c Counts) bool {
	return c.Requests == 0
}

// MissingUsageFallbackCounts returns a conservative non-zero estimate for an
// already-delivered response whose upstream omitted usage. The input estimate
// is based on request JSON size so very large prompts pay more than the floor.
func MissingUsageFallbackCounts(requestBody []byte) Counts {
	input := int64(len(requestBody)+3) / 4
	if input < MissingUsageFallbackMinInputTokens {
		input = MissingUsageFallbackMinInputTokens
	}
	return Counts{
		InputTokens:  input,
		OutputTokens: MissingUsageFallbackMinOutputTokens,
		Requests:     1,
	}
}
