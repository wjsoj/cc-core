package downstream

import (
	"encoding/json"
	"net/http"
	"regexp"
)

const ClaudeSafeguardsUnsupportedType = "invalid_request_error"
const ClaudeSafeguardsUnsupportedMessage = "The safeguards parameter is not supported by this upstream."

// Match explicit capability rejection, not malformed input or absent verdicts.
// Keep each phrase local to the capability, excluding unrelated field errors.
var claudeSafeguardsUnsupportedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsafeguards["']?\s*:?\s*(?:(?:parameter|field)\s+)?(?:is\s+|are\s+)?(?:not supported|unsupported)(?:$|[.;,]|\s+(?:by|for|on|in|with)\b)`),
	regexp.MustCompile(`(?i)\b(?:unsupported|unknown|unrecognized)\s+(?:parameter|field|argument)\s*:?\s*["']?safeguards(?:["']|\s|$)`),
	regexp.MustCompile(`(?i)\bsafeguards["']?\s*:\s*extra inputs are not permitted\b`),
	regexp.MustCompile(`(?i)\b(?:unsupported|unknown|unrecognized)\s+beta(?:\s+(?:header|flag|feature))?\s*:?\s*["']?dangerous-tool-use-\d{4}-\d{2}-\d{2}\b`),
	regexp.MustCompile(`(?i)\bdangerous-tool-use-\d{4}-\d{2}-\d{2}["']?\s*(?:beta\s*)?(?::\s*)?(?:is\s+)?(?:not supported\b|unsupported\b)`),
}

// IsClaudeSafeguardsUnsupported recognizes only HTTP 400 capability errors.
// Callers must emit the constants above, never the matched upstream message:
// diagnostics may include keys, URLs or account identifiers. This preserves
// native unsupported-capability fallback without inventing classifier results.
func IsClaudeSafeguardsUnsupported(status int, body []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	var payload struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	// Relays may omit type, but explicit auth/policy/server errors must not match.
	switch payload.Error.Type {
	case "", "invalid_request_error", "invalid_request", "bad_request":
	default:
		return false
	}
	for _, pattern := range claudeSafeguardsUnsupportedPatterns {
		if pattern.MatchString(payload.Error.Message) {
			return true
		}
	}
	return false
}

// ScrubHTTPErrorPayload handles this narrow Claude compatibility case before
// the existing identity scrubber; all other errors retain their prior behavior.
func ScrubHTTPErrorPayload(status int, body []byte) ([]byte, bool) {
	if IsClaudeSafeguardsUnsupported(status, body) {
		out, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    ClaudeSafeguardsUnsupportedType,
				"message": ClaudeSafeguardsUnsupportedMessage,
			},
		})
		return out, true
	}
	return ScrubErrorPayload(body)
}
