package servicetier

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NormalizeRequest canonicalizes only the top-level service_tier. All other
// bytes (including Codex frame key order and user content) remain unchanged.
// Unknown/null tiers are removed; a non-string tier or duplicate tier is an
// error so the upstream and billing cannot interpret the same body differently.
func NormalizeRequest(body []byte) ([]byte, string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return body, "", fmt.Errorf("service tier: expected a JSON object")
	}
	start, end, valueStart := -1, -1, -1
	var value json.RawMessage
	for dec.More() {
		keyStart := int(dec.InputOffset())
		key, err := dec.Token()
		if err != nil {
			return body, "", err
		}
		vs := int(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return body, "", err
		}
		if key == "service_tier" {
			if start >= 0 {
				return body, "", fmt.Errorf("service tier: duplicate service_tier")
			}
			start, end, valueStart, value = keyStart, int(dec.InputOffset()), vs, raw
		}
	}
	if _, err := dec.Token(); err != nil || !json.Valid(body) {
		return body, "", fmt.Errorf("service tier: invalid JSON object")
	}
	if start < 0 {
		return body, "", nil
	}
	var rawTier string
	if err := json.Unmarshal(value, &rawTier); err != nil {
		return body, "", fmt.Errorf("service tier: service_tier must be a string")
	}
	tier := Normalize(rawTier)
	if tier != "" {
		if tier == rawTier {
			return body, tier, nil
		}
		for valueStart < end && (space(body[valueStart]) || body[valueStart] == ':') {
			valueStart++
		}
		quoted, _ := json.Marshal(tier)
		return splice(body, valueStart, end, quoted), tier, nil
	}
	// InputOffset before the key includes its leading comma (if any).
	for start < end && space(body[start]) {
		start++
	}
	if body[start] != ',' {
		// First/only member: remove the following comma instead.
		for end < len(body) && space(body[end]) {
			end++
		}
		if end < len(body) && body[end] == ',' {
			end++
		}
	}
	return splice(body, start, end, nil), "", nil
}

func splice(body []byte, start, end int, replacement []byte) []byte {
	out := make([]byte, 0, len(body)-(end-start)+len(replacement))
	out = append(out, body[:start]...)
	out = append(out, replacement...)
	return append(out, body[end:]...)
}

func space(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

// Request reads the canonical outbound tier without changing the body.
func Request(body []byte) string {
	var request struct {
		Tier string `json:"service_tier"`
	}
	if json.Unmarshal(body, &request) != nil {
		return ""
	}
	return Normalize(request.Tier)
}

// Response reads either an ordinary JSON response or a Responses lifecycle
// event. Observe it before downstream.ScrubCodexEvent removes service_tier.
func Response(body []byte) string {
	var response struct {
		Tier     string `json:"service_tier"`
		Response *struct {
			Tier string `json:"service_tier"`
		} `json:"response"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	if response.Response != nil {
		return Normalize(response.Response.Tier)
	}
	return Normalize(response.Tier)
}
