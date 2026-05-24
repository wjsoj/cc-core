package kirobridge

import "encoding/json"

// NormalizeJSONSchema coerces a tool input_schema into the well-formed shape
// Kiro requires. MCP-defined schemas in the wild often have `required: null`,
// `properties: null`, missing `type`, etc., which cause the server to reject
// the whole request with 400 "Improperly formed request".
//
// The defaults applied:
//   - type missing/null/non-string  → "object"
//   - properties missing/non-object → {}
//   - required missing/non-array    → []  (also: non-string elements dropped)
//   - additionalProperties missing  → true  (bool or object kept as-is)
//
// Non-object input (e.g. JSON `null`, `true`, an array) is replaced with the
// canonical empty object schema.
//
// Mirrors kiro.rs normalize_json_schema() in src/anthropic/converter.rs.
func NormalizeJSONSchema(raw json.RawMessage) json.RawMessage {
	canonical := json.RawMessage(`{"type":"object","properties":{},"required":[],"additionalProperties":true}`)
	if len(raw) == 0 {
		return canonical
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return canonical
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return canonical
	}

	// type: must be a non-empty string
	if t, ok := obj["type"].(string); !ok || t == "" {
		obj["type"] = "object"
	}

	// properties: must be an object
	if _, ok := obj["properties"].(map[string]any); !ok {
		obj["properties"] = map[string]any{}
	}

	// required: must be an array of strings
	switch req := obj["required"].(type) {
	case []any:
		filtered := make([]string, 0, len(req))
		for _, item := range req {
			if s, ok := item.(string); ok {
				filtered = append(filtered, s)
			}
		}
		obj["required"] = filtered
	default:
		obj["required"] = []string{}
	}

	// additionalProperties: bool OR object are both fine; anything else → true
	if v, ok := obj["additionalProperties"]; ok {
		switch v.(type) {
		case bool, map[string]any:
			// keep
		default:
			obj["additionalProperties"] = true
		}
	} else {
		obj["additionalProperties"] = true
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return canonical
	}
	return out
}
