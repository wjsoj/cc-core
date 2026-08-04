package thinkingsig

import "encoding/json"

// sourceSessionID returns the genuine Claude Code source session embedded in
// metadata.user_id. Claude Code serializes user_id as a JSON string rather than
// a nested object. Distinct conversations can start with identical reminder
// text, so this is the authoritative conversation key when present.
func sourceSessionID(body []byte) string {
	var obj struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil || obj.Metadata.UserID == "" {
		return ""
	}
	var identity struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(obj.Metadata.UserID), &identity); err != nil {
		return ""
	}
	return identity.SessionID
}

// firstUserText returns the first user message's text content from a
// /v1/messages JSON body. Used as the conversation anchor inside this
// package; mirrors what callers' SessionIDFor does so the switch
// detection grain matches their session-id derivation.
//
// content can be either a plain string ("hi") or an array of typed
// blocks ([{"type":"text","text":"hi"}]). Returns "" when neither
// shape applies — caller treats that as "no signal".
func firstUserText(body []byte) string {
	var obj struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	for _, m := range obj.Messages {
		if m.Role != "user" {
			continue
		}
		var asString string
		if err := json.Unmarshal(m.Content, &asString); err == nil {
			return asString
		}
		var blocks []map[string]any
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			for _, b := range blocks {
				if t, _ := b["type"].(string); t == "text" {
					if s, _ := b["text"].(string); s != "" {
						return s
					}
				}
			}
		}
		return ""
	}
	return ""
}
