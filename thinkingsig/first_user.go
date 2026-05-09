package thinkingsig

import "encoding/json"

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
