package kirobridge

import "strings"

// ModelMap maps Anthropic model names → Kiro modelId values. Entries follow
// kiro.rs map_model() — extend here when bumping Claude families.
//
// Unknown inputs fall through to "auto" so the Kiro server picks a default
// instead of returning ValidationException.
var ModelMap = map[string]string{
	// Claude 3.5 / 3.7 Sonnet family
	"claude-3-5-sonnet-20240620":    "CLAUDE_3_5_SONNET_V1_0",
	"claude-3-5-sonnet-20241022":    "CLAUDE_3_5_SONNET_20241022_V2_0",
	"claude-3-5-sonnet-latest":      "CLAUDE_3_5_SONNET_20241022_V2_0",
	"claude-3-7-sonnet-20250219":    "CLAUDE_3_7_SONNET_20250219_V1_0",
	"claude-3-7-sonnet-latest":      "CLAUDE_3_7_SONNET_20250219_V1_0",
	// Claude 4 Sonnet / Opus
	"claude-sonnet-4-20250514":      "CLAUDE_SONNET_4_20250514_V1_0",
	"claude-sonnet-4-5-20250929":    "CLAUDE_SONNET_4_5_V1_0",
	"claude-sonnet-4-6":             "CLAUDE_SONNET_4_5_V1_0",
	"claude-opus-4-20250514":        "CLAUDE_OPUS_4_20250514_V1_0",
	"claude-opus-4-1-20250805":      "CLAUDE_OPUS_4_1_20250805_V1_0",
	"claude-opus-4-7":               "CLAUDE_OPUS_4_1_20250805_V1_0",
	// Haiku
	"claude-3-5-haiku-20241022":     "CLAUDE_3_5_HAIKU_20241022_V1_0",
	"claude-haiku-4-5-20251001":     "CLAUDE_HAIKU_4_5_V1_0",
}

// MapModel returns the Kiro modelId for an Anthropic model name. Falls back
// to a prefix match and finally to "auto" if nothing matches.
func MapModel(anthropicModel string) string {
	if anthropicModel == "" {
		return "auto"
	}
	if id, ok := ModelMap[anthropicModel]; ok {
		return id
	}
	// Prefix fallback: e.g. unknown "claude-opus-4-1-20251231" matches the
	// "claude-opus-4-1-" prefix already in the map.
	for k, v := range ModelMap {
		// Strip trailing date suffix from k and compare prefix.
		if i := strings.LastIndexByte(k, '-'); i > 0 {
			if strings.HasPrefix(anthropicModel, k[:i+1]) {
				return v
			}
		}
	}
	return "auto"
}
