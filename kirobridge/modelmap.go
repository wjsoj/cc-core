package kirobridge

import "strings"

// Kiro server-side modelId values. Verified against
// crack/kiro/rows/03 (ListAvailableModels response), 2026-05 capture.
const (
	ModelAuto             = "auto"
	ModelClaudeOpus47     = "claude-opus-4.7"
	ModelClaudeOpus46     = "claude-opus-4.6"
	ModelClaudeOpus45     = "claude-opus-4.5"
	ModelClaudeSonnet46   = "claude-sonnet-4.6"
	ModelClaudeSonnet45   = "claude-sonnet-4.5"
	ModelClaudeSonnet4    = "claude-sonnet-4"
	ModelClaudeHaiku45    = "claude-haiku-4.5"
	ModelDeepseek32       = "deepseek-3.2"
	ModelMinimaxM25       = "minimax-m2.5"
	ModelMinimaxM21       = "minimax-m2.1"
	ModelGLM5             = "glm-5"
	ModelQwen3CoderNext   = "qwen3-coder-next"
)

// MapModel returns the Kiro modelId for an Anthropic model name. Matching is
// case-insensitive and substring-based on family + version, so dated suffixes
// (`-20250929`) and tags (`-latest`, `-thinking`) all collapse to the right id.
//
// Mirrors kiro.rs map_model() in src/anthropic/converter.rs.
//
// Returns "" if the input doesn't look like a known family — caller can decide
// whether to fall back to ModelAuto or reject.
func MapModel(model string) string {
	low := strings.ToLower(model)
	switch {
	case strings.Contains(low, "sonnet"):
		switch {
		case strings.Contains(low, "4-6") || strings.Contains(low, "4.6"):
			return ModelClaudeSonnet46
		case strings.Contains(low, "4-5") || strings.Contains(low, "4.5"):
			return ModelClaudeSonnet45
		case strings.Contains(low, "sonnet-4"):
			return ModelClaudeSonnet4
		default:
			return ModelClaudeSonnet45 // newest sonnet without a version
		}
	case strings.Contains(low, "opus"):
		switch {
		case strings.Contains(low, "4-7") || strings.Contains(low, "4.7"):
			return ModelClaudeOpus47
		case strings.Contains(low, "4-6") || strings.Contains(low, "4.6"):
			return ModelClaudeOpus46
		case strings.Contains(low, "4-5") || strings.Contains(low, "4.5"):
			return ModelClaudeOpus45
		default:
			return ModelClaudeOpus47 // newest opus without a version
		}
	case strings.Contains(low, "haiku"):
		return ModelClaudeHaiku45
	case strings.Contains(low, "deepseek"):
		return ModelDeepseek32
	case strings.Contains(low, "minimax"):
		if strings.Contains(low, "2.5") || strings.Contains(low, "m2-5") {
			return ModelMinimaxM25
		}
		return ModelMinimaxM21
	case strings.Contains(low, "glm"):
		return ModelGLM5
	case strings.Contains(low, "qwen"):
		return ModelQwen3CoderNext
	}
	return ""
}

// ContextWindow returns the published context window size (in tokens) for a
// Kiro modelId. Opus 4.6 / Opus 4.7 / Sonnet 4.6 went to 1M on 2026-03-24
// (kiro.rs get_context_window_size); everything else is 200K.
//
// Pass the result of MapModel(...), not the Anthropic-side name.
func ContextWindow(kiroModelID string) int {
	switch kiroModelID {
	case ModelClaudeOpus47, ModelClaudeOpus46, ModelClaudeSonnet46:
		return 1_000_000
	default:
		return 200_000
	}
}

// SupportedInputTypes reports whether the model accepts a given Anthropic
// content block type. From ListAvailableModels:
//   - TEXT  — every model
//   - IMAGE — every model except glm-5 and minimax-m2.5
func SupportedInputTypes(kiroModelID string) []string {
	switch kiroModelID {
	case ModelGLM5, ModelMinimaxM25:
		return []string{"TEXT"}
	default:
		return []string{"TEXT", "IMAGE"}
	}
}
