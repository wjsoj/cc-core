package kirobridge

import (
	"crypto/sha256"
	"encoding/hex"
)

// ToolNameMaxLen is the Kiro server-side cap on tool names. Anything longer
// gets the truncate+hash treatment via ShortenToolName so request bodies stay
// valid; the original name is recoverable via the returned map.
const ToolNameMaxLen = 63

// ShortenToolName returns a stable short name for name when it exceeds
// ToolNameMaxLen, using the truncated prefix + "_" + first-8-hex-of-sha256
// scheme kiro.rs uses. The result is deterministic and reversible only via
// the (short → original) map kept alongside.
func ShortenToolName(name string) string {
	if len(name) <= ToolNameMaxLen {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	hashSuffix := hex.EncodeToString(sum[:])[:8]
	// 54 chars of prefix + "_" + 8 hash = 63 total
	const prefixLen = 54
	prefix := name[:prefixLen]
	return prefix + "_" + hashSuffix
}

// ToolNameMap remembers the (Kiro-side short → Anthropic-side original) names
// so a fork can de-rename tool_use events on the way back to the client.
type ToolNameMap map[string]string

// Apply registers (shortName → originalName) only when shortening actually
// happened (short != original).
func (m ToolNameMap) Apply(short, original string) {
	if short != original {
		m[short] = original
	}
}

// Original returns the original tool name for short, or short itself if no
// renaming was recorded.
func (m ToolNameMap) Original(short string) string {
	if orig, ok := m[short]; ok {
		return orig
	}
	return short
}
