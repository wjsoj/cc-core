package kirobridge

import "encoding/json"

// --- Anthropic side: subset of /v1/messages we need to translate from/to ---

// AnthropicRequest is the input body. We only model fields that participate in
// the Kiro translation; unrelated fields (top_p, top_k, stop_sequences, etc.)
// are ignored.
type AnthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    json.RawMessage    `json:"system,omitempty"`     // string OR array of system blocks
	Messages  []AnthropicMessage `json:"messages"`
	Tools     []AnthropicTool    `json:"tools,omitempty"`
	Stream    bool               `json:"stream,omitempty"`
	Metadata  *AnthropicMetadata `json:"metadata,omitempty"`
}

// AnthropicMetadata mirrors the Anthropic-side opaque metadata blob.
// user_id is parsed for a session UUID to use as Kiro conversationId — see
// ExtractSessionID in convert.go.
type AnthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

// AnthropicMessage is one entry in the messages array. Content is either a
// string OR a heterogeneous array of content blocks.
type AnthropicMessage struct {
	Role    string          `json:"role"` // "user" | "assistant"
	Content json.RawMessage `json:"content"`
}

// AnthropicTool is one tool definition Claude can call.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ContentBlock is one item inside a multi-block message content array.
// At most one of Text / Image / ToolUse / ToolResult is populated per block.
type ContentBlock struct {
	Type string `json:"type"`

	// type=text
	Text string `json:"text,omitempty"`

	// type=image
	Source *ImageSource `json:"source,omitempty"`

	// type=tool_use (Anthropic assistant turn)
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// type=tool_result (Anthropic user turn echoing a tool's output)
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"` // string | array of blocks | object
	IsError   bool            `json:"is_error,omitempty"`
}

// ImageSource is the wrapped image data on a type=image content block.
// Anthropic supports two source.type values:
//   - "base64": MediaType + Data (raw base64, no data: prefix)
//   - "url": URL to fetch (caller responsible for download; we don't fetch
//     remotely at this layer)
type ImageSource struct {
	Type      string `json:"type"`                 // "base64" | "url"
	MediaType string `json:"media_type,omitempty"` // "image/png" | "image/jpeg" | ...
	Data      string `json:"data,omitempty"`       // base64 payload
	URL       string `json:"url,omitempty"`        // when type=url
}

// parseContent yields a normalized list of blocks regardless of whether the
// upstream content was a bare string or a real block array.
func parseContent(raw json.RawMessage) []ContentBlock {
	if len(raw) == 0 {
		return nil
	}
	// Try array form first.
	if raw[0] == '[' {
		var blocks []ContentBlock
		if err := json.Unmarshal(raw, &blocks); err == nil {
			return blocks
		}
	}
	// Try string form.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []ContentBlock{{Type: "text", Text: s}}
	}
	// Last resort: a single object.
	var one ContentBlock
	if err := json.Unmarshal(raw, &one); err == nil {
		return []ContentBlock{one}
	}
	return nil
}

// parseSystem normalizes the Anthropic `system` field into plain concatenated
// text. Both `"system":"…"` and `"system":[{"type":"text","text":"…"}, …]` are
// accepted; cache_control on system blocks is ignored at this layer (Kiro has
// no equivalent — caching is server-managed).
func parseSystem(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	if raw[0] == '[' {
		var blocks []ContentBlock
		if err := json.Unmarshal(raw, &blocks); err == nil {
			var out string
			for i, b := range blocks {
				if b.Type == "text" && b.Text != "" {
					if i > 0 {
						out += "\n\n"
					}
					out += b.Text
				}
			}
			return out
		}
	}
	return ""
}
