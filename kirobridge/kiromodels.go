// Package kirobridge translates between Anthropic /v1/messages and Kiro
// GenerateAssistantResponse. Forks proxying Claude requests to a Kiro
// credential pool import this package to avoid hand-rolling the conversion.
//
// Scope as of v0.7.0:
//   - Request: system + messages + tools + tool_result → Kiro
//     ConversationState (current message + history + toolSpecifications).
//   - Response: Kiro event-stream → Anthropic SSE event sequence
//     (message_start, content_block_start/delta/stop, message_delta, message_stop).
//   - Model mapping for the four current Claude families.
//
// Not yet implemented in v0.7.0 (planned for v0.7.x):
//   - WebSearch tool transform (kiro.rs websearch.rs).
//   - Image content blocks (text-only for now).
//   - Full JSON-schema normalization for MCP-defined tools (kiro.rs
//     normalize_json_schema). Schema is passed through verbatim.
//
// Wire shapes verified against crack/kiro/rows/06 + 14 + 25.
package kirobridge

import "encoding/json"

// --- Kiro side: request types (matches kiro.rs requests/{conversation,tool,kiro}.rs) ---

// KiroRequest is the top-level body sent to GenerateAssistantResponse.
type KiroRequest struct {
	ConversationState KiroConversationState `json:"conversationState"`
	ProfileARN        string                `json:"profileArn,omitempty"`
}

// KiroConversationState carries the active turn plus prior history.
type KiroConversationState struct {
	AgentContinuationID string             `json:"agentContinuationId,omitempty"`
	AgentTaskType       string             `json:"agentTaskType,omitempty"` // typically "vibe"
	ChatTriggerType     string             `json:"chatTriggerType,omitempty"` // "MANUAL" | "AUTO"
	ConversationID      string             `json:"conversationId"`
	CurrentMessage      KiroCurrentMessage `json:"currentMessage"`
	History             []KiroHistoryEntry `json:"history,omitempty"`
}

// KiroCurrentMessage wraps the in-flight user message.
type KiroCurrentMessage struct {
	UserInputMessage KiroUserInputMessage `json:"userInputMessage"`
}

// KiroUserInputMessage is the structure shared by both the active turn and
// the user-side history entries.
type KiroUserInputMessage struct {
	Content                 string                      `json:"content"`
	ModelID                 string                      `json:"modelId"`
	Origin                  string                      `json:"origin,omitempty"` // "AI_EDITOR" or similar
	Images                  []KiroImage                 `json:"images,omitempty"`
	UserInputMessageContext KiroUserInputMessageContext `json:"userInputMessageContext"`
}

// KiroUserInputMessageContext carries tool specs (only on current message) and
// any tool results for the prior turn.
type KiroUserInputMessageContext struct {
	Tools       []KiroTool       `json:"tools,omitempty"`
	ToolResults []KiroToolResult `json:"toolResults,omitempty"`
}

// KiroImage is one inline image attachment.
type KiroImage struct {
	Format string          `json:"format"` // "jpeg" | "png" | "gif" | "webp"
	Source KiroImageSource `json:"source"`
}

// KiroImageSource is the bytes wrapper Kiro expects.
type KiroImageSource struct {
	Bytes string `json:"bytes"` // base64-encoded
}

// KiroHistoryEntry is either a HistoryUserMessage or HistoryAssistantMessage.
// We discriminate by which field is non-nil; the JSON shape is `untagged` —
// the receiver detects which field is present on parse.
type KiroHistoryEntry struct {
	UserInputMessage         *KiroUserInputMessage  `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *KiroAssistantMessage  `json:"assistantResponseMessage,omitempty"`
}

// KiroAssistantMessage is the assistant-side history entry.
type KiroAssistantMessage struct {
	Content  string             `json:"content"`
	ToolUses []KiroToolUseEntry `json:"toolUses,omitempty"`
}

// KiroToolUseEntry records one assistant-side tool invocation in history.
type KiroToolUseEntry struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

// KiroTool is one entry in toolSpecifications.
type KiroTool struct {
	ToolSpecification KiroToolSpec `json:"toolSpecification"`
}

// KiroToolSpec describes one callable tool.
type KiroToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema KiroInputSchema `json:"inputSchema"`
}

// KiroInputSchema wraps a JSON Schema under the {"json": ...} key Kiro expects.
type KiroInputSchema struct {
	JSON json.RawMessage `json:"json"`
}

// KiroToolResult reports the outcome of a prior assistant tool_use back to Kiro.
type KiroToolResult struct {
	ToolUseID string                     `json:"toolUseId"`
	Content   []map[string]any           `json:"content"` // typically [{"text": "..."}] or [{"json": {...}}]
	Status    string                     `json:"status,omitempty"`  // "success" | "error"
	IsError   bool                       `json:"isError,omitempty"`
}
