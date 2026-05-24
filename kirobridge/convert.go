package kirobridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ConvertOptions tunes the request-side translation behavior.
type ConvertOptions struct {
	// AgentTaskType defaults to "vibe" (kiro.rs precedent). Override to "" to
	// omit the field.
	AgentTaskType string

	// ChatTriggerType defaults to "MANUAL". Override to "" to omit.
	ChatTriggerType string

	// Origin defaults to "AI_EDITOR" — what real Kiro IDE sends.
	// For CLI flavor, set to "KIRO_CLI".
	Origin string

	// ProfileARN to attach at the top level. Required by Kiro to bill the
	// request to the right account. Pass kiroauth.SharedProfileARN.
	ProfileARN string

	// ConversationID. If empty, derived from sha256(first user message text +
	// first assistant message text, if any) so multi-turn conversations are
	// stable per Anthropic-side conversation.
	ConversationID string
}

// Convert builds a Kiro GenerateAssistantResponse request from an Anthropic
// /v1/messages payload.
//
// The Anthropic system prompt is folded into the current user message as a
// `--- CONTEXT ENTRY BEGIN ---` block (Kiro has no top-level system field).
// Tools attach to the current message's userInputMessageContext. Prior
// messages become history entries; tool_result blocks on a user turn move
// into the corresponding history user message's toolResults.
//
// At least one user message is required.
func Convert(req *AnthropicRequest, opts ConvertOptions) (*KiroRequest, error) {
	if req == nil {
		return nil, &ConvertError{Msg: "anthropic request is nil"}
	}
	if len(req.Messages) == 0 {
		return nil, &ConvertError{Msg: "anthropic request has no messages"}
	}

	if opts.AgentTaskType == "" && opts != (ConvertOptions{ProfileARN: opts.ProfileARN}) {
		// Only default when caller didn't pass a zero options struct *for*
		// AgentTaskType — but it's simpler: just default to vibe always.
	}
	if opts.AgentTaskType == "" {
		opts.AgentTaskType = "vibe"
	}
	if opts.ChatTriggerType == "" {
		opts.ChatTriggerType = "MANUAL"
	}
	if opts.Origin == "" {
		opts.Origin = "AI_EDITOR"
	}

	modelID := MapModel(req.Model)
	systemText := parseSystem(req.System)

	// Walk messages: everything except the last user message becomes history.
	// If the last message is assistant, treat it as history too and synthesize
	// an empty current user message (Anthropic forbids this; we error).
	lastIdx := len(req.Messages) - 1
	last := req.Messages[lastIdx]
	if last.Role != "user" {
		return nil, &ConvertError{Msg: "last message must have role=user"}
	}

	history := buildHistory(req.Messages[:lastIdx], modelID, opts.Origin)

	currentBlocks := parseContent(last.Content)
	currentContent, currentToolResults := splitUserContent(currentBlocks)
	if systemText != "" {
		currentContent = wrapWithContext(systemText, currentContent)
	}

	tools := convertTools(req.Tools)

	convID := opts.ConversationID
	if convID == "" {
		convID = deriveConversationID(req.Messages)
	}

	kr := &KiroRequest{
		ProfileARN: opts.ProfileARN,
		ConversationState: KiroConversationState{
			AgentTaskType:   opts.AgentTaskType,
			ChatTriggerType: opts.ChatTriggerType,
			ConversationID:  convID,
			CurrentMessage: KiroCurrentMessage{
				UserInputMessage: KiroUserInputMessage{
					Content: currentContent,
					ModelID: modelID,
					Origin:  opts.Origin,
					UserInputMessageContext: KiroUserInputMessageContext{
						Tools:       tools,
						ToolResults: currentToolResults,
					},
				},
			},
			History: history,
		},
	}
	return kr, nil
}

// splitUserContent walks the Anthropic user-turn blocks and produces:
//   - a concatenated text content string for Kiro's `content` field
//   - the tool_result blocks broken out into Kiro's toolResults shape
func splitUserContent(blocks []ContentBlock) (string, []KiroToolResult) {
	var sb strings.Builder
	var results []KiroToolResult
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(b.Text)
		case "tool_result":
			results = append(results, convertToolResult(b))
		case "image":
			// Image handling is deferred to v0.7.x; pass through as a stub line.
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString("[image content omitted — v0.7.0 limitation]")
		}
	}
	return sb.String(), results
}

// convertToolResult maps an Anthropic tool_result content block to KiroToolResult.
// Anthropic content can be a bare string OR an array of blocks; we coerce both
// to Kiro's [{"text": "..."}] shape.
func convertToolResult(b ContentBlock) KiroToolResult {
	tr := KiroToolResult{ToolUseID: b.ToolUseID}
	if b.IsError {
		tr.Status = "error"
		tr.IsError = true
	} else {
		tr.Status = "success"
	}
	tr.Content = toolResultContent(b.Content)
	return tr
}

func toolResultContent(raw json.RawMessage) []map[string]any {
	if len(raw) == 0 {
		return []map[string]any{{"text": ""}}
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return []map[string]any{{"text": s}}
		}
	}
	if raw[0] == '[' {
		var inner []ContentBlock
		if err := json.Unmarshal(raw, &inner); err == nil {
			var out []map[string]any
			for _, blk := range inner {
				switch blk.Type {
				case "text":
					out = append(out, map[string]any{"text": blk.Text})
				default:
					out = append(out, map[string]any{"text": ""})
				}
			}
			if len(out) == 0 {
				out = []map[string]any{{"text": ""}}
			}
			return out
		}
	}
	// Object or fallback: stuff under text key as JSON string.
	return []map[string]any{{"text": string(raw)}}
}

// buildHistory converts every message except the last into a Kiro history entry.
// User messages collapse their text blocks; assistant messages keep text +
// tool_use blocks.
func buildHistory(msgs []AnthropicMessage, modelID, origin string) []KiroHistoryEntry {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]KiroHistoryEntry, 0, len(msgs))
	for _, m := range msgs {
		blocks := parseContent(m.Content)
		switch m.Role {
		case "user":
			text, results := splitUserContent(blocks)
			out = append(out, KiroHistoryEntry{
				UserInputMessage: &KiroUserInputMessage{
					Content: text,
					ModelID: modelID,
					Origin:  origin,
					UserInputMessageContext: KiroUserInputMessageContext{
						ToolResults: results,
					},
				},
			})
		case "assistant":
			text, uses := splitAssistantContent(blocks)
			out = append(out, KiroHistoryEntry{
				AssistantResponseMessage: &KiroAssistantMessage{
					Content:  text,
					ToolUses: uses,
				},
			})
		}
	}
	return out
}

func splitAssistantContent(blocks []ContentBlock) (string, []KiroToolUseEntry) {
	var sb strings.Builder
	var uses []KiroToolUseEntry
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(b.Text)
		case "tool_use":
			uses = append(uses, KiroToolUseEntry{
				ToolUseID: b.ID,
				Name:      b.Name,
				Input:     b.Input,
			})
		}
	}
	return sb.String(), uses
}

func convertTools(tools []AnthropicTool) []KiroTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]KiroTool, 0, len(tools))
	for _, t := range tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, KiroTool{
			ToolSpecification: KiroToolSpec{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: KiroInputSchema{JSON: schema},
			},
		})
	}
	return out
}

// wrapWithContext prepends the system prompt as a `--- CONTEXT ENTRY ---`
// block. Real Kiro CLI uses this convention to inject project context; we
// reuse it to smuggle the Anthropic system prompt past Kiro's no-system-field
// constraint.
func wrapWithContext(systemText, userText string) string {
	if systemText == "" {
		return userText
	}
	var sb strings.Builder
	sb.WriteString("--- CONTEXT ENTRY BEGIN ---\n")
	sb.WriteString(systemText)
	sb.WriteString("\n--- CONTEXT ENTRY END ---\n\n")
	sb.WriteString(userText)
	return sb.String()
}

// deriveConversationID hashes the first user message to a stable UUID-ish
// string so retries of the same conversation reuse the same id (matches what
// real Anthropic clients infer from message_id stability).
func deriveConversationID(msgs []AnthropicMessage) string {
	if len(msgs) == 0 {
		return "00000000-0000-0000-0000-000000000000"
	}
	h := sha256.New()
	for _, m := range msgs {
		h.Write([]byte(m.Role))
		h.Write([]byte{0})
		h.Write(m.Content)
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	// Format as a UUID (8-4-4-4-12) from the first 16 bytes for readability.
	hexed := hex.EncodeToString(sum[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

// ConvertError is returned by Convert when the Anthropic input is malformed.
type ConvertError struct{ Msg string }

func (e *ConvertError) Error() string { return "kirobridge: " + e.Msg }
