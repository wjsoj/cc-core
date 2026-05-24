package kirobridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ConvertOptions tunes the request-side translation behavior.
type ConvertOptions struct {
	// AgentTaskType defaults to "vibe" (kiro.rs precedent).
	AgentTaskType string
	// ChatTriggerType defaults to "MANUAL" — "AUTO" can trigger 400s upstream.
	ChatTriggerType string
	// Origin defaults to "AI_EDITOR" (kiro.rs IDE flavor). Use "KIRO_CLI" for
	// CLI flavor.
	Origin string
	// ProfileARN to attach at the top level. Required for billing; pass
	// kiroauth.SharedProfileARN unless you have a custom enterprise profile.
	ProfileARN string
	// ConversationID. If empty, derives from req.metadata.user_id (when it
	// carries a session UUID) or from a sha256 of the messages.
	ConversationID string
	// AllowImages toggles image content block processing. Set false for
	// FlavorCLI requests targeting text-only models (e.g. glm-5).
	AllowImages bool
}

// ConvertResult is the return shape — KiroRequest plus the tool-name map so a
// fork can rename tool_use events on the response side back to their original
// names when ShortenToolName fired.
type ConvertResult struct {
	Request     *KiroRequest
	ToolNameMap ToolNameMap
}

// Convert builds a Kiro GenerateAssistantResponse request from an Anthropic
// /v1/messages payload.
//
// Translation rules (mirrors kiro.rs convert_request):
//
//  1. Map model name → Kiro modelId. Falls through to ModelAuto if unknown.
//  2. Drop a trailing assistant message (Claude 4.x deprecates prefill;
//     Kiro rejects it).
//  3. Derive conversationId from metadata.user_id session UUID, then from
//     content hash if missing.
//  4. Walk messages: last user message → currentMessage, prior → history.
//  5. Fold system prompt into currentMessage.content as a CONTEXT ENTRY block.
//  6. Convert images on the last message via media_type → format inference.
//  7. Validate tool_use ↔ tool_result pairing; drop orphans on both sides.
//  8. Add placeholder Tool entries for any tool name used in history but
//     missing from tools[] (Kiro requires every used tool to be declared).
//  9. Shorten tool names > 63 chars; record the mapping.
// 10. Normalize each tool's input_schema.
//
// Requires at least one user message; returns *ConvertError otherwise.
func Convert(req *AnthropicRequest, opts ConvertOptions) (*ConvertResult, error) {
	if req == nil {
		return nil, &ConvertError{Msg: "anthropic request is nil"}
	}
	if len(req.Messages) == 0 {
		return nil, &ConvertError{Msg: "anthropic request has no messages"}
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
	if modelID == "" {
		modelID = ModelAuto
	}
	systemText := parseSystem(req.System)

	// Strip trailing assistant (prefill) by truncating to the last user msg.
	msgs := dropTrailingAssistant(req.Messages)
	if len(msgs) == 0 {
		return nil, &ConvertError{Msg: "no user messages after prefill strip"}
	}
	lastIdx := len(msgs) - 1
	last := msgs[lastIdx]
	if last.Role != "user" {
		return nil, &ConvertError{Msg: "last message must have role=user"}
	}

	currentBlocks := parseContent(last.Content)
	currentContent, currentImages, currentToolResults := splitUserContent(currentBlocks, opts.AllowImages)
	if systemText != "" {
		currentContent = wrapWithContext(systemText, currentContent)
	}

	history := buildHistory(msgs[:lastIdx], modelID, opts.Origin, opts.AllowImages)

	// Validate tool_use ↔ tool_result pairing; remove orphans.
	validated, orphans := validateToolPairing(history, currentToolResults)
	removeOrphanedToolUses(history, orphans)

	nameMap := make(ToolNameMap)
	tools := convertTools(req.Tools, nameMap)

	// Add placeholders for any history tool name missing from tools[].
	existing := make(map[string]bool, len(tools))
	for _, t := range tools {
		existing[strings.ToLower(t.ToolSpecification.Name)] = true
	}
	for _, name := range collectHistoryToolNames(history) {
		if !existing[strings.ToLower(name)] {
			tools = append(tools, placeholderTool(name))
			existing[strings.ToLower(name)] = true
		}
	}

	convID := opts.ConversationID
	if convID == "" {
		if req.Metadata != nil {
			convID = ExtractSessionID(req.Metadata.UserID)
		}
	}
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
					Images:  currentImages,
					UserInputMessageContext: KiroUserInputMessageContext{
						Tools:       tools,
						ToolResults: validated,
					},
				},
			},
			History: history,
		},
	}
	return &ConvertResult{Request: kr, ToolNameMap: nameMap}, nil
}

// dropTrailingAssistant truncates msgs to the last user message. Returns the
// original slice when the last message is already user (no copy).
func dropTrailingAssistant(msgs []AnthropicMessage) []AnthropicMessage {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[:i+1]
		}
	}
	return nil
}

// splitUserContent walks Anthropic user-turn blocks into:
//   - concatenated text content for Kiro's `content` field
//   - image attachments
//   - tool_result entries
func splitUserContent(blocks []ContentBlock, allowImages bool) (string, []KiroImage, []KiroToolResult) {
	var sb strings.Builder
	var images []KiroImage
	var results []KiroToolResult
	for _, b := range blocks {
		switch b.Type {
		case "text":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(b.Text)
		case "image":
			if !allowImages || b.Source == nil {
				continue
			}
			img := convertImage(b.Source)
			if img != nil {
				images = append(images, *img)
			}
		case "tool_result":
			results = append(results, convertToolResult(b))
		}
	}
	return sb.String(), images, results
}

// convertImage maps an Anthropic image source to a KiroImage. Returns nil
// when the media_type is unsupported or the data is unfetchable (url-source).
func convertImage(src *ImageSource) *KiroImage {
	if src == nil {
		return nil
	}
	if src.Type != "base64" {
		// url-source: we don't fetch remote at this layer. Caller can
		// pre-process by downloading + setting Type="base64" + Data.
		return nil
	}
	format := imageFormatFromMediaType(src.MediaType)
	if format == "" {
		return nil
	}
	return &KiroImage{
		Format: format,
		Source: KiroImageSource{Bytes: src.Data},
	}
}

func imageFormatFromMediaType(mt string) string {
	switch strings.ToLower(mt) {
	case "image/jpeg", "image/jpg":
		return "jpeg"
	case "image/png":
		return "png"
	case "image/gif":
		return "gif"
	case "image/webp":
		return "webp"
	default:
		return ""
	}
}

// convertToolResult maps an Anthropic tool_result block to KiroToolResult.
// Anthropic content can be a string OR an array of text blocks; we coerce
// both to Kiro's [{"text": "..."}] shape (joined with newlines).
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
			// kiro.rs joins all text blocks into a single {"text": joined}.
			var parts []string
			for _, blk := range inner {
				if blk.Type == "text" {
					parts = append(parts, blk.Text)
				}
			}
			if len(parts) > 0 {
				return []map[string]any{{"text": strings.Join(parts, "\n")}}
			}
			return []map[string]any{{"text": ""}}
		}
	}
	// Object or fallback: serialize verbatim as text.
	return []map[string]any{{"text": string(raw)}}
}

// buildHistory converts every message except the last into Kiro history entries.
func buildHistory(msgs []AnthropicMessage, modelID, origin string, allowImages bool) []KiroHistoryEntry {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]KiroHistoryEntry, 0, len(msgs))
	for _, m := range msgs {
		blocks := parseContent(m.Content)
		switch m.Role {
		case "user":
			text, images, results := splitUserContent(blocks, allowImages)
			out = append(out, KiroHistoryEntry{
				UserInputMessage: &KiroUserInputMessage{
					Content: text,
					ModelID: modelID,
					Origin:  origin,
					Images:  images,
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
			input := b.Input
			if len(input) == 0 {
				input = json.RawMessage(`{}`)
			}
			uses = append(uses, KiroToolUseEntry{
				ToolUseID: b.ID,
				Name:      b.Name,
				Input:     input,
			})
		}
	}
	return sb.String(), uses
}

func convertTools(tools []AnthropicTool, nameMap ToolNameMap) []KiroTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]KiroTool, 0, len(tools))
	for _, t := range tools {
		short := ShortenToolName(t.Name)
		nameMap.Apply(short, t.Name)
		out = append(out, KiroTool{
			ToolSpecification: KiroToolSpec{
				Name:        short,
				Description: t.Description,
				InputSchema: KiroInputSchema{JSON: NormalizeJSONSchema(t.InputSchema)},
			},
		})
	}
	return out
}

// validateToolPairing walks history to collect all tool_use IDs and which of
// them already have a tool_result in history. Then for each currentResult:
//   - if it matches an unpaired history tool_use ID → keep
//   - if it matches an already-paired tool_use ID → drop (duplicate)
//   - if it matches no known tool_use → drop (orphan)
//
// Returns kept tool_results AND the set of tool_use IDs from history that
// never got a tool_result (orphan tool_use; caller must scrub from history).
func validateToolPairing(history []KiroHistoryEntry, currentResults []KiroToolResult) ([]KiroToolResult, map[string]bool) {
	allUseIDs := make(map[string]bool)
	pairedUseIDs := make(map[string]bool)
	for _, e := range history {
		if e.AssistantResponseMessage != nil {
			for _, tu := range e.AssistantResponseMessage.ToolUses {
				allUseIDs[tu.ToolUseID] = true
			}
		}
		if e.UserInputMessage != nil {
			for _, tr := range e.UserInputMessage.UserInputMessageContext.ToolResults {
				pairedUseIDs[tr.ToolUseID] = true
			}
		}
	}
	unpaired := make(map[string]bool, len(allUseIDs))
	for id := range allUseIDs {
		if !pairedUseIDs[id] {
			unpaired[id] = true
		}
	}

	kept := make([]KiroToolResult, 0, len(currentResults))
	for _, r := range currentResults {
		if unpaired[r.ToolUseID] {
			kept = append(kept, r)
			delete(unpaired, r.ToolUseID)
		}
		// else: orphan or duplicate → silently drop (kiro.rs would log; we omit logger dep)
	}
	return kept, unpaired
}

// removeOrphanedToolUses scrubs ToolUses entries from history whose ID is in
// orphans. Entries become nil-out if they end up empty.
func removeOrphanedToolUses(history []KiroHistoryEntry, orphans map[string]bool) {
	if len(orphans) == 0 {
		return
	}
	for i := range history {
		am := history[i].AssistantResponseMessage
		if am == nil || len(am.ToolUses) == 0 {
			continue
		}
		kept := am.ToolUses[:0]
		for _, tu := range am.ToolUses {
			if !orphans[tu.ToolUseID] {
				kept = append(kept, tu)
			}
		}
		if len(kept) == 0 {
			am.ToolUses = nil
		} else {
			am.ToolUses = kept
		}
	}
}

func collectHistoryToolNames(history []KiroHistoryEntry) []string {
	seen := make(map[string]bool)
	var out []string
	for _, e := range history {
		if e.AssistantResponseMessage == nil {
			continue
		}
		for _, tu := range e.AssistantResponseMessage.ToolUses {
			if !seen[tu.Name] {
				seen[tu.Name] = true
				out = append(out, tu.Name)
			}
		}
	}
	return out
}

// placeholderTool synthesizes a minimal Tool entry. Kiro requires every tool
// name referenced in history to be declared in currentMessage.tools — even if
// the tool definition has since been removed by the caller.
func placeholderTool(name string) KiroTool {
	return KiroTool{
		ToolSpecification: KiroToolSpec{
			Name:        name,
			Description: "Tool used in conversation history",
			InputSchema: KiroInputSchema{JSON: json.RawMessage(
				`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{},"required":[],"additionalProperties":true}`)},
		},
	}
}

// wrapWithContext prepends the system prompt as a CONTEXT ENTRY block so it
// reaches the model through Kiro's no-top-level-system constraint.
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

// ExtractSessionID pulls a session UUID out of an Anthropic metadata.user_id
// value. Supports both formats kiro.rs accepts:
//
//	JSON object:  {"device_id":"…","account_uuid":"…","session_id":"<UUID>"}
//	String tag:   user_xxx_account__session_<UUID>
//
// Returns "" if neither matches a valid UUID.
func ExtractSessionID(userID string) string {
	if userID == "" {
		return ""
	}
	// Try JSON object form.
	if strings.HasPrefix(strings.TrimSpace(userID), "{") {
		var obj struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal([]byte(userID), &obj); err == nil && isValidUUID(obj.SessionID) {
			return obj.SessionID
		}
	}
	// Try string-tag form.
	if i := strings.Index(userID, "session_"); i >= 0 {
		s := userID[i+len("session_"):]
		if len(s) >= 36 && isValidUUID(s[:36]) {
			return s[:36]
		}
	}
	return ""
}

func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	count := 0
	for _, c := range s {
		if c == '-' {
			count++
		}
	}
	return count == 4
}

// deriveConversationID hashes the messages into a stable UUID-shape string.
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
	hexed := hex.EncodeToString(sum[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

// ConvertError is returned by Convert when the Anthropic input is malformed.
type ConvertError struct{ Msg string }

func (e *ConvertError) Error() string { return "kirobridge: " + e.Msg }
