package mimicry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PreparationErrorCode is a stable, privacy-safe classification for a local
// request-preparation rejection. Callers must log the code rather than the
// underlying error text: that text can contain downstream field names and is
// not useful to an end user.
type PreparationErrorCode string

const (
	PreparationErrorInvalidJSON               PreparationErrorCode = "invalid_json_body"
	PreparationErrorInvalidMessages           PreparationErrorCode = "invalid_messages"
	PreparationErrorInvalidMessageRole        PreparationErrorCode = "invalid_message_role"
	PreparationErrorInvalidMessageContent     PreparationErrorCode = "invalid_message_content"
	PreparationErrorInvalidDirectiveStructure PreparationErrorCode = "invalid_directive_structure"
	PreparationErrorInvalidSystem             PreparationErrorCode = "invalid_system"
	PreparationErrorInvalidTools              PreparationErrorCode = "invalid_tools"
	PreparationErrorInvalidToolChoice         PreparationErrorCode = "invalid_tool_choice"
	PreparationErrorInvalidOutputConfig       PreparationErrorCode = "invalid_output_config"
	PreparationErrorInvalidContextManagement  PreparationErrorCode = "invalid_context_management"
)

// PreparationError carries no request content. It deliberately exposes only a
// stable code so hosts can make retry/fallback decisions without matching
// free-form error messages.
type PreparationError struct {
	Code PreparationErrorCode
	err  error
}

func (e *PreparationError) Error() string {
	if e == nil {
		return ""
	}
	if e.err == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.err.Error()
}

func (e *PreparationError) Unwrap() error { return e.err }

func newPreparationError(code PreparationErrorCode, format string, args ...any) error {
	return &PreparationError{Code: code, err: fmt.Errorf(format, args...)}
}

// PreparationErrorCodeOf returns a stable error code for a preparation error.
// Empty means that the error was not classified by this package.
func PreparationErrorCodeOf(err error) PreparationErrorCode {
	var preparationErr *PreparationError
	if errors.As(err, &preparationErr) {
		return preparationErr.Code
	}
	return ""
}

// IsClientRequestPreparationError reports errors caused by an invalid Generic
// Messages shape. Such a request must not be tried against another OAuth
// account or an API key: it is deterministic and would only amplify traffic.
func IsClientRequestPreparationError(err error) bool {
	switch PreparationErrorCodeOf(err) {
	case PreparationErrorInvalidJSON,
		PreparationErrorInvalidMessages,
		PreparationErrorInvalidMessageRole,
		PreparationErrorInvalidMessageContent,
		PreparationErrorInvalidDirectiveStructure,
		PreparationErrorInvalidSystem,
		PreparationErrorInvalidTools,
		PreparationErrorInvalidToolChoice,
		PreparationErrorInvalidOutputConfig,
		PreparationErrorInvalidContextManagement:
		return true
	default:
		return false
	}
}

const structuredOutputsBeta = "structured-outputs-2025-12-15"

// normalizeGenericSynthesisBody accepts the interoperable subset of the
// Anthropic Messages request that can be faithfully placed in a Claude Code
// OAuth request. It never invents user content or tool arguments. It moves
// ordinary system-role messages into top-level system, while retaining the
// special directive-only system form (empty content plus output_config) that
// Anthropic accepts in the message list.
func normalizeGenericSynthesisBody(body []byte) (map[string]json.RawMessage, string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, "", newPreparationError(PreparationErrorInvalidJSON, "generic body is not a JSON object")
	}
	if err := requireStringMember(obj, "model", PreparationErrorInvalidJSON); err != nil {
		return nil, "", err
	}

	systemBlocks, err := normalizeTopLevelSystem(obj)
	if err != nil {
		return nil, "", err
	}
	messages, directiveOutputConfigs, err := normalizeGenericMessages(obj, &systemBlocks)
	if err != nil {
		return nil, "", err
	}
	if err := normalizeToolsAndChoice(obj); err != nil {
		return nil, "", err
	}
	beta, err := genericBetaForBody(obj, directiveOutputConfigs)
	if err != nil {
		return nil, "", err
	}

	stripCacheControlFromBlocks(systemBlocks)
	applySystemCacheBreakpoints(systemBlocks)
	if err := applyGenericMessageCacheBreakpoints(messages); err != nil {
		return nil, "", err
	}

	billing := buildExternalBillingBlock(body, CLICurrentVersion)
	fullSystem := []json.RawMessage{billing, buildSystemTextBlock(ClaudeCodeSystemPrompt, false, false)}
	fullSystem = append(fullSystem, systemBlocks...)
	encodedSystem, err := json.Marshal(fullSystem)
	if err != nil {
		return nil, "", fmt.Errorf("marshal normalized generic system: %w", err)
	}
	encodedMessages, err := json.Marshal(messages)
	if err != nil {
		return nil, "", fmt.Errorf("marshal normalized generic messages: %w", err)
	}
	obj["system"] = encodedSystem
	obj["messages"] = encodedMessages
	return obj, beta, nil
}

func requireStringMember(obj map[string]json.RawMessage, key string, code PreparationErrorCode) error {
	raw, ok := obj[key]
	if !ok {
		return newPreparationError(code, "generic body has no %q", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return newPreparationError(code, "generic body %q is not a non-empty string", key)
	}
	return nil
}

func normalizeTopLevelSystem(obj map[string]json.RawMessage) ([]json.RawMessage, error) {
	raw, ok := obj["system"]
	if !ok || isJSONNull(raw) {
		return nil, nil
	}
	return normalizeSystemBlocks(raw)
}

func normalizeSystemBlocks(raw json.RawMessage) ([]json.RawMessage, error) {
	if isJSONNull(raw) {
		return nil, newPreparationError(PreparationErrorInvalidSystem, "system may not be null in this position")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		block, marshalErr := json.Marshal(map[string]any{"type": "text", "text": text})
		if marshalErr != nil {
			return nil, marshalErr
		}
		return []json.RawMessage{block}, nil
	}

	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, newPreparationError(PreparationErrorInvalidSystem, "system is neither a string nor a block array")
	}
	normalized := make([]json.RawMessage, 0, len(blocks))
	for i, rawBlock := range blocks {
		block, err := normalizeSystemTextBlock(rawBlock)
		if err != nil {
			return nil, newPreparationError(PreparationErrorInvalidSystem, "system block %d: %v", i, err)
		}
		normalized = append(normalized, block)
	}
	return normalized, nil
}

func normalizeSystemTextBlock(raw json.RawMessage) (json.RawMessage, error) {
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil || block == nil {
		return nil, errors.New("not an object")
	}
	var blockType, text string
	if err := json.Unmarshal(block["type"], &blockType); err != nil || blockType != "text" {
		return nil, errors.New("not a text block")
	}
	if err := json.Unmarshal(block["text"], &text); err != nil {
		return nil, errors.New("text is not a string")
	}
	delete(block, "cache_control")
	return json.Marshal(block)
}

func normalizeGenericMessages(obj map[string]json.RawMessage, systemBlocks *[]json.RawMessage) ([]map[string]json.RawMessage, []json.RawMessage, error) {
	rawMessages, ok := obj["messages"]
	if !ok || isJSONNull(rawMessages) || len(bytes.TrimSpace(rawMessages)) == 0 {
		return nil, nil, newPreparationError(PreparationErrorInvalidMessages, "generic body requires a messages array")
	}
	var rawItems []json.RawMessage
	if err := json.Unmarshal(rawMessages, &rawItems); err != nil || len(rawItems) == 0 {
		return nil, nil, newPreparationError(PreparationErrorInvalidMessages, "generic body requires a non-empty messages array")
	}

	normalized := make([]map[string]json.RawMessage, 0, len(rawItems))
	directiveOutputConfigs := make([]json.RawMessage, 0)
	for i, rawItem := range rawItems {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(rawItem, &message); err != nil || message == nil {
			return nil, nil, newPreparationError(PreparationErrorInvalidMessages, "message %d is not an object", i)
		}
		var role string
		if err := json.Unmarshal(message["role"], &role); err != nil {
			return nil, nil, newPreparationError(PreparationErrorInvalidMessageRole, "message %d has no string role", i)
		}
		switch role {
		case "system":
			directive, outputConfig, err := normalizeSystemMessage(message)
			if err != nil {
				return nil, nil, fmt.Errorf("message %d: %w", i, err)
			}
			if directive {
				encoded, marshalErr := json.Marshal(message)
				if marshalErr != nil {
					return nil, nil, marshalErr
				}
				var canonical map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &canonical); err != nil {
					return nil, nil, err
				}
				normalized = append(normalized, canonical)
				directiveOutputConfigs = append(directiveOutputConfigs, outputConfig)
				continue
			}
			blocks, blockErr := normalizeSystemBlocks(message["content"])
			if blockErr != nil {
				return nil, nil, newPreparationError(PreparationErrorInvalidSystem, "message %d system content: %v", i, blockErr)
			}
			*systemBlocks = append(*systemBlocks, blocks...)
		case "user", "assistant":
			if err := normalizeConversationMessage(message); err != nil {
				return nil, nil, fmt.Errorf("message %d: %w", i, err)
			}
			normalized = append(normalized, message)
		default:
			return nil, nil, newPreparationError(PreparationErrorInvalidMessageRole, "message %d has unsupported role", i)
		}
	}
	if len(normalized) == 0 {
		return nil, nil, newPreparationError(PreparationErrorInvalidMessages, "generic body has no user, assistant, or directive message")
	}
	return normalized, directiveOutputConfigs, nil
}

// normalizeSystemMessage distinguishes an ordinary system instruction, which
// must be moved to top-level system, from Anthropic's directive-only form. The
// latter has no prose to move and is intentionally retained at its original
// position.
func normalizeSystemMessage(message map[string]json.RawMessage) (bool, json.RawMessage, error) {
	content, ok := message["content"]
	if !ok {
		return false, nil, newPreparationError(PreparationErrorInvalidMessageContent, "system message has no content")
	}
	outputConfig, hasOutputConfig := message["output_config"]
	if hasOutputConfig {
		if !isEmptyContentArray(content) {
			return false, nil, newPreparationError(PreparationErrorInvalidDirectiveStructure, "system directive must have empty block content")
		}
		if _, err := validateOutputConfig(outputConfig); err != nil {
			return false, nil, err
		}
		for key := range message {
			if key != "role" && key != "content" && key != "output_config" {
				return false, nil, newPreparationError(PreparationErrorInvalidDirectiveStructure, "system directive has unsupported fields")
			}
		}
		return true, outputConfig, nil
	}
	if isEmptyContentArray(content) {
		return false, nil, newPreparationError(PreparationErrorInvalidDirectiveStructure, "empty system content requires output_config")
	}
	for key := range message {
		if key != "role" && key != "content" {
			return false, nil, newPreparationError(PreparationErrorInvalidSystem, "system message has unsupported fields")
		}
	}
	return false, nil, nil
}

func normalizeConversationMessage(message map[string]json.RawMessage) error {
	content, ok := message["content"]
	if !ok {
		return newPreparationError(PreparationErrorInvalidMessageContent, "message has no content")
	}
	var role string
	if err := json.Unmarshal(message["role"], &role); err != nil {
		return newPreparationError(PreparationErrorInvalidMessageRole, "message has no role")
	}
	// Signature recovery can legitimately strip all signed thinking blocks from
	// a historical assistant turn. Retain that empty assistant placeholder; it
	// keeps the surrounding conversation ordering without fabricating prose.
	if err := normalizeContent(content, role == "assistant"); err != nil {
		return err
	}
	return stripCacheControlFromMessage(message)
}

func normalizeContent(raw json.RawMessage, allowEmpty bool) error {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return nil
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return newPreparationError(PreparationErrorInvalidMessageContent, "content is neither a string nor a block array")
	}
	if !allowEmpty && len(blocks) == 0 {
		return newPreparationError(PreparationErrorInvalidMessageContent, "content block array is empty")
	}
	for i, rawBlock := range blocks {
		var block map[string]json.RawMessage
		if err := json.Unmarshal(rawBlock, &block); err != nil || block == nil {
			return newPreparationError(PreparationErrorInvalidMessageContent, "content block %d is not an object", i)
		}
		var blockType string
		if err := json.Unmarshal(block["type"], &blockType); err != nil || strings.TrimSpace(blockType) == "" {
			return newPreparationError(PreparationErrorInvalidMessageContent, "content block %d has no string type", i)
		}
	}
	return nil
}

func stripCacheControlFromMessage(message map[string]json.RawMessage) error {
	content := message["content"]
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(content, &blocks); err != nil {
		return nil // string content has no per-block cache control.
	}
	for _, block := range blocks {
		delete(block, "cache_control")
	}
	encoded, err := json.Marshal(blocks)
	if err != nil {
		return err
	}
	message["content"] = encoded
	return nil
}

func applyGenericMessageCacheBreakpoints(messages []map[string]json.RawMessage) error {
	for i := len(messages) - 1; i >= 0; i-- {
		var role string
		if err := json.Unmarshal(messages[i]["role"], &role); err != nil || (role != "user" && role != "assistant") {
			continue
		}
		return addCacheControlToLastTextBlock(messages[i])
	}
	return nil
}

func addCacheControlToLastTextBlock(message map[string]json.RawMessage) error {
	content := message["content"]
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		encoded, marshalErr := json.Marshal([]map[string]any{{
			"type": "text", "text": text,
			"cache_control": map[string]any{"type": "ephemeral", "ttl": ClaudeDefaultCacheTTL},
		}})
		if marshalErr != nil {
			return marshalErr
		}
		message["content"] = encoded
		return nil
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(content, &blocks); err != nil {
		return newPreparationError(PreparationErrorInvalidMessageContent, "cached message content is invalid")
	}
	for i := len(blocks) - 1; i >= 0; i-- {
		var blockType string
		if err := json.Unmarshal(blocks[i]["type"], &blockType); err != nil || blockType != "text" {
			continue
		}
		cacheControl, marshalErr := json.Marshal(map[string]any{"type": "ephemeral", "ttl": ClaudeDefaultCacheTTL})
		if marshalErr != nil {
			return marshalErr
		}
		blocks[i]["cache_control"] = cacheControl
		encoded, encodeErr := json.Marshal(blocks)
		if encodeErr != nil {
			return encodeErr
		}
		message["content"] = encoded
		return nil
	}
	// A tool-only trailing message has no universally cacheable content block.
	// Keeping it unannotated is safer than attaching cache_control to an
	// unsupported block type and causing an upstream validation error.
	return nil
}

func normalizeToolsAndChoice(obj map[string]json.RawMessage) error {
	rawTools, hasTools := obj["tools"]
	toolNames := make(map[string]struct{})
	if hasTools && !isJSONNull(rawTools) {
		var tools []json.RawMessage
		if err := json.Unmarshal(rawTools, &tools); err != nil {
			return newPreparationError(PreparationErrorInvalidTools, "tools is not an array")
		}
		canonical := make([]json.RawMessage, 0, len(tools))
		for i, rawTool := range tools {
			var tool map[string]json.RawMessage
			if err := json.Unmarshal(rawTool, &tool); err != nil || tool == nil {
				return newPreparationError(PreparationErrorInvalidTools, "tool %d is not an object", i)
			}
			var name string
			if err := json.Unmarshal(tool["name"], &name); err != nil || strings.TrimSpace(name) == "" {
				return newPreparationError(PreparationErrorInvalidTools, "tool %d has no non-empty name", i)
			}
			if _, duplicate := toolNames[name]; duplicate {
				return newPreparationError(PreparationErrorInvalidTools, "tools contain duplicate names")
			}
			toolNames[name] = struct{}{}
			encoded, marshalErr := json.Marshal(tool)
			if marshalErr != nil {
				return marshalErr
			}
			canonical = append(canonical, encoded)
		}
		encoded, err := json.Marshal(canonical)
		if err != nil {
			return err
		}
		obj["tools"] = encoded
	} else {
		delete(obj, "tools")
	}

	rawChoice, hasChoice := obj["tool_choice"]
	if !hasChoice || isJSONNull(rawChoice) {
		delete(obj, "tool_choice")
		return nil
	}
	if len(toolNames) == 0 {
		return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice requires tools")
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(rawChoice, &choice); err != nil || choice == nil {
		return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice is not an object")
	}
	var choiceType string
	if err := json.Unmarshal(choice["type"], &choiceType); err != nil {
		return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice has no string type")
	}
	switch choiceType {
	case "auto", "any", "none":
	case "tool":
		var name string
		if err := json.Unmarshal(choice["name"], &name); err != nil {
			return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice tool has no name")
		}
		if _, ok := toolNames[name]; !ok {
			return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice names an undeclared tool")
		}
	default:
		return newPreparationError(PreparationErrorInvalidToolChoice, "tool_choice has unsupported type")
	}
	encoded, err := json.Marshal(choice)
	if err != nil {
		return err
	}
	obj["tool_choice"] = encoded
	return nil
}

func genericBetaForBody(obj map[string]json.RawMessage, directiveOutputConfigs []json.RawMessage) (string, error) {
	structured := false
	if raw, ok := obj["output_config"]; ok {
		usesStructured, err := validateOutputConfig(raw)
		if err != nil {
			return "", err
		}
		structured = structured || usesStructured
	}
	for _, raw := range directiveOutputConfigs {
		usesStructured, err := validateOutputConfig(raw)
		if err != nil {
			return "", err
		}
		structured = structured || usesStructured
	}
	if raw, ok := obj["context_management"]; ok && !isJSONNull(raw) {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			return "", newPreparationError(PreparationErrorInvalidContextManagement, "context_management is not an object")
		}
	}
	if raw, ok := obj["thinking"]; ok && !isJSONNull(raw) {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			return "", newPreparationError(PreparationErrorInvalidOutputConfig, "thinking is not an object")
		}
	}
	if !structured {
		return ClaudeAnthropicBetaFull, nil
	}
	// A structured output body must carry the same capability marker as the
	// captured Claude Code title path. Do not accept an arbitrary downstream
	// beta list: Generic uses a controlled profile, not a copied one.
	return ClaudeAnthropicBetaFull + "," + structuredOutputsBeta, nil
}

func validateOutputConfig(raw json.RawMessage) (bool, error) {
	if isJSONNull(raw) {
		return false, newPreparationError(PreparationErrorInvalidOutputConfig, "output_config may not be null")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil || config == nil {
		return false, newPreparationError(PreparationErrorInvalidOutputConfig, "output_config is not an object")
	}
	rawFormat, hasFormat := config["format"]
	if !hasFormat || isJSONNull(rawFormat) {
		return false, nil
	}
	var format map[string]json.RawMessage
	if err := json.Unmarshal(rawFormat, &format); err != nil || format == nil {
		return false, newPreparationError(PreparationErrorInvalidOutputConfig, "output_config.format is not an object")
	}
	var formatType string
	if err := json.Unmarshal(format["type"], &formatType); err != nil || formatType != "json_schema" {
		return false, newPreparationError(PreparationErrorInvalidOutputConfig, "output_config.format has unsupported type")
	}
	if rawSchema, ok := format["schema"]; !ok || isJSONNull(rawSchema) {
		return false, newPreparationError(PreparationErrorInvalidOutputConfig, "output_config.format has no schema")
	}
	return true, nil
}

// validateSynthesizedGenericBody re-checks the final, account-bound payload
// immediately before it can be installed on an OAuth request. Keeping this
// independent from the transformer makes a future partial refactor fail
// closed rather than putting an invalid intermediate body on the wire.
func validateSynthesizedGenericBody(body []byte) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return "", newPreparationError(PreparationErrorInvalidJSON, "prepared generic body is not a JSON object")
	}
	if err := requireStringMember(obj, "model", PreparationErrorInvalidJSON); err != nil {
		return "", err
	}
	if _, _, _, err := parseSingleBillingSystem(obj["system"]); err != nil {
		return "", fmt.Errorf("prepared generic system: %w", err)
	}

	// The first two blocks are proxy-owned. The remaining system prompt must
	// still conform to the same text-block contract as normalized ingress.
	var system []json.RawMessage
	if err := json.Unmarshal(obj["system"], &system); err != nil || len(system) < 2 {
		return "", newPreparationError(PreparationErrorInvalidSystem, "prepared generic system is not a block array")
	}
	for i, raw := range system[2:] {
		if _, err := normalizeSystemTextBlock(raw); err != nil {
			return "", newPreparationError(PreparationErrorInvalidSystem, "prepared system block %d: %v", i+2, err)
		}
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(obj["messages"], &messages); err != nil || len(messages) == 0 {
		return "", newPreparationError(PreparationErrorInvalidMessages, "prepared generic messages is not a non-empty array")
	}
	directiveOutputConfigs := make([]json.RawMessage, 0)
	for i, raw := range messages {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(raw, &message); err != nil || message == nil {
			return "", newPreparationError(PreparationErrorInvalidMessages, "prepared message %d is not an object", i)
		}
		var role string
		if err := json.Unmarshal(message["role"], &role); err != nil {
			return "", newPreparationError(PreparationErrorInvalidMessageRole, "prepared message %d has no role", i)
		}
		switch role {
		case "user", "assistant":
			if err := normalizeConversationMessage(message); err != nil {
				return "", fmt.Errorf("prepared message %d: %w", i, err)
			}
		case "system":
			directive, outputConfig, err := normalizeSystemMessage(message)
			if err != nil {
				return "", fmt.Errorf("prepared message %d: %w", i, err)
			}
			if !directive {
				return "", newPreparationError(PreparationErrorInvalidMessageRole, "prepared message %d retains a non-directive system role", i)
			}
			directiveOutputConfigs = append(directiveOutputConfigs, outputConfig)
		default:
			return "", newPreparationError(PreparationErrorInvalidMessageRole, "prepared message %d has unsupported role", i)
		}
	}
	if err := normalizeToolsAndChoice(obj); err != nil {
		return "", err
	}
	return genericBetaForBody(obj, directiveOutputConfigs)
}

func isEmptyContentArray(raw json.RawMessage) bool {
	var blocks []json.RawMessage
	return !isJSONNull(raw) && json.Unmarshal(raw, &blocks) == nil && len(blocks) == 0
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// ClaudeRequestStructureSHA256 returns a domain-separated digest of JSON
// shape, never of prompt text, tool arguments, tokens, UUIDs, or headers. It
// is safe to store for deduplicating deterministic request failures.
func ClaudeRequestStructureSHA256(body []byte) string {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		sum := sha256.Sum256([]byte("claude-structure/v1\x00invalid-json"))
		return fmt.Sprintf("%x", sum[:])
	}
	redacted := redactJSONStrings(value)
	canonical, err := json.Marshal(redacted)
	if err != nil {
		canonical = []byte("marshal-error")
	}
	sum := sha256.Sum256(append([]byte("claude-structure/v1\x00"), canonical...))
	return fmt.Sprintf("%x", sum[:])
}

func redactJSONStrings(value any) any {
	switch typed := value.(type) {
	case string:
		return "<string>"
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactJSONStrings(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = redactJSONStrings(item)
		}
		return out
	default:
		return value
	}
}
