// Package kiroapi provides typed clients for the CodeWhisperer / AmazonQ
// API surface that Kiro uses, plus the toolkit-telemetry sink.
//
// Three endpoints:
//
//   - ListAvailableModels — sync RPC, returns the model catalog the
//     current credential is allowed to use.
//   - GenerateAssistantResponse — streaming, the actual chat call. Returns
//     an iterator over decoded event-stream frames.
//   - SendTelemetryEvent — fire-and-forget, business-side conversation
//     metrics (timeToFirstChunk, perTurn token usage).
//
// One additional endpoint lives elsewhere on the wire:
//
//   - client-telemetry.<region>.amazonaws.com/metrics — toolkit / product
//     telemetry, SigV4-signed via kirocognito-issued anonymous STS creds.
//     Exposed here as ToolkitTelemetry.
//
// All wire shapes verified against crack/kiro/rows/.
package kiroapi

import (
	"encoding/json"
	"fmt"

	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

// ListAvailableModelsRequest is the body sent to x-amz-target
// AmazonCodeWhispererService.ListAvailableModels.
//
// Wire (crack/kiro/rows/03): {"origin":"KIRO_CLI","profileArn":"..."}.
type ListAvailableModelsRequest struct {
	Origin     string `json:"origin"`               // "KIRO_CLI" for CLI flavor, "KIRO_IDE" for IDE
	ProfileARN string `json:"profileArn,omitempty"` // shared profile ARN from credentials
}

// ListAvailableModelsResponse mirrors the upstream payload (subset).
type ListAvailableModelsResponse struct {
	DefaultModel struct {
		ModelID string `json:"modelId"`
	} `json:"defaultModel"`
	Models []ModelInfo `json:"models"`
}

// ModelInfo is one entry in the models catalog.
type ModelInfo struct {
	ModelID             string                       `json:"modelId"`
	ModelName           string                       `json:"modelName"`
	Description         string                       `json:"description"`
	RateMultiplier      float64                      `json:"rateMultiplier"`
	RateUnit            string                       `json:"rateUnit"`
	SupportedInputTypes []string                     `json:"supportedInputTypes"`
	TokenLimits         *TokenLimits                 `json:"tokenLimits,omitempty"`
	PromptCaching       *PromptCachingCfg            `json:"promptCaching,omitempty"`
	AdditionalRaw       map[string]json.RawMessage   `json:"-"` // overflow bucket
	AdditionalFields    map[string]json.RawMessage   `json:"additionalModelRequestFieldsSchema,omitempty"`
}

// TokenLimits is the published context window for the model.
type TokenLimits struct {
	MaxInputTokens  int64 `json:"maxInputTokens"`
	MaxOutputTokens int64 `json:"maxOutputTokens"`
}

// PromptCachingCfg surfaces whether prompt caching is offered and at what scale.
type PromptCachingCfg struct {
	SupportsPromptCaching            bool  `json:"supportsPromptCaching"`
	MaximumCacheCheckpointsPerRequest int  `json:"maximumCacheCheckpointsPerRequest"`
	MinimumTokensPerCacheCheckpoint   int64 `json:"minimumTokensPerCacheCheckpoint"`
}

// GenerateAssistantResponseRequest is the envelope. The heavy nested
// ConversationState (history + currentMessage + tools + …) is kept as raw
// JSON so callers can compose it directly — the kirobridge package (v0.7.0)
// will provide a builder; here we stay minimal.
//
// Wire (crack/kiro/rows/06):
//
//	{
//	  "conversationState": { ... see ConversationState ... },
//	  "profileArn": "arn:aws:codewhisperer:..."
//	}
type GenerateAssistantResponseRequest struct {
	ConversationState json.RawMessage `json:"conversationState"`
	ProfileARN        string          `json:"profileArn,omitempty"`
}

// SendTelemetryEventRequest mirrors the captured wire shape (crack/kiro/rows/07).
// The full event payload is kept raw for the same reason as ConversationState.
type SendTelemetryEventRequest struct {
	ClientToken    string          `json:"clientToken"`    // UUIDv4 per session
	TelemetryEvent json.RawMessage `json:"telemetryEvent"` // {"chatAddMessageEvent":{...}}
	UserContext    json.RawMessage `json:"userContext,omitempty"`
}

// MessageType is the value of the ":message-type" header on a frame.
type MessageType string

const (
	MessageEvent     MessageType = "event"
	MessageError     MessageType = "error"
	MessageException MessageType = "exception"
)

// EventType is the value of ":event-type" on a normal event frame.
type EventType string

const (
	EventInitialResponse  EventType = "initial-response"
	EventAssistantResponse EventType = "assistantResponseEvent"
	EventToolUse          EventType = "toolUseEvent"
	EventMetering         EventType = "meteringEvent"
	EventContextUsage     EventType = "contextUsageEvent"
	EventMessageMetadata  EventType = "messageMetadataEvent"
	EventCodeReference    EventType = "codeReferenceEvent"
)

// AssistantResponseEvent is the typed payload of an assistantResponseEvent frame.
type AssistantResponseEvent struct {
	Content string `json:"content"`
}

// ToolUseEvent is the typed payload of a toolUseEvent frame.
//
// Kiro sends `input` on the wire as a JSON-encoded STRING that — when the
// stream is reassembled across all fragments — yields the full JSON-encoded
// tool input. We MUST deserialize it as a Go string so that JSON unescaping
// runs (matching kiro.rs `pub input: String` semantics in
// src/kiro/model/events/tool_use.rs). Reading it as json.RawMessage preserves
// the outer quotes + escapes, and forwarding that verbatim as Anthropic
// `partial_json` causes Claude Code to see a JSON string literal instead of
// the tool input object → "Invalid tool parameters" rejection.
type ToolUseEvent struct {
	ToolUseID string `json:"toolUseId"`
	Name      string `json:"name"`
	Input     string `json:"input,omitempty"` // streamed partial JSON, already unescaped
	Stop      bool   `json:"stop,omitempty"`  // true on the last fragment
}

// ContextUsageEvent reports prompt cache hit/miss + token counts.
type ContextUsageEvent struct {
	InputTokens          int64 `json:"inputTokens,omitempty"`
	OutputTokens         int64 `json:"outputTokens,omitempty"`
	CacheReadInputTokens int64 `json:"cacheReadInputTokens,omitempty"`
	CacheCreationTokens  int64 `json:"cacheCreationInputTokens,omitempty"`
}

// MessageMetadataEvent is the final billing summary frame.
type MessageMetadataEvent struct {
	ConversationID string `json:"conversationId,omitempty"`
	UtteranceID    string `json:"utteranceId,omitempty"`
}

// ParseEvent decodes one Frame into a typed Go event.
//
// Returns:
//   - (eventType, parsedValue, nil) for known event-type strings — parsedValue
//     is one of the *Event structs above (or nil for unknown).
//   - (eventType, raw json.RawMessage, nil) for an unrecognized event-type —
//     callers can still see the wire payload.
//   - (_, _, *RemoteError) for ":message-type"="error" frames.
//   - (_, _, *RemoteException) for ":message-type"="exception" frames.
//   - (_, _, err) for JSON parse errors.
func ParseEvent(frame *eventstream.Frame) (EventType, any, error) {
	switch MessageType(frame.MessageType()) {
	case MessageError, "":
		if MessageType(frame.MessageType()) == MessageError {
			return "", nil, &RemoteError{
				Code:    frame.Headers.ErrorCode(),
				Message: string(frame.Payload),
			}
		}
		// empty message-type → treat as event (some legacy frames omit it)
		fallthrough
	case MessageEvent:
		et := EventType(frame.EventType())
		switch et {
		case EventAssistantResponse:
			var v AssistantResponseEvent
			if err := frame.PayloadJSON(&v); err != nil {
				return et, nil, fmt.Errorf("kiroapi: parse %s: %w", et, err)
			}
			return et, &v, nil
		case EventToolUse:
			var v ToolUseEvent
			if err := frame.PayloadJSON(&v); err != nil {
				return et, nil, fmt.Errorf("kiroapi: parse %s: %w", et, err)
			}
			return et, &v, nil
		case EventContextUsage:
			var v ContextUsageEvent
			if err := frame.PayloadJSON(&v); err != nil {
				return et, nil, fmt.Errorf("kiroapi: parse %s: %w", et, err)
			}
			return et, &v, nil
		case EventMessageMetadata:
			var v MessageMetadataEvent
			if err := frame.PayloadJSON(&v); err != nil {
				return et, nil, fmt.Errorf("kiroapi: parse %s: %w", et, err)
			}
			return et, &v, nil
		default:
			// Unknown / metering / initial-response / etc: return raw payload.
			return et, json.RawMessage(frame.Payload), nil
		}
	case MessageException:
		return "", nil, &RemoteException{
			Type:    frame.Headers.ExceptionType(),
			Message: string(frame.Payload),
		}
	default:
		return EventType(frame.EventType()), json.RawMessage(frame.Payload), nil
	}
}

// RemoteError is a structured ":message-type"="error" frame.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("kiroapi: remote error %q: %s", e.Code, truncate(e.Message, 200))
}

// RemoteException is a structured ":message-type"="exception" frame
// (e.g. ThrottlingException, ValidationException, MonthlyRequestLimitExceeded).
type RemoteException struct {
	Type    string
	Message string
}

func (e *RemoteException) Error() string {
	return fmt.Sprintf("kiroapi: remote exception %q: %s", e.Type, truncate(e.Message, 200))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
