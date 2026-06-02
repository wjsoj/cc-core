package kirobridge

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/wjsoj/cc-core/kiroapi"
	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

// SSEEvent is one SSE event ready to write to the Anthropic client.
//
// Wire format: `event: <Name>\ndata: <Data>\n\n`. Callers serialize via
// (*SSEEvent).Marshal() or write the two fields directly.
type SSEEvent struct {
	Name string // e.g. "message_start", "content_block_delta"
	Data []byte // JSON payload
}

// Marshal returns the canonical SSE-on-wire bytes for this event.
func (e *SSEEvent) Marshal() []byte {
	out := make([]byte, 0, len(e.Name)+len(e.Data)+16)
	out = append(out, "event: "...)
	out = append(out, e.Name...)
	out = append(out, "\ndata: "...)
	out = append(out, e.Data...)
	out = append(out, "\n\n"...)
	return out
}

// StreamTranslator converts a kiroapi.Stream of Kiro event-stream frames into
// the Anthropic SSE event sequence. Caller pulls SSE events one at a time
// via Next() until either it returns false (clean end) or Err() is non-nil.
//
// Emitted events follow Anthropic's published schema:
//
//	message_start            (once, with message id + model + empty content)
//	content_block_start      (per content block: text, tool_use, etc.)
//	content_block_delta      (per delta chunk)
//	content_block_stop       (per block end)
//	message_delta            (with stop_reason + final usage)
//	message_stop
//
// Tool-use blocks accumulate input_json from streamed toolUseEvent frames;
// we emit a content_block_start with empty input and stream input_json_delta
// for each fragment, then content_block_stop when stop=true.
type StreamTranslator struct {
	src          *kiroapi.Stream
	model        string // Anthropic model name to echo in message_start
	messageID    string
	nameMap      ToolNameMap // optional short→original tool-name reverse map

	queue        []SSEEvent
	current      SSEEvent
	err          error
	closed       bool

	// State:
	started      bool                // emitted message_start
	textOpen     bool                // an open text content_block index 0
	textIndex    int
	nextIndex    int
	openTools    map[string]int      // toolUseId → block index
	stopReason   string              // accumulates "tool_use" or "end_turn"
	usage        anthropicUsage      // final input/output tokens (from messageMetadataEvent etc.)
	usageStarted bool
}

type anthropicUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens,omitempty"`
}

// NewStreamTranslator wraps src with translation state. messageID should be a
// caller-generated UUID (will end up as `message.id` in the SSE stream);
// pass kirotransport.NewInvocationID() if you don't have one.
func NewStreamTranslator(src *kiroapi.Stream, anthropicModel, messageID string) *StreamTranslator {
	return NewStreamTranslatorWithMap(src, anthropicModel, messageID, nil)
}

// NewStreamTranslatorWithMap is NewStreamTranslator that additionally accepts
// the (short→original) tool-name map produced by Convert. When set, the
// translator restores the original Anthropic tool name in every
// content_block_start it emits (mirrors kiro.rs process_tool_use's
// `tool_name_map.get(&tool_use.name)` lookup). Pass nil when no shortening
// happened on the way in.
func NewStreamTranslatorWithMap(src *kiroapi.Stream, anthropicModel, messageID string, nameMap ToolNameMap) *StreamTranslator {
	return &StreamTranslator{
		src:       src,
		model:     anthropicModel,
		messageID: messageID,
		nameMap:   nameMap,
		openTools: make(map[string]int),
		nextIndex: 0,
	}
}

// Next advances to the next SSE event. Returns false on clean end or error.
// Check Err() to distinguish.
func (t *StreamTranslator) Next() bool {
	// Always drain queued events first — even after closed=true, the
	// final message_delta + message_stop need to be served.
	if len(t.queue) > 0 {
		t.current = t.queue[0]
		t.queue = t.queue[1:]
		return true
	}
	if t.err != nil || t.closed {
		return false
	}
	// Pull next Kiro frame and translate it; this may enqueue several events.
	for len(t.queue) == 0 {
		if !t.src.Next() {
			if err := t.src.Err(); err != nil {
				t.err = err
				return false
			}
			// End of source — emit final close events if we haven't yet,
			// then drain them via the top-of-loop queue check.
			if t.started && !t.closed {
				t.emitCloseEvents()
				t.closed = true
				if len(t.queue) > 0 {
					t.current = t.queue[0]
					t.queue = t.queue[1:]
					return true
				}
			}
			return false
		}
		t.translateFrame(t.src.Frame())
	}
	t.current = t.queue[0]
	t.queue = t.queue[1:]
	return true
}

// Event returns the most recent SSE event from Next().
func (t *StreamTranslator) Event() SSEEvent { return t.current }

// Err returns the terminating error, or nil on clean stream end.
func (t *StreamTranslator) Err() error { return t.err }

func (t *StreamTranslator) translateFrame(frame *eventstream.Frame) {
	et, payload, perr := kiroapi.ParseEvent(frame)
	if perr != nil {
		// Surface as a final message_stop with stop_reason="error" — Anthropic
		// callers expect a stream-terminating event, not a mid-stream panic.
		t.err = perr
		return
	}

	if !t.started {
		t.emit("message_start", t.messageStartPayload())
		t.started = true
	}

	switch v := payload.(type) {
	case *kiroapi.AssistantResponseEvent:
		t.ensureTextBlock()
		t.emit("content_block_delta", textDeltaPayload(t.textIndex, v.Content))
		t.usage.OutputTokens++ // rough estimate; replaced by metadata if present
	case *kiroapi.ToolUseEvent:
		t.handleToolUse(v)
	case *kiroapi.ContextUsageEvent:
		t.usage.InputTokens = v.InputTokens
		if v.OutputTokens > 0 {
			t.usage.OutputTokens = v.OutputTokens
		}
		t.usage.CacheReadInputTokens = v.CacheReadInputTokens
		t.usage.CacheCreationInputTokens = v.CacheCreationTokens
		t.usageStarted = true
	case *kiroapi.MessageMetadataEvent:
		// Conversation metadata — fold into nothing user-visible at the SSE layer.
	case json.RawMessage:
		// Unknown / metering / initial-response: ignore. EventType is in et.
		_ = et
	case nil:
		_ = et
	}
}

func (t *StreamTranslator) ensureTextBlock() {
	if t.textOpen {
		return
	}
	t.textIndex = t.nextIndex
	t.nextIndex++
	t.emit("content_block_start", contentBlockStartTextPayload(t.textIndex))
	t.textOpen = true
}

func (t *StreamTranslator) handleToolUse(ev *kiroapi.ToolUseEvent) {
	idx, exists := t.openTools[ev.ToolUseID]
	if !exists {
		// Close any open text block first — Anthropic emits content_block_stop
		// before opening a new tool_use block.
		if t.textOpen {
			t.emit("content_block_stop", contentBlockStopPayload(t.textIndex))
			t.textOpen = false
		}
		idx = t.nextIndex
		t.nextIndex++
		t.openTools[ev.ToolUseID] = idx
		// Restore original tool name if Convert shortened it on the way in.
		name := ev.Name
		if t.nameMap != nil {
			name = t.nameMap.Original(ev.Name)
		}
		t.emit("content_block_start", contentBlockStartToolUsePayload(idx, ev.ToolUseID, name))
	}
	// ev.Input is already a JSON-unescaped fragment of the tool input (Kiro
	// wire format ships it as a JSON-encoded string and ToolUseEvent.Input
	// is a Go string, so json.Unmarshal does the unquoting for us). Emit it
	// verbatim as partial_json — Claude Code reassembles the full input by
	// concatenating fragments across frames.
	if ev.Input != "" {
		t.emit("content_block_delta", inputJSONDeltaPayload(idx, ev.Input))
	}
	if ev.Stop {
		t.emit("content_block_stop", contentBlockStopPayload(idx))
		delete(t.openTools, ev.ToolUseID)
		t.stopReason = "tool_use"
	}
}

func (t *StreamTranslator) emitCloseEvents() {
	if t.textOpen {
		t.emit("content_block_stop", contentBlockStopPayload(t.textIndex))
		t.textOpen = false
	}
	for id, idx := range t.openTools {
		t.emit("content_block_stop", contentBlockStopPayload(idx))
		delete(t.openTools, id)
	}
	stop := t.stopReason
	if stop == "" {
		stop = "end_turn"
	}
	t.emit("message_delta", messageDeltaPayload(stop, t.usage))
	t.emit("message_stop", []byte(`{"type":"message_stop"}`))
}

func (t *StreamTranslator) emit(name string, data []byte) {
	t.queue = append(t.queue, SSEEvent{Name: name, Data: data})
}

// --- payload builders ---

var startPayloadPool = sync.Pool{New: func() any { return make([]byte, 0, 256) }}

func (t *StreamTranslator) messageStartPayload() []byte {
	v := map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            t.messageID,
			"type":          "message",
			"role":          "assistant",
			"model":         t.model,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": anthropicUsage{
				InputTokens:  0,
				OutputTokens: 0,
			},
		},
	}
	out, _ := json.Marshal(v)
	return out
}

func contentBlockStartTextPayload(index int) []byte {
	v := map[string]any{
		"type":          "content_block_start",
		"index":         index,
		"content_block": map[string]any{"type": "text", "text": ""},
	}
	out, _ := json.Marshal(v)
	return out
}

func contentBlockStartToolUsePayload(index int, id, name string) []byte {
	v := map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    id,
			"name":  name,
			"input": map[string]any{},
		},
	}
	out, _ := json.Marshal(v)
	return out
}

func textDeltaPayload(index int, text string) []byte {
	v := map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	out, _ := json.Marshal(v)
	return out
}

func inputJSONDeltaPayload(index int, fragment string) []byte {
	v := map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": fragment},
	}
	out, _ := json.Marshal(v)
	return out
}

func contentBlockStopPayload(index int) []byte {
	return []byte(fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, index))
}

func messageDeltaPayload(stopReason string, u anthropicUsage) []byte {
	v := map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": u,
	}
	out, _ := json.Marshal(v)
	return out
}
