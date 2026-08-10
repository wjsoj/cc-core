package apicompat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// responses_chat.go is the return leg of the bridge: a Responses reply — either
// a completed response object or the SSE event stream that produced it — is
// rendered back into what a Chat Completions client expects.

// ---------------------------------------------------------------------------
// Non-streaming: Responses object → chat.completion
// ---------------------------------------------------------------------------

// ResponsesToChatCompletion converts a completed Responses object into a
// chat.completion reply.
//
// model is echoed back to the client as-is; the upstream may have resolved an
// alias to a different name and clients match on what they asked for. created
// is supplied by the caller so the value stays deterministic under test.
func ResponsesToChatCompletion(response []byte, model string, created int64) ([]byte, error) {
	var resp struct {
		ID                string `json:"id"`
		Model             string `json:"model"`
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Output []responsesOutputItem `json:"output"`
		Usage  *ResponsesUsage       `json:"usage"`
	}
	if err := json.Unmarshal(response, &resp); err != nil {
		return nil, fmt.Errorf("decode responses object: %w", err)
	}

	var text, reasoning strings.Builder
	toolCalls := make([]map[string]any, 0, 2)
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, part := range item.Content {
				switch part.Type {
				case "output_text", "text":
					text.WriteString(part.Text)
				}
			}
		case "reasoning":
			// Surfaced separately as reasoning_content. Folding it into the
			// answer would make clients render the model's scratchpad as the
			// reply; dropping it loses it for clients that do display it.
			for _, part := range item.Summary {
				reasoning.WriteString(part.Text)
			}
			for _, part := range item.Content {
				if part.Type == "reasoning_text" {
					reasoning.WriteString(part.Text)
				}
			}
		case "function_call":
			args := item.Arguments
			if args == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, map[string]any{
				"id": item.CallID, "type": "function", "index": len(toolCalls),
				"function": map[string]any{"name": item.Name, "arguments": args},
			})
		}
	}

	message := map[string]any{"role": "assistant", "content": text.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	incompleteReason := ""
	if resp.IncompleteDetails != nil {
		incompleteReason = resp.IncompleteDetails.Reason
	}

	if model == "" {
		model = resp.Model
	}
	out := map[string]any{
		"id":      ChatCompletionID(resp.ID),
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason(resp.Status, incompleteReason, len(toolCalls) > 0),
		}},
	}
	if resp.Usage != nil {
		out["usage"] = resp.Usage.chatUsage()
	}
	return json.Marshal(out)
}

type responsesOutputItem struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	CallID    string `json:"call_id"`
	Arguments string `json:"arguments"`
	Content   []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Summary []struct {
		Text string `json:"text"`
	} `json:"summary"`
}

// finishReason maps a Responses terminal status onto the Chat Completions
// vocabulary. An incomplete response is only "length" when the cap is what cut
// it short — a content filter has its own reason, and anything else is an
// ordinary stop.
func finishReason(status, incompleteReason string, sawToolCall bool) string {
	switch status {
	case "incomplete":
		switch incompleteReason {
		case "max_output_tokens":
			return "length"
		case "content_filter":
			return "content_filter"
		}
		return "stop"
	case "completed":
		if sawToolCall {
			return "tool_calls"
		}
		return "stop"
	default:
		if sawToolCall {
			return "tool_calls"
		}
		return "stop"
	}
}

// ChatCompletionID derives the client-facing completion id from the upstream
// response id, so a request stays correlatable across the bridge. Derived
// rather than random, matching the content-addressed identity convention used
// everywhere else in this module.
func ChatCompletionID(responseID string) string {
	id := strings.TrimPrefix(responseID, "resp_")
	if id == "" {
		return "chatcmpl-codex"
	}
	return "chatcmpl-" + id
}

// ResponsesUsage is the Responses token accounting block.
type ResponsesUsage struct {
	InputTokens        int64 `json:"input_tokens"`
	OutputTokens       int64 `json:"output_tokens"`
	TotalTokens        int64 `json:"total_tokens"`
	InputTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

// chatUsage renders the block in the Chat Completions shape. Cached input stays
// counted inside prompt_tokens and is broken out under prompt_tokens_details,
// as OpenAI reports it.
func (u *ResponsesUsage) chatUsage() map[string]any {
	total := u.TotalTokens
	if total == 0 {
		total = u.InputTokens + u.OutputTokens
	}
	out := map[string]any{
		"prompt_tokens":     u.InputTokens,
		"completion_tokens": u.OutputTokens,
		"total_tokens":      total,
	}
	if u.InputTokensDetails != nil {
		out["prompt_tokens_details"] = map[string]any{"cached_tokens": u.InputTokensDetails.CachedTokens}
	}
	if u.OutputTokensDetails != nil {
		out["completion_tokens_details"] = map[string]any{"reasoning_tokens": u.OutputTokensDetails.ReasoningTokens}
	}
	return out
}

// ---------------------------------------------------------------------------
// Streaming: Responses SSE events → chat.completion.chunk frames
// ---------------------------------------------------------------------------

// StreamState converts a sequence of Responses SSE events into Chat
// Completions SSE frames. One instance per request; not safe for concurrent
// use (callers drive it from a single reader goroutine).
type StreamState struct {
	id           string
	model        string
	created      int64
	includeUsage bool

	roleSent    bool
	sawToolCall bool
	finalized   bool
	usage       *ResponsesUsage
	// Responses identifies a streaming function call by output_index (stable
	// for the whole call) and item_id (present on the delta events). Both are
	// tracked because backends are inconsistent about which they populate.
	toolIndexByOutput map[int]int
	toolIndexByItem   map[string]int
}

// NewStreamState returns a stream converter for one request. includeUsage
// mirrors the client's stream_options.include_usage: the trailing choice-less
// usage frame breaks clients that assume every frame carries a choice, so it is
// emitted only on request. created is caller-supplied for determinism.
func NewStreamState(model string, includeUsage bool, created int64) *StreamState {
	return &StreamState{
		id:                "chatcmpl-codex",
		model:             model,
		created:           created,
		includeUsage:      includeUsage,
		toolIndexByOutput: map[int]int{},
		toolIndexByItem:   map[string]int{},
	}
}

// DoneFrame is the sentinel frame that terminates a Chat Completions SSE
// stream. Exported so transports can recognise it without string matching.
var DoneFrame = []byte("data: [DONE]\n\n")

// IsDoneFrame reports whether frame is the stream terminator.
func IsDoneFrame(frame []byte) bool { return bytes.Equal(frame, DoneFrame) }

// Translate maps one Responses SSE data payload onto zero or more Chat
// Completions SSE frames. terminal reports that the stream has ended; the last
// frame of a terminal batch is always DoneFrame.
//
// Unknown event types produce no frames — the Responses stream carries a lot of
// lifecycle chatter (response.in_progress, *.done, content_part.*) that has no
// Chat representation and must not reach the client as empty frames.
func (st *StreamState) Translate(payload []byte) (frames [][]byte, terminal bool) {
	var ev struct {
		Type        string `json:"type"`
		Delta       string `json:"delta"`
		ItemID      string `json:"item_id"`
		OutputIndex *int   `json:"output_index"`
		Item        struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			CallID    string `json:"call_id"`
			Arguments string `json:"arguments"`
		} `json:"item"`
		Usage    *ResponsesUsage    `json:"usage"`
		Response *responsesEnvelope `json:"response"`
	}
	if json.Unmarshal(payload, &ev) != nil {
		return nil, false
	}

	// The first frame of a Chat stream must announce the assistant role;
	// clients that assemble the message incrementally rely on it.
	emitRole := func() {
		if !st.roleSent {
			st.roleSent = true
			frames = append(frames, st.frame(map[string]any{"role": "assistant", "content": ""}, nil))
		}
	}

	switch ev.Type {
	case "response.created":
		if ev.Response != nil && ev.Response.ID != "" {
			st.id = ChatCompletionID(ev.Response.ID)
		}
	case "response.output_text.delta":
		if ev.Delta == "" {
			return nil, false
		}
		emitRole()
		frames = append(frames, st.frame(map[string]any{"content": ev.Delta}, nil))
	case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
		if ev.Delta == "" {
			return nil, false
		}
		emitRole()
		frames = append(frames, st.frame(map[string]any{"reasoning_content": ev.Delta}, nil))
	case "response.output_item.added":
		if ev.Item.Type != "function_call" {
			return nil, false
		}
		emitRole()
		idx := st.newToolIndex(ev.OutputIndex, ev.Item.ID)
		frames = append(frames, st.frame(map[string]any{"tool_calls": []any{map[string]any{
			"index": idx, "id": ev.Item.CallID, "type": "function",
			"function": map[string]any{"name": ev.Item.Name, "arguments": ""},
		}}}, nil))
	case "response.function_call_arguments.delta":
		if ev.Delta == "" {
			return nil, false
		}
		idx, ok := st.lookupToolIndex(ev.OutputIndex, ev.ItemID)
		if !ok {
			// Arguments for a call whose `added` event never arrived: open a
			// slot rather than dropping the payload on the floor.
			idx = st.newToolIndex(ev.OutputIndex, ev.ItemID)
			emitRole()
		}
		frames = append(frames, st.frame(map[string]any{"tool_calls": []any{map[string]any{
			"index": idx, "function": map[string]any{"arguments": ev.Delta},
		}}}, nil))
	case "response.completed", "response.failed", "response.incomplete",
		"response.cancelled", "response.canceled":
		return append(frames, st.finish(ev.Type, ev.Usage, ev.Response)...), true
	}
	return frames, false
}

// Finalize closes a stream whose upstream ended without a terminal event, so
// the client still receives a well-formed finish frame and [DONE] instead of a
// truncated stream it will report as a disconnect. Returns nil if the stream
// was already terminated.
func (st *StreamState) Finalize() [][]byte {
	if st.finalized {
		return nil
	}
	return st.finish("response.completed", nil, nil)
}

// responsesEnvelope is the `response` object carried by lifecycle events.
type responsesEnvelope struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Usage *ResponsesUsage `json:"usage"`
}

func (st *StreamState) finish(evType string, usage *ResponsesUsage, response *responsesEnvelope) [][]byte {
	st.finalized = true
	if usage != nil {
		st.usage = usage
	}
	status := strings.TrimPrefix(evType, "response.")
	incompleteReason := ""
	if response != nil {
		if response.Usage != nil {
			st.usage = response.Usage
		}
		if response.Status != "" {
			status = response.Status
		}
		if response.IncompleteDetails != nil {
			incompleteReason = response.IncompleteDetails.Reason
		}
	}

	var frames [][]byte
	if !st.roleSent {
		st.roleSent = true
		frames = append(frames, st.frame(map[string]any{"role": "assistant", "content": ""}, nil))
	}
	frames = append(frames, st.frame(map[string]any{}, finishReason(status, incompleteReason, st.sawToolCall)))
	if st.includeUsage && st.usage != nil {
		if payload, err := json.Marshal(map[string]any{
			"id": st.id, "object": "chat.completion.chunk", "created": st.created,
			"model": st.model, "choices": []any{}, "usage": st.usage.chatUsage(),
		}); err == nil {
			frames = append(frames, sseFrame(payload))
		}
	}
	return append(frames, DoneFrame)
}

// newToolIndex assigns the next Chat tool_calls index to a streaming function
// call and records it under both identifiers the backend may use later.
func (st *StreamState) newToolIndex(outputIndex *int, itemID string) int {
	if idx, ok := st.lookupToolIndex(outputIndex, itemID); ok {
		return idx
	}
	idx := max(len(st.toolIndexByOutput), len(st.toolIndexByItem))
	if outputIndex != nil {
		st.toolIndexByOutput[*outputIndex] = idx
	}
	if itemID != "" {
		st.toolIndexByItem[itemID] = idx
	}
	st.sawToolCall = true
	return idx
}

func (st *StreamState) lookupToolIndex(outputIndex *int, itemID string) (int, bool) {
	if itemID != "" {
		if idx, ok := st.toolIndexByItem[itemID]; ok {
			return idx, true
		}
	}
	if outputIndex != nil {
		if idx, ok := st.toolIndexByOutput[*outputIndex]; ok {
			return idx, true
		}
	}
	return 0, false
}

// frame renders one chat.completion.chunk SSE frame carrying a choice delta.
func (st *StreamState) frame(delta map[string]any, finish any) []byte {
	payload, err := json.Marshal(map[string]any{
		"id": st.id, "object": "chat.completion.chunk", "created": st.created, "model": st.model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	})
	if err != nil {
		return nil
	}
	return sseFrame(payload)
}

func sseFrame(payload []byte) []byte {
	out := make([]byte, 0, len(payload)+8)
	out = append(out, "data: "...)
	out = append(out, payload...)
	return append(out, '\n', '\n')
}
