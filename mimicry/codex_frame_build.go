package mimicry

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// Building a `response.create` frame from an HTTP-shaped Responses body.
//
// The two Codex transports carry the SAME request in two envelopes. The HTTP
// path POSTs the Responses body as-is; the WebSocket path sends that body's
// fields spread into a frame whose first key is `"type":"response.create"`.
// So a proxy that accepts an HTTP request and wants to forward it over a
// WebSocket needs the body's fields, plus that key, in the captured order.
//
// # Why this REORDERS rather than preserves
//
// Everywhere else in this package, a body rewrite is a byte splice, because
// Go's map-based encoder emits keys sorted and the captured order is part of
// the shape. Here the opposite is true, and it is worth being explicit about
// why the usual rule is inverted.
//
// The input to this function is the output of SanitizeCodexRequestBody, which
// unmarshals into a map[string]any and marshals it back. Its result is
// therefore ALREADY alphabetical: model, include, input, parallel_tool_calls,
// prompt_cache_key, reasoning, store, stream, text, tool_choice. There is no
// original order left to preserve — it was destroyed one call earlier — so
// splicing `type` onto the front produces `type` followed by an alphabetical
// run, which is an order no genuine client emits.
//
// Given that the information is already gone, rendering into the CAPTURED
// order is strictly better than leaving the alphabetical one. It is the only
// point in the pipeline where the frame's real shape can be restored.
//
// Ground truth for the order: crack/codexapp0.147.0/rows/15 (turn-opening) and
// rows/18 (continuation, which inserts previous_response_id directly after
// model and is otherwise identical). `stream_options` appears on a real turn
// and not on a prewarm; `generate` appears on a prewarm and not on a turn;
// both sit in the positions listed below when present.

// CodexResponseCreateType is the frame type that opens a turn on the Codex
// WebSocket transport.
const CodexResponseCreateType = "response.create"

// codexFrameKeyOrder is the captured top-level key order of a response.create
// frame. Keys absent from the body are skipped, so one slice renders the
// prewarm, turn and continuation variants alike.
//
// client_metadata is last and is normally not present yet at this point —
// RewriteCodexClientFrame appends it — but it is listed so a body that already
// carries one keeps it in the right place instead of being treated as unknown.
var codexFrameKeyOrder = []string{
	"type",
	"model",
	"previous_response_id",
	"input",
	"tool_choice",
	"parallel_tool_calls",
	"reasoning",
	"store",
	"stream",
	"stream_options",
	"include",
	"prompt_cache_key",
	"text",
	"generate",
	"client_metadata",
}

// NewCodexResponseCreateFrame wraps a Responses request body as the
// `response.create` frame the Codex WebSocket transport expects, with its keys
// in the captured order.
//
// body must be a JSON object — the sanitized upstream body that would otherwise
// have been POSTed to /codex/responses. Values are copied verbatim; only the
// key ORDER changes, plus the added `type`. A key the captures do not name is
// preserved and emitted after the known ones (sorted, so the output is
// deterministic) and before client_metadata: dropping a field the caller sent
// would change the request, which is never this function's job.
//
// A body that already declares a top-level `type` is accepted when that type is
// already response.create, and rejected otherwise — silently re-typing a frame
// the caller meant as something else would turn a control message into a turn.
//
// The result still needs RewriteCodexClientFrame to bind it to the connection's
// identity; that call synthesizes the client_metadata this frame does not have
// and rebinds prompt_cache_key. Sending the output of THIS function directly
// would present a frame with no client_metadata at all, which no genuine client
// emits.
//
// The caller does NOT need to force `stream`. SanitizeCodexRequestBody already
// sets it true unconditionally, because the backend only emits completed
// responses over SSE; a caller that sets it again through a map round-trip
// would undo the ordering this function exists to restore.
func NewCodexResponseCreateFrame(body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("mimicry: response.create frame body is not a JSON object")
	}
	switch t := codexFrameType(trimmed); t {
	case CodexResponseCreateType, "":
		// Expected: an HTTP Responses body has no `type`, and a frame we
		// already built has the right one.
	default:
		return nil, errors.New("mimicry: refusing to re-type frame " + t + " as response.create")
	}
	return orderCodexFrame(trimmed, true)
}

// CanonicalizeCodexFrameKeys re-emits a response.create frame with its
// top-level keys in the captured order, leaving every value byte-identical.
//
// It exists because the ordering has to be the LAST thing done to a frame we
// assembled ourselves. Two steps between building and sending round-trip the
// body through a Go map and therefore re-sort it: SanitizeCodexRequestBody
// before, and servicetier.NormalizeRequest inside RewriteCodexClientFrame
// after. Ordering in the builder alone is silently undone by the second one —
// which is exactly what happened, and what a key-order assertion caught.
//
// Callers that must preserve a DOWNSTREAM client's own byte order (the WS
// ingress relay forwards genuine client frames) must not call this. It is for
// frames this process built, where there is no original order to protect.
//
// A frame that is not a response.create is returned unchanged.
func CanonicalizeCodexFrameKeys(frame []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return frame, nil
	}
	if codexFrameType(trimmed) != CodexResponseCreateType {
		return frame, nil
	}
	return orderCodexFrame(trimmed, false)
}

func orderCodexFrame(trimmed []byte, addType bool) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	if addType {
		fields["type"] = json.RawMessage(`"` + CodexResponseCreateType + `"`)
	}

	known := make(map[string]bool, len(codexFrameKeyOrder))
	for _, k := range codexFrameKeyOrder {
		known[k] = true
	}
	extra := make([]string, 0, len(fields))
	for k := range fields {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)

	var out bytes.Buffer
	out.Grow(len(trimmed) + 32)
	out.WriteByte('{')
	first := true
	write := func(k string) {
		v, ok := fields[k]
		if !ok {
			return
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		key, _ := json.Marshal(k)
		out.Write(key)
		out.WriteByte(':')
		out.Write(v)
	}
	for _, k := range codexFrameKeyOrder {
		if k == "client_metadata" {
			continue // emitted last, after the unknown keys
		}
		write(k)
	}
	for _, k := range extra {
		write(k)
	}
	write("client_metadata")
	out.WriteByte('}')
	return out.Bytes(), nil
}
